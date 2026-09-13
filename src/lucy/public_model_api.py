"""Private, cost-admitted model service for Public Lucy."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lucy.cost_admission import ProviderCostAdmissionService
from lucy.db import create_session_factory
from lucy.public_inference import PublicInferenceCoordinator, PublicInferenceUnavailable
from lucy.public_model import PublicConversationEngine, PublicModelRejected
from lucy.public_model_admission import (
    AdmittedPublicJsonModel,
    OpenRouterInferenceProvider,
)
from lucy.public_model_service import (
    PublicModelServiceHandler,
    PublicModelServiceRequest,
    PublicModelServiceUnavailable,
)
from lucy.public_openrouter import OpenRouterPublicError, OpenRouterPublicJsonModel
from lucy.recovery_acknowledgement import HttpRecoveryAcknowledgementClient
from lucy.recovery_journal import RecoveryStreamKind
from lucy.recovery_writer_client import HttpRecoveryJournalWriterClient

_HOSTPORT = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?:[0-9]{2,5}\Z")
_LOGIN = re.compile(r"lucy_cost_admission\Z")
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_MODEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}/[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}\Z")
_RATE_VERSION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,79}\Z")


class PublicModelApiConfigurationError(ValueError):
    """Content-free model service configuration failure."""


@dataclass(frozen=True)
class PublicModelApiConfiguration:
    database_url: str
    expected_database_login: str
    api_token: str
    allowed_snapshot_digests: tuple[str, ...]
    node_id: UUID
    channel_binding_id: UUID
    model: str
    allowed_providers: tuple[str, ...]
    rate_version: str
    openrouter_api_key: str
    maximum_prompt_usd_per_million: float
    maximum_completion_usd_per_million: float
    generator_maximum_microusd: int
    verifier_maximum_microusd: int
    generator_max_output_tokens: int
    verifier_max_output_tokens: int
    timeout_seconds: int
    maximum_request_bytes: int
    request_commitment_key: bytes
    provider_reference_commitment_key: bytes
    cost_writer_hostport: str
    cost_writer_token: str
    recovery_ack_hostport: str
    recovery_ack_token: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> PublicModelApiConfiguration:
        values = os.environ if environment is None else environment
        login = _required(values, "LUCY_PUBLIC_MODEL_EXPECTED_DATABASE_LOGIN")
        database_url = _required(values, "LUCY_PUBLIC_MODEL_DATABASE_URL")
        token = _required(values, "LUCY_PUBLIC_MODEL_TOKEN")
        model = _required(values, "LUCY_PUBLIC_MODEL_ID")
        rate_version = _required(values, "LUCY_PUBLIC_MODEL_RATE_VERSION")
        if _LOGIN.fullmatch(login) is None or not 32 <= len(token) <= 512:
            raise PublicModelApiConfigurationError("public model identity is invalid")
        try:
            parsed_database = make_url(database_url)
        except Exception:
            raise PublicModelApiConfigurationError("public model database is invalid") from None
        if (
            parsed_database.drivername not in {"postgresql", "postgresql+psycopg"}
            or parsed_database.username != login
            or not parsed_database.password
            or not parsed_database.host
            or not parsed_database.database
        ):
            raise PublicModelApiConfigurationError("public model database is invalid")
        if values.get("LUCY_ENVIRONMENT") == "production" and (
            _PRIVATE_RENDER_HOST.fullmatch(parsed_database.host) is None
            or _LUCY_DATABASE.fullmatch(parsed_database.database) is None
            or parsed_database.port not in (None, 5432)
        ):
            raise PublicModelApiConfigurationError("public model database boundary is invalid")
        if _MODEL.fullmatch(model) is None or _RATE_VERSION.fullmatch(rate_version) is None:
            raise PublicModelApiConfigurationError("public model pin is invalid")
        digests = tuple(
            item.strip()
            for item in _required(
                values, "LUCY_PUBLIC_MODEL_ALLOWED_SNAPSHOT_DIGESTS"
            ).split(",")
            if item.strip()
        )
        if (
            not digests
            or len(set(digests)) != len(digests)
            or any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in digests)
        ):
            raise PublicModelApiConfigurationError("public model snapshot allowlist is invalid")
        providers = tuple(
            item.strip()
            for item in _required(values, "LUCY_PUBLIC_MODEL_ALLOWED_PROVIDERS").split(",")
            if item.strip()
        )
        if not providers or any(len(item) > 100 for item in providers):
            raise PublicModelApiConfigurationError("public model provider allowlist is invalid")
        try:
            node_id = UUID(_required(values, "LUCY_PUBLIC_MODEL_NODE_ID"))
            channel_id = UUID(_required(values, "LUCY_PUBLIC_MODEL_CHANNEL_BINDING_ID"))
        except ValueError:
            raise PublicModelApiConfigurationError("public model scope is invalid") from None
        writer_hostport = _hostport(values, "LUCY_COST_WRITER_HOSTPORT")
        ack_hostport = _hostport(values, "LUCY_RECOVERY_ACK_HOSTPORT")
        return cls(
            database_url=database_url,
            expected_database_login=login,
            api_token=token,
            allowed_snapshot_digests=digests,
            node_id=node_id,
            channel_binding_id=channel_id,
            model=model,
            allowed_providers=providers,
            rate_version=rate_version,
            openrouter_api_key=_required(values, "OPENROUTER_API_KEY"),
            maximum_prompt_usd_per_million=_positive_float(
                values, "LUCY_PUBLIC_MODEL_MAX_PROMPT_USD_PER_MILLION"
            ),
            maximum_completion_usd_per_million=_positive_float(
                values, "LUCY_PUBLIC_MODEL_MAX_COMPLETION_USD_PER_MILLION"
            ),
            generator_maximum_microusd=_bounded_int(
                values, "LUCY_PUBLIC_MODEL_GENERATOR_MAX_MICROUSD", 1, 1_000_000
            ),
            verifier_maximum_microusd=_bounded_int(
                values, "LUCY_PUBLIC_MODEL_VERIFIER_MAX_MICROUSD", 1, 1_000_000
            ),
            generator_max_output_tokens=_bounded_int(
                values, "LUCY_PUBLIC_MODEL_GENERATOR_MAX_TOKENS", 64, 4_096
            ),
            verifier_max_output_tokens=_bounded_int(
                values, "LUCY_PUBLIC_MODEL_VERIFIER_MAX_TOKENS", 64, 4_096
            ),
            timeout_seconds=_bounded_int(
                values, "LUCY_PUBLIC_MODEL_TIMEOUT_SECONDS", 1, 30
            ),
            maximum_request_bytes=_bounded_int(
                values, "LUCY_PUBLIC_MODEL_MAX_REQUEST_BYTES", 10_000, 1_000_000
            ),
            request_commitment_key=_base64_key(
                values, "LUCY_PUBLIC_MODEL_REQUEST_COMMITMENT_KEY_B64"
            ),
            provider_reference_commitment_key=_base64_key(
                values, "LUCY_PUBLIC_MODEL_PROVIDER_REFERENCE_KEY_B64"
            ),
            cost_writer_hostport=writer_hostport,
            cost_writer_token=_private_token(values, "LUCY_COST_WRITER_TOKEN"),
            recovery_ack_hostport=ack_hostport,
            recovery_ack_token=_private_token(values, "LUCY_RECOVERY_ACK_TOKEN"),
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise PublicModelApiConfigurationError(f"required model configuration is missing: {name}")
    return value


def _hostport(values: Mapping[str, str], name: str) -> str:
    value = _required(values, name)
    if _HOSTPORT.fullmatch(value) is None or int(value.rsplit(":", 1)[1]) > 65_535:
        raise PublicModelApiConfigurationError(f"public model host is invalid: {name}")
    return value


def _private_token(values: Mapping[str, str], name: str) -> str:
    value = _required(values, name)
    if not 32 <= len(value) <= 512:
        raise PublicModelApiConfigurationError(f"public model token is invalid: {name}")
    return value


def _base64_key(values: Mapping[str, str], name: str) -> bytes:
    try:
        value = base64.b64decode(_required(values, name), validate=True)
    except ValueError:
        raise PublicModelApiConfigurationError(f"public model key is invalid: {name}") from None
    if len(value) < 32:
        raise PublicModelApiConfigurationError(f"public model key is invalid: {name}")
    return value


def _bounded_int(
    values: Mapping[str, str], name: str, minimum: int, maximum: int
) -> int:
    try:
        value = int(_required(values, name))
    except ValueError:
        raise PublicModelApiConfigurationError(f"public model limit is invalid: {name}") from None
    if not minimum <= value <= maximum:
        raise PublicModelApiConfigurationError(f"public model limit is invalid: {name}")
    return value


def _positive_float(values: Mapping[str, str], name: str) -> float:
    try:
        value = float(_required(values, name))
    except ValueError:
        raise PublicModelApiConfigurationError(f"public model price is invalid: {name}") from None
    if not 0 < value <= 1_000:
        raise PublicModelApiConfigurationError(f"public model price is invalid: {name}")
    return value


@dataclass(frozen=True)
class PublicModelApiDependencies:
    config: PublicModelApiConfiguration
    sessions: sessionmaker[Session]
    handler: PublicModelServiceHandler


@lru_cache(maxsize=1)
def _dependencies() -> PublicModelApiDependencies:
    config = PublicModelApiConfiguration.from_environment()
    sessions = create_session_factory(config.database_url)
    admission = ProviderCostAdmissionService(sessions)
    journal = HttpRecoveryJournalWriterClient(
        RecoveryStreamKind.COST,
        config.cost_writer_hostport,
        config.cost_writer_token,
    )
    recovery = HttpRecoveryAcknowledgementClient(
        config.recovery_ack_hostport, config.recovery_ack_token
    )
    direct_model = OpenRouterPublicJsonModel(
        api_key=config.openrouter_api_key,
        model=config.model,
        allowed_providers=config.allowed_providers,
        maximum_prompt_usd_per_million=config.maximum_prompt_usd_per_million,
        maximum_completion_usd_per_million=config.maximum_completion_usd_per_million,
    )
    coordinator = PublicInferenceCoordinator(
        admission,
        journal,
        recovery,
        OpenRouterInferenceProvider(direct_model),
        provider_reference_commitment_key=config.provider_reference_commitment_key,
    )

    def engine_factory(request: PublicModelServiceRequest) -> PublicConversationEngine:
        admitted = AdmittedPublicJsonModel(
            coordinator,
            request_id=request.request_id,
            model=config.model,
            rate_version=config.rate_version,
            node_id=config.node_id,
            channel_binding_id=config.channel_binding_id,
            session_commitment=request.session_commitment,
            ip_commitment=request.ip_commitment,
            request_commitment_key=config.request_commitment_key,
        )
        return PublicConversationEngine(
            admitted,
            admitted,
            generator_max_output_tokens=config.generator_max_output_tokens,
            verifier_max_output_tokens=config.verifier_max_output_tokens,
            timeout_seconds=config.timeout_seconds,
            generator_maximum_microusd=config.generator_maximum_microusd,
            verifier_maximum_microusd=config.verifier_maximum_microusd,
        )

    return PublicModelApiDependencies(
        config=config,
        sessions=sessions,
        handler=PublicModelServiceHandler(config.allowed_snapshot_digests, engine_factory),
    )


def check_cost_identity(dependencies: PublicModelApiDependencies) -> None:
    """Admit only the exact execute-only cost identity and ready runtime."""

    with dependencies.sessions.begin() as session:
        session.execute(text("SET TRANSACTION READ ONLY"))
        actual = session.scalar(text("SELECT session_user"))
        if actual != dependencies.config.expected_database_login:
            raise PublicModelServiceUnavailable("public model database identity differs")
        elevated = session.scalar(
            text(
                "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR "
                "rolbypassrls FROM pg_roles WHERE rolname=session_user"
            )
        )
        if elevated is not False:
            raise PublicModelServiceUnavailable("public model database identity is elevated")
        readiness = session.execute(
            text(
                "SELECT a.state,l.state AS lifecycle FROM lucy.runtime_admission a "
                "CROSS JOIN lucy.lifecycle l WHERE a.singleton AND l.singleton"
            )
        ).one_or_none()
        if readiness is None or readiness.state != "ready" or readiness.lifecycle != "ready":
            raise PublicModelServiceUnavailable("public model storage is not admitted")
        for function in (
            "lucy.reserve_provider_attempt_v1(uuid,text,uuid,uuid,text,text,text,text,text,"
            "text,bigint,integer,integer,integer,integer,timestamptz)",
            "lucy.claim_provider_submission_v1(uuid)",
            "lucy.mark_provider_attempt_unknown_v1(uuid)",
            "lucy.settle_provider_attempt_v1(uuid,bigint,text)",
        ):
            if not session.scalar(
                text("SELECT has_function_privilege(session_user,:function,'EXECUTE')"),
                {"function": function},
            ):
                raise PublicModelServiceUnavailable(
                    "public model database identity lacks cost authority"
                )
        for table in (
            "lucy.provider_cost_policies_v1",
            "lucy.provider_attempts_v1",
            "lucy.exposure_reservations_v1",
            "lucy.cost_events_v1",
            "lucy.cost_recovery_outbox_v1",
        ):
            if session.scalar(
                text(
                    "SELECT has_table_privilege(session_user,:table,'SELECT') OR "
                    "has_table_privilege(session_user,:table,'INSERT') OR "
                    "has_table_privilege(session_user,:table,'UPDATE') OR "
                    "has_table_privilege(session_user,:table,'DELETE') OR "
                    "has_table_privilege(session_user,:table,'TRUNCATE')"
                ),
                {"table": table},
            ):
                raise PublicModelServiceUnavailable(
                    "public model database identity exceeds cost authority"
                )


app = FastAPI(
    title="Lucy Public Model API",
    version="1.0.0",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/public-model/answer", tags=["private"])
async def public_model_answer(request: Request) -> JSONResponse:
    try:
        dependencies = _dependencies()
    except (PublicModelApiConfigurationError, ValueError):
        return _response(503, "Public model is unavailable")
    authorization = request.headers.get("authorization")
    if authorization is None or not secrets.compare_digest(
        authorization, f"Bearer {dependencies.config.api_token}"
    ):
        return _response(401, "Invalid model credential")
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        return _response(415, "JSON request required")
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > dependencies.config.maximum_request_bytes:
                return _response(413, "Model request is too large")
        except ValueError:
            return _response(400, "Invalid model request")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > dependencies.config.maximum_request_bytes:
            return _response(413, "Model request is too large")
    try:
        payload = PublicModelServiceRequest.model_validate(json.loads(body))
        result = dependencies.handler.answer(payload)
    except (json.JSONDecodeError, UnicodeError, ValidationError, TypeError):
        return _response(400, "Invalid model request")
    except (
        PublicModelServiceUnavailable,
        PublicInferenceUnavailable,
        PublicModelRejected,
        OpenRouterPublicError,
        SQLAlchemyError,
    ):
        return _response(503, "Public model is unavailable")
    return JSONResponse(
        status_code=200,
        content=result.model_dump(mode="json"),
        headers={"Cache-Control": "no-store"},
    )


def _response(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers={"Cache-Control": "no-store"},
    )
