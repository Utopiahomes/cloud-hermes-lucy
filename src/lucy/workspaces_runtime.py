"""Fail-closed construction and startup for the private Workspaces Cloud Lucy API."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from lucy.contracts.security_v1_3 import AuthenticationStrength, PrincipalType
from lucy.db import create_session_factory
from lucy.internal_admission import (
    PostgresDirectoryAdmissionAuthorizer,
    RealmInternalAdmissionService,
    VerifiedCustomerIdentityV1,
)
from lucy.publication import PublicProjectionReader
from lucy.realm_sessions import RealmRuntimeBindingV1, RealmSessionRegistry
from lucy.runtime import _listener_port
from lucy.workspaces_admission import WorkspacesExperienceGateway
from lucy.workspaces_admission_api import (
    WorkspacesAdmissionAPISettingsV1,
    create_workspaces_admission_app,
)
from lucy.workspaces_operations import ApprovedProjectionWorkspacesOperations
from lucy.workspaces_tasks import PostgresWorkspacesTaskQueue

WORKSPACES_SCHEMA_REVISION = "0067_memory_deletion_recovery"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LOGIN = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_AUTHORITY_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
_ACTION = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class WorkspacesRuntimeConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class WorkspacesRuntimeConfiguration:
    binding: RealmRuntimeBindingV1
    expected_database_login: str
    directory_database_url: SecretStr
    expected_directory_login: str
    transport_token: SecretStr
    authority_token: SecretStr
    authority_subject: str
    authority_session_id: UUID
    room_capabilities: frozenset[str]
    authority_mode: str
    authority_ref: str
    projection_hostname: str
    projection_storage_epoch: UUID
    projection_snapshot_digest: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> WorkspacesRuntimeConfiguration:
        values = os.environ if environment is None else environment
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise WorkspacesRuntimeConfigurationError("transcript capture must remain disabled")
        try:
            binding = RealmRuntimeBindingV1.model_validate_json(
                _required(values, "LUCY_WORKSPACES_RUNTIME_BINDING_JSON")
            )
            capabilities_value = json.loads(
                _required(values, "LUCY_WORKSPACES_ROOM_CAPABILITIES_JSON")
            )
            if (
                not isinstance(capabilities_value, list)
                or not 1 <= len(capabilities_value) <= 16
                or any(
                    not isinstance(value, str) or _ACTION.fullmatch(value) is None
                    for value in capabilities_value
                )
                or len(set(capabilities_value)) != len(capabilities_value)
            ):
                raise ValueError
            capabilities = frozenset(capabilities_value)
            authority_session_id = UUID(
                _required(values, "LUCY_WORKSPACES_AUTHORITY_SESSION_ID")
            )
            projection_epoch = UUID(
                _required(values, "LUCY_WORKSPACES_PROJECTION_STORAGE_EPOCH")
            )
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise WorkspacesRuntimeConfigurationError(
                "private Workspaces configuration is invalid"
            ) from exc
        if not capabilities or not capabilities.issubset(binding.allowed_actions):
            raise WorkspacesRuntimeConfigurationError(
                "room capabilities exceed the fixed runtime binding"
            )
        if "task.delegate" in capabilities and "task.execute" not in binding.allowed_actions:
            raise WorkspacesRuntimeConfigurationError(
                "task delegation requires the fixed task executor binding"
            )
        expected_login = _required(values, "LUCY_EXPECTED_DATABASE_LOGIN")
        expected_directory_login = _required(
            values, "LUCY_WORKSPACES_EXPECTED_DIRECTORY_LOGIN"
        )
        try:
            parsed = make_url(binding.database_url.get_secret_value())
            directory_url = _required(values, "LUCY_WORKSPACES_DIRECTORY_DATABASE_URL")
            parsed_directory = make_url(directory_url)
        except Exception as exc:
            raise WorkspacesRuntimeConfigurationError(
                "private Workspaces database identity is invalid"
            ) from exc
        if (
            _LOGIN.fullmatch(expected_login) is None
            or parsed.drivername not in {"postgresql", "postgresql+psycopg"}
            or parsed.username != expected_login
            or not parsed.password
            or not parsed.host
            or not parsed.database
            or _LOGIN.fullmatch(expected_directory_login) is None
            or parsed_directory.drivername not in {"postgresql", "postgresql+psycopg"}
            or parsed_directory.username != expected_directory_login
            or not parsed_directory.password
            or not parsed_directory.host
            or not parsed_directory.database
            or (parsed_directory.host, parsed_directory.port, parsed_directory.database)
            != (parsed.host, parsed.port, parsed.database)
        ):
            raise WorkspacesRuntimeConfigurationError(
                "private Workspaces database identity is invalid"
            )
        if values.get("LUCY_ENVIRONMENT") == "production" and (
            values.get("RENDER") != "true"
            or _PRIVATE_RENDER_HOST.fullmatch(parsed.host) is None
            or parsed.port not in (None, 5432)
            or _PRIVATE_RENDER_HOST.fullmatch(parsed_directory.host) is None
        ):
            raise WorkspacesRuntimeConfigurationError(
                "private Workspaces database boundary is invalid"
            )
        transport = _required(values, "LUCY_WORKSPACES_TRANSPORT_TOKEN")
        authority = _required(values, "LUCY_WORKSPACES_AUTHORITY_TOKEN")
        subject = _required(values, "LUCY_WORKSPACES_AUTHORITY_SUBJECT")
        mode = _required(values, "LUCY_WORKSPACES_AUTHORITY_MODE")
        reference = _required(values, "LUCY_WORKSPACES_AUTHORITY_REF")
        hostname = _required(values, "LUCY_WORKSPACES_PROJECTION_HOSTNAME").lower()
        digest = _required(values, "LUCY_WORKSPACES_PROJECTION_SNAPSHOT_DIGEST")
        if (
            not 32 <= len(transport) <= 512
            or not 32 <= len(authority) <= 512
            or not 1 <= len(subject) <= 512
            or mode != "approved_knowledge"
            or _AUTHORITY_REF.fullmatch(reference) is None
            or _DIGEST.fullmatch(digest) is None
            or _HOSTNAME.fullmatch(hostname) is None
        ):
            raise WorkspacesRuntimeConfigurationError(
                "private Workspaces configuration is invalid"
            )
        return cls(
            binding=binding,
            expected_database_login=expected_login,
            directory_database_url=SecretStr(directory_url),
            expected_directory_login=expected_directory_login,
            transport_token=SecretStr(transport),
            authority_token=SecretStr(authority),
            authority_subject=subject,
            authority_session_id=authority_session_id,
            room_capabilities=capabilities,
            authority_mode=mode,
            authority_ref=reference,
            projection_hostname=hostname,
            projection_storage_epoch=projection_epoch,
            projection_snapshot_digest=digest,
        )


class FixedWorkspacesAuthorityVerifier:
    """Verify the server-held Workspaces authority credential without user input."""

    def __init__(self, config: WorkspacesRuntimeConfiguration) -> None:
        self._config = config

    def verify(
        self,
        credential: SecretStr,
        *,
        expected_issuer: str,
        expected_audience: str,
        checked_at: datetime,
    ) -> VerifiedCustomerIdentityV1:
        if not secrets.compare_digest(
            credential.get_secret_value(), self._config.authority_token.get_secret_value()
        ):
            raise PermissionError("Workspaces authority is invalid")
        return VerifiedCustomerIdentityV1(
            issuer=expected_issuer,
            subject=self._config.authority_subject,
            audience=expected_audience,
            principal_type=PrincipalType.SERVICE,
            authentication_strength=AuthenticationStrength.WORKLOAD_IDENTITY,
            auth_time=checked_at - timedelta(seconds=1),
            expires_at=checked_at + timedelta(minutes=5),
            session_id=self._config.authority_session_id,
        )


def build_workspaces_app(config: WorkspacesRuntimeConfiguration) -> FastAPI:
    registry = RealmSessionRegistry((config.binding,))
    bound = registry.for_verified_workload(
        config.binding.workload_subject, action=next(iter(config.room_capabilities))
    )
    directory = PostgresDirectoryAdmissionAuthorizer(
        create_session_factory(config.directory_database_url.get_secret_value())
    )
    admission = RealmInternalAdmissionService(
        sessions=registry,
        verified_workload_subject=config.binding.workload_subject,
        identity_verifier=FixedWorkspacesAuthorityVerifier(config),
        directory=directory,
    )
    gateway = WorkspacesExperienceGateway(
        admission=admission,
        workspace_id=config.binding.workspace_id,
        room_capabilities=config.room_capabilities,
        authority_mode="approved_knowledge",
        authority_ref=config.authority_ref,
    )
    queue = PostgresWorkspacesTaskQueue(bound.sessions)
    operations = ApprovedProjectionWorkspacesOperations(
        reader=PublicProjectionReader(bound.sessions),
        hostname=config.projection_hostname,
        storage_epoch=config.projection_storage_epoch,
        snapshot_digest=config.projection_snapshot_digest,
        task_delegator=queue,
    )
    return create_workspaces_admission_app(
        settings=WorkspacesAdmissionAPISettingsV1(
            transport_token=config.transport_token,
            lucy_authority_credential=config.authority_token,
        ),
        gateway=gateway,
        operations=operations,
    )


def check_workspaces_readiness(config: WorkspacesRuntimeConfiguration) -> None:
    registry = RealmSessionRegistry((config.binding,))
    bound = registry.for_verified_workload(
        config.binding.workload_subject, action=next(iter(config.room_capabilities))
    )
    with bound.sessions.begin() as session:
        session.execute(text("SET TRANSACTION READ ONLY"))
        if session.scalar(text("SELECT session_user")) != config.expected_database_login:
            raise WorkspacesRuntimeConfigurationError("database identity mismatch")
        elevated = session.scalar(
            text(
                "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR "
                "rolbypassrls FROM pg_roles WHERE rolname=current_user"
            )
        )
        if elevated is not False:
            raise WorkspacesRuntimeConfigurationError("database identity is elevated")
        can_administer = session.scalar(
            text(
                "SELECT has_database_privilege(current_user,current_database(),'CREATE') OR "
                "has_schema_privilege(current_user,'lucy','CREATE') OR "
                "has_schema_privilege(current_user,'public','CREATE')"
            )
        )
        if can_administer:
            raise WorkspacesRuntimeConfigurationError("database identity can administer storage")
        revisions = list(session.scalars(text("SELECT version_num FROM public.alembic_version")))
        if revisions != [WORKSPACES_SCHEMA_REVISION]:
            raise WorkspacesRuntimeConfigurationError("database schema is not ready")
        for signature in (
            "lucy.enqueue_workspaces_task_v1(uuid,uuid,uuid,uuid,uuid,text,text)",
            "lucy.claim_workspaces_task_v1(uuid,integer)",
            "lucy.heartbeat_workspaces_task_v1(uuid,uuid,integer)",
            "lucy.complete_workspaces_task_v1(uuid,uuid,text,jsonb)",
            "lucy.public_projection_answer_v2(text,text,uuid)",
        ):
            if session.scalar(
                text("SELECT has_function_privilege(current_user,:function,'EXECUTE')"),
                {"function": signature},
            ) is not True:
                raise WorkspacesRuntimeConfigurationError("required database capability is missing")
        for table in ("lucy.workspaces_tasks_v1", "lucy.workspaces_task_events_v1"):
            if session.scalar(
                text(
                    "SELECT has_table_privilege("
                    "current_user,:table,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')"
                ),
                {"table": table},
            ):
                raise WorkspacesRuntimeConfigurationError("task storage is not execute-only")
    directory_sessions = create_session_factory(
        config.directory_database_url.get_secret_value()
    )
    with directory_sessions.begin() as session:
        session.execute(text("SET TRANSACTION READ ONLY"))
        if session.scalar(text("SELECT session_user")) != config.expected_directory_login:
            raise WorkspacesRuntimeConfigurationError("directory database identity mismatch")
        elevated = session.scalar(
            text(
                "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR "
                "rolbypassrls FROM pg_roles WHERE rolname=current_user"
            )
        )
        if elevated is not False:
            raise WorkspacesRuntimeConfigurationError("directory database identity is elevated")
        if session.scalar(
            text(
                "SELECT has_function_privilege(current_user,:function,'EXECUTE')"
            ),
            {
                "function": (
                    "lucy.resolve_internal_admission_v1(text,text,text,uuid,uuid,uuid,"
                    "bigint,uuid,bigint,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,bigint,"
                    "timestamptz)"
                )
            },
        ) is not True:
            raise WorkspacesRuntimeConfigurationError("directory capability is missing")
        if session.scalar(
            text(
                "SELECT has_table_privilege(current_user,:table,'SELECT,INSERT,UPDATE,"
                "DELETE,TRUNCATE')"
            ),
            {"table": "lucy.realm_service_bindings_v1"},
        ):
            raise WorkspacesRuntimeConfigurationError("directory identity can read authority data")


def main() -> None:
    try:
        config = WorkspacesRuntimeConfiguration.from_environment()
        check_workspaces_readiness(config)
        app = build_workspaces_app(config)
    except (WorkspacesRuntimeConfigurationError, SQLAlchemyError) as exc:
        raise SystemExit(f"Workspaces Cloud Lucy startup gate failed: {exc}") from exc
    uvicorn.run(app, host="0.0.0.0", port=_listener_port(), access_log=False)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise WorkspacesRuntimeConfigurationError(f"missing required configuration: {name}")
    return value


if __name__ == "__main__":
    main()
