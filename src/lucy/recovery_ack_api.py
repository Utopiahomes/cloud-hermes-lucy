"""Private, path-only API for independent recovery acknowledgement."""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lucy.authority_recovery import AuthorityTransitionService
from lucy.cost_admission import (
    ProviderAttemptAdmissionV1,
    ProviderCostOverrun,
    ProviderCostRecoveryService,
)
from lucy.cost_recovery import CostJournalPreparationService, PendingCostEventV1
from lucy.db import create_session_factory
from lucy.readiness import RECOVERY_SCHEMA_REVISIONS
from lucy.recovery_acknowledgement import (
    AuthorityAcknowledgementReceiver,
    CostAcknowledgementReceiver,
)
from lucy.recovery_journal import (
    RecoveryJournalError,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
)
from lucy.recovery_journal_aws import AwsDynamoRecoveryJournal, DynamoRecoveryClient

_LOGIN = re.compile(r"[a-z][a-z0-9_]{2,62}\Z")
_ROLE_ARN = re.compile(
    r"arn:aws:iam::(\d{12}):role/(?:[A-Za-z0-9+=,.@_-]+/)*"
    r"([A-Za-z0-9+=,.@_-]+)\Z"
)

app = FastAPI(title="Lucy Recovery Acknowledgement API", version="1.0.0")


class AcknowledgementResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    stream_kind: RecoveryStreamKind
    state: Literal["DURABLY_RECORDED", "ADMITTED", "SETTLED", "OVER_CAP"]


@dataclass(frozen=True)
class RecoveryAckDependencies:
    authority: AuthorityAcknowledgementReceiver
    cost: CostAcknowledgementReceiver
    authority_journal: AwsDynamoRecoveryJournal
    cost_journal: AwsDynamoRecoveryJournal


@app.exception_handler(RecoveryJournalError)
@app.exception_handler(SQLAlchemyError)
@app.exception_handler(LookupError)
def unavailable(_request: Request, _error: Exception) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": "acknowledgement unavailable"})


def _authorize(
    stream_kind: RecoveryStreamKind, authorization: str | None
) -> None:
    token = os.getenv(f"LUCY_{stream_kind.value.upper()}_RECOVERY_ACK_TOKEN")
    if (
        not token
        or authorization is None
        or not secrets.compare_digest(authorization, f"Bearer {token}")
    ):
        raise HTTPException(status_code=401, detail="invalid acknowledgement credential")


def _verified_sessions(prefix: str) -> sessionmaker[Session]:
    try:
        expected_login = os.environ[f"LUCY_{prefix}_RECOVERY_DATABASE_LOGIN"]
        database_url = os.environ[f"LUCY_{prefix}_RECOVERY_DATABASE_URL"]
    except KeyError:
        raise RecoveryJournalError("acknowledgement configuration is incomplete") from None
    if _LOGIN.fullmatch(expected_login) is None:
        raise RecoveryJournalError("acknowledgement database identity is invalid")
    if not expected_login.endswith(f"_{prefix.lower()}_recovery"):
        raise RecoveryJournalError("acknowledgement database identity is cross-stream")
    sessions = create_session_factory(database_url)
    with sessions() as session:
        identity = session.execute(
            text(
                "SELECT current_user,r.rolcanlogin,r.rolsuper,r.rolinherit,"
                "r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls "
                "FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
            )
        ).one()
        revision = session.execute(
            text("SELECT version_num FROM public.alembic_version")
        ).scalar_one()
    if tuple(identity) != (expected_login, True, False, False, False, False, False, False):
        raise RecoveryJournalError("acknowledgement database identity is elevated or differs")
    if revision not in RECOVERY_SCHEMA_REVISIONS:
        raise RecoveryJournalError("acknowledgement schema revision differs")
    return sessions


def _journal(
    prefix: str,
    *,
    client: DynamoRecoveryClient,
    account_id: str,
    region: str,
    expected_recovery_identity: str,
) -> AwsDynamoRecoveryJournal:
    try:
        table_name = os.environ[f"LUCY_{prefix}_RECOVERY_JOURNAL_TABLE"]
        binding = RecoveryStreamBindingV1.model_validate(
            json.loads(os.environ[f"LUCY_{prefix}_RECOVERY_STREAM_BINDING_JSON"])
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        raise RecoveryJournalError("acknowledgement journal configuration is incomplete") from None
    if binding.recovery_identity != expected_recovery_identity:
        raise RecoveryJournalError("acknowledgement journal recovery identity differs")
    return AwsDynamoRecoveryJournal.from_configuration(
        client,
        region=region,
        account_id=account_id,
        table_name=table_name,
        binding=binding,
    )


def _verify_workload_identity(
    identity: dict[str, Any], *, account_id: str, role_arn: str
) -> None:
    match = _ROLE_ARN.fullmatch(role_arn)
    if match is None or match.group(1) != account_id:
        raise RecoveryJournalError("acknowledgement AWS role binding is invalid")
    expected = f"arn:aws:sts::{account_id}:assumed-role/{match.group(2)}/"
    if identity.get("Account") != account_id or not str(identity.get("Arn", "")).startswith(
        expected
    ):
        raise RecoveryJournalError("active acknowledgement AWS identity differs")


@lru_cache
def _dependencies() -> RecoveryAckDependencies:
    try:
        region = os.environ["AWS_REGION"]
        account_id = os.environ["LUCY_AWS_ACCOUNT_ID"]
        role_arn = os.environ["AWS_ROLE_ARN"]
    except KeyError:
        raise RecoveryJournalError("acknowledgement AWS identity is incomplete") from None
    if os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_SECRET_ACCESS_KEY"):
        raise RecoveryJournalError("static acknowledgement AWS credentials are prohibited")
    sts: Any = boto3.client("sts", region_name=region)
    _verify_workload_identity(
        sts.get_caller_identity(), account_id=account_id, role_arn=role_arn
    )
    client: Any = boto3.client("dynamodb", region_name=region)
    authority_journal = _journal(
        "AUTHORITY",
        client=client,
        account_id=account_id,
        region=region,
        expected_recovery_identity=role_arn,
    )
    cost_journal = _journal(
        "COST",
        client=client,
        account_id=account_id,
        region=region,
        expected_recovery_identity=role_arn,
    )
    authority_sessions = _verified_sessions("AUTHORITY")
    cost_sessions = _verified_sessions("COST")
    return RecoveryAckDependencies(
        authority=AuthorityAcknowledgementReceiver(
            AuthorityTransitionService(authority_sessions), authority_journal
        ),
        cost=CostAcknowledgementReceiver(
            _CostAcknowledgementStore(cost_sessions), cost_journal
        ),
        authority_journal=authority_journal,
        cost_journal=cost_journal,
    )


class _CostAcknowledgementStore:
    """One constrained session factory implementing the two cost receiver protocols."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._pending = CostJournalPreparationService(sessions)
        self._recovery = ProviderCostRecoveryService(sessions)

    def pending(self, event_id: UUID) -> PendingCostEventV1:
        return self._pending.pending(event_id)

    def acknowledge(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1:
        return self._recovery.acknowledge(
            attempt_id=attempt_id, event_id=event_id, head_digest=head_digest
        )

    def acknowledge_outcome(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1:
        return self._recovery.acknowledge_outcome(
            attempt_id=attempt_id, event_id=event_id, head_digest=head_digest
        )


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", tags=["operations"])
def ready() -> dict[str, str]:
    dependencies = _dependencies()
    dependencies.authority_journal.head()
    dependencies.cost_journal.head()
    return {"status": "ready"}


@app.post("/v1/recovery/{stream_kind}/acknowledgements/{event_id}")
async def acknowledge(
    stream_kind: RecoveryStreamKind,
    event_id: UUID,
    request: Request,
    authorization: str | None = Header(default=None),
) -> AcknowledgementResponseV1:
    _authorize(stream_kind, authorization)
    if await request.body():
        raise HTTPException(status_code=400, detail="acknowledgement body is prohibited")
    dependencies = _dependencies()
    if stream_kind is RecoveryStreamKind.AUTHORITY:
        authority_result = dependencies.authority.receive(event_id)
        if authority_result.state != "DURABLY_RECORDED":
            raise RecoveryJournalError("authority acknowledgement did not complete")
        return AcknowledgementResponseV1(
            event_id=authority_result.event_id,
            stream_kind=stream_kind,
            state=authority_result.state,
        )
    try:
        cost_result = dependencies.cost.receive(event_id)
    except ProviderCostOverrun as exc:
        cost_result = exc.result
    if cost_result.state == "ADMITTED":
        response_state: Literal["ADMITTED", "SETTLED", "OVER_CAP"] = "ADMITTED"
    elif cost_result.state == "SETTLED":
        response_state = "SETTLED"
    elif cost_result.state == "OVER_CAP":
        response_state = "OVER_CAP"
    else:
        raise RecoveryJournalError("cost acknowledgement did not complete")
    return AcknowledgementResponseV1(
        event_id=cost_result.event_id,
        stream_kind=stream_kind,
        state=response_state,
    )
