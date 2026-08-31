"""Narrow companion API exposed to the pinned Hermes runtime."""

import os
import re
import secrets
from functools import lru_cache
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lucy.archive import (
    CaptureModeInput,
    CaptureModeResult,
    ConversationArchiveService,
    ConversationMessageArchiveInput,
    ConversationMessageArchiveResult,
    LatestRetainedEvidenceResult,
    TurnCaptureInput,
    TurnCaptureResult,
)
from lucy.archive_crypto import (
    ArchiveCipher,
    ArchiveKeyStore,
    archive_dependencies_from_environment,
    archive_key_store_from_environment,
)
from lucy.authorization import (
    GatewaySensitiveActionPermitRequest,
    SensitiveActionPermitRequest,
    SensitiveActionPermitService,
    SensitiveActionPermitSigner,
    SensitiveActionPermitV1,
    SensitiveActionPermitVerifier,
)
from lucy.db import create_session_factory
from lucy.deletion_journal import DeletionJournalError, deletion_journal_from_environment
from lucy.evidence import (
    EvidenceDeletionRequest,
    EvidenceDeletionResult,
    EvidenceRetrievalRequest,
    EvidenceRetrievalResult,
    EvidenceService,
    ForgetLastRequest,
)
from lucy.memory import MemoryService
from lucy.model_execution import (
    ModelExecutionBegin,
    ModelExecutionBeginResult,
    ModelExecutionService,
    ModelExecutionSettlement,
    ModelExecutionSettlementResult,
)
from lucy.proposals import GatewayMemoryProposalInput, MemoryProposalService
from lucy.readiness import (
    SERVICE_MODES as SERVICE_MODES,
)
from lucy.readiness import (
    ReadinessError,
    ServiceReadiness,
    admitted_session_factory,
    expected_storage_epoch,
    service_mode_from_environment,
)
from lucy.secret_filter import MemorySecretDetected

app = FastAPI(title="Lucy Companion API", version="0.1.0")


@app.exception_handler(ReadinessError)
@app.exception_handler(DeletionJournalError)
def admission_closed(_request: Request, _error: ReadinessError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": "Lucy storage is not admitted"})


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", tags=["operations"])
def ready() -> dict[str, str]:
    _ready_sessions()
    return {"status": "ready"}


def _authorize(authorization: str | None) -> None:
    token = os.getenv("LUCY_ADAPTER_TOKEN")
    if (
        not token
        or authorization is None
        or not secrets.compare_digest(authorization, f"Bearer {token}")
    ):
        raise HTTPException(status_code=401, detail="invalid adapter credential")


def _authorize_owner(authorization: str | None) -> None:
    token = os.getenv("LUCY_OWNER_TOKEN")
    if (
        not token
        or authorization is None
        or not secrets.compare_digest(authorization, f"Bearer {token}")
    ):
        raise HTTPException(status_code=401, detail="invalid owner credential")


def _authorize_policy_gateway(authorization: str | None) -> None:
    token = os.getenv("LUCY_POLICY_GATEWAY_TOKEN")
    if (
        not token
        or authorization is None
        or not secrets.compare_digest(authorization, f"Bearer {token}")
    ):
        raise HTTPException(status_code=401, detail="invalid policy gateway credential")


def _service_mode() -> str:
    try:
        return service_mode_from_environment()
    except ReadinessError as exc:
        raise HTTPException(status_code=503, detail="invalid Lucy service mode") from exc


def _require_mode(*allowed: str) -> None:
    if _service_mode() not in {*allowed, "all-local"}:
        # Do not advertise sensitive endpoints from the wrong execution identity.
        raise HTTPException(status_code=404, detail="endpoint unavailable")


def _ready_sessions() -> sessionmaker[Session]:
    database_url = os.getenv("LUCY_DATABASE_URL")
    if database_url is None:
        raise HTTPException(status_code=503, detail="memory store unavailable")
    try:
        mode = _service_mode()
        epoch = expected_storage_epoch(mode)
        # Cache engines rather than creating a new connection pool per request.
        sessions = _readiness_sessions(database_url)
        journal = None if mode == "policy" else deletion_journal_from_environment()
        ServiceReadiness(sessions, mode=mode, storage_epoch=epoch, journal=journal).check()
        return admitted_session_factory(
            database_url, epoch, journal, journal_required=mode != "policy"
        )
    except (ReadinessError, DeletionJournalError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=503, detail="Lucy storage is not admitted") from exc


@lru_cache(maxsize=8)
def _readiness_sessions(database_url: str) -> sessionmaker[Session]:
    return create_session_factory(database_url)


def _archive_crypto() -> tuple[ArchiveCipher, ArchiveKeyStore]:
    try:
        return archive_dependencies_from_environment()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="archive encryption unavailable") from exc


def _archive_service() -> ConversationArchiveService:
    cipher, key_store = _archive_crypto()
    try:
        if key_store.registry_identity != deletion_journal_from_environment().head().registry_id:
            raise DeletionJournalError("archive registry identity mismatch")
    except (DeletionJournalError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="archive boundary unavailable") from exc
    return ConversationArchiveService(
        _ready_sessions(),
        cipher,
        key_store,
        capture_authorized=os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") == "true",
    )


def _evidence_service() -> EvidenceService:
    cipher, key_store = _archive_crypto()
    try:
        if key_store.registry_identity != deletion_journal_from_environment().head().registry_id:
            raise DeletionJournalError("archive registry identity mismatch")
    except (DeletionJournalError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="evidence boundary unavailable") from exc
    return EvidenceService(
        _ready_sessions(),
        cipher,
        key_store,
        SensitiveActionPermitVerifier.from_environment(),
    )


def _deletion_service() -> EvidenceService:
    try:
        key_store = archive_key_store_from_environment()
        verifier = SensitiveActionPermitVerifier.from_environment()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="deletion boundary unavailable") from exc
    return EvidenceService(
        _ready_sessions(),
        None,
        key_store,
        verifier,
        journal=deletion_journal_from_environment(),
    )


class MemoryLookupInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    query: str = Field(min_length=1, max_length=200)


@app.post("/v1/memory/lookup", tags=["memory"])
def read_only_memory_lookup(
    request: MemoryLookupInput, authorization: str | None = Header(default=None)
) -> dict[str, object]:
    """Return a bounded projection; never expose or mutate archive evidence."""

    _require_mode("routine")
    _authorize(authorization)
    sessions = _ready_sessions()
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="query must not be blank")
    context = MemoryService(sessions).build_context(request.query)
    return {"query": request.query, "claims": context.claims, "read_only": True}


@app.post("/v1/memory/proposals", tags=["memory"], status_code=202)
def propose_memory(
    candidate: GatewayMemoryProposalInput,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, object]:
    """Create a gated candidate; this endpoint can never apply a memory write."""
    _require_mode("routine")
    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    if os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "true":
        raise HTTPException(status_code=403, detail="live retention is not authorized")
    if not isinstance(candidate, GatewayMemoryProposalInput):
        raise HTTPException(status_code=400, detail="turn-bound provenance is required")
    if (
        re.fullmatch(
            r"hermes-memory-proposal:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}"
            r"-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            idempotency_key,
        )
        is None
    ):
        raise HTTPException(status_code=400, detail="opaque proposal idempotency key required")
    sessions = _ready_sessions()
    try:
        result = MemoryProposalService(sessions).submit(idempotency_key, candidate)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="immutable evidence does not exist") from exc
    except MemorySecretDetected as exc:
        raise HTTPException(
            status_code=422,
            detail="credential-like content cannot be promoted to normal memory",
        ) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="retention not authorized") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc
    return result.model_dump(mode="json")


@app.post(
    "/internal/v1/model-executions/begin",
    tags=["internal"],
    response_model=ModelExecutionBeginResult,
)
def begin_model_execution(
    request: ModelExecutionBegin,
    authorization: str | None = Header(default=None),
) -> ModelExecutionBeginResult:
    """Reserve once immediately before the Hermes provider call."""
    _require_mode("routine")
    _authorize(authorization)
    return ModelExecutionService(_ready_sessions()).begin(request)


@app.post(
    "/internal/v1/model-executions/settle",
    tags=["internal"],
    response_model=ModelExecutionSettlementResult,
)
def settle_model_execution(
    request: ModelExecutionSettlement,
    authorization: str | None = Header(default=None),
) -> ModelExecutionSettlementResult:
    """Settle usage after the wrapped provider call completes."""
    _require_mode("routine")
    _authorize(authorization)
    return ModelExecutionService(_ready_sessions()).settle(request)


@app.post(
    "/internal/v1/conversations/accept-turn",
    tags=["internal"],
    response_model=TurnCaptureResult,
)
def accept_conversation_turn(
    request: TurnCaptureInput,
    authorization: str | None = Header(default=None),
) -> TurnCaptureResult:
    _require_mode("routine")
    _authorize(authorization)
    return _archive_service().accept_turn(request)


@app.post(
    "/internal/v1/conversations/messages",
    tags=["internal"],
    response_model=ConversationMessageArchiveResult,
    status_code=201,
)
def archive_conversation_message(
    request: ConversationMessageArchiveInput,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> ConversationMessageArchiveResult:
    """Preserve an authenticated Hermes message; never infer a memory claim."""

    _require_mode("routine")
    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _archive_service().preserve_message(idempotency_key.strip(), request)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="retention not authorized") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc


@app.get(
    "/internal/v1/conversations/capture-mode",
    tags=["internal"],
    response_model=CaptureModeResult,
)
def get_capture_mode(
    source_conversation_id: str,
    authorization: str | None = Header(default=None),
) -> CaptureModeResult:
    _require_mode("routine")
    _authorize(authorization)
    return _archive_service().capture_mode("telegram", source_conversation_id)


@app.get(
    "/internal/v1/conversations/latest-retained-evidence",
    tags=["internal"],
    response_model=LatestRetainedEvidenceResult,
)
def get_latest_retained_evidence(
    source_conversation_id: str,
    authorization: str | None = Header(default=None),
) -> LatestRetainedEvidenceResult:
    _require_mode("deletion")
    _authorize(authorization)
    try:
        return LatestRetainedEvidenceResult(
            evidence_id=_deletion_service().latest_retained_evidence(
                "telegram", source_conversation_id
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="retained message unavailable") from exc


@app.post(
    "/internal/v1/conversations/capture-mode",
    tags=["internal"],
    response_model=CaptureModeResult,
)
def set_capture_mode(
    request: CaptureModeInput,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> CaptureModeResult:
    _require_mode("routine")
    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _archive_service().set_capture_mode(idempotency_key.strip(), request)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="live capture is not authorized") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc


@app.post(
    "/internal/v1/conversations/forget-last",
    tags=["internal"],
    response_model=EvidenceDeletionResult,
)
def forget_last_conversation_message(
    request: ForgetLastRequest,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> EvidenceDeletionResult:
    """Honor the allowlisted owner's exact deterministic forget command."""

    _require_mode("deletion")
    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _deletion_service().delete_last_message(idempotency_key.strip(), request)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="retained message unavailable") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="deletion not authorized") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc


@app.post(
    "/v1/evidence/retrieve",
    tags=["memory"],
    response_model=EvidenceRetrievalResult,
)
def retrieve_provenance_evidence(
    request: EvidenceRetrievalRequest,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> EvidenceRetrievalResult:
    """Retrieve one exact source only through a current linked claim."""

    _require_mode("evidence")
    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _evidence_service().retrieve(idempotency_key.strip(), request, owner=False)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="evidence unavailable") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="retrieval not authorized") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc


@app.post(
    "/owner/v1/evidence/retrieve",
    tags=["owner"],
    response_model=EvidenceRetrievalResult,
)
def owner_retrieve_evidence(
    request: EvidenceRetrievalRequest,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> EvidenceRetrievalResult:
    _require_mode("evidence")
    _authorize_owner(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _evidence_service().retrieve(idempotency_key.strip(), request, owner=True)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="evidence unavailable") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="retrieval not authorized") from exc
    except ValueError as exc:
        detail = (
            "invalid owner retrieval reason"
            if "owner reason" in str(exc)
            else "idempotency conflict"
        )
        status_code = 400 if "owner reason" in str(exc) else 409
        raise HTTPException(status_code=status_code, detail=detail) from exc


@app.post(
    "/owner/v1/evidence/{evidence_id}/delete",
    tags=["owner"],
    response_model=EvidenceDeletionResult,
)
def owner_delete_evidence(
    evidence_id: UUID,
    request: EvidenceDeletionRequest,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> EvidenceDeletionResult:
    _require_mode("deletion")
    _authorize_owner(authorization)
    if evidence_id != request.evidence_id:
        raise HTTPException(status_code=400, detail="evidence identity mismatch")
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _deletion_service().delete(idempotency_key.strip(), request)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="evidence unavailable") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="deletion not authorized") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc


@app.post(
    "/owner/v1/sensitive-action-permits",
    tags=["owner"],
    response_model=SensitiveActionPermitV1,
    status_code=201,
)
def issue_sensitive_action_permit(
    request: SensitiveActionPermitRequest,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> SensitiveActionPermitV1:
    """Issue a five-minute, exact-record permit from the non-AWS policy identity."""

    _require_mode("policy")
    _authorize_owner(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    owner_subject = os.getenv("LUCY_OWNER_SUBJECT", "").strip()
    if not owner_subject or request.owner_subject != owner_subject:
        raise HTTPException(status_code=403, detail="owner subject does not match")
    try:
        signer = SensitiveActionPermitSigner.from_environment()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="permit issuer unavailable") from exc
    try:
        return SensitiveActionPermitService(_ready_sessions(), signer).issue(
            idempotency_key.strip(), request
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc


@app.post(
    "/internal/v1/sensitive-action-permits",
    tags=["internal"],
    response_model=SensitiveActionPermitV1,
    status_code=201,
)
def issue_gateway_sensitive_action_permit(
    request: GatewaySensitiveActionPermitRequest,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> SensitiveActionPermitV1:
    """Quarantined until an independently verified owner-event broker exists."""

    _require_mode("policy")
    _authorize_policy_gateway(authorization)
    raise HTTPException(status_code=403, detail="verified owner interaction required")
