"""Narrow companion API exposed to the pinned Hermes runtime."""

import os
import secrets
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from lucy.archive import (
    CaptureModeInput,
    CaptureModeResult,
    ConversationArchiveService,
    ConversationMessageArchiveInput,
    ConversationMessageArchiveResult,
)
from lucy.archive_crypto import (
    ArchiveCipher,
    ArchiveKeyStore,
    archive_dependencies_from_environment,
)
from lucy.contracts import RejoiningState
from lucy.db import create_session_factory
from lucy.db.models import LifecycleRow
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
from lucy.proposals import MemoryProposalInput, MemoryProposalService

app = FastAPI(title="Lucy Companion API", version="0.1.0")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", tags=["operations"])
def ready() -> dict[str, str]:
    database_url = os.getenv("LUCY_DATABASE_URL")
    if database_url is None:
        raise HTTPException(status_code=503, detail="memory store unavailable")
    with create_session_factory(database_url)() as session:
        lifecycle = session.scalar(select(LifecycleRow).where(LifecycleRow.singleton))
        if lifecycle is None or lifecycle.state != RejoiningState.READY:
            raise HTTPException(status_code=503, detail="Lucy is not ready")
    return {"status": "ready"}


def _authorize(authorization: str | None) -> None:
    token = os.getenv("LUCY_ADAPTER_TOKEN")
    if token is None or authorization is None or not secrets.compare_digest(
        authorization, f"Bearer {token}"
    ):
        raise HTTPException(status_code=401, detail="invalid adapter credential")


def _authorize_owner(authorization: str | None) -> None:
    token = os.getenv("LUCY_OWNER_TOKEN")
    if not token or authorization is None or not secrets.compare_digest(
        authorization, f"Bearer {token}"
    ):
        raise HTTPException(status_code=401, detail="invalid owner credential")


def _ready_sessions() -> sessionmaker[Session]:
    database_url = os.getenv("LUCY_DATABASE_URL")
    if database_url is None:
        raise HTTPException(status_code=503, detail="memory store unavailable")
    sessions = create_session_factory(database_url)
    with sessions() as session:
        lifecycle = session.scalar(select(LifecycleRow).where(LifecycleRow.singleton))
        if lifecycle is None or lifecycle.state != RejoiningState.READY:
            raise HTTPException(status_code=503, detail="Lucy is not ready")
    return sessions


def _archive_crypto() -> tuple[ArchiveCipher, ArchiveKeyStore]:
    try:
        return archive_dependencies_from_environment()
    except ValueError as exc:
        raise HTTPException(
            status_code=503, detail="archive encryption unavailable"
        ) from exc


def _archive_service() -> ConversationArchiveService:
    cipher, key_store = _archive_crypto()
    return ConversationArchiveService(_ready_sessions(), cipher, key_store)


def _evidence_service() -> EvidenceService:
    cipher, key_store = _archive_crypto()
    return EvidenceService(_ready_sessions(), cipher, key_store)


@app.get("/v1/memory/lookup", tags=["memory"])
def read_only_memory_lookup(
    query: str, authorization: str | None = Header(default=None)
) -> dict[str, object]:
    """Return a bounded projection; never expose or mutate archive evidence."""

    _authorize(authorization)
    sessions = _ready_sessions()
    context = MemoryService(sessions).build_context(query)
    return {"query": query, "claims": context.claims, "read_only": True}


@app.post("/v1/memory/proposals", tags=["memory"], status_code=202)
def propose_memory(
    candidate: MemoryProposalInput,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, object]:
    """Create a gated candidate; this endpoint can never apply a memory write."""
    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    sessions = _ready_sessions()
    try:
        result = MemoryProposalService(sessions).submit(idempotency_key, candidate)
    except LookupError as exc:
        raise HTTPException(
            status_code=404, detail="immutable evidence does not exist"
        ) from exc
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
    _authorize(authorization)
    return ModelExecutionService(_ready_sessions()).settle(request)


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

    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _archive_service().preserve_message(idempotency_key.strip(), request)
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
    _authorize(authorization)
    return _archive_service().capture_mode("telegram", source_conversation_id)


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
    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _archive_service().set_capture_mode(idempotency_key.strip(), request)
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

    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _evidence_service().delete_last_message(
            idempotency_key.strip(), request
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="retained message unavailable") from exc
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

    _authorize(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _evidence_service().retrieve(
            idempotency_key.strip(), request, owner=False
        )
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
    _authorize_owner(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _evidence_service().retrieve(
            idempotency_key.strip(), request, owner=True
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="evidence unavailable") from exc
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
    _authorize_owner(authorization)
    if evidence_id != request.evidence_id:
        raise HTTPException(status_code=400, detail="evidence identity mismatch")
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        return _evidence_service().delete(idempotency_key.strip(), request)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="evidence unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency conflict") from exc
