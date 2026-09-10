"""Narrow companion API exposed to the pinned Hermes runtime."""

import base64
import json
import os
import re
import secrets
from functools import lru_cache
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
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
from lucy.contracts.security_v1_2 import (
    ContractTrustStore,
    DeletionTargetManifestV1,
    DeploymentEnvironment,
    Ed25519ContractSigner,
    ExecutorReceiptV1,
    OwnerInteractionAssertionV1,
    SensitiveActionPermitV2,
    SensitiveActionV2,
    SensitiveExecutionGrantV1,
    SensitiveReasonCode,
    VerificationKeyV1,
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
    expected_database_login_from_environment,
    expected_storage_epoch,
    security_baseline_from_environment,
    service_mode_from_environment,
)
from lucy.realm_archive_commit import (
    RealmConversationArchiveService,
    realm_conversation_archive_from_environment,
)
from lucy.secret_filter import MemorySecretDetected
from lucy.security_workflows import (
    BotoLambdaExecutorInvoker,
    DeletionCoordinator,
    DeletionWorkflowResultV1,
    ExecutorBindingV1,
    HttpPolicyNotaryClient,
    PolicyNotaryService,
    RetrievalCoordinator,
    RetrievalWorkflowResultV1,
    SqlSecurityWorkflowStore,
    WorkflowRejected,
)

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


def _require_legacy_sensitive_api_allowed() -> None:
    if (
        os.getenv("LUCY_SECURITY_ENVIRONMENT", "").strip() == "production"
        or security_baseline_from_environment() == "v1.3"
    ):
        raise HTTPException(status_code=404, detail="endpoint unavailable")


def _require_v12_sensitive_api() -> None:
    if security_baseline_from_environment() != "v1.2":
        raise HTTPException(status_code=404, detail="endpoint unavailable")


def _ready_sessions() -> sessionmaker[Session]:
    database_url = os.getenv("LUCY_DATABASE_URL")
    if database_url is None:
        raise HTTPException(status_code=503, detail="memory store unavailable")
    try:
        mode = _service_mode()
        baseline = security_baseline_from_environment()
        epoch = expected_storage_epoch(mode)
        # Cache engines rather than creating a new connection pool per request.
        sessions = _readiness_sessions(database_url)
        journal = (
            deletion_journal_from_environment()
            if baseline == "v1.2" and mode == "routine"
            else None
        )
        ServiceReadiness(
            sessions,
            mode=mode,
            storage_epoch=epoch,
            journal=journal,
            baseline=baseline,
            expected_database_login=expected_database_login_from_environment(baseline),
        ).check()
        return admitted_session_factory(
            database_url,
            epoch,
            journal,
            journal_required=baseline == "v1.2" and mode == "routine",
        )
    except (ReadinessError, DeletionJournalError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=503, detail="Lucy storage is not admitted") from exc


@lru_cache(maxsize=8)
def _readiness_sessions(database_url: str) -> sessionmaker[Session]:
    return create_session_factory(database_url)


def _required_environment(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"required configuration is missing: {name}")
    return value


def _positive_environment_int(name: str) -> int:
    try:
        value = int(_required_environment(name))
    except ValueError as exc:
        raise ValueError(f"required integer configuration is invalid: {name}") from exc
    if value < 1:
        raise ValueError(f"required integer configuration is invalid: {name}")
    return value


def _verification_keys(name: str) -> tuple[VerificationKeyV1, ...]:
    try:
        payload = json.loads(_required_environment(name))
        if not isinstance(payload, list):
            raise ValueError("verification-key inventory must be a list")
        keys = tuple(VerificationKeyV1.model_validate(item) for item in payload)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("verification-key inventory is invalid") from exc
    if not keys:
        raise ValueError("verification-key inventory is empty")
    return keys


@lru_cache(maxsize=1)
def _policy_notary() -> PolicyNotaryService:
    environment = DeploymentEnvironment(_required_environment("LUCY_SECURITY_ENVIRONMENT"))
    try:
        private_seed = base64.b64decode(
            _required_environment("LUCY_POLICY_SIGNING_PRIVATE_KEY_B64"),
            validate=True,
        )
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_seed)
    except ValueError as exc:
        raise ValueError("policy signing key is invalid") from exc
    signer = Ed25519ContractSigner(
        private_key,
        key_id=_required_environment("LUCY_POLICY_KEY_ID"),
    )
    return PolicyNotaryService(
        SqlSecurityWorkflowStore(_ready_sessions()),
        owner_trust_store=ContractTrustStore(
            _verification_keys("LUCY_OWNER_TRUST_STORE_JSON")
        ),
        receipt_trust_store=ContractTrustStore(
            _verification_keys("LUCY_EXECUTOR_RECEIPT_TRUST_STORE_JSON")
        ),
        signer=signer,
        issuer=_required_environment("LUCY_POLICY_ISSUER"),
        environment=environment,
        bindings=(
            ExecutorBindingV1(
                action=SensitiveActionV2.EVIDENCE_RETRIEVE,
                environment=environment,
                executor_identity=_required_environment(
                    "LUCY_RETRIEVAL_EXECUTOR_IDENTITY"
                ),
                executor_alias_arn=_required_environment(
                    "LUCY_RETRIEVAL_EXECUTOR_ALIAS_ARN"
                ),
                executor_version=_positive_environment_int(
                    "LUCY_RETRIEVAL_EXECUTOR_VERSION"
                ),
            ),
            ExecutorBindingV1(
                action=SensitiveActionV2.EVIDENCE_DELETE,
                environment=environment,
                executor_identity=_required_environment(
                    "LUCY_DELETION_EXECUTOR_IDENTITY"
                ),
                executor_alias_arn=_required_environment(
                    "LUCY_DELETION_EXECUTOR_ALIAS_ARN"
                ),
                executor_version=_positive_environment_int(
                    "LUCY_DELETION_EXECUTOR_VERSION"
                ),
            ),
        ),
    )


@lru_cache(maxsize=2)
def _policy_workflow_client(mode: str) -> HttpPolicyNotaryClient:
    if mode not in {"evidence", "deletion"}:
        raise ValueError("policy client is unavailable in this service mode")
    return HttpPolicyNotaryClient(
        _required_environment("LUCY_POLICY_HOSTPORT"),
        _required_environment("LUCY_POLICY_GATEWAY_TOKEN"),
    )


@lru_cache(maxsize=2)
def _executor_invoker(mode: str) -> BotoLambdaExecutorInvoker:
    if mode not in {"evidence", "deletion"}:
        raise ValueError("executor client is unavailable in this service mode")
    client = boto3.client(
        "lambda",
        region_name=_required_environment("AWS_REGION"),
    )
    if mode == "evidence":
        return BotoLambdaExecutorInvoker(
            client,
            retrieval_alias_arn=_required_environment(
                "LUCY_AWS_RETRIEVAL_EXECUTOR_ALIAS_ARN"
            ),
        )
    return BotoLambdaExecutorInvoker(
        client,
        deletion_alias_arn=_required_environment(
            "LUCY_AWS_DELETION_EXECUTOR_ALIAS_ARN"
        ),
    )


def _archive_crypto() -> tuple[ArchiveCipher, ArchiveKeyStore]:
    try:
        return archive_dependencies_from_environment()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="archive encryption unavailable") from exc


def _archive_service() -> ConversationArchiveService | RealmConversationArchiveService:
    if os.getenv("LUCY_ARCHIVE_BACKEND") == "aws-kms-dynamodb-v13":
        try:
            return realm_conversation_archive_from_environment()
        except ValueError as exc:
            raise HTTPException(
                status_code=503, detail="realm archive boundary unavailable"
            ) from exc
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
    _require_legacy_sensitive_api_allowed()
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
    _require_legacy_sensitive_api_allowed()
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
    _require_legacy_sensitive_api_allowed()
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
    _require_legacy_sensitive_api_allowed()
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


class PermitIssueV2Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    assertion: OwnerInteractionAssertionV1
    reason: SensitiveReasonCode
    record_version: int = Field(ge=1)


class DeletionManifestV2Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    permit: SensitiveActionPermitV2
    idempotency_key: str = Field(min_length=1, max_length=512)


class RetrievalExecuteV2Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    permit: SensitiveActionPermitV2


class DeletionExecuteV2Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    permit: SensitiveActionPermitV2


class DeliveryOutcomeV2Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    accepted: bool


_POLICY_PERMIT_STORAGE_FAILURE_CODES = {
    "invalid permit issuance idempotency key": "invalid_idempotency_key",
    "signed authorization contracts must be JSON objects": "invalid_contract_container",
    "owner assertion contains unknown fields": "assertion_unknown_fields",
    "V2 permit contains unknown fields": "permit_unknown_fields",
    "invalid owner assertion contract domain": "assertion_domain_invalid",
    "invalid V2 permit contract domain": "permit_domain_invalid",
    "owner assertion and permit bindings differ": "assertion_permit_binding_mismatch",
    "authorization environment or epoch mismatch": "authorization_epoch_mismatch",
    "owner assertion is outside its freshness window": "assertion_freshness_invalid",
    "permit is outside its claim window": "permit_freshness_invalid",
    "authorization nonce length is invalid": "nonce_length_invalid",
    "retrieval permit scope is invalid": "retrieval_scope_invalid",
    "deletion permit scope is invalid": "deletion_scope_invalid",
    "unsupported sensitive action": "action_invalid",
    "evidence is unavailable for new authorization": "evidence_unavailable",
    "permit issuance idempotency conflict": "idempotency_conflict",
    "malformed v1.2 authorization contract": "contract_malformed",
}

_POLICY_PERMIT_VALUE_FAILURE_CODES = {
    "verification-key inventory is invalid": "verification_key_inventory_invalid",
    "verification-key inventory is empty": "verification_key_inventory_empty",
    "verification-key inventory contains duplicate key IDs": "verification_key_id_duplicate",
    "policy signing key is invalid": "policy_signing_key_invalid",
    "signing key ID is invalid": "policy_signing_key_id_invalid",
    "policy requires one exact binding for each sensitive action": "executor_binding_set_invalid",
    "policy executor binding environment differs": "executor_binding_environment_invalid",
    "Ed25519 signer cannot sign this contract algorithm": "permit_algorithm_invalid",
    "contract key ID does not match the signer": "permit_signing_key_mismatch",
    "unsigned contract unexpectedly contains a signature": "permit_signature_state_invalid",
    "security workflow function returned no result": "permit_store_no_result",
}


def _policy_permit_storage_failure_code(error: SQLAlchemyError) -> str:
    original = getattr(error, "orig", None)
    diagnostic = getattr(original, "diag", None)
    primary = getattr(diagnostic, "message_primary", None)
    if not isinstance(primary, str):
        return "unclassified_database_error"
    return _POLICY_PERMIT_STORAGE_FAILURE_CODES.get(
        primary,
        "unclassified_database_error",
    )


def _policy_permit_value_failure_code(error: ValueError) -> str:
    return _POLICY_PERMIT_VALUE_FAILURE_CODES.get(
        str(error),
        "unclassified_value_error",
    )


@app.post(
    "/owner/v2/security/permits",
    tags=["owner"],
    response_model=SensitiveActionPermitV2,
    status_code=201,
)
def issue_sensitive_action_permit_v2(
    request: PermitIssueV2Input,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> SensitiveActionPermitV2:
    """Accept only a fresh broker-signed owner interaction and issue an exact V2 permit."""

    _require_mode("policy")
    _require_v12_sensitive_api()
    _authorize_owner(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    owner_subject = os.getenv("LUCY_OWNER_SUBJECT", "").strip()
    if not owner_subject or request.assertion.owner_subject != owner_subject:
        raise HTTPException(status_code=403, detail="owner subject does not match")
    try:
        notary = _policy_notary()
    except ValidationError as exc:
        print("Lucy policy permit failed closed: policy_configuration_validation_error", flush=True)
        raise HTTPException(status_code=409, detail="permit issuance failed closed") from exc
    except ValueError as exc:
        failure_code = _policy_permit_value_failure_code(exc)
        print(f"Lucy policy permit failed closed: {failure_code}", flush=True)
        raise HTTPException(status_code=409, detail="permit issuance failed closed") from exc
    try:
        return notary.issue_permit(
            request.assertion,
            reason=request.reason,
            record_version=request.record_version,
            idempotency_key=idempotency_key.strip(),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="owner assertion not authorized") from exc
    except WorkflowRejected as exc:
        raise HTTPException(status_code=403, detail="sensitive action not authorized") from exc
    except ValidationError as exc:
        print("Lucy policy permit failed closed: permit_contract_validation_error", flush=True)
        raise HTTPException(status_code=409, detail="permit issuance failed closed") from exc
    except ValueError as exc:
        failure_code = _policy_permit_value_failure_code(exc)
        print(f"Lucy policy permit failed closed: {failure_code}", flush=True)
        raise HTTPException(status_code=409, detail="permit issuance failed closed") from exc
    except SQLAlchemyError as exc:
        failure_code = _policy_permit_storage_failure_code(exc)
        print(f"Lucy policy permit failed closed: {failure_code}", flush=True)
        raise HTTPException(status_code=409, detail="permit issuance failed closed") from exc


@app.post(
    "/internal/v2/security/deletion-manifests",
    tags=["internal"],
    response_model=DeletionTargetManifestV1,
)
def prepare_deletion_manifest_v2(
    request: DeletionManifestV2Input,
    authorization: str | None = Header(default=None),
) -> DeletionTargetManifestV1:
    _require_mode("policy")
    _require_v12_sensitive_api()
    _authorize_policy_gateway(authorization)
    try:
        return _policy_notary().prepare_deletion_manifest(
            request.permit,
            idempotency_key=request.idempotency_key,
        )
    except WorkflowRejected as exc:
        status = 409 if exc.code == "bulk_required" else 403
        raise HTTPException(status_code=status, detail=exc.code) from exc
    except (ValueError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=409, detail="deletion scope failed closed") from exc


@app.post(
    "/internal/v2/security/operations/{operation_id}/grant",
    tags=["internal"],
    response_model=SensitiveExecutionGrantV1,
)
def notarize_sensitive_operation_v2(
    operation_id: UUID,
    authorization: str | None = Header(default=None),
) -> SensitiveExecutionGrantV1:
    _require_mode("policy")
    _require_v12_sensitive_api()
    _authorize_policy_gateway(authorization)
    try:
        return _policy_notary().notarize_operation(operation_id)
    except (WorkflowRejected, ValueError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=403, detail="operation not eligible for grant") from exc


@app.post(
    "/internal/v2/security/operations/{operation_id}/receipt-attestation",
    tags=["internal"],
)
def attest_executor_receipt_v2(
    operation_id: UUID,
    receipt: ExecutorReceiptV1,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    _require_mode("policy")
    _require_v12_sensitive_api()
    _authorize_policy_gateway(authorization)
    try:
        return {"receipt_digest": _policy_notary().attest_receipt(operation_id, receipt)}
    except (PermissionError, WorkflowRejected, ValueError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=403, detail="executor receipt not trusted") from exc


@app.post(
    "/owner/v2/evidence/retrieve",
    tags=["owner"],
    response_model=RetrievalWorkflowResultV1,
)
def owner_retrieve_evidence_v2(
    request: RetrievalExecuteV2Input,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> RetrievalWorkflowResultV1:
    _require_mode("evidence")
    _require_v12_sensitive_api()
    _authorize_owner(authorization)
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        mode = _service_mode()
        return RetrievalCoordinator(
            SqlSecurityWorkflowStore(_ready_sessions()),
            _policy_workflow_client(mode),
            _executor_invoker(mode),
        ).execute(request.permit, idempotency_key=idempotency_key.strip())
    except WorkflowRejected as exc:
        raise HTTPException(status_code=403, detail=exc.code) from exc
    except (ValueError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=409, detail="retrieval failed closed") from exc


@app.post(
    "/internal/v2/evidence/{operation_id}/delivery",
    tags=["internal"],
)
def record_evidence_delivery_v2(
    operation_id: UUID,
    request: DeliveryOutcomeV2Input,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    _require_mode("evidence")
    _require_v12_sensitive_api()
    _authorize(authorization)
    try:
        state = SqlSecurityWorkflowStore(_ready_sessions()).record_delivery(
            operation_id,
            "accepted" if request.accepted else "unknown",
        )
        return {"state": state.value}
    except (ValueError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=409, detail="delivery outcome failed closed") from exc


@app.post(
    "/owner/v2/evidence/{evidence_id}/delete",
    tags=["owner"],
    response_model=DeletionWorkflowResultV1,
)
def owner_delete_evidence_v2(
    evidence_id: UUID,
    request: DeletionExecuteV2Input,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> DeletionWorkflowResultV1:
    _require_mode("deletion")
    _require_v12_sensitive_api()
    _authorize_owner(authorization)
    if request.permit.evidence_id != evidence_id:
        raise HTTPException(status_code=400, detail="evidence identity mismatch")
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    try:
        mode = _service_mode()
        policy = _policy_workflow_client(mode)
        manifest = policy.prepare_deletion_manifest(
            request.permit,
            idempotency_key=idempotency_key.strip(),
        )
        return DeletionCoordinator(
            SqlSecurityWorkflowStore(_ready_sessions()),
            policy,
            _executor_invoker(mode),
        ).execute(
            request.permit,
            manifest,
            idempotency_key=idempotency_key.strip(),
        )
    except WorkflowRejected as exc:
        status = 409 if exc.code == "bulk_required" else 403
        raise HTTPException(status_code=status, detail=exc.code) from exc
    except (ValueError, SQLAlchemyError) as exc:
        raise HTTPException(status_code=409, detail="deletion failed closed") from exc
