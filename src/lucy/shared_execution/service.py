"""Local-only state machine for beginning the Tiamat executor implementation.

The in-memory store is intentionally not a production adapter. It exercises the RC1 transition
contract and provides a seam for a durable fenced PostgreSQL store without claiming crash safety.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, replace
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from lucy.shared_execution.output_validation import validate_output
from lucy.shared_execution.wire import (
    CostReceipt,
    ExecutionRequest,
    ExecutionResponse,
    JsonSchemaOutput,
    OutputResult,
    Usage,
)


@dataclass(frozen=True)
class ExecutionProfile:
    profile_id: str
    release_id: str
    allowed_modes: frozenset[Literal["text", "json_schema"]]
    maximum_output_tokens: int
    maximum_cost_microusd: int


@dataclass(frozen=True)
class ProviderResult:
    content: str | dict[str, Any]
    input_tokens: int
    generated_tokens: int
    output_tokens: int | None
    reasoning_tokens: int | None
    cost_microusd: int


class ProviderTransport(Protocol):
    def execute(self, request: ExecutionRequest, profile: ExecutionProfile) -> ProviderResult: ...


@dataclass(frozen=True)
class ExecutionRecord:
    execution_id: UUID
    identity_digest: str
    state: Literal["admitted", "dispatched", "completed", "failed", "outcome_unknown"]
    reserved_microusd: int
    response: ExecutionResponse | None = None


class IdempotencyConflict(RuntimeError):
    """A scoped key was already used for a different canonical operation."""


class ExecutionInProgress(RuntimeError):
    """The one admitted operation has not reached a replayable terminal state."""


class ExecutionFailure(RuntimeError):
    """A mapped post-dispatch RC1 failure without provider details."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class InMemoryExecutionStore:
    """Atomic local test store; replace with durable fenced state before deployment."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], ExecutionRecord] = {}

    def create_or_get(
        self, caller: str, key: str, identity_digest: str, reserved_microusd: int
    ) -> tuple[ExecutionRecord, bool]:
        scoped = (caller, key)
        with self._lock:
            existing = self._records.get(scoped)
            if existing is not None:
                if existing.identity_digest != identity_digest:
                    raise IdempotencyConflict
                return existing, False
            record = ExecutionRecord(
                execution_id=uuid4(),
                identity_digest=identity_digest,
                state="admitted",
                reserved_microusd=reserved_microusd,
            )
            self._records[scoped] = record
            return record, True

    def transition(
        self,
        caller: str,
        key: str,
        expected: str,
        state: Literal["admitted", "dispatched", "completed", "failed", "outcome_unknown"],
        *,
        response: ExecutionResponse | None = None,
    ) -> ExecutionRecord:
        scoped = (caller, key)
        with self._lock:
            record = self._records[scoped]
            if record.state != expected:
                raise ExecutionInProgress
            updated = replace(record, state=state, response=response)
            self._records[scoped] = updated
            return updated


class SharedExecutionService:
    """Profile-pinned, single-dispatch executor over an injected provider transport."""

    def __init__(
        self,
        store: InMemoryExecutionStore,
        transport: ProviderTransport,
        profiles: dict[str, ExecutionProfile],
    ) -> None:
        self._store = store
        self._transport = transport
        self._profiles = dict(profiles)

    def execute(
        self,
        *,
        caller: str,
        idempotency_key: str,
        request_id: UUID,
        request: ExecutionRequest,
    ) -> ExecutionResponse:
        profile = self._profiles.get(request.execution_profile_id)
        if profile is None or request.output.mode not in profile.allowed_modes:
            raise PermissionError("execution profile is not authorized for this route")
        if request.limits.max_output_tokens > profile.maximum_output_tokens:
            raise ValueError("output contract exceeds the profile")
        if request.limits.max_cost_microusd < profile.maximum_cost_microusd:
            raise ValueError("cost ceiling cannot reserve the complete profile maximum")

        identity = canonical_identity(request)
        record, created = self._store.create_or_get(
            caller, idempotency_key, identity, profile.maximum_cost_microusd
        )
        if not created:
            if record.state == "completed" and record.response is not None:
                return record.response.model_copy(
                    update={"request_id": request_id, "replayed": True}
                )
            raise ExecutionInProgress

        # This durable-before-send ordering is the important seam. The in-memory adapter exercises
        # it, while the production adapter must add fencing, leases, and ambiguous-commit recovery.
        self._store.transition(caller, idempotency_key, "admitted", "dispatched")
        result = self._transport.execute(request, profile)
        if result.cost_microusd > profile.maximum_cost_microusd:
            self._store.transition(caller, idempotency_key, "dispatched", "failed")
            raise ExecutionFailure("cost_settlement_violation")
        if result.generated_tokens > request.limits.max_output_tokens:
            self._store.transition(caller, idempotency_key, "dispatched", "failed")
            raise ExecutionFailure("output_limit_reached")

        output_mode = request.output.mode
        if output_mode == "text" and not isinstance(result.content, str):
            self._store.transition(caller, idempotency_key, "dispatched", "failed")
            raise ExecutionFailure("provider_response_invalid")
        if isinstance(result.content, str) and len(result.content.encode("utf-8")) > 65_536:
            self._store.transition(caller, idempotency_key, "dispatched", "failed")
            raise ExecutionFailure("provider_response_too_large")
        if isinstance(request.output, JsonSchemaOutput) and (
            not isinstance(result.content, dict)
            or not validate_output(request.output.schema_, result.content)
        ):
            self._store.transition(caller, idempotency_key, "dispatched", "failed")
            raise ExecutionFailure("provider_response_invalid")
        if isinstance(result.content, dict):
            output_bytes = json.dumps(
                result.content,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if len(output_bytes) > 65_536:
                self._store.transition(caller, idempotency_key, "dispatched", "failed")
                raise ExecutionFailure("provider_response_too_large")

        response = ExecutionResponse(
            contract="stoin.inference.execute.response.v1",
            request_id=request_id,
            execution_id=record.execution_id,
            replayed=False,
            execution_profile_id=profile.profile_id,
            profile_release_id=profile.release_id,
            output=OutputResult(mode=output_mode, content=result.content),
            finish_reason="stop",
            usage=Usage(
                input_tokens=result.input_tokens,
                generated_tokens=result.generated_tokens,
                output_tokens=result.output_tokens,
                reasoning_tokens=result.reasoning_tokens,
            ),
            cost=CostReceipt(
                reserved_microusd=profile.maximum_cost_microusd,
                settled_microusd=result.cost_microusd,
                settlement_status="settled",
            ),
        )
        response_bytes = response.model_dump_json(by_alias=True).encode("utf-8")
        if len(response_bytes) > 131_072:
            self._store.transition(caller, idempotency_key, "dispatched", "failed")
            raise ExecutionFailure("provider_response_too_large")
        self._store.transition(
            caller, idempotency_key, "dispatched", "completed", response=response
        )
        return response


def canonical_identity(request: ExecutionRequest) -> str:
    """Hash the current JSON subset; RFC 8785 differential proof remains a Tier B gate."""

    payload = request.model_dump(mode="json", by_alias=True)
    encoded = json.dumps(
        payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
