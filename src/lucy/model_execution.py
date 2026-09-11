"""Internal Hermes model-execution budget bridge."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session, sessionmaker

from lucy.actions import ActionControlService
from lucy.db.models import ActionExecutionRow
from lucy.policy import ActionIntent

MODEL = "openai/gpt-oss-20b"
RESERVATION_MICROUSD = 5_000


class ModelExecutionBegin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    idempotency_key: str = Field(min_length=1, max_length=500)
    model: Literal["openai/gpt-oss-20b"]
    reservation_microusd: Literal[5000]
    session_id: str = Field(max_length=500)
    api_request_id: str = Field(min_length=1, max_length=500)
    telegram_event_id: UUID | None = None
    telegram_model_step: int | None = Field(default=None, ge=1)
    telegram_holder_id: UUID | None = None
    telegram_lease_fence: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def idempotency_key_matches_request(self) -> "ModelExecutionBegin":
        expected = f"hermes-model:{self.session_id}:{self.api_request_id}"
        if self.idempotency_key != expected:
            raise ValueError("idempotency key does not match request identity")
        telegram_fields = (
            self.telegram_event_id,
            self.telegram_model_step,
            self.telegram_holder_id,
            self.telegram_lease_fence,
        )
        if any(value is not None for value in telegram_fields) and not all(
            value is not None for value in telegram_fields
        ):
            raise ValueError("Telegram execution identity must be complete")
        if self.telegram_event_id is not None and (
            self.session_id != f"telegram-event:{self.telegram_event_id}"
            or self.api_request_id != f"model-step:{self.telegram_model_step}"
        ):
            raise ValueError("Telegram execution identity does not match the event")
        return self


class ModelExecutionBeginResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: UUID
    status: str
    execute: bool
    replayed: bool


class ModelUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    provider_cost_microusd: int | None = Field(default=None, ge=0)


class ModelExecutionSettlement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: UUID
    actual_microusd: int = Field(ge=0, le=RESERVATION_MICROUSD)
    succeeded: bool
    usage: ModelUsage
    telegram_event_id: UUID | None = None
    telegram_model_step: int | None = Field(default=None, ge=1)
    telegram_holder_id: UUID | None = None
    telegram_lease_fence: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def telegram_identity_is_complete(self) -> "ModelExecutionSettlement":
        fields = (
            self.telegram_event_id,
            self.telegram_model_step,
            self.telegram_holder_id,
            self.telegram_lease_fence,
        )
        if any(value is not None for value in fields) and not all(
            value is not None for value in fields
        ):
            raise ValueError("Telegram execution identity must be complete")
        return self


class ModelExecutionSettlementResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: UUID
    status: str
    replayed: bool


class ModelExecutionService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions
        self._actions = ActionControlService(sessions)

    def begin(self, request: ModelExecutionBegin) -> ModelExecutionBeginResult:
        submitted = self._actions.submit(
            idempotency_key=request.idempotency_key,
            intent=ActionIntent(
                action_type="model.infer.openrouter",
                estimated_microusd=request.reservation_microusd,
            ),
            payload={
                "model": request.model,
                "session_id": request.session_id,
                "api_request_id": request.api_request_id,
            },
        )
        if submitted.status != "reserved":
            return ModelExecutionBeginResult(
                action_id=submitted.action_id,
                status=submitted.status,
                execute=False,
                replayed=True,
            )
        executing = self._actions.begin_execution(submitted.action_id)
        return ModelExecutionBeginResult(
            action_id=executing.action_id,
            status=executing.status,
            execute=not executing.replayed,
            replayed=executing.replayed,
        )

    def settle(
        self, request: ModelExecutionSettlement
    ) -> ModelExecutionSettlementResult:
        with self._sessions() as session:
            row = session.get(ActionExecutionRow, request.action_id)
            if (
                row is None
                or row.action_type != "model.infer.openrouter"
                or row.estimated_microusd != RESERVATION_MICROUSD
            ):
                raise PermissionError("action is not a Hermes model execution")
        result = self._actions.settle(
            request.action_id,
            actual_microusd=request.actual_microusd,
            succeeded=request.succeeded,
            result={
                "kind": "hermes_openrouter_inference",
                "usage": request.usage.model_dump(mode="json"),
            },
        )
        return ModelExecutionSettlementResult(
            action_id=result.action_id,
            status=result.status,
            replayed=result.replayed,
        )
