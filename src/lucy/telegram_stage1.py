"""Content-free restart and duplicate-delivery ledger for private Telegram Stage 1."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lucy.model_execution import (
    ModelExecutionBegin,
    ModelExecutionBeginResult,
    ModelExecutionSettlement,
    ModelExecutionSettlementResult,
)


class TelegramStage1Unavailable(RuntimeError):
    """The database-enforced Stage 1 boundary rejected the operation."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TelegramGatewayBinding(_StrictModel):
    node_id: UUID
    realm_id: UUID
    channel_binding_id: UUID
    bot_id: int = Field(gt=0)

    @classmethod
    def from_environment(cls) -> TelegramGatewayBinding:
        try:
            return cls.model_validate(
                {
                    "node_id": os.environ["LUCY_TELEGRAM_NODE_ID"],
                    "realm_id": os.environ["LUCY_TELEGRAM_REALM_ID"],
                    "channel_binding_id": os.environ["LUCY_TELEGRAM_CHANNEL_BINDING_ID"],
                    "bot_id": int(os.environ["LUCY_TELEGRAM_BOT_ID"]),
                }
            )
        except (KeyError, ValueError) as exc:
            raise TelegramStage1Unavailable("Stage 1 binding is unavailable") from exc


class GatewayLeaseRequest(_StrictModel):
    holder_id: UUID
    lease_seconds: Literal[30] = 30


class GatewayLeaseResult(_StrictModel):
    holder_id: UUID
    fence: int = Field(ge=1)
    lease_until: datetime
    acquired: bool


class TelegramEventClaimRequest(_StrictModel):
    holder_id: UUID
    fence: int = Field(ge=1)
    event_id: UUID
    update_id: int = Field(ge=0)
    chat_id: int
    message_id: int = Field(gt=0)


class TelegramEventClaimResult(_StrictModel):
    event_id: UUID
    state: str
    admitted: bool
    replayed: bool


TelegramEventState = Literal[
    "INFERENCE_STARTED",
    "INFERENCE_SETTLED",
    "SEND_STARTED",
    "SENT",
    "COMPLETED_NO_REPLY",
    "INTERRUPTED",
    "DELIVERY_UNCERTAIN",
]


class TelegramEventTransitionRequest(_StrictModel):
    holder_id: UUID
    fence: int = Field(ge=1)
    event_id: UUID
    state: TelegramEventState
    outbound_message_id: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def outbound_id_matches_state(self) -> TelegramEventTransitionRequest:
        if (self.state == "SENT") != (self.outbound_message_id is not None):
            raise ValueError("outbound message ID is required only for SENT")
        return self


class TelegramEventTransitionResult(_StrictModel):
    event_id: UUID
    state: str
    replayed: bool


class TelegramStage1Service:
    """Invoke execute-only PostgreSQL functions bound to one routine identity."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        binding: TelegramGatewayBinding,
    ) -> None:
        self._sessions = sessions
        self._binding = binding

    def acquire(self, request: GatewayLeaseRequest) -> GatewayLeaseResult:
        return GatewayLeaseResult.model_validate(
            self._call(
                "SELECT lucy.acquire_telegram_gateway_lease_v1("
                ":node,:realm,:channel,:bot,:holder,:seconds) AS result",
                request,
            )
        )

    def heartbeat(self, request: GatewayLeaseRequest) -> GatewayLeaseResult:
        return GatewayLeaseResult.model_validate(
            self._call(
                "SELECT lucy.heartbeat_telegram_gateway_lease_v1("
                ":node,:realm,:channel,:bot,:holder,:seconds) AS result",
                request,
            )
        )

    def release(self, request: GatewayLeaseRequest) -> GatewayLeaseResult:
        return GatewayLeaseResult.model_validate(
            self._call(
                "SELECT lucy.release_telegram_gateway_lease_v1("
                ":node,:realm,:channel,:bot,:holder) AS result",
                request,
            )
        )

    def claim(self, request: TelegramEventClaimRequest) -> TelegramEventClaimResult:
        return TelegramEventClaimResult.model_validate(
            self._call(
                "SELECT lucy.claim_telegram_event_v1("
                ":node,:realm,:channel,:bot,:holder,:fence,:event_id,"
                ":update_id,:chat_id,:message_id) AS result",
                request,
            )
        )

    def transition(
        self, request: TelegramEventTransitionRequest
    ) -> TelegramEventTransitionResult:
        return TelegramEventTransitionResult.model_validate(
            self._call(
                "SELECT lucy.transition_telegram_event_v1("
                ":node,:realm,:channel,:bot,:holder,:fence,:event_id,"
                ":state,:outbound_message_id) AS result",
                request,
            )
        )

    def begin_model_execution(
        self, request: ModelExecutionBegin
    ) -> ModelExecutionBeginResult:
        if (
            request.telegram_event_id is None
            or request.telegram_model_step is None
            or request.telegram_holder_id is None
            or request.telegram_lease_fence is None
        ):
            raise TelegramStage1Unavailable("Stage 1 model identity is unavailable")
        action_id = uuid5(
            NAMESPACE_URL,
            "lucy-stage1-model:"
            f"{request.telegram_event_id}:{request.telegram_model_step}",
        )
        return ModelExecutionBeginResult.model_validate(
            self._call(
                "SELECT lucy.begin_telegram_model_operation_v1("
                ":node,:realm,:channel,:bot,:telegram_holder_id,"
                ":telegram_lease_fence,:telegram_event_id,:telegram_model_step,"
                ":action_id,:idempotency_key,:model,:reservation_microusd) AS result",
                request,
                extra={"action_id": action_id},
            )
        )

    def settle_model_execution(
        self, request: ModelExecutionSettlement
    ) -> ModelExecutionSettlementResult:
        if (
            request.telegram_event_id is None
            or request.telegram_model_step is None
            or request.telegram_holder_id is None
            or request.telegram_lease_fence is None
        ):
            raise TelegramStage1Unavailable("Stage 1 model identity is unavailable")
        return ModelExecutionSettlementResult.model_validate(
            self._call(
                "SELECT lucy.settle_telegram_model_operation_v1("
                ":node,:realm,:channel,:bot,:telegram_holder_id,"
                ":telegram_lease_fence,:telegram_event_id,:telegram_model_step,"
                ":action_id,:actual_microusd,:succeeded) AS result",
                request,
            )
        )

    def _call(
        self,
        statement: str,
        request: BaseModel,
        *,
        extra: dict[str, object] | None = None,
    ) -> object:
        request_values = request.model_dump(mode="python")
        if "holder_id" in request_values:
            request_values["holder"] = request_values.pop("holder_id")
        if "lease_seconds" in request_values:
            request_values["seconds"] = request_values.pop("lease_seconds")
        values = {
            "node": self._binding.node_id,
            "realm": self._binding.realm_id,
            "channel": self._binding.channel_binding_id,
            "bot": self._binding.bot_id,
            **request_values,
            **(extra or {}),
        }
        values.setdefault("seconds", 30)
        values.setdefault("fence", 0)
        values.setdefault("event_id", uuid4())
        values.setdefault("update_id", 0)
        values.setdefault("chat_id", 0)
        values.setdefault("message_id", 1)
        values.setdefault("state", "INTERRUPTED")
        values.setdefault("outbound_message_id", None)
        try:
            with self._sessions.begin() as session:
                result = session.execute(text(statement), values).scalar_one()
        except SQLAlchemyError as exc:
            raise TelegramStage1Unavailable("Stage 1 ledger operation unavailable") from exc
        if not isinstance(result, dict):
            raise TelegramStage1Unavailable("Stage 1 ledger returned an invalid result")
        return result


def utc_now() -> datetime:
    """A timezone-aware clock helper used by black-box tests and ledgers."""

    return datetime.now(UTC)
