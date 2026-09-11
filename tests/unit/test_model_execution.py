from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.model_execution import (
    MODEL,
    RESERVATION_MICROUSD,
    ModelExecutionBegin,
    ModelExecutionSettlement,
    ModelUsage,
)


def test_begin_contract_pins_model_and_reservation() -> None:
    request = ModelExecutionBegin(
        idempotency_key="hermes-model:session:request",
        model=MODEL,
        reservation_microusd=RESERVATION_MICROUSD,
        session_id="session",
        api_request_id="request",
    )
    assert request.model == MODEL
    with pytest.raises(ValidationError):
        ModelExecutionBegin(
            idempotency_key="hermes-model:session:request",
            model="unreviewed/model",
            reservation_microusd=RESERVATION_MICROUSD,
            session_id="session",
            api_request_id="request",
        )
    with pytest.raises(ValidationError):
        ModelExecutionBegin(
            idempotency_key="hermes-model:wrong:key",
            model=MODEL,
            reservation_microusd=RESERVATION_MICROUSD,
            session_id="session",
            api_request_id="request",
        )
    with pytest.raises(ValidationError):
        ModelExecutionBegin(
            idempotency_key="hermes-model:session:request",
            model=MODEL,
            reservation_microusd=1,
            session_id="session",
            api_request_id="request",
        )


def test_settlement_cannot_exceed_reservation() -> None:
    with pytest.raises(ValidationError):
        ModelExecutionSettlement(
            action_id=uuid4(),
            actual_microusd=RESERVATION_MICROUSD + 1,
            succeeded=True,
            usage=ModelUsage(),
        )


def test_telegram_execution_identity_is_complete_and_event_bound() -> None:
    event_id, holder_id = uuid4(), uuid4()
    request = ModelExecutionBegin(
        idempotency_key=f"hermes-model:telegram-event:{event_id}:model-step:1",
        model=MODEL,
        reservation_microusd=RESERVATION_MICROUSD,
        session_id=f"telegram-event:{event_id}",
        api_request_id="model-step:1",
        telegram_event_id=event_id,
        telegram_model_step=1,
        telegram_holder_id=holder_id,
        telegram_lease_fence=2,
    )
    assert request.telegram_event_id == event_id
    with pytest.raises(ValidationError):
        ModelExecutionBegin.model_validate(
            {**request.model_dump(), "telegram_model_step": None}
        )
