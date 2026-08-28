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
