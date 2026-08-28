import pytest

from lucy.policy import ActionDisposition, ActionIntent, classify_action


@pytest.mark.parametrize(
    ("action_type", "expected"),
    [
        ("memory.lookup", ActionDisposition.ALLOW),
        ("model.evaluate.synthetic", ActionDisposition.ALLOW),
        ("model.infer", ActionDisposition.DENY),
        ("memory.propose", ActionDisposition.REQUIRE_APPROVAL),
        ("telegram.send", ActionDisposition.REQUIRE_APPROVAL),
        ("approval.decide", ActionDisposition.DENY),
        ("shell.execute", ActionDisposition.DENY),
        ("invented.by.model", ActionDisposition.DENY),
    ],
)
def test_action_policy_is_explicit_and_fail_closed(
    action_type: str, expected: ActionDisposition
) -> None:
    decision = classify_action(ActionIntent(action_type=action_type, estimated_microusd=10))
    assert decision.disposition == expected


def test_model_cannot_smuggle_policy_fields() -> None:
    with pytest.raises(ValueError):
        ActionIntent.model_validate(
            {"action_type": "memory.lookup", "estimated_microusd": 0, "approved": True}
        )
