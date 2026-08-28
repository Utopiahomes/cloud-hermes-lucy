"""Fail-closed deterministic action classification."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ActionDisposition(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ActionIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_type: str = Field(min_length=1, max_length=200)
    estimated_microusd: int = Field(ge=0)


class ActionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    disposition: ActionDisposition
    reason: str
    budget_name: str | None = None


_LOW_RISK = {
    "memory.lookup": "model.daily",
    "model.evaluate.synthetic": "model.daily",
    "status.read": None,
}

_GATED = {
    "memory.propose": "model.daily",
    "telegram.send": "action.daily",
    "calendar.write": "action.daily",
    "file.write": "action.daily",
}

_DENIED = {
    "shell.execute",
    "database.raw",
    "approval.decide",
    "budget.raise",
    "archive.mutate",
    "audit.mutate",
}


def classify_action(intent: ActionIntent) -> ActionDecision:
    """Classify an intent without consulting model-authored text."""
    if intent.action_type in _DENIED:
        return ActionDecision(
            disposition=ActionDisposition.DENY, reason="action_type_denied"
        )
    if intent.action_type in _LOW_RISK:
        return ActionDecision(
            disposition=ActionDisposition.ALLOW, reason="known_low_risk_action",
            budget_name=_LOW_RISK[intent.action_type],
        )
    if intent.action_type in _GATED:
        return ActionDecision(
            disposition=ActionDisposition.REQUIRE_APPROVAL,
            reason="human_approval_required", budget_name=_GATED[intent.action_type],
        )
    return ActionDecision(
        disposition=ActionDisposition.DENY, reason="unknown_action_type"
    )
