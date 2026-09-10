"""R1 provider-cost admission contracts and exact PostgreSQL gateway.

This boundary carries content-free request metadata only.  It reserves the
maximum possible provider charge before submission and deliberately treats an
unknown provider outcome as outstanding exposure.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.canonical import canonical_json_bytes

_COMMITMENT = re.compile(r"[0-9a-f]{64}\Z")


class ProviderCostPolicyV1(BaseModel):
    """One immutable, fully specified public-inference policy version."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: UUID
    version: int = Field(ge=1)
    node_id: UUID
    channel_binding_id: UUID
    provider: str = Field(min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=200)
    rate_version: str = Field(min_length=1, max_length=80)
    effective_at: datetime
    kill_state: Literal["enabled", "disabled"]
    platform_daily_cap_microusd: int = Field(ge=0)
    node_daily_cap_microusd: int = Field(ge=0)
    site_daily_cap_microusd: int = Field(ge=0)
    provider_daily_cap_microusd: int = Field(ge=0)
    outstanding_cap_microusd: int = Field(ge=0)
    concurrency_limit: int = Field(ge=1)
    requests_per_minute: int = Field(ge=1)
    session_requests_per_minute: int = Field(ge=1)
    ip_requests_per_minute: int = Field(ge=1)
    per_request_cap_microusd: int = Field(ge=0)
    max_input_tokens: int = Field(ge=1)
    max_output_tokens: int = Field(ge=1)
    max_request_bytes: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)

    @model_validator(mode="after")
    def caps_are_coherent(self) -> ProviderCostPolicyV1:
        daily = (
            self.platform_daily_cap_microusd,
            self.node_daily_cap_microusd,
            self.site_daily_cap_microusd,
            self.provider_daily_cap_microusd,
        )
        if self.per_request_cap_microusd > min(*daily, self.outstanding_cap_microusd):
            raise ValueError("per-request cost cap exceeds an enclosing cap")
        return self

    def digest_hex(self) -> str:
        return hashlib.sha256(
            b"LUCY-PROVIDER-COST-POLICY-V1\0"
            + canonical_json_bytes(self.model_dump(mode="json"))
        ).hexdigest()


class ProviderAttemptRequestV1(BaseModel):
    """Content-free maximum-cost request presented to the admission gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=300)
    node_id: UUID
    channel_binding_id: UUID
    provider: str = Field(min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=200)
    rate_version: str = Field(min_length=1, max_length=80)
    request_commitment: str
    session_commitment: str
    ip_commitment: str
    maximum_microusd: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    request_bytes: int = Field(ge=0)
    timeout_seconds: int = Field(ge=1)
    requested_at: datetime

    @model_validator(mode="after")
    def commitments_and_time_are_canonical(self) -> ProviderAttemptRequestV1:
        if any(
            _COMMITMENT.fullmatch(value) is None
            for value in (
                self.request_commitment,
                self.session_commitment,
                self.ip_commitment,
            )
        ):
            raise ValueError("provider attempt commitments must be lowercase SHA-256 values")
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("provider attempt time must be timezone-aware")
        return self


class ProviderAttemptAdmissionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt_id: UUID
    policy_id: UUID
    policy_version: int = Field(ge=1)
    state: Literal[
        "PERSISTENCE_PENDING",
        "ADMITTED",
        "SUBMITTED",
        "UNKNOWN",
        "SETTLEMENT_PENDING",
        "OVER_CAP_PENDING",
        "SETTLED",
        "OVER_CAP",
    ]
    reserved_microusd: int = Field(ge=0)
    unresolved_microusd: int = Field(ge=0)
    event_id: UUID
    replayed: bool


class ProviderCostAdmissionService:
    """Execute-only client for database-enforced provider-cost transitions."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def reserve(self, request: ProviderAttemptRequestV1) -> ProviderAttemptAdmissionV1:
        with self._sessions.begin() as session:
            result = session.execute(
                text(
                    "SELECT lucy.reserve_provider_attempt_v1("
                    ":attempt_id,:idempotency_key,:node_id,:channel_binding_id,:provider,"
                    ":model,:rate_version,:request_commitment,:session_commitment,"
                    ":ip_commitment,:maximum_microusd,:input_tokens,:output_tokens,"
                    ":request_bytes,:timeout_seconds,:requested_at)"
                ),
                request.model_dump(mode="python"),
            ).scalar_one()
        return ProviderAttemptAdmissionV1.model_validate(result)

    def acknowledge(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1:
        if _COMMITMENT.fullmatch(head_digest) is None:
            raise ValueError("cost journal head digest is invalid")
        return self._transition(
            "acknowledge_provider_reservation_v1",
            {"attempt_id": attempt_id, "event_id": event_id, "head_digest": head_digest},
        )

    def claim_submission(self, attempt_id: UUID) -> ProviderAttemptAdmissionV1:
        return self._transition("claim_provider_submission_v1", {"attempt_id": attempt_id})

    def mark_unknown(self, attempt_id: UUID) -> ProviderAttemptAdmissionV1:
        return self._transition("mark_provider_attempt_unknown_v1", {"attempt_id": attempt_id})

    def settle(
        self,
        *,
        attempt_id: UUID,
        incurred_microusd: int,
        provider_reference_commitment: str,
    ) -> ProviderAttemptAdmissionV1:
        if incurred_microusd < 0 or _COMMITMENT.fullmatch(provider_reference_commitment) is None:
            raise ValueError("provider settlement is invalid")
        result = self._transition(
            "settle_provider_attempt_v1",
            {
                "attempt_id": attempt_id,
                "incurred_microusd": incurred_microusd,
                "provider_reference_commitment": provider_reference_commitment,
            },
        )
        return result

    def acknowledge_outcome(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1:
        if _COMMITMENT.fullmatch(head_digest) is None:
            raise ValueError("cost journal head digest is invalid")
        result = self._transition(
            "acknowledge_provider_outcome_v1",
            {"attempt_id": attempt_id, "event_id": event_id, "head_digest": head_digest},
        )
        if result.state == "OVER_CAP":
            raise ProviderCostOverrun(result)
        return result

    def _transition(self, function: str, values: dict[str, object]) -> ProviderAttemptAdmissionV1:
        arguments = ",".join(f":{name}" for name in values)
        with self._sessions.begin() as session:
            result = session.execute(
                text(f"SELECT lucy.{function}({arguments})"), values
            ).scalar_one()
        return ProviderAttemptAdmissionV1.model_validate(result)


class ProviderCostOverrun(RuntimeError):
    """The real charge was recorded, but exceeded the admitted maximum."""

    def __init__(self, result: ProviderAttemptAdmissionV1) -> None:
        self.result = result
        super().__init__("provider cost exceeded the admitted maximum")


def utc_now() -> datetime:
    return datetime.now(UTC)
