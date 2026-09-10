"""Content-free contracts for independent R1 authority and cost recovery journals.

These contracts describe evidence retained outside restored PostgreSQL. They do
not grant authority to perform a domain transition or to reopen admission.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import canonical_sha256

_SAFE_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$"
_DIGEST = r"^[0-9a-f]{64}$"
_MAX_PAUSE = timedelta(seconds=60)

SafeIdentifier = Annotated[str, Field(min_length=1, max_length=512, pattern=_SAFE_IDENTIFIER)]
DigestHex = Annotated[str, Field(pattern=_DIGEST)]


class RecoveryJournalError(RuntimeError):
    """Content-free recovery failure; callers must remain quarantined."""


class StrictRecoveryContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RecoveryStreamKind(StrEnum):
    AUTHORITY = "authority"
    COST = "cost"


class RecoveryStreamBindingV1(StrictRecoveryContract):
    contract_version: Literal["1"] = "1"
    stream_kind: RecoveryStreamKind
    stream_id: UUID
    authority_epoch: int = Field(ge=1)
    independent_store_id: SafeIdentifier
    writer_identity: SafeIdentifier
    recovery_identity: SafeIdentifier
    binding_manifest_digest: DigestHex


class RecoveryJournalHeadV1(StrictRecoveryContract):
    contract_version: Literal["1"] = "1"
    stream_kind: RecoveryStreamKind
    stream_id: UUID
    authority_epoch: int = Field(ge=1)
    independent_store_id: SafeIdentifier
    binding_manifest_digest: DigestHex
    sequence: int = Field(ge=0)
    event_digest: DigestHex

    @model_validator(mode="after")
    def genesis_is_explicit(self) -> Self:
        if self.sequence == 0 and self.event_digest != "0" * 64:
            raise ValueError("recovery journal genesis digest is invalid")
        return self


AuthorityTransition = Literal[
    "principal_disabled",
    "membership_granted",
    "membership_revoked",
    "channel_activated",
    "channel_withdrawn",
    "service_binding_activated",
    "service_binding_revoked",
    "publication_published",
    "publication_withdrawn",
]
AuthorityState = Literal[
    "absent", "pending", "active", "published", "disabled", "revoked", "inactive", "withdrawn"
]


class AuthorityJournalEffectV1(StrictRecoveryContract):
    effect_type: Literal["authority"] = "authority"
    transition: AuthorityTransition
    security_realm_id: UUID
    workspace_id: UUID
    subject_id: UUID
    previous_generation: int = Field(ge=0)
    new_generation: int = Field(ge=1)
    previous_state: AuthorityState
    new_state: AuthorityState

    @model_validator(mode="after")
    def transition_is_monotonic_and_typed(self) -> Self:
        expected: dict[str, tuple[str, str]] = {
            "principal_disabled": ("active", "disabled"),
            "membership_granted": ("pending", "active"),
            "membership_revoked": ("active", "revoked"),
            "channel_activated": ("inactive", "active"),
            "channel_withdrawn": ("active", "inactive"),
            "service_binding_activated": ("inactive", "active"),
            "service_binding_revoked": ("active", "inactive"),
            "publication_published": ("withdrawn", "published"),
            "publication_withdrawn": ("published", "withdrawn"),
        }
        if (self.previous_state, self.new_state) != expected[self.transition]:
            raise ValueError("authority transition states do not match its type")
        if self.new_generation != self.previous_generation + 1:
            raise ValueError("authority generation must advance exactly once")
        return self


CostTransition = Literal["reservation", "unknown", "settlement", "over_cap", "release"]


class CostJournalEffectV1(StrictRecoveryContract):
    effect_type: Literal["cost"] = "cost"
    transition: CostTransition
    node_id: UUID
    channel_binding_id: UUID
    attempt_id: UUID
    policy_id: UUID
    policy_version: int = Field(ge=1)
    rate_version: SafeIdentifier
    accounting_period: datetime
    maximum_microusd: int = Field(ge=0)
    incurred_microusd: int = Field(ge=0)
    unresolved_microusd: int = Field(ge=0)
    request_commitment: DigestHex
    provider_reference_commitment: DigestHex | None = None

    @model_validator(mode="after")
    def accounting_is_coherent(self) -> Self:
        _require_aware(self.accounting_period, "accounting_period")
        if self.transition == "reservation":
            if self.incurred_microusd or self.unresolved_microusd != self.maximum_microusd:
                raise ValueError("cost reservation accounting is invalid")
        elif self.transition == "unknown":
            if self.unresolved_microusd != self.maximum_microusd:
                raise ValueError("unknown cost must retain maximum exposure")
        elif self.transition in {"settlement", "release"}:
            if self.incurred_microusd > self.maximum_microusd or self.unresolved_microusd:
                raise ValueError("settled cost accounting is invalid")
        elif self.incurred_microusd <= self.maximum_microusd or self.unresolved_microusd:
            raise ValueError("over-cap accounting is invalid")
        if self.transition in {"settlement", "over_cap"}:
            if self.provider_reference_commitment is None:
                raise ValueError("provider outcome commitment is required")
        elif self.provider_reference_commitment is not None:
            raise ValueError("provider outcome commitment is not allowed")
        return self


JournalEffectV1 = Annotated[
    AuthorityJournalEffectV1 | CostJournalEffectV1,
    Field(discriminator="effect_type"),
]


class RecoveryJournalEventV1(StrictRecoveryContract):
    contract_version: Literal["1"] = "1"
    event_id: UUID
    stream_kind: RecoveryStreamKind
    stream_id: UUID
    authority_epoch: int = Field(ge=1)
    independent_store_id: SafeIdentifier
    binding_manifest_digest: DigestHex
    sequence: int = Field(ge=1)
    previous_digest: DigestHex
    operation_id: UUID
    idempotency_key: SafeIdentifier
    source_authority_ref: SafeIdentifier
    source_authority_digest: DigestHex
    source_generation: int = Field(ge=1)
    occurred_at: datetime
    effect: JournalEffectV1
    event_digest: DigestHex

    @model_validator(mode="after")
    def event_is_bound_and_canonical(self) -> Self:
        _require_aware(self.occurred_at, "occurred_at")
        if self.stream_kind.value != self.effect.effect_type:
            raise ValueError("journal effect does not match stream kind")
        expected = recovery_event_digest(self)
        if not secrets.compare_digest(self.event_digest, expected):
            raise ValueError("recovery journal event digest is invalid")
        return self


class RecoveryAppendAcknowledgementV1(StrictRecoveryContract):
    contract_version: Literal["1"] = "1"
    event_id: UUID
    event_digest: DigestHex
    resulting_head: RecoveryJournalHeadV1
    acknowledged_at: datetime

    @model_validator(mode="after")
    def acknowledgement_is_exact(self) -> Self:
        _require_aware(self.acknowledged_at, "acknowledged_at")
        if self.resulting_head.event_digest != self.event_digest:
            raise ValueError("acknowledgement does not match resulting head")
        return self


class RecoveryWriterPauseV1(StrictRecoveryContract):
    contract_version: Literal["1"] = "1"
    pause_id: UUID
    recovery_id: UUID
    stream_kind: RecoveryStreamKind
    stream_id: UUID
    authority_epoch: int = Field(ge=1)
    independent_store_id: SafeIdentifier
    binding_manifest_digest: DigestHex
    held_head_sequence: int = Field(ge=0)
    held_head_digest: DigestHex
    fencing_generation: int = Field(ge=1)
    acquired_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def pause_is_short_and_explicit(self) -> Self:
        _require_aware(self.acquired_at, "acquired_at")
        _require_aware(self.expires_at, "expires_at")
        if not self.acquired_at < self.expires_at <= self.acquired_at + _MAX_PAUSE:
            raise ValueError("recovery writer pause lifetime is invalid")
        if self.held_head_sequence == 0 and self.held_head_digest != "0" * 64:
            raise ValueError("recovery writer pause genesis digest is invalid")
        return self


class RecoveryActivationHandoffV1(StrictRecoveryContract):
    contract_version: Literal["1"] = "1"
    recovery_id: UUID
    target_runtime_epoch: UUID
    binding_manifest_digest: DigestHex
    pauses: tuple[RecoveryWriterPauseV1, ...] = Field(min_length=1)
    created_at: datetime

    @model_validator(mode="after")
    def handoff_has_one_pause_per_stream(self) -> Self:
        _require_aware(self.created_at, "created_at")
        keys = [(pause.stream_kind, pause.stream_id) for pause in self.pauses]
        if len(keys) != len(set(keys)):
            raise ValueError("recovery handoff contains duplicate streams")
        if any(
            pause.recovery_id != self.recovery_id
            or pause.binding_manifest_digest != self.binding_manifest_digest
            for pause in self.pauses
        ):
            raise ValueError("recovery handoff pause binding differs")
        return self


def recovery_event_digest(event: RecoveryJournalEventV1) -> str:
    return canonical_sha256(
        event.model_dump(mode="python", exclude={"event_digest"}),
        prefix=b"LUCY-RECOVERY-JOURNAL-EVENT-V1\0",
    )


def advance_recovery_head(
    previous: RecoveryJournalHeadV1, event: RecoveryJournalEventV1
) -> RecoveryJournalHeadV1:
    _same_stream(previous, event)
    if event.sequence != previous.sequence + 1 or event.previous_digest != previous.event_digest:
        raise RecoveryJournalError("recovery journal chain is not contiguous")
    return RecoveryJournalHeadV1(
        stream_kind=event.stream_kind,
        stream_id=event.stream_id,
        authority_epoch=event.authority_epoch,
        independent_store_id=event.independent_store_id,
        binding_manifest_digest=event.binding_manifest_digest,
        sequence=event.sequence,
        event_digest=event.event_digest,
    )


def required_replay_sequences(
    restored: RecoveryJournalHeadV1,
    live: RecoveryJournalHeadV1,
    witness: RecoveryJournalHeadV1,
) -> range:
    _same_stream(restored, live)
    _same_stream(live, witness)
    if live.sequence < witness.sequence or (
        live.sequence == witness.sequence and live.event_digest != witness.event_digest
    ):
        raise RecoveryJournalError("independent recovery journal is below its witness")
    if restored.sequence > live.sequence or (
        restored.sequence == live.sequence and restored.event_digest != live.event_digest
    ):
        raise RecoveryJournalError("restored recovery journal prefix conflicts with live authority")
    return range(restored.sequence + 1, live.sequence + 1)


def verify_activation_handoff(
    handoff: RecoveryActivationHandoffV1,
    *,
    replayed_heads: Mapping[tuple[RecoveryStreamKind, UUID], RecoveryJournalHeadV1],
    live_heads: Mapping[tuple[RecoveryStreamKind, UUID], RecoveryJournalHeadV1],
    now: datetime,
) -> None:
    _require_aware(now, "now")
    pauses = {(pause.stream_kind, pause.stream_id): pause for pause in handoff.pauses}
    if set(replayed_heads) != set(pauses) or set(live_heads) != set(pauses):
        raise RecoveryJournalError("recovery handoff does not cover every required stream")
    for key, pause in pauses.items():
        replayed = replayed_heads[key]
        live = live_heads[key]
        _same_stream(replayed, live)
        if now >= pause.expires_at:
            raise RecoveryJournalError("recovery writer pause expired")
        expected = (pause.held_head_sequence, pause.held_head_digest)
        if (replayed.sequence, replayed.event_digest) != expected:
            raise RecoveryJournalError("recovery replay did not reach the paused head")
        if (live.sequence, live.event_digest) != expected:
            raise RecoveryJournalError("recovery journal advanced during handoff")


class InMemoryRecoveryJournal:
    """Thread-safe acceptance provider for conditional journal semantics.

    This provider is deliberately non-durable and must never be selected in
    production. It exists to exercise the transaction contract without AWS.
    """

    def __init__(self, binding: RecoveryStreamBindingV1) -> None:
        self._binding = binding
        self._head = RecoveryJournalHeadV1(
            stream_kind=binding.stream_kind,
            stream_id=binding.stream_id,
            authority_epoch=binding.authority_epoch,
            independent_store_id=binding.independent_store_id,
            binding_manifest_digest=binding.binding_manifest_digest,
            sequence=0,
            event_digest="0" * 64,
        )
        self._events_by_id: dict[UUID, RecoveryJournalEventV1] = {}
        self._events_by_sequence: dict[int, RecoveryJournalEventV1] = {}
        self._pause: RecoveryWriterPauseV1 | None = None
        self._fencing_generation = 0
        self._lock = Lock()

    def head(self) -> RecoveryJournalHeadV1:
        with self._lock:
            return self._head

    def event(self, sequence: int) -> RecoveryJournalEventV1:
        with self._lock:
            try:
                return self._events_by_sequence[sequence]
            except KeyError:
                raise RecoveryJournalError("recovery journal event is unavailable") from None

    def append(
        self,
        event: RecoveryJournalEventV1,
        expected: RecoveryJournalHeadV1,
    ) -> RecoveryAppendAcknowledgementV1:
        with self._lock:
            existing = self._events_by_id.get(event.event_id)
            if existing is not None:
                if existing.event_digest != event.event_digest:
                    raise RecoveryJournalError("recovery journal event ID conflicts")
                return self._acknowledgement(existing)
            now = datetime.now(UTC)
            if self._pause is not None and now < self._pause.expires_at:
                raise RecoveryJournalError("recovery journal writer is paused")
            if expected != self._head:
                raise RecoveryJournalError("recovery journal advanced")
            next_head = advance_recovery_head(expected, event)
            self._events_by_id[event.event_id] = event
            self._events_by_sequence[event.sequence] = event
            self._head = next_head
            return self._acknowledgement(event)

    def acquire_pause(
        self,
        *,
        pause_id: UUID,
        recovery_id: UUID,
        expected: RecoveryJournalHeadV1,
        duration: timedelta,
        now: datetime,
    ) -> RecoveryWriterPauseV1:
        _require_aware(now, "now")
        if duration <= timedelta(0) or duration > _MAX_PAUSE:
            raise RecoveryJournalError("recovery writer pause duration is invalid")
        with self._lock:
            if expected != self._head:
                raise RecoveryJournalError("recovery journal advanced before writer pause")
            if self._pause is not None and now < self._pause.expires_at:
                raise RecoveryJournalError("recovery journal writer is already paused")
            self._fencing_generation += 1
            self._pause = RecoveryWriterPauseV1(
                pause_id=pause_id,
                recovery_id=recovery_id,
                stream_kind=self._binding.stream_kind,
                stream_id=self._binding.stream_id,
                authority_epoch=self._binding.authority_epoch,
                independent_store_id=self._binding.independent_store_id,
                binding_manifest_digest=self._binding.binding_manifest_digest,
                held_head_sequence=self._head.sequence,
                held_head_digest=self._head.event_digest,
                fencing_generation=self._fencing_generation,
                acquired_at=now,
                expires_at=now + duration,
            )
            return self._pause

    def _acknowledgement(
        self, event: RecoveryJournalEventV1
    ) -> RecoveryAppendAcknowledgementV1:
        return RecoveryAppendAcknowledgementV1(
            event_id=event.event_id,
            event_digest=event.event_digest,
            resulting_head=RecoveryJournalHeadV1(
                stream_kind=event.stream_kind,
                stream_id=event.stream_id,
                authority_epoch=event.authority_epoch,
                independent_store_id=event.independent_store_id,
                binding_manifest_digest=event.binding_manifest_digest,
                sequence=event.sequence,
                event_digest=event.event_digest,
            ),
            acknowledged_at=datetime.now(UTC),
        )


def _same_stream(left: object, right: object) -> None:
    fields = (
        "stream_kind",
        "stream_id",
        "authority_epoch",
        "independent_store_id",
        "binding_manifest_digest",
    )
    if any(getattr(left, field) != getattr(right, field) for field in fields):
        raise RecoveryJournalError("recovery journal stream binding mismatch")


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
