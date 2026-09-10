from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from lucy.recovery_journal import (
    AuthorityJournalEffectV1,
    CostJournalEffectV1,
    InMemoryRecoveryJournal,
    RecoveryActivationHandoffV1,
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
    RecoveryWriterPauseV1,
    advance_recovery_head,
    recovery_event_digest,
    required_replay_sequences,
    verify_activation_handoff,
)


def binding(kind: RecoveryStreamKind = RecoveryStreamKind.AUTHORITY) -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=kind,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id="arn:aws:dynamodb:us-east-1:429870640638:table/synthetic",
        writer_identity="arn:aws:iam::429870640638:role/synthetic-writer",
        recovery_identity="arn:aws:iam::429870640638:role/synthetic-recovery",
        binding_manifest_digest="a" * 64,
    )


def head(
    bound: RecoveryStreamBindingV1, sequence: int = 0, digest: str | None = None
) -> RecoveryJournalHeadV1:
    return RecoveryJournalHeadV1(
        **bound.model_dump(
            exclude={"writer_identity", "recovery_identity"}, mode="python"
        ),
        sequence=sequence,
        event_digest=digest if digest is not None else "0" * 64,
    )


def event(
    bound: RecoveryStreamBindingV1, previous: RecoveryJournalHeadV1
) -> RecoveryJournalEventV1:
    values = {
        **bound.model_dump(
            exclude={"writer_identity", "recovery_identity"}, mode="python"
        ),
        "event_id": uuid4(),
        "sequence": previous.sequence + 1,
        "previous_digest": previous.event_digest,
        "operation_id": uuid4(),
        "idempotency_key": f"authority:{uuid4()}",
        "source_authority_ref": "synthetic-owner-proof",
        "source_authority_digest": "b" * 64,
        "source_generation": 1,
        "occurred_at": datetime.now(UTC),
        "effect": AuthorityJournalEffectV1(
            transition="membership_revoked",
            security_realm_id=uuid4(),
            workspace_id=uuid4(),
            subject_id=uuid4(),
            previous_generation=1,
            new_generation=2,
            previous_state="active",
            new_state="revoked",
        ),
        "event_digest": "0" * 64,
    }
    unsigned = RecoveryJournalEventV1.model_construct(**values)
    values["event_digest"] = recovery_event_digest(unsigned)
    return RecoveryJournalEventV1.model_validate(values)


def pause(
    bound: RecoveryStreamBindingV1,
    held: RecoveryJournalHeadV1,
    recovery_id: UUID,
    *,
    expires_delta: timedelta = timedelta(seconds=30),
) -> RecoveryWriterPauseV1:
    now = datetime.now(UTC)
    return RecoveryWriterPauseV1(
        pause_id=uuid4(),
        recovery_id=recovery_id,
        stream_kind=bound.stream_kind,
        stream_id=bound.stream_id,
        authority_epoch=bound.authority_epoch,
        independent_store_id=bound.independent_store_id,
        binding_manifest_digest=bound.binding_manifest_digest,
        held_head_sequence=held.sequence,
        held_head_digest=held.event_digest,
        fencing_generation=1,
        acquired_at=now,
        expires_at=now + expires_delta,
    )


def test_event_advances_only_one_exact_stream_head() -> None:
    bound = binding()
    before = head(bound)
    change = event(bound, before)
    after = advance_recovery_head(before, change)
    assert (after.sequence, after.event_digest) == (1, change.event_digest)

    wrong = head(binding())
    with pytest.raises(RecoveryJournalError, match="binding"):
        advance_recovery_head(wrong, change)
    with pytest.raises(ValidationError, match="digest"):
        RecoveryJournalEventV1.model_validate(
            change.model_copy(update={"event_digest": "f" * 64}).model_dump()
        )


def test_authority_transition_cannot_mint_an_arbitrary_state_or_generation() -> None:
    values = AuthorityJournalEffectV1(
        transition="membership_revoked",
        security_realm_id=uuid4(),
        workspace_id=uuid4(),
        subject_id=uuid4(),
        previous_generation=1,
        new_generation=2,
        previous_state="active",
        new_state="revoked",
    ).model_dump()
    with pytest.raises(ValidationError, match="states"):
        AuthorityJournalEffectV1.model_validate({**values, "new_state": "active"})
    with pytest.raises(ValidationError, match="generation"):
        AuthorityJournalEffectV1.model_validate({**values, "new_generation": 3})


def test_cost_effect_is_content_free_and_cannot_release_unresolved_exposure() -> None:
    values = {
        "transition": "reservation",
        "node_id": uuid4(),
        "channel_binding_id": uuid4(),
        "attempt_id": uuid4(),
        "policy_id": uuid4(),
        "policy_version": 1,
        "rate_version": "synthetic-v1",
        "accounting_period": datetime.now(UTC),
        "maximum_microusd": 5_000,
        "incurred_microusd": 0,
        "unresolved_microusd": 5_000,
        "request_commitment": "a" * 64,
    }
    CostJournalEffectV1.model_validate(values)
    with pytest.raises(ValidationError):
        CostJournalEffectV1.model_validate({**values, "prompt": "forbidden"})
    with pytest.raises(ValidationError, match="reservation accounting"):
        CostJournalEffectV1.model_validate({**values, "unresolved_microusd": 0})


def test_append_acknowledgement_must_name_the_exact_resulting_head() -> None:
    bound = binding()
    before = head(bound)
    change = event(bound, before)
    after = advance_recovery_head(before, change)
    RecoveryAppendAcknowledgementV1(
        event_id=change.event_id,
        event_digest=change.event_digest,
        resulting_head=after,
        acknowledged_at=datetime.now(UTC),
    )
    with pytest.raises(ValidationError, match="resulting head"):
        RecoveryAppendAcknowledgementV1(
            event_id=change.event_id,
            event_digest="f" * 64,
            resulting_head=after,
            acknowledged_at=datetime.now(UTC),
        )


def test_valid_lower_prefix_requires_replay_and_rollback_below_witness_fails() -> None:
    bound = binding()
    genesis = head(bound)
    first = advance_recovery_head(genesis, event(bound, genesis))
    second = advance_recovery_head(first, event(bound, first))
    assert list(required_replay_sequences(genesis, second, first)) == [1, 2]
    assert list(required_replay_sequences(first, second, first)) == [2]
    with pytest.raises(RecoveryJournalError, match="below its witness"):
        required_replay_sequences(genesis, first, second)
    conflicting = second.model_copy(update={"event_digest": "f" * 64})
    with pytest.raises(RecoveryJournalError, match="conflicts"):
        required_replay_sequences(conflicting, second, first)


def test_activation_requires_live_exact_heads_under_unexpired_writer_pauses() -> None:
    authority = binding()
    cost = binding(RecoveryStreamKind.COST)
    authority_head = head(authority)
    cost_head = head(cost)
    recovery_id = uuid4()
    pauses = (
        pause(authority, authority_head, recovery_id),
        pause(cost, cost_head, recovery_id),
    )
    handoff = RecoveryActivationHandoffV1(
        recovery_id=recovery_id,
        target_runtime_epoch=uuid4(),
        binding_manifest_digest="a" * 64,
        pauses=pauses,
        created_at=datetime.now(UTC),
    )
    replayed = {
        (RecoveryStreamKind.AUTHORITY, authority.stream_id): authority_head,
        (RecoveryStreamKind.COST, cost.stream_id): cost_head,
    }
    verify_activation_handoff(
        handoff,
        replayed_heads=replayed,
        live_heads=replayed,
        now=datetime.now(UTC),
    )

    advanced_cost = cost_head.model_copy(update={"sequence": 1, "event_digest": "c" * 64})
    with pytest.raises(RecoveryJournalError, match="advanced"):
        verify_activation_handoff(
            handoff,
            replayed_heads=replayed,
            live_heads={**replayed, (RecoveryStreamKind.COST, cost.stream_id): advanced_cost},
            now=datetime.now(UTC),
        )
    with pytest.raises(RecoveryJournalError, match="expired"):
        verify_activation_handoff(
            handoff,
            replayed_heads=replayed,
            live_heads=replayed,
            now=max(item.expires_at for item in pauses),
        )


def test_conditional_provider_replays_exact_event_and_rejects_conflict() -> None:
    bound = binding()
    journal = InMemoryRecoveryJournal(bound)
    before = journal.head()
    change = event(bound, before)
    first = journal.append(change, before)
    replay = journal.append(change, before)
    assert replay.event_id == first.event_id
    assert replay.resulting_head == first.resulting_head

    conflicting = change.model_copy(update={"event_digest": "f" * 64})
    with pytest.raises(RecoveryJournalError, match="ID conflicts"):
        journal.append(conflicting, before)


def test_conditional_provider_serializes_competing_appends() -> None:
    bound = binding()
    journal = InMemoryRecoveryJournal(bound)
    before = journal.head()
    changes = (event(bound, before), event(bound, before))

    def append(change: RecoveryJournalEventV1) -> str:
        try:
            journal.append(change, before)
            return "APPENDED"
        except RecoveryJournalError:
            return "DENIED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(append, changes)) == ["APPENDED", "DENIED"]
    assert journal.head().sequence == 1


def test_writer_pause_fences_append_until_expiry() -> None:
    bound = binding()
    journal = InMemoryRecoveryJournal(bound)
    before = journal.head()
    now = datetime.now(UTC)
    journal.acquire_pause(
        recovery_id=uuid4(), expected=before, duration=timedelta(seconds=30), now=now
    )
    with pytest.raises(RecoveryJournalError, match="paused"):
        journal.append(event(bound, before), before)
