from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from lucy.authority_recovery import (
    AuthorityTransitionCoordinator,
    AuthorityTransitionRequestV1,
    AuthorityTransitionResultV1,
)
from lucy.recovery_journal import RecoveryJournalError


class FakeTransitions:
    def __init__(self) -> None:
        self.event_id = uuid4()
        self.calls = 0
        self.durable = False

    def revoke_membership(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._result(request, "membership_revoked")

    def withdraw_publication(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._result(request, "publication_withdrawn")

    def activate_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._result(request, "channel_activated")

    def withdraw_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._result(request, "channel_withdrawn")

    def _result(
        self, request: AuthorityTransitionRequestV1, event_type: str
    ) -> AuthorityTransitionResultV1:
        self.calls += 1
        return AuthorityTransitionResultV1.model_validate(
            {
                "event_id": self.event_id,
                "state": "DURABLY_RECORDED" if self.durable else "PERSISTENCE_PENDING",
                "stream_id": request.stream_id,
                "authority_epoch": request.authority_epoch,
                "event_type": event_type,
                "security_realm_id": uuid4(),
                "workspace_id": uuid4(),
                "subject_id": request.subject_id,
                "previous_generation": 1,
                "new_generation": 2,
                "transition_digest": "d" * 64,
                "journal_sequence": 1 if self.durable else None,
                "journal_previous_digest": "0" * 64 if self.durable else None,
                "journal_event_digest": "e" * 64 if self.durable else None,
                "journal_head_digest": "e" * 64 if self.durable else None,
                "replayed": self.calls > 1,
            }
        )


class FakeWriter:
    def __init__(self, transitions: FakeTransitions, *, fail: bool = False) -> None:
        self.transitions = transitions
        self.fail = fail
        self.calls: list[UUID] = []

    def append_pending(self, event_id: UUID) -> SimpleNamespace:
        self.calls.append(event_id)
        if self.fail:
            raise RecoveryJournalError("synthetic writer unavailable")
        return SimpleNamespace(event_id=event_id, event_digest="e" * 64)


class FakeAcknowledgements:
    def __init__(self, transitions: FakeTransitions) -> None:
        self.transitions = transitions
        self.calls: list[tuple[UUID, str]] = []

    def acknowledge_authority(
        self, event_id: UUID, *, head_digest: str
    ) -> SimpleNamespace:
        self.calls.append((event_id, head_digest))
        self.transitions.durable = True
        return SimpleNamespace(
            event_id=event_id,
            state="DURABLY_RECORDED",
        )


def request() -> AuthorityTransitionRequestV1:
    return AuthorityTransitionRequestV1(
        subject_id=uuid4(),
        actor_id=uuid4(),
        stream_id=uuid4(),
        authority_epoch=1,
        idempotency_key=f"authority:{uuid4()}",
        source_authority_ref=f"owner:{uuid4()}",
        source_authority_digest="a" * 64,
    )


@pytest.mark.parametrize(
    "operation",
    ["revoke_membership", "withdraw_publication", "activate_channel", "withdraw_channel"],
)
def test_restriction_returns_only_after_both_durable_barriers(operation: str) -> None:
    transitions = FakeTransitions()
    writer = FakeWriter(transitions)
    acknowledgements = FakeAcknowledgements(transitions)
    coordinator = AuthorityTransitionCoordinator(transitions, writer, acknowledgements)
    result = getattr(coordinator, operation)(request())
    assert result.state == "DURABLY_RECORDED"
    assert transitions.calls == 2
    assert writer.calls == [transitions.event_id]
    assert acknowledgements.calls == [(transitions.event_id, "e" * 64)]


def test_local_restriction_remains_pending_when_journal_is_unavailable() -> None:
    transitions = FakeTransitions()
    writer = FakeWriter(transitions, fail=True)
    coordinator = AuthorityTransitionCoordinator(
        transitions, writer, FakeAcknowledgements(transitions)
    )
    with pytest.raises(RecoveryJournalError, match="writer unavailable"):
        coordinator.revoke_membership(request())
    assert transitions.calls == 1
    assert transitions.durable is False


def test_durable_replay_performs_no_external_writes() -> None:
    transitions = FakeTransitions()
    transitions.durable = True
    writer = FakeWriter(transitions)
    acknowledgements = FakeAcknowledgements(transitions)
    result = AuthorityTransitionCoordinator(
        transitions, writer, acknowledgements
    ).revoke_membership(request())
    assert result.state == "DURABLY_RECORDED"
    assert writer.calls == []
    assert acknowledgements.calls == []
