from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from lucy.db import create_session_factory
from lucy.recovery_coordinator import PostgresRecoveryActivator
from lucy.recovery_journal import (
    RecoveryActivationHandoffV1,
    RecoveryJournalError,
    RecoveryJournalHeadV1,
    RecoveryStreamKind,
    RecoveryWriterPauseV1,
)

OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not OWNER_URL,
    reason="requires PostgreSQL recovery-activation integration database",
)


def _head(kind: RecoveryStreamKind) -> RecoveryJournalHeadV1:
    return RecoveryJournalHeadV1(
        stream_kind=kind,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id=f"synthetic:{kind.value}",
        binding_manifest_digest="a" * 64,
        sequence=1,
        event_digest=("b" if kind is RecoveryStreamKind.AUTHORITY else "c") * 64,
    )


def _handoff(
    heads: tuple[RecoveryJournalHeadV1, RecoveryJournalHeadV1],
    runtime_epoch=None,
) -> RecoveryActivationHandoffV1:
    recovery_id = uuid4()
    now = datetime.now(UTC)
    pauses = tuple(
        RecoveryWriterPauseV1(
            pause_id=uuid4(),
            recovery_id=recovery_id,
            stream_kind=head.stream_kind,
            stream_id=head.stream_id,
            authority_epoch=head.authority_epoch,
            independent_store_id=head.independent_store_id,
            binding_manifest_digest=head.binding_manifest_digest,
            held_head_sequence=head.sequence,
            held_head_digest=head.event_digest,
            fencing_generation=1,
            acquired_at=now,
            expires_at=now + timedelta(seconds=30),
        )
        for head in heads
    )
    return RecoveryActivationHandoffV1(
        recovery_id=recovery_id,
        target_runtime_epoch=runtime_epoch or uuid4(),
        binding_manifest_digest="a" * 64,
        pauses=pauses,
        created_at=now,
    )


@pytest.fixture(autouse=True)
def recovered_boundary():
    assert OWNER_URL is not None
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        if connection.scalar(text("SELECT current_database()")) != "lucy_test":
            raise RuntimeError("refusing to alter a non-synthetic database")
        connection.execute(
            text(
                "TRUNCATE lucy.restored_cost_exposures_v1,"
                "lucy.restored_cost_admission_v1,lucy.restored_recovery_events_v1,"
                "lucy.restored_recovery_heads_v1 CASCADE"
            )
        )
        connection.execute(text("UPDATE lucy.lifecycle SET state='ready' WHERE singleton"))
        connection.execute(
            text(
                "UPDATE lucy.runtime_admission SET state='quarantined',storage_epoch=NULL,"
                "updated_at=now() WHERE singleton"
            )
        )
    engine.dispose()


def _install_heads(heads: tuple[RecoveryJournalHeadV1, RecoveryJournalHeadV1]) -> None:
    assert OWNER_URL is not None
    with create_engine(OWNER_URL).begin() as connection:
        for head in heads:
            connection.execute(
                text(
                    "INSERT INTO lucy.restored_recovery_heads_v1 VALUES "
                    "(:kind,:stream,:epoch,:store,:manifest,:sequence,:digest,now())"
                ),
                {
                    "kind": head.stream_kind.value,
                    "stream": head.stream_id,
                    "epoch": head.authority_epoch,
                    "store": head.independent_store_id,
                    "manifest": head.binding_manifest_digest,
                    "sequence": head.sequence,
                    "digest": head.event_digest,
                },
            )
        cost = next(head for head in heads if head.stream_kind is RecoveryStreamKind.COST)
        connection.execute(
            text(
                "INSERT INTO lucy.restored_cost_admission_v1 "
                "VALUES (:stream,'finalized',false,now(),now()+interval '90 seconds')"
            ),
            {"stream": cost.stream_id},
        )


def test_exact_recovery_handoff_activates_once_under_target_epoch() -> None:
    assert OWNER_URL is not None
    heads = (_head(RecoveryStreamKind.AUTHORITY), _head(RecoveryStreamKind.COST))
    _install_heads(heads)
    handoff = _handoff(heads)
    activator = PostgresRecoveryActivator(create_session_factory(OWNER_URL))
    mapping = {(head.stream_kind, head.stream_id): head for head in heads}

    activator.activate(handoff, mapping)
    activator.activate(handoff, mapping)

    with create_engine(OWNER_URL).connect() as connection:
        assert connection.execute(
            text("SELECT state,storage_epoch FROM lucy.runtime_admission WHERE singleton")
        ).one() == ("ready", handoff.target_runtime_epoch)


def test_changed_restored_head_cannot_activate() -> None:
    assert OWNER_URL is not None
    heads = (_head(RecoveryStreamKind.AUTHORITY), _head(RecoveryStreamKind.COST))
    _install_heads(heads)
    handoff = _handoff(heads)
    changed = heads[1].model_copy(update={"sequence": 2, "event_digest": "d" * 64})
    mapping = {
        (heads[0].stream_kind, heads[0].stream_id): heads[0],
        (changed.stream_kind, changed.stream_id): changed,
    }

    with pytest.raises(RecoveryJournalError, match="heads changed"):
        PostgresRecoveryActivator(create_session_factory(OWNER_URL)).activate(handoff, mapping)
    with create_engine(OWNER_URL).connect() as connection:
        assert connection.scalar(
            text("SELECT state FROM lucy.runtime_admission WHERE singleton")
        ) == "quarantined"
