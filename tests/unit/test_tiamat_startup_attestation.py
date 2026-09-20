from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg
import pytest

from lucy.shared_execution.recovery_anchor import (
    InMemoryExternalRecoveryAnchor,
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)
from lucy.shared_execution.startup_attestation import (
    StartupAttestationIssuer,
    StartupAttestationRejected,
)

NOW = datetime(2026, 9, 20, 12, tzinfo=UTC)
CHECKPOINT = "a" * 64


class _CheckpointSource:
    def read_checkpoint_digest(self, identity: RecoveryAnchorIdentity) -> str:
        return CHECKPOINT


class _Result:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, Any] | None:
        return self._row


class _Connection:
    def __init__(
        self,
        identity: RecoveryAnchorIdentity,
        *,
        database_now: datetime,
        floor_version: int = 0,
        floor_digest: str | None = None,
    ) -> None:
        self.identity = identity
        self.database_now = database_now
        self.floor_version = floor_version
        self.floor_digest = floor_digest
        self.executed: list[tuple[str, tuple[Any, ...] | None]] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def transaction(self) -> Any:
        return nullcontext()

    def execute(self, query: str, params: tuple[Any, ...] | None = None) -> _Result:
        self.executed.append((query, params))
        normalized = " ".join(query.split())
        if "set_config" in normalized:
            return _Result(None)
        if normalized == "SELECT current_user":
            return _Result({"current_user": "tiamat_recovery"})
        if "FROM tiamat.restore_gate AS gate" in normalized:
            return _Result(
                {
                    "storage_epoch": self.identity.storage_epoch,
                    "recovery_generation": 1,
                    "dispatch_blocked": False,
                    "anchor_floor_version": self.floor_version,
                    "anchor_floor_sha256": self.floor_digest,
                    "ledger_id": self.identity.ledger_id,
                }
            )
        if "pg_control_system" in normalized:
            return _Result(
                {
                    "system_identifier": "123",
                    "timeline_id": 1,
                    "flushed_wal_lsn": "0/200",
                }
            )
        if "FROM tiamat.startup_attestations" in normalized:
            return _Result(None)
        if "SELECT clock_timestamp() AS now" in normalized:
            return _Result({"now": self.database_now})
        if "UPDATE tiamat.restore_gate" in normalized:
            return _Result(None)
        if "INSERT INTO tiamat.startup_attestations" in normalized:
            return _Result(
                {"attestation_id": uuid4(), "expires_at": params[-1] if params else None}
            )
        raise AssertionError(f"unexpected query: {normalized}")


def _transition(identity: RecoveryAnchorIdentity) -> VerifiedAnchorTransition:
    witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=1,
        witness_revision=1,
        status="reconciled",
        checkpoint_digest=CHECKPOINT,
        release_heads_sha256="b" * 64,
        checkpoint_settlement_position_sha256="c" * 64,
        witness_inventory_digest="d" * 64,
        exact_jws=b"witness",
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
    )
    return VerifiedAnchorTransition(
        witness=witness,
        transition_version=1,
        previous_transition_sha256=None,
        continuity="continuity_established",
        beacon=PostgresContinuityBeacon("123", 1, "0/100", CHECKPOINT),
        exact_jws=b"transition",
    )


def test_issuer_atomically_writes_floor_and_short_lived_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    anchor = InMemoryExternalRecoveryAnchor()
    transition = _transition(identity)
    anchor.install(transition, expected_transition_sha256=None, now=NOW)
    connection = _Connection(identity, database_now=NOW)
    monkeypatch.setattr(
        "lucy.shared_execution.startup_attestation.psycopg.connect",
        lambda *_args, **_kwargs: connection,
    )

    receipt = StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url="postgresql://recovery@example/tiamat",
        checkpoint_source=_CheckpointSource(),
    ).issue(now=NOW)

    assert receipt.anchor_transition_sha256 == transition.exact_sha256
    assert receipt.expires_at == NOW + timedelta(minutes=10)
    assert any("UPDATE tiamat.restore_gate" in query for query, _ in connection.executed)
    assert any(
        "INSERT INTO tiamat.startup_attestations" in query for query, _ in connection.executed
    )


def test_issuer_rejects_a_checkpoint_source_that_disagrees_with_signed_authority() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    anchor = InMemoryExternalRecoveryAnchor()
    transition = _transition(identity)
    anchor.install(transition, expected_transition_sha256=None, now=NOW)

    class _WrongCheckpoint:
        def read_checkpoint_digest(self, identity: RecoveryAnchorIdentity) -> str:
            return "e" * 64

    issuer = StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url="postgresql://unreachable/tiamat",
        checkpoint_source=_WrongCheckpoint(),
    )
    with pytest.raises(StartupAttestationRejected, match="checkpoint_digest_mismatch"):
        issuer.issue(now=NOW)


def test_issuer_rejects_a_conflicting_equal_version_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    anchor = InMemoryExternalRecoveryAnchor()
    transition = _transition(identity)
    anchor.install(transition, expected_transition_sha256=None, now=NOW)
    connection = _Connection(
        identity,
        database_now=NOW,
        floor_version=1,
        floor_digest="f" * 64,
    )
    monkeypatch.setattr(
        "lucy.shared_execution.startup_attestation.psycopg.connect",
        lambda *_args, **_kwargs: connection,
    )

    issuer = StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url="postgresql://recovery@example/tiamat",
        checkpoint_source=_CheckpointSource(),
    )
    with pytest.raises(StartupAttestationRejected, match="startup_anchor_floor_rollback"):
        issuer.issue(now=NOW)


def test_issuer_maps_database_expiry_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    anchor = InMemoryExternalRecoveryAnchor()
    transition = _transition(identity)
    anchor.install(transition, expected_transition_sha256=None, now=NOW)

    class _DatabaseExpiry(psycopg.DatabaseError):
        @property
        def sqlstate(self) -> str:
            return "ZX105"

    def reject_connection(*_args: object, **_kwargs: object) -> None:
        raise _DatabaseExpiry("synthetic expiry rejection")

    monkeypatch.setattr(
        "lucy.shared_execution.startup_attestation.psycopg.connect", reject_connection
    )
    issuer = StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url="postgresql://recovery@example/tiamat",
        checkpoint_source=_CheckpointSource(),
    )
    with pytest.raises(StartupAttestationRejected, match="startup_attestation_expired"):
        issuer.issue(now=NOW)
