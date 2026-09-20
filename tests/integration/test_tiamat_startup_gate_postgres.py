"""Launcher startup-gate proof against a disposable PostgreSQL 16 database.

Every case here is a refusal. The gate must leave no claimant behind when authority is missing,
quarantined, unverifiable or unreachable, so each test asserts the claimant table stayed empty.

DynamoDB is only ever read. The deployed staging anchor record is fetched with a strongly
consistent GetItem and verified locally; nothing is written, signed or commissioned.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from sqlalchemy.engine import make_url

from deploy.postgres.issue_tiamat_startup_attestation_v1 import (
    StartupGateRejected,
    run_startup_gate,
)
from lucy.shared_execution.recovery_anchor import (
    InMemoryExternalRecoveryAnchor,
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
    StartupAttestationRejected,
)

ROOT = Path(__file__).resolve().parents[2]
TRUST_PACKAGE = ROOT / "deploy" / "aws" / "tiamat-staging-recovery-bootstrap-public-2026-09-18.json"
TEST_DATABASE_PREFIX = "tiamat_test_d1"
STAGING_STORE = {
    "TIAMAT_RECOVERY_ANCHOR_TABLE": "stoin-staging-tiamat-recovery-anchor-v1",
    "AWS_REGION": "us-east-1",
}
COMMISSIONING_TIME = datetime(2026, 9, 18, 21, tzinfo=UTC)


@dataclass(frozen=True, repr=False)
class _Disposable:
    owner: str
    recovery: str
    environment: str

    def __repr__(self) -> str:
        return "_Disposable(credentials=redacted)"


def _trust_document() -> dict[str, Any]:
    document: Any = json.loads(TRUST_PACKAGE.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


@pytest.fixture(scope="module")
def disposable() -> _Disposable:
    owner_url = os.environ.get("TIAMAT_D1_TEST_DATABASE_URL")
    if not owner_url:
        pytest.skip("TIAMAT_D1_TEST_DATABASE_URL is not configured")
    database = make_url(owner_url).database or ""
    if not database.startswith(TEST_DATABASE_PREFIX):
        pytest.fail("the startup-gate proof runs only on a disposable database", pytrace=False)
    environment = os.environ.copy()
    environment["TIAMAT_MIGRATION_DATABASE_URL"] = owner_url
    migrated = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "tiamat_alembic.ini", "upgrade", "head"],
        cwd=str(ROOT),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if migrated.returncode != 0:
        pytest.fail("startup-gate proof migration failed", pytrace=False)
    password = token_urlsafe(32)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        existing = owner.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = 'tiamat_recovery'"
        ).fetchone()
        if existing:
            # Only the password is reset: a managed owner may not touch role attributes it does
            # not hold, and the role's existing least-privilege attributes are the ones under test.
            owner.execute(
                sql.SQL("ALTER ROLE tiamat_recovery LOGIN PASSWORD {}").format(
                    sql.Literal(password)
                )
            )
        else:
            owner.execute(
                sql.SQL(
                    "CREATE ROLE tiamat_recovery LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(sql.Literal(password))
            )
        owner.execute("GRANT USAGE ON SCHEMA tiamat TO tiamat_recovery")
        owner.execute(
            "GRANT SELECT, INSERT, UPDATE ON tiamat.startup_attestations TO tiamat_recovery"
        )
        owner.execute("GRANT SELECT, INSERT ON tiamat.recovery_checkpoints TO tiamat_recovery")
        owner.execute("GRANT SELECT, INSERT, UPDATE ON tiamat.restore_gate TO tiamat_recovery")
        owner.execute("GRANT SELECT ON tiamat.ledger_identity TO tiamat_recovery")
    recovery_url = (
        make_url(owner_url)
        .set(username="tiamat_recovery", password=password)
        .render_as_string(hide_password=False)
    )
    return _Disposable(owner=owner_url, recovery=recovery_url, environment="staging")


def _seed_staging_gate(disposable: _Disposable, trust: dict[str, Any], *, generation: int) -> str:
    """Seed the gate and the retained checkpoint for the deployed staging identity."""

    from lucy.shared_execution.recovery_checkpoint import construct_recovery_checkpoint

    identity = RecoveryAnchorIdentity(
        str(trust["environment"]),
        UUID(str(trust["ledger_id"])),
        UUID(str(trust["storage_epoch"])),
    )
    checkpoint = construct_recovery_checkpoint(dict(trust["checkpoint"]), identity=identity)
    with psycopg.connect(disposable.recovery, autocommit=True) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (identity.environment,)
        )
        # The recovery role holds no DELETE, exactly as in production, so any claimant left by an
        # earlier case is superseded rather than removed.
        recovery.execute(
            """
            UPDATE tiamat.startup_attestations SET superseded_at = clock_timestamp()
            WHERE environment = %s AND consumed_at IS NULL AND superseded_at IS NULL
            """,
            (identity.environment,),
        )
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate
              (environment, storage_epoch, recovery_generation, coordinator_generation,
               dispatch_blocked, verified_at, anchor_floor_version, anchor_floor_sha256)
            VALUES (%s, %s, %s, 1, false, clock_timestamp(), 0, NULL)
            ON CONFLICT (environment) DO UPDATE
              SET storage_epoch = EXCLUDED.storage_epoch,
                  recovery_generation = EXCLUDED.recovery_generation,
                  dispatch_blocked = false
            """,
            (identity.environment, identity.storage_epoch, generation),
        )
        recovery.execute(
            """
            INSERT INTO tiamat.recovery_checkpoints
              (environment, recovery_generation, ledger_id, storage_epoch,
               checkpoint_sha256, release_heads_sha256, settlement_position_sha256, checkpoint)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (
                identity.environment,
                generation,
                identity.ledger_id,
                identity.storage_epoch,
                checkpoint.checkpoint_sha256,
                checkpoint.release_heads_sha256,
                checkpoint.settlement_position_sha256,
                psycopg.types.json.Jsonb(checkpoint.object),
            ),
        )
    return checkpoint.checkpoint_sha256


def _active_claimants(disposable: _Disposable) -> int:
    with psycopg.connect(disposable.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, true)", (disposable.environment,)
        )
        # Scoped to this environment: the disposable database also carries claimants from the
        # earlier D1 and M2 proofs, which are not part of this one.
        row = recovery.execute(
            "SELECT count(*) FROM tiamat.startup_attestations "
            "WHERE environment = %s AND consumed_at IS NULL AND superseded_at IS NULL",
            (disposable.environment,),
        ).fetchone()
    assert row is not None
    return int(row[0])


def test_c1_the_expired_witness_key_refuses_the_current_anchor(disposable: _Disposable) -> None:
    """C1, cause one: today the pinned inventory's key window has lapsed."""

    trust = _trust_document()
    _seed_staging_gate(disposable, trust, generation=1)

    with pytest.raises(StartupGateRejected) as refused:
        run_startup_gate(
            trust_document=trust,
            recovery_database_url=disposable.recovery,
            expected_ledger_id=UUID(str(trust["ledger_id"])),
            now=datetime.now(UTC),
            environment_values=STAGING_STORE,
        )

    assert "witness_inventory_rejected" in str(refused.value)
    assert _active_claimants(disposable) == 0


def test_c1_the_quarantined_record_refuses_even_when_trust_is_current(
    disposable: _Disposable,
) -> None:
    """C1, cause two: evaluated inside the key window, the record is still quarantined."""

    trust = _trust_document()
    _seed_staging_gate(disposable, trust, generation=1)

    with pytest.raises(StartupGateRejected) as refused:
        run_startup_gate(
            trust_document=trust,
            recovery_database_url=disposable.recovery,
            expected_ledger_id=UUID(str(trust["ledger_id"])),
            now=COMMISSIONING_TIME,
            environment_values=STAGING_STORE,
        )

    assert "recovery_continuity_not_established" in str(refused.value)
    assert _active_claimants(disposable) == 0


def test_c2_an_unreachable_anchor_store_refuses(disposable: _Disposable) -> None:
    """C2: the anchor store cannot be read, so no claimant may exist."""

    trust = _trust_document()
    _seed_staging_gate(disposable, trust, generation=1)

    with pytest.raises(StartupGateRejected) as refused:
        run_startup_gate(
            trust_document=trust,
            recovery_database_url=disposable.recovery,
            expected_ledger_id=UUID(str(trust["ledger_id"])),
            now=COMMISSIONING_TIME,
            environment_values={
                "TIAMAT_RECOVERY_ANCHOR_TABLE": "stoin-staging-tiamat-recovery-anchor-absent",
                "AWS_REGION": "us-east-1",
            },
        )

    assert "startup_attestation_authority_unavailable" in str(refused.value)
    assert _active_claimants(disposable) == 0


def _established(
    identity: RecoveryAnchorIdentity, checkpoint_digest: str, beacon: PostgresContinuityBeacon
) -> VerifiedAnchorTransition:
    """A synthetic established transition; it is never written to DynamoDB."""

    now = datetime.now(UTC)
    witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=1,
        witness_revision=1,
        status="reconciled",
        checkpoint_digest=checkpoint_digest,
        release_heads_sha256="c" * 64,
        checkpoint_settlement_position_sha256="d" * 64,
        witness_inventory_digest="e" * 64,
        exact_jws=b"startup-gate-proof-witness",
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(minutes=30),
    )
    return VerifiedAnchorTransition(
        witness=witness,
        transition_version=1,
        previous_transition_sha256=None,
        continuity="continuity_established",
        beacon=beacon,
        exact_jws=b"startup-gate-proof-transition",
    )


def _live_beacon(disposable: _Disposable, checkpoint_digest: str) -> PostgresContinuityBeacon:
    with psycopg.connect(disposable.recovery) as recovery:
        row = recovery.execute(
            """
            SELECT (pg_catalog.pg_control_system()).system_identifier::text,
                   (pg_catalog.pg_control_checkpoint()).timeline_id::bigint,
                   pg_catalog.pg_current_wal_flush_lsn()::text
            """
        ).fetchone()
    assert row is not None
    return PostgresContinuityBeacon(str(row[0]), int(row[1]), str(row[2]), checkpoint_digest)


def _issue(
    disposable: _Disposable, identity: RecoveryAnchorIdentity, transition: VerifiedAnchorTransition
) -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    anchor.install(transition, expected_transition_sha256=None, now=datetime.now(UTC))
    StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url=disposable.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(disposable.recovery),
    ).issue(now=datetime.now(UTC))


def test_c1t_a_beacon_from_another_cluster_refuses(disposable: _Disposable) -> None:
    """C1-T: the signed continuity beacon does not describe this database."""

    trust = _trust_document()
    digest = _seed_staging_gate(disposable, trust, generation=1)
    identity = RecoveryAnchorIdentity(
        str(trust["environment"]),
        UUID(str(trust["ledger_id"])),
        UUID(str(trust["storage_epoch"])),
    )
    live = _live_beacon(disposable, digest)
    foreign = PostgresContinuityBeacon(
        str(int(live.system_identifier) + 1), live.timeline_id, live.flushed_wal_lsn, digest
    )

    with pytest.raises(StartupAttestationRejected) as refused:
        _issue(disposable, identity, _established(identity, digest, foreign))

    assert "recovery_continuity_beacon_mismatch" in str(refused.value)
    assert _active_claimants(disposable) == 0


def test_c1t_a_beacon_ahead_of_this_database_refuses(disposable: _Disposable) -> None:
    """C1-T: a stale attachment has not reached the signed durable WAL position."""

    trust = _trust_document()
    digest = _seed_staging_gate(disposable, trust, generation=1)
    identity = RecoveryAnchorIdentity(
        str(trust["environment"]),
        UUID(str(trust["ledger_id"])),
        UUID(str(trust["storage_epoch"])),
    )
    live = _live_beacon(disposable, digest)
    ahead = PostgresContinuityBeacon(
        live.system_identifier, live.timeline_id, "FFFFFFFF/FFFFFFFF", digest
    )

    with pytest.raises(StartupAttestationRejected) as refused:
        _issue(disposable, identity, _established(identity, digest, ahead))

    assert "recovery_continuity_beacon_mismatch" in str(refused.value)
    assert _active_claimants(disposable) == 0


def test_c1t_a_checkpoint_the_witness_does_not_attest_refuses(disposable: _Disposable) -> None:
    """C1-T: the retained checkpoint and the signed witness must agree exactly."""

    trust = _trust_document()
    digest = _seed_staging_gate(disposable, trust, generation=1)
    identity = RecoveryAnchorIdentity(
        str(trust["environment"]),
        UUID(str(trust["ledger_id"])),
        UUID(str(trust["storage_epoch"])),
    )
    other_digest = "f" * 64
    live = _live_beacon(disposable, other_digest)

    with pytest.raises(StartupAttestationRejected) as refused:
        _issue(disposable, identity, _established(identity, other_digest, live))

    assert "startup_checkpoint_digest_mismatch" in str(refused.value)
    assert digest != other_digest
    assert _active_claimants(disposable) == 0


def test_c1t_a_checkpoint_bound_to_another_ledger_refuses(disposable: _Disposable) -> None:
    """C1-T: the retained checkpoint must belong to the ledger being started."""

    trust = _trust_document()
    digest = _seed_staging_gate(disposable, trust, generation=1)
    foreign_identity = RecoveryAnchorIdentity(
        str(trust["environment"]), uuid4(), UUID(str(trust["storage_epoch"]))
    )
    live = _live_beacon(disposable, digest)

    with pytest.raises(StartupAttestationRejected) as refused:
        _issue(disposable, foreign_identity, _established(foreign_identity, digest, live))

    assert "startup_attestation_authority_unavailable" in str(refused.value)
    assert _active_claimants(disposable) == 0
