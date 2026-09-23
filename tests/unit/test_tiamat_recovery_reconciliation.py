"""Signed recovery_pending and continuity_established steps: build, verify, install via M4."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.anchor_writer import AnchorWriter, AnchorWriteRequest, AnchorWriteResult
from lucy.shared_execution.recovery_anchor import (
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
)
from lucy.shared_execution.recovery_anchor_dynamodb import DynamoDbExternalRecoveryAnchor
from lucy.shared_execution.recovery_anchor_reconciliation import (
    AnchorHead,
    ReconciliationStep,
    ReconciliationStepRejected,
    build_continuity_established,
    build_recovery_pending,
    install_through_writer,
    verify_reconciliation_package,
    writer_request,
)
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpoint,
    construct_recovery_checkpoint,
)
from tests.unit.test_tiamat_anchor_writer import (
    NOW,
    ROOT_KEY_ID,
    ConditionalTable,
    _bootstrap,
    _key,
    _request,
    _root,
)

PENDING_AT = NOW + timedelta(hours=1)
ESTABLISHED_AT = NOW + timedelta(hours=2)
INVENTORY_DIGEST = "b" * 64


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _identity() -> RecoveryAnchorIdentity:
    return RecoveryAnchorIdentity("staging", uuid4(), uuid4())


def _checkpoint(
    identity: RecoveryAnchorIdentity,
    *,
    generation: int = 2,
    inventory: dict[str, object] | None = None,
    positions: list[dict[str, object]] | None = None,
) -> RecoveryCheckpoint:
    return construct_recovery_checkpoint(
        {
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "recovery_generation": generation,
            "release_inventory": inventory or {"generation": 1, "jws_sha256": INVENTORY_DIGEST},
            "release_heads": [],
            "settlement_position": positions or [],
        },
        identity=identity,
    )


def _head(identity: RecoveryAnchorIdentity, root: Ed25519PrivateKey) -> tuple[Any, AnchorHead]:
    bootstrap = _bootstrap(identity, root)
    return bootstrap, AnchorHead(
        transition_jws=bootstrap.transition_jws,
        witness_jws=bootstrap.witness_jws,
        inventory_jws=bootstrap.inventory_jws,
        witness_key_id=bootstrap.witness_key_id,
    )


def _pending(
    identity: RecoveryAnchorIdentity,
    root: Ed25519PrivateKey,
    head: AnchorHead,
    checkpoint: RecoveryCheckpoint | None = None,
) -> ReconciliationStep:
    step, _ = build_recovery_pending(
        head=head,
        identity=identity,
        root_key_id=ROOT_KEY_ID,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.reconciled.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint=checkpoint or _checkpoint(identity),
        now=PENDING_AT,
    )
    return step


def _beacon(checkpoint: RecoveryCheckpoint) -> PostgresContinuityBeacon:
    return PostgresContinuityBeacon(
        "7310000000000000001", 1, "0/16B3748", checkpoint.checkpoint_sha256
    )


def _established(pending: ReconciliationStep, root: Ed25519PrivateKey) -> ReconciliationStep:
    step, _ = build_continuity_established(
        pending=pending,
        root_private_key=root,
        beacon=_beacon(pending.checkpoint),
        now=ESTABLISHED_AT,
    )
    return step


def _verify(step: ReconciliationStep, *, now: datetime, package: dict[str, object] | None = None):  # type: ignore[no-untyped-def]
    return verify_reconciliation_package(
        package or step.public_package(),
        now=now,
        expected_root_public_sha256=hashlib.sha256(
            base64.b64decode(step.root_public_key_b64)
        ).hexdigest(),
        expected_ceremony=step.ceremony,
    )


@pytest.fixture
def chain() -> tuple[RecoveryAnchorIdentity, Ed25519PrivateKey, AnchorHead]:
    identity, root = _identity(), Ed25519PrivateKey.generate()
    _, head = _head(identity, root)
    return identity, root, head


def test_pending_carries_a_reconciled_higher_generation_witness(chain: Any) -> None:
    identity, root, head = chain
    step = _pending(identity, root, head)
    verified = _verify(step, now=PENDING_AT)
    assert verified.head.continuity == "quarantined"
    assert verified.candidate.continuity == "recovery_pending"
    assert verified.candidate.transition_version == 2
    assert verified.candidate.previous_transition_sha256 == verified.head.exact_sha256
    witness = verified.candidate.witness
    assert (witness.status, witness.recovery_generation, witness.witness_revision) == (
        "reconciled",
        2,
        1,
    )
    assert witness.checkpoint_digest == step.checkpoint.checkpoint_sha256
    # Signed under a successor witness inventory; the head's key signs no authority.
    assert step.inventory_jws != head.inventory_jws
    assert b"PRIVATE" not in json.dumps(step.public_package()).encode()


def test_a_generation_jump_is_signed_when_the_checkpoint_names_it(chain: Any) -> None:
    identity, root, head = chain
    step = _pending(identity, root, head, _checkpoint(identity, generation=5))
    assert _verify(step, now=PENDING_AT).candidate.witness.recovery_generation == 5


def test_established_reuses_the_pending_witness_and_binds_the_beacon(chain: Any) -> None:
    identity, root, head = chain
    pending = _pending(identity, root, head)
    established = _established(pending, root)
    verified = _verify(established, now=ESTABLISHED_AT)
    assert verified.head.continuity == "recovery_pending"
    assert verified.candidate.continuity == "continuity_established"
    assert verified.candidate.transition_version == 3
    assert established.witness_jws == pending.witness_jws
    assert established.inventory_jws == pending.inventory_jws
    assert verified.candidate.beacon == _beacon(pending.checkpoint)
    assert (
        established.trust_document()["inventory_jws_b64"]
        == base64.b64encode(pending.inventory_jws).decode()
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("not_higher", "reconciliation_generation_not_higher"),
        ("not_installed", "checkpoint"),
        ("pending_head", "reconciliation_requires_quarantined_head"),
        ("other_root", "recovery_witness_inventory_invalid"),
        ("settlement", "reconciliation_checkpoint_projection_unsupported"),
    ],
)
def test_pending_is_signed_only_from_quarantine_to_a_higher_installed_checkpoint(
    chain: Any, change: str, reason: str
) -> None:
    identity, root, head = chain
    checkpoint = _checkpoint(identity)
    signing_root = root
    if change == "not_higher":
        checkpoint = _checkpoint(identity, generation=1)
    elif change == "pending_head":
        pending = _pending(identity, root, head)
        head = AnchorHead(
            pending.transition_jws,
            pending.witness_jws,
            pending.inventory_jws,
            pending.witness_key_id,
        )
    elif change == "other_root":
        signing_root = Ed25519PrivateKey.generate()
    elif change == "settlement":
        # Only the empty-ledger projection may be signed until populated ones are specified.
        checkpoint = _checkpoint(identity, positions=[_position()])
    if change == "not_installed":
        with pytest.raises(ValueError, match=reason):
            _pending(
                identity,
                root,
                head,
                construct_recovery_checkpoint(
                    {
                        **_checkpoint(identity).object,
                        "release_inventory": {"state": "not_installed"},
                    },
                    identity=identity,
                ),
            )
        return
    with pytest.raises(ValueError, match=reason):
        _pending(identity, signing_root, head, checkpoint)


def test_established_requires_a_beacon_for_the_signed_checkpoint(chain: Any) -> None:
    identity, root, head = chain
    pending = _pending(identity, root, head)
    wrong = replace(_beacon(pending.checkpoint), checkpoint_digest="f" * 64)
    with pytest.raises(ReconciliationStepRejected, match="beacon_checkpoint_mismatch"):
        build_continuity_established(
            pending=pending, root_private_key=root, beacon=wrong, now=ESTABLISHED_AT
        )


def test_established_requires_the_pending_witness_to_be_current(chain: Any) -> None:
    identity, root, head = chain
    pending = _pending(identity, root, head)
    with pytest.raises(ReconciliationStepRejected, match="witness_not_current"):
        build_continuity_established(
            pending=pending,
            root_private_key=root,
            beacon=_beacon(pending.checkpoint),
            now=PENDING_AT + timedelta(hours=13),
        )


def test_established_is_signed_only_by_the_pending_root(chain: Any) -> None:
    identity, root, head = chain
    pending = _pending(identity, root, head)
    with pytest.raises(ValueError, match="pending step's root"):
        build_continuity_established(
            pending=pending,
            root_private_key=Ed25519PrivateKey.generate(),
            beacon=_beacon(pending.checkpoint),
            now=ESTABLISHED_AT,
        )


def _tampered(package: dict[str, object], member: str, value: object) -> dict[str, object]:
    return {**package, member: value}


@pytest.mark.parametrize(
    "tamper",
    [
        "root_pin",
        "transition_digest",
        "checkpoint_other_inventory",
        "checkpoint_other_settlement",
        "extra_member",
        "wrong_ceremony",
        "beacon_on_pending",
        "head_swapped",
    ],
)
def test_a_tampered_pending_package_is_refused(chain: Any, tamper: str) -> None:
    identity, root, head = chain
    step = _pending(identity, root, head)
    package = step.public_package()
    if tamper == "root_pin":
        package = _tampered(package, "root_public_key_sha256", "0" * 64)
    elif tamper == "transition_digest":
        package = _tampered(package, "transition_sha256", "0" * 64)
    elif tamper == "checkpoint_other_inventory":
        other = _checkpoint(identity, inventory={"generation": 1, "jws_sha256": "c" * 64})
        package = _tampered(package, "checkpoint", other.object)
    elif tamper == "checkpoint_other_settlement":
        other = _checkpoint(identity, positions=[_position()])
        package = _tampered(package, "checkpoint", other.object)
    elif tamper == "extra_member":
        package = _tampered(package, "comment", "x")
    elif tamper == "wrong_ceremony":
        package = _tampered(package, "ceremony", "continuity_established")
    elif tamper == "beacon_on_pending":
        package = _tampered(package, "beacon", _established(step, root).public_package()["beacon"])
    else:
        other_identity_head = _head(identity, root)[1]
        package = _tampered(
            package,
            "head_transition_jws_b64",
            base64.b64encode(other_identity_head.transition_jws).decode(),
        )
    with pytest.raises(ValueError):
        _verify(step, now=PENDING_AT, package=package)


@pytest.mark.parametrize("tamper", ["beacon", "inventory", "witness"])
def test_a_tampered_established_package_is_refused(chain: Any, tamper: str) -> None:
    identity, root, head = chain
    pending = _pending(identity, root, head)
    step = _established(pending, root)
    package = step.public_package()
    if tamper == "beacon":
        original = package["beacon"]
        assert isinstance(original, dict)
        beacon = {**original, "flushed_wal_lsn": "0/1"}
        package = _tampered(package, "beacon", beacon)
    elif tamper == "inventory":
        package = _tampered(package, "inventory_jws_b64", package["head_inventory_jws_b64"])
        package = _tampered(
            package, "head_inventory_jws_b64", base64.b64encode(head.inventory_jws).decode()
        )
    else:
        other = _pending(identity, root, head)
        package = _tampered(
            package, "witness_jws_b64", base64.b64encode(other.witness_jws).decode()
        )
    with pytest.raises(ValueError):
        _verify(step, now=ESTABLISHED_AT, package=package)


def _position() -> dict[str, object]:
    return {
        "partition_id": "p",
        "budget_period_id": "b",
        "settled_microusd": 1,
        "reserved_microusd": 0,
        "pending_reconciliation_count": 0,
        "forfeited_microusd": 0,
        "contingency_used_microusd": 0,
        "external_liability_marker": "none",
    }


def _installed_world(
    identity: RecoveryAnchorIdentity, root: Ed25519PrivateKey
) -> tuple[ConditionalTable, AnchorWriter, _Clock, AnchorHead]:
    bootstrap, head = _head(identity, root)
    table, clock = ConditionalTable(), _Clock(NOW)
    writer = AnchorWriter(
        roots={_key(identity): _root(root)},
        client=table,
        table_name="tiamat-recovery-anchor",
        clock=clock,
    )
    writer.write(_request(identity, bootstrap))
    return table, writer, clock, head


def _store(table: ConditionalTable, verified: Any) -> DynamoDbExternalRecoveryAnchor:
    return DynamoDbExternalRecoveryAnchor(
        client=table, table_name="tiamat-recovery-anchor", decode_transition=verified.decoder()
    )


def test_pending_then_established_install_through_the_writer() -> None:
    identity, root = _identity(), Ed25519PrivateKey.generate()
    table, writer, clock, head = _installed_world(identity, root)
    pending = _pending(identity, root, head)
    verified = _verify(pending, now=PENDING_AT)
    assert writer_request(verified).head_inventory_jws == head.inventory_jws
    clock.now = PENDING_AT
    assert install_through_writer(_store(table, verified), writer.write, verified) == (
        "installed_and_verified"
    )
    established = _established(pending, root)
    verified_established = _verify(established, now=ESTABLISHED_AT)
    # The established step shares the pending step's inventory, so no head inventory is sent.
    assert writer_request(verified_established).head_inventory_jws is None
    clock.now = ESTABLISHED_AT
    store = _store(table, verified_established)
    assert install_through_writer(store, writer.write, verified_established) == (
        "installed_and_verified"
    )
    puts = table.puts
    assert install_through_writer(store, writer.write, verified_established) == (
        "already_installed_and_verified"
    )
    assert table.puts == puts
    assert store.read(identity.key).continuity == "continuity_established"


def test_established_cannot_skip_pending_at_the_writer() -> None:
    """G9 at the writer: an established transition on the quarantined head never installs."""

    identity, root = _identity(), Ed25519PrivateKey.generate()
    table, writer, clock, head = _installed_world(identity, root)
    established = _established(_pending(identity, root, head), root)
    clock.now = ESTABLISHED_AT
    request = AnchorWriteRequest(
        anchor_key=_key(identity),
        transition_jws=established.transition_jws,
        witness_jws=established.witness_jws,
        inventory_jws=established.inventory_jws,
        head_inventory_jws=head.inventory_jws,
    )
    puts = table.puts
    with pytest.raises(Exception):  # noqa: B017 - any refusal; the write must not happen
        writer.write(request)
    assert table.puts == puts


def test_a_different_head_refuses_before_any_write() -> None:
    identity, root = _identity(), Ed25519PrivateKey.generate()
    table, writer, clock, head = _installed_world(identity, root)
    pending = _pending(identity, root, head)
    verified = _verify(pending, now=PENDING_AT)
    clock.now = PENDING_AT
    install_through_writer(_store(table, verified), writer.write, verified)
    # A second, different pending step for the same quarantined head no longer matches the head.
    other = _verify(_pending(identity, root, head), now=PENDING_AT)
    calls: list[AnchorWriteRequest] = []

    def write(request: AnchorWriteRequest) -> AnchorWriteResult:
        calls.append(request)
        return writer.write(request)

    store = DynamoDbExternalRecoveryAnchor(
        client=table,
        table_name="tiamat-recovery-anchor",
        decode_transition=lambda t, w: (
            verified.candidate if t == verified.candidate.exact_jws else other.decoder()(t, w)
        ),
    )
    with pytest.raises(RecoveryAnchorRejected, match="compare_failed"):
        install_through_writer(store, write, other)
    assert calls == []


def test_an_unclear_invocation_is_resolved_by_one_readback() -> None:
    identity, root = _identity(), Ed25519PrivateKey.generate()
    table, writer, clock, head = _installed_world(identity, root)
    verified = _verify(_pending(identity, root, head), now=PENDING_AT)
    clock.now = PENDING_AT

    def lost_answer(request: AnchorWriteRequest) -> AnchorWriteResult:
        writer.write(request)
        raise RecoveryAnchorRejected("recovery_anchor_writer_unavailable")

    assert install_through_writer(_store(table, verified), lost_answer, verified) == (
        "already_installed_and_verified"
    )

    def failed(request: AnchorWriteRequest) -> AnchorWriteResult:
        raise RecoveryAnchorRejected("recovery_anchor_writer_unavailable")

    identity2 = _identity()
    table2, _, _, head2 = _installed_world(identity2, root)
    verified2 = _verify(_pending(identity2, root, head2), now=PENDING_AT)
    with pytest.raises(RecoveryAnchorRejected, match="writer_unavailable"):
        install_through_writer(_store(table2, verified2), failed, verified2)


class _NeverRead:
    def read(self, key: Any) -> Any:
        raise AssertionError("the anchor must not be read for an unsupported projection")


def test_authorization_refuses_an_unsupported_projection_on_its_own() -> None:
    """Defense in depth: the signer refuses these checkpoints, and so does authorization, before
    reading the anchor or connecting to any database."""

    from lucy.shared_execution.recovery import RecoveryRejected, authorize_recovery_generation
    from lucy.shared_execution.recovery_anchor import (
        VerifiedAnchorTransition,
        VerifiedRecoveryWitness,
    )

    identity = _identity()
    checkpoint = _checkpoint(identity, positions=[_position()])
    witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=2,
        witness_revision=1,
        status="reconciled",
        checkpoint_digest=checkpoint.checkpoint_sha256,
        release_heads_sha256=checkpoint.release_heads_sha256,
        checkpoint_settlement_position_sha256=checkpoint.settlement_position_sha256,
        witness_inventory_digest="e" * 64,
        exact_jws=b"witness",
        not_before=NOW,
        not_after=NOW + timedelta(hours=1),
    )
    pending = VerifiedAnchorTransition(
        witness=witness,
        transition_version=2,
        previous_transition_sha256="a" * 64,
        continuity="recovery_pending",
        beacon=None,
        exact_jws=b"transition",
    )
    with pytest.raises(RecoveryRejected, match="settlement_projection_unsupported"):
        authorize_recovery_generation(
            "postgresql://unused.invalid/never",
            anchor=_NeverRead(),
            authorized=pending,
            checkpoint=checkpoint,
            source_recovery_generation=1,
        )
