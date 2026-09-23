"""Offline construction and exact-byte verification of the reconciliation anchor transitions.

Draft 0.5 section 7 leaves quarantine in two root-signed steps. Step 5 installs a
``recovery_pending`` transition carrying a newly signed ``reconciled`` witness for a strictly
higher recovery generation, bound to a reconciled checkpoint with an installed release inventory.
Step 7 installs ``continuity_established``, which must carry that same witness, byte for byte, and
a PostgreSQL continuity beacon read from the ledger after the checkpoint was bound.

Like the bootstrap builders, this module performs no network or storage I/O and never writes a
private key. It signs nothing it has not first checked, and self-verifies everything it signs.
The public packages it emits carry the anchor head they succeed, so an online installer can
verify the complete step, and the M4 writer can verify that head, without any signing key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lucy.shared_execution.anchor_writer import AnchorWriteRequest, AnchorWriteResult
from lucy.shared_execution.recovery_anchor import (
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    RecoveryAnchorKey,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
    validate_anchor_successor,
)
from lucy.shared_execution.recovery_anchor_commissioning import (
    _sign_compact,
    _timestamp,
    canonical_uuid4,
)
from lucy.shared_execution.recovery_anchor_jws import (
    ANCHOR_TRANSITION_TYP,
    verify_anchor_transition,
)
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpoint,
    construct_recovery_checkpoint,
)
from lucy.shared_execution.recovery_witness_jws import (
    RECOVERY_WITNESS_INVENTORY_TYP,
    RECOVERY_WITNESS_TYP,
    RecoveryAnchorRecordDecoder,
    verify_recovery_witness,
    verify_recovery_witness_inventory,
)
from lucy.shared_execution.signed_releases import _verify_compact

ReconciliationCeremony = Literal["recovery_pending", "continuity_established"]


class ReconciliationStepRejected(ValueError):
    """A reconciliation anchor step, or its package, is not exactly what the protocol allows."""


@dataclass(frozen=True)
class AnchorHead:
    """The exact signed anchor head a reconciliation step succeeds.

    ``inventory_jws`` is the RECOVERY-WITNESS inventory the head's witness was signed under. The
    head is verified at its own witness's signed ``issued_at``: an expired quarantine witness is
    still the authentic predecessor, and it is only ever the compare-and-swap predecessor here.
    """

    transition_jws: bytes
    witness_jws: bytes
    inventory_jws: bytes
    witness_key_id: str


@dataclass(frozen=True)
class ReconciliationStep:
    """One signed reconciliation transition, the head it succeeds, and what verifies it."""

    ceremony: ReconciliationCeremony
    identity: RecoveryAnchorIdentity
    root_key_id: str
    root_public_key_b64: str
    head: AnchorHead
    witness_key_id: str
    inventory_jws: bytes
    witness_jws: bytes
    transition_jws: bytes
    checkpoint: RecoveryCheckpoint
    beacon: PostgresContinuityBeacon | None

    @property
    def transition_sha256(self) -> str:
        return hashlib.sha256(self.transition_jws).hexdigest()

    def public_package(self) -> dict[str, object]:
        """Content-free signed bytes and public keys only; no private key material."""

        package: dict[str, object] = {
            "format_version": "1",
            "ceremony": self.ceremony,
            "environment": self.identity.environment,
            "ledger_id": str(self.identity.ledger_id),
            "storage_epoch": str(self.identity.storage_epoch),
            "root_key_id": self.root_key_id,
            "root_public_key_b64": self.root_public_key_b64,
            "root_public_key_sha256": hashlib.sha256(
                base64.b64decode(self.root_public_key_b64, validate=True)
            ).hexdigest(),
            "head_transition_jws_b64": _b64(self.head.transition_jws),
            "head_witness_jws_b64": _b64(self.head.witness_jws),
            "head_inventory_jws_b64": _b64(self.head.inventory_jws),
            "head_witness_key_id": self.head.witness_key_id,
            "head_transition_sha256": hashlib.sha256(self.head.transition_jws).hexdigest(),
            "witness_key_id": self.witness_key_id,
            "inventory_jws_b64": _b64(self.inventory_jws),
            "witness_jws_b64": _b64(self.witness_jws),
            "transition_jws_b64": _b64(self.transition_jws),
            "transition_sha256": self.transition_sha256,
            "checkpoint": self.checkpoint.object,
            "beacon": None
            if self.beacon is None
            else {
                "system_identifier": self.beacon.system_identifier,
                "timeline_id": self.beacon.timeline_id,
                "flushed_wal_lsn": self.beacon.flushed_wal_lsn,
                "checkpoint_digest": self.beacon.checkpoint_digest,
            },
        }
        return package

    def trust_document(self) -> dict[str, object]:
        """The launcher's anchor trust file: the root pin and this step's witness inventory."""

        return {
            "environment": self.identity.environment,
            "ledger_id": str(self.identity.ledger_id),
            "storage_epoch": str(self.identity.storage_epoch),
            "root_key_id": self.root_key_id,
            "root_public_key_b64": self.root_public_key_b64,
            "root_public_key_sha256": hashlib.sha256(
                base64.b64decode(self.root_public_key_b64, validate=True)
            ).hexdigest(),
            "witness_key_id": self.witness_key_id,
            "inventory_jws_b64": _b64(self.inventory_jws),
        }


def require_reconcilable_checkpoint(
    checkpoint: RecoveryCheckpoint, *, identity: RecoveryAnchorIdentity
) -> None:
    """A reconciled checkpoint must name an installed RELEASE inventory (Draft 0.5 section 4)."""

    rebuilt = construct_recovery_checkpoint(dict(checkpoint.object), identity=identity)
    if rebuilt != checkpoint:
        raise ReconciliationStepRejected("reconciliation_checkpoint_not_canonical")
    if not checkpoint.release_inventory_installed:
        raise ReconciliationStepRejected("reconciliation_checkpoint_inventory_not_installed")


def build_recovery_pending(
    *,
    head: AnchorHead,
    identity: RecoveryAnchorIdentity,
    root_key_id: str,
    root_private_key: Ed25519PrivateKey,
    witness_key_id: str,
    witness_private_key: Ed25519PrivateKey,
    checkpoint: RecoveryCheckpoint,
    now: datetime,
    validity: timedelta = timedelta(hours=12),
) -> tuple[ReconciliationStep, VerifiedAnchorTransition]:
    """Sign the section 7 step 5 transition: quarantined head to ``recovery_pending``.

    The witness is ``reconciled``, revision one, for the checkpoint's generation, which must
    exceed the quarantine generation. It is signed under a root-signed successor RECOVERY-WITNESS
    inventory naming only the new witness key, so the head's expired key never signs authority.
    """

    current = now.astimezone(UTC).replace(microsecond=0)
    if not timedelta(minutes=1) <= validity <= timedelta(hours=24):
        raise ValueError("recovery witness validity must be between one minute and 24 hours")
    root_public = root_private_key.public_key()
    if (
        not witness_key_id
        or witness_key_id == root_key_id
        or root_private_key.private_bytes_raw() == witness_private_key.private_bytes_raw()
    ):
        raise ValueError("recovery root and witness signing authority must be purpose-distinct")
    previous = _verify_head(
        head, identity=identity, root_key_id=root_key_id, root_public=root_public
    )
    if previous.continuity != "quarantined" or previous.witness.status != "quarantined":
        raise ReconciliationStepRejected("reconciliation_requires_quarantined_head")
    require_reconcilable_checkpoint(checkpoint, identity=identity)
    target = checkpoint.object["recovery_generation"]
    assert isinstance(target, int)
    if target <= previous.witness.recovery_generation:
        raise ReconciliationStepRejected("reconciliation_generation_not_higher")
    head_inventory = _inventory_payload(head.inventory_jws, root_key_id, root_public)
    head_inventory_generation = head_inventory.get("inventory_generation")
    if not isinstance(head_inventory_generation, int):
        raise ReconciliationStepRejected("reconciliation_head_inventory_invalid")
    until = current + validity
    inventory_payload: dict[str, object] = {
        "format_version": "1",
        "inventory_generation": head_inventory_generation + 1,
        "previous_inventory_digest": hashlib.sha256(head.inventory_jws).hexdigest(),
        "issued_at": _timestamp(current),
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "root_key_id": root_key_id,
        "keys": [
            {
                "kid": witness_key_id,
                "issuer": "stoin:control",
                "environment": identity.environment,
                "purpose": "policy_notary_v13",
                "use": "tiamat-recovery-witness",
                "algorithm": "EdDSA",
                "public_key_b64": _b64(witness_private_key.public_key().public_bytes_raw()),
                "status": "active",
                "ledger_id": str(identity.ledger_id),
                "valid_from": _timestamp(current),
                "issuance_not_after": _timestamp(until),
                "verify_not_after": _timestamp(until),
                "revoked_at": None,
                "active_release_policy": "invalidate_immediately",
            }
        ],
    }
    inventory_jws = _sign_compact(
        inventory_payload,
        key_id=root_key_id,
        typ=RECOVERY_WITNESS_INVENTORY_TYP,
        private_key=root_private_key,
    )
    context = verify_recovery_witness_inventory(
        inventory_jws,
        root_key_id=root_key_id,
        root_public_key=root_public,
        identity=identity,
        witness_key_id=witness_key_id,
        now=current,
    )
    witness_jws = _sign_compact(
        {
            "format_version": "1",
            "witness_id": str(uuid4()),
            "issuer": "stoin:control",
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "recovery_generation": target,
            "witness_revision": 1,
            "status": "reconciled",
            "issued_at": _timestamp(current),
            "not_before": _timestamp(current),
            "not_after": _timestamp(until),
            "inventory_generation": context.inventory_generation,
            "inventory_jws_sha256": context.inventory_jws_sha256,
            "release_heads_sha256": checkpoint.release_heads_sha256,
            "checkpoint_settlement_position_sha256": checkpoint.settlement_position_sha256,
            "checkpoint_digest": checkpoint.checkpoint_sha256,
        },
        key_id=witness_key_id,
        typ=RECOVERY_WITNESS_TYP,
        private_key=witness_private_key,
    )
    witness = verify_recovery_witness(witness_jws, context=context)
    transition_jws = _sign_compact(
        _transition_payload(
            identity,
            version=previous.transition_version + 1,
            previous_sha256=previous.exact_sha256,
            generation=target,
            witness_sha256=witness.exact_sha256,
            continuity="recovery_pending",
            beacon=None,
        ),
        key_id=root_key_id,
        typ=ANCHOR_TRANSITION_TYP,
        private_key=root_private_key,
    )
    transition = verify_anchor_transition(
        transition_jws, root_key_id=root_key_id, root_public_key=root_public, witness=witness
    )
    validate_anchor_successor(previous, transition)
    step = ReconciliationStep(
        ceremony="recovery_pending",
        identity=identity,
        root_key_id=root_key_id,
        root_public_key_b64=_b64(root_public.public_bytes_raw()),
        head=head,
        witness_key_id=witness_key_id,
        inventory_jws=inventory_jws,
        witness_jws=witness_jws,
        transition_jws=transition_jws,
        checkpoint=checkpoint,
        beacon=None,
    )
    return step, transition


def build_continuity_established(
    *,
    pending: ReconciliationStep,
    root_private_key: Ed25519PrivateKey,
    beacon: PostgresContinuityBeacon,
    now: datetime,
) -> tuple[ReconciliationStep, VerifiedAnchorTransition]:
    """Sign the section 7 step 7 transition: ``recovery_pending`` to ``continuity_established``.

    The witness and its inventory are reused unchanged (G9). Only the root signs, binding the
    beacon read from the ledger after the checkpoint was bound. The witness must still be valid.
    """

    if pending.ceremony != "recovery_pending":
        raise ReconciliationStepRejected("reconciliation_requires_pending_step")
    root_public = root_private_key.public_key()
    if _b64(root_public.public_bytes_raw()) != pending.root_public_key_b64:
        raise ValueError("continuity must be established by the pending step's root")
    head = AnchorHead(
        transition_jws=pending.transition_jws,
        witness_jws=pending.witness_jws,
        inventory_jws=pending.inventory_jws,
        witness_key_id=pending.witness_key_id,
    )
    previous = _verify_head(
        head, identity=pending.identity, root_key_id=pending.root_key_id, root_public=root_public
    )
    if previous.continuity != "recovery_pending" or previous.witness.status != "reconciled":
        raise ReconciliationStepRejected("reconciliation_requires_pending_head")
    if not previous.witness.valid_at(now.astimezone(UTC)):
        raise ReconciliationStepRejected("reconciliation_witness_not_current")
    if beacon.checkpoint_digest != previous.witness.checkpoint_digest:
        raise ReconciliationStepRejected("reconciliation_beacon_checkpoint_mismatch")
    transition_jws = _sign_compact(
        _transition_payload(
            pending.identity,
            version=previous.transition_version + 1,
            previous_sha256=previous.exact_sha256,
            generation=previous.witness.recovery_generation,
            witness_sha256=previous.witness.exact_sha256,
            continuity="continuity_established",
            beacon=beacon,
        ),
        key_id=pending.root_key_id,
        typ=ANCHOR_TRANSITION_TYP,
        private_key=root_private_key,
    )
    transition = verify_anchor_transition(
        transition_jws,
        root_key_id=pending.root_key_id,
        root_public_key=root_public,
        witness=previous.witness,
    )
    validate_anchor_successor(previous, transition)
    step = ReconciliationStep(
        ceremony="continuity_established",
        identity=pending.identity,
        root_key_id=pending.root_key_id,
        root_public_key_b64=pending.root_public_key_b64,
        head=head,
        witness_key_id=pending.witness_key_id,
        inventory_jws=pending.inventory_jws,
        witness_jws=pending.witness_jws,
        transition_jws=transition_jws,
        checkpoint=pending.checkpoint,
        beacon=beacon,
    )
    return step, transition


@dataclass(frozen=True)
class VerifiedReconciliationStep:
    """A package after exact-byte verification, ready for a compare-and-swap install."""

    step: ReconciliationStep
    head: VerifiedAnchorTransition
    candidate: VerifiedAnchorTransition

    def decoder(self) -> ReconciliationStepDecoder:
        return ReconciliationStepDecoder(self.head, self.candidate)


@dataclass(frozen=True)
class ReconciliationStepDecoder:
    """Ceremony-scoped decoder accepting exactly the pinned head and candidate records.

    It lets the installer strong-read the anchor before and after its one write. It is not a
    runtime trust context and must never back a serving process's anchor reader.
    """

    head: VerifiedAnchorTransition
    candidate: VerifiedAnchorTransition

    def __call__(
        self, exact_transition_jws: bytes, exact_witness_jws: bytes
    ) -> VerifiedAnchorTransition:
        for transition in (self.head, self.candidate):
            if (
                exact_transition_jws == transition.exact_jws
                and exact_witness_jws == transition.witness.exact_jws
            ):
                return transition
        raise ValueError("reconciliation ceremony record is not pinned")


_PACKAGE_MEMBERS = frozenset(
    {
        "format_version",
        "ceremony",
        "environment",
        "ledger_id",
        "storage_epoch",
        "root_key_id",
        "root_public_key_b64",
        "root_public_key_sha256",
        "head_transition_jws_b64",
        "head_witness_jws_b64",
        "head_inventory_jws_b64",
        "head_witness_key_id",
        "head_transition_sha256",
        "witness_key_id",
        "inventory_jws_b64",
        "witness_jws_b64",
        "transition_jws_b64",
        "transition_sha256",
        "checkpoint",
        "beacon",
    }
)


def verify_reconciliation_package(
    package: dict[str, object],
    *,
    now: datetime,
    expected_root_public_sha256: str,
    expected_ceremony: ReconciliationCeremony,
) -> VerifiedReconciliationStep:
    """Re-derive and verify one published step without any signing key or storage access."""

    if (
        set(package) != _PACKAGE_MEMBERS
        or package.get("format_version") != "1"
        or package.get("ceremony") != expected_ceremony
    ):
        raise ReconciliationStepRejected("reconciliation_package_shape_invalid")
    try:
        identity = RecoveryAnchorIdentity(
            str(package["environment"]),
            canonical_uuid4(str(package["ledger_id"])),
            canonical_uuid4(str(package["storage_epoch"])),
        )
        root_key_id = str(package["root_key_id"])
        root_public_bytes = base64.b64decode(str(package["root_public_key_b64"]), validate=True)
        root_public = Ed25519PublicKey.from_public_bytes(root_public_bytes)
        head = AnchorHead(
            transition_jws=_unb64(package["head_transition_jws_b64"]),
            witness_jws=_unb64(package["head_witness_jws_b64"]),
            inventory_jws=_unb64(package["head_inventory_jws_b64"]),
            witness_key_id=str(package["head_witness_key_id"]),
        )
        inventory_jws = _unb64(package["inventory_jws_b64"])
        witness_jws = _unb64(package["witness_jws_b64"])
        transition_jws = _unb64(package["transition_jws_b64"])
        checkpoint_raw = package["checkpoint"]
        if not isinstance(checkpoint_raw, dict):
            raise ValueError("checkpoint is not an object")
        checkpoint = construct_recovery_checkpoint(checkpoint_raw, identity=identity)
        beacon = _beacon(package["beacon"])
    except (TypeError, ValueError, binascii.Error) as exc:
        if isinstance(exc, ReconciliationStepRejected):
            raise
        raise ReconciliationStepRejected("reconciliation_package_encoding_invalid") from exc
    observed_root = hashlib.sha256(root_public_bytes).hexdigest()
    if observed_root != package["root_public_key_sha256"] or observed_root != (
        expected_root_public_sha256
    ):
        raise ReconciliationStepRejected("reconciliation_root_pin_invalid")
    if (
        hashlib.sha256(head.transition_jws).hexdigest() != package["head_transition_sha256"]
        or hashlib.sha256(transition_jws).hexdigest() != package["transition_sha256"]
    ):
        raise ReconciliationStepRejected("reconciliation_transition_digest_invalid")
    if checkpoint.object != checkpoint_raw:
        # The package must carry the canonical object exactly as the witness digests describe it.
        raise ReconciliationStepRejected("reconciliation_checkpoint_not_canonical")
    require_reconcilable_checkpoint(checkpoint, identity=identity)
    previous = _verify_head(
        head, identity=identity, root_key_id=root_key_id, root_public=root_public
    )
    context = verify_recovery_witness_inventory(
        inventory_jws,
        root_key_id=root_key_id,
        root_public_key=root_public,
        identity=identity,
        witness_key_id=str(package["witness_key_id"]),
        now=now,
    )
    candidate = RecoveryAnchorRecordDecoder(context, root_key_id, root_public)(
        transition_jws, witness_jws
    )
    validate_anchor_successor(previous, candidate)
    witness = candidate.witness
    if (
        witness.status != "reconciled"
        or witness.witness_revision != 1
        or witness.recovery_generation != checkpoint.object["recovery_generation"]
        or witness.checkpoint_digest != checkpoint.checkpoint_sha256
        or witness.release_heads_sha256 != checkpoint.release_heads_sha256
        or witness.checkpoint_settlement_position_sha256 != checkpoint.settlement_position_sha256
        or not witness.valid_at(now)
    ):
        raise ReconciliationStepRejected("reconciliation_witness_binding_invalid")
    if expected_ceremony == "recovery_pending":
        if (
            previous.continuity != "quarantined"
            or candidate.continuity != "recovery_pending"
            or beacon is not None
        ):
            raise ReconciliationStepRejected("reconciliation_pending_step_invalid")
        inventory = _inventory_payload(inventory_jws, root_key_id, root_public)
        head_inventory = _inventory_payload(head.inventory_jws, root_key_id, root_public)
        if inventory.get("previous_inventory_digest") != hashlib.sha256(
            head.inventory_jws
        ).hexdigest() or inventory.get("inventory_generation") != _plus_one(
            head_inventory.get("inventory_generation")
        ):
            raise ReconciliationStepRejected("reconciliation_inventory_chain_invalid")
    else:
        if (
            previous.continuity != "recovery_pending"
            or candidate.continuity != "continuity_established"
            or head.inventory_jws != inventory_jws
            or head.witness_key_id != package["witness_key_id"]
            or beacon is None
            or candidate.beacon != beacon
        ):
            raise ReconciliationStepRejected("reconciliation_established_step_invalid")
    step = ReconciliationStep(
        ceremony=expected_ceremony,
        identity=identity,
        root_key_id=root_key_id,
        root_public_key_b64=str(package["root_public_key_b64"]),
        head=head,
        witness_key_id=str(package["witness_key_id"]),
        inventory_jws=inventory_jws,
        witness_jws=witness_jws,
        transition_jws=transition_jws,
        checkpoint=checkpoint,
        beacon=beacon,
    )
    return VerifiedReconciliationStep(step=step, head=previous, candidate=candidate)


def _verify_head(
    head: AnchorHead,
    *,
    identity: RecoveryAnchorIdentity,
    root_key_id: str,
    root_public: Ed25519PublicKey,
) -> VerifiedAnchorTransition:
    issued_at = _unverified_issued_at(head.witness_jws)
    context = verify_recovery_witness_inventory(
        head.inventory_jws,
        root_key_id=root_key_id,
        root_public_key=root_public,
        identity=identity,
        witness_key_id=head.witness_key_id,
        now=issued_at,
    )
    return RecoveryAnchorRecordDecoder(context, root_key_id, root_public)(
        head.transition_jws, head.witness_jws
    )


def _unverified_issued_at(witness_jws: bytes) -> datetime:
    """Read only the time to verify at; the signature check that follows authenticates it."""

    try:
        segment = witness_jws.split(b".")[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4)))
        return datetime.strptime(str(claims["issued_at"]), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (IndexError, KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ReconciliationStepRejected("reconciliation_head_witness_invalid") from exc


def _inventory_payload(
    inventory_jws: bytes, root_key_id: str, root_public: Ed25519PublicKey
) -> dict[str, object]:
    return _verify_compact(
        inventory_jws,
        expected_kid=root_key_id,
        public_key=root_public,
        expected_typ=RECOVERY_WITNESS_INVENTORY_TYP,
    )


def _transition_payload(
    identity: RecoveryAnchorIdentity,
    *,
    version: int,
    previous_sha256: str,
    generation: int,
    witness_sha256: str,
    continuity: ReconciliationCeremony,
    beacon: PostgresContinuityBeacon | None,
) -> dict[str, object]:
    return {
        "format_version": "1",
        "transition_version": version,
        "previous_transition_sha256": previous_sha256,
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": generation,
        "witness_revision": 1,
        "witness_jws_sha256": witness_sha256,
        "continuity": continuity,
        "beacon": None
        if beacon is None
        else {
            "system_identifier": beacon.system_identifier,
            "timeline_id": beacon.timeline_id,
            "flushed_wal_lsn": beacon.flushed_wal_lsn,
            "checkpoint_digest": beacon.checkpoint_digest,
        },
    }


def _beacon(value: object) -> PostgresContinuityBeacon | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "system_identifier",
        "timeline_id",
        "flushed_wal_lsn",
        "checkpoint_digest",
    }:
        raise ValueError("beacon shape is invalid")
    timeline = value["timeline_id"]
    if not isinstance(timeline, int) or isinstance(timeline, bool):
        raise ValueError("beacon timeline is invalid")
    return PostgresContinuityBeacon(
        str(value["system_identifier"]),
        timeline,
        str(value["flushed_wal_lsn"]),
        str(value["checkpoint_digest"]),
    )


def _plus_one(value: object) -> int | None:
    return value + 1 if isinstance(value, int) and not isinstance(value, bool) else None


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected base64 text")
    return base64.b64decode(value, validate=True)


class AnchorReader(Protocol):
    def read(self, key: RecoveryAnchorKey) -> VerifiedAnchorTransition: ...


def writer_request(verified: VerifiedReconciliationStep) -> AnchorWriteRequest:
    """The M4 writer invocation for one verified step.

    The pending step's witness is signed under a successor inventory, so the writer is also given
    the head's inventory to verify the stored quarantine head. The established step reuses the
    pending step's inventory, which verifies both head and candidate.
    """

    step = verified.step
    return AnchorWriteRequest(
        anchor_key=f"ENV#{step.identity.environment}#LEDGER#{step.identity.ledger_id}",
        transition_jws=step.transition_jws,
        witness_jws=step.witness_jws,
        inventory_jws=step.inventory_jws,
        head_inventory_jws=(
            None if step.head.inventory_jws == step.inventory_jws else step.head.inventory_jws
        ),
    )


def install_through_writer(
    store: AnchorReader,
    write: Callable[[AnchorWriteRequest], AnchorWriteResult],
    verified: VerifiedReconciliationStep,
) -> str:
    """Strong-read, one write through the M4 writer, strong read back. Never retries blindly.

    ``store`` must decode with :meth:`VerifiedReconciliationStep.decoder`, so it recognizes only
    the exact head and candidate. A head other than the verified one refuses before any write. An
    unclear invocation is resolved by one readback: the candidate installed is success, anything
    else is the original failure.
    """

    key = verified.step.identity.key
    head = store.read(key)
    if head.exact_sha256 == verified.candidate.exact_sha256:
        return "already_installed_and_verified"
    if head.exact_sha256 != verified.head.exact_sha256:
        raise RecoveryAnchorRejected("recovery_anchor_compare_failed")
    try:
        result = write(writer_request(verified))
    except RecoveryAnchorRejected:
        if store.read(key).exact_sha256 != verified.candidate.exact_sha256:
            raise
        return "already_installed_and_verified"
    observed = store.read(key)
    if (
        result.transition_sha256 != verified.candidate.exact_sha256
        or result.transition_version != verified.candidate.transition_version
        or observed.exact_sha256 != verified.candidate.exact_sha256
        or observed.continuity != verified.candidate.continuity
    ):
        raise RuntimeError("reconciliation step strong-read verification failed")
    return "installed_and_verified"
