"""Offline construction of exact signed Tiamat recovery-anchor bootstrap artifacts.

This module performs no network or storage I/O. Root and witness private keys remain in the
offline commissioning boundary; the online installer receives only the resulting signed bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorIdentity,
    VerifiedAnchorTransition,
    validate_anchor_successor,
)
from lucy.shared_execution.recovery_anchor_jws import (
    ANCHOR_TRANSITION_TYP,
    verify_anchor_transition,
)
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpoint,
    construct_recovery_checkpoint,
    require_day_zero_quarantine_checkpoint,
)
from lucy.shared_execution.recovery_witness_jws import (
    RECOVERY_WITNESS_INVENTORY_TYP,
    RECOVERY_WITNESS_TYP,
    RecoveryAnchorRecordDecoder,
    verify_recovery_witness,
    verify_recovery_witness_inventory,
)
from lucy.shared_execution.signed_releases import _verify_compact


@dataclass(frozen=True)
class RecoveryBootstrapArtifacts:
    root_key_id: str
    root_public_key_b64: str
    witness_key_id: str
    inventory_jws: bytes
    witness_jws: bytes
    transition_jws: bytes
    checkpoint: RecoveryCheckpoint

    @property
    def transition_sha256(self) -> str:
        return hashlib.sha256(self.transition_jws).hexdigest()

    def public_package(self, identity: RecoveryAnchorIdentity) -> dict[str, object]:
        """Return a content-free, signed-artifact package containing no private key material."""

        return {
            "format_version": "1",
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "root_key_id": self.root_key_id,
            "root_public_key_b64": self.root_public_key_b64,
            "root_public_key_sha256": hashlib.sha256(
                base64.b64decode(self.root_public_key_b64, validate=True)
            ).hexdigest(),
            "witness_key_id": self.witness_key_id,
            "inventory_jws_b64": base64.b64encode(self.inventory_jws).decode("ascii"),
            "witness_jws_b64": base64.b64encode(self.witness_jws).decode("ascii"),
            "transition_jws_b64": base64.b64encode(self.transition_jws).decode("ascii"),
            "transition_sha256": self.transition_sha256,
            "checkpoint": self.checkpoint.object,
        }


@dataclass(frozen=True)
class ContinuedQuarantineSuccessorArtifacts:
    """Offline-only successor artifacts for renewing an expired quarantined witness.

    This deliberately has a different type from bootstrap artifacts.  A caller cannot pass it to
    the empty-anchor installer or accidentally turn an expired quarantine into serving authority.
    """

    predecessor: RecoveryBootstrapArtifacts
    witness_key_id: str
    inventory_jws: bytes
    witness_jws: bytes
    transition_jws: bytes
    predecessor_verified_at: datetime

    @property
    def transition_sha256(self) -> str:
        return hashlib.sha256(self.transition_jws).hexdigest()

    def public_package(self, identity: RecoveryAnchorIdentity) -> dict[str, object]:
        return {
            "format_version": "1",
            "ceremony": "continued_quarantine_successor",
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "root_key_id": self.predecessor.root_key_id,
            "root_public_key_b64": self.predecessor.root_public_key_b64,
            "root_public_key_sha256": hashlib.sha256(
                base64.b64decode(self.predecessor.root_public_key_b64, validate=True)
            ).hexdigest(),
            "predecessor_inventory_jws_b64": base64.b64encode(
                self.predecessor.inventory_jws
            ).decode("ascii"),
            "predecessor_witness_jws_b64": base64.b64encode(self.predecessor.witness_jws).decode(
                "ascii"
            ),
            "predecessor_transition_jws_b64": base64.b64encode(
                self.predecessor.transition_jws
            ).decode("ascii"),
            "predecessor_transition_sha256": self.predecessor.transition_sha256,
            "predecessor_witness_key_id": self.predecessor.witness_key_id,
            "predecessor_verified_at": _timestamp(self.predecessor_verified_at),
            "witness_key_id": self.witness_key_id,
            "inventory_jws_b64": base64.b64encode(self.inventory_jws).decode("ascii"),
            "witness_jws_b64": base64.b64encode(self.witness_jws).decode("ascii"),
            "transition_jws_b64": base64.b64encode(self.transition_jws).decode("ascii"),
            "transition_sha256": self.transition_sha256,
            "checkpoint": self.predecessor.checkpoint.object,
        }


@dataclass(frozen=True)
class ContinuedQuarantineSuccessorDecoder:
    """A ceremony-scoped decoder accepting exactly the pinned predecessor and candidate bytes.

    Historical validation is limited to the known predecessor needed for compare-and-swap.  It is
    not a runtime trust context and must never be used by a serving-process anchor reader.
    """

    predecessor_transition: VerifiedAnchorTransition
    successor_transition: VerifiedAnchorTransition

    def __call__(
        self, exact_transition_jws: bytes, exact_witness_jws: bytes
    ) -> VerifiedAnchorTransition:
        for transition in (self.predecessor_transition, self.successor_transition):
            if (
                exact_transition_jws == transition.exact_jws
                and exact_witness_jws == transition.witness.exact_jws
            ):
                return transition
        raise ValueError("continued quarantine ceremony record is not pinned")


def verify_continued_quarantine_successor_package(
    package: dict[str, object], *, now: datetime, expected_root_public_sha256: str
) -> tuple[
    RecoveryAnchorIdentity,
    VerifiedAnchorTransition,
    VerifiedAnchorTransition,
    ContinuedQuarantineSuccessorDecoder,
]:
    """Verify the complete public chain without any signing key or storage access."""

    expected = {
        "format_version",
        "ceremony",
        "environment",
        "ledger_id",
        "storage_epoch",
        "root_key_id",
        "root_public_key_b64",
        "root_public_key_sha256",
        "predecessor_inventory_jws_b64",
        "predecessor_witness_jws_b64",
        "predecessor_transition_jws_b64",
        "predecessor_transition_sha256",
        "predecessor_witness_key_id",
        "predecessor_verified_at",
        "witness_key_id",
        "inventory_jws_b64",
        "witness_jws_b64",
        "transition_jws_b64",
        "transition_sha256",
        "checkpoint",
    }
    if (
        set(package) != expected
        or package.get("format_version") != "1"
        or package.get("ceremony") != "continued_quarantine_successor"
    ):
        raise ValueError("continued quarantine package shape is invalid")
    try:
        identity = RecoveryAnchorIdentity(
            str(package["environment"]),
            canonical_uuid4(str(package["ledger_id"])),
            canonical_uuid4(str(package["storage_epoch"])),
        )
        root_key_id = str(package["root_key_id"])
        root_public_bytes = base64.b64decode(str(package["root_public_key_b64"]), validate=True)
        root_public = Ed25519PublicKey.from_public_bytes(root_public_bytes)
        predecessor_inventory = base64.b64decode(
            str(package["predecessor_inventory_jws_b64"]), validate=True
        )
        predecessor_witness = base64.b64decode(
            str(package["predecessor_witness_jws_b64"]), validate=True
        )
        predecessor_transition = base64.b64decode(
            str(package["predecessor_transition_jws_b64"]), validate=True
        )
        successor_inventory = base64.b64decode(str(package["inventory_jws_b64"]), validate=True)
        successor_witness = base64.b64decode(str(package["witness_jws_b64"]), validate=True)
        successor_transition = base64.b64decode(str(package["transition_jws_b64"]), validate=True)
        historical = datetime.strptime(
            str(package["predecessor_verified_at"]), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise ValueError("continued quarantine package encoding is invalid") from exc
    observed_root_digest = hashlib.sha256(root_public_bytes).hexdigest()
    if (
        observed_root_digest != package["root_public_key_sha256"]
        or observed_root_digest != expected_root_public_sha256
    ):
        raise ValueError("continued quarantine root trust pin is invalid")
    if (
        hashlib.sha256(predecessor_transition).hexdigest()
        != package["predecessor_transition_sha256"]
        or hashlib.sha256(successor_transition).hexdigest() != package["transition_sha256"]
    ):
        raise ValueError("continued quarantine transition digest is invalid")
    old_context = verify_recovery_witness_inventory(
        predecessor_inventory,
        root_key_id=root_key_id,
        root_public_key=root_public,
        identity=identity,
        witness_key_id=str(package["predecessor_witness_key_id"]),
        now=historical,
    )
    old = RecoveryAnchorRecordDecoder(old_context, root_key_id, root_public)(
        predecessor_transition, predecessor_witness
    )
    checkpoint_raw = package["checkpoint"]
    if not isinstance(checkpoint_raw, dict):
        raise ValueError("continued quarantine checkpoint is invalid")
    checkpoint = construct_recovery_checkpoint(checkpoint_raw, identity=identity)
    require_day_zero_quarantine_checkpoint(checkpoint)
    if (
        old.transition_version != 1
        or old.previous_transition_sha256 is not None
        or old.continuity != "quarantined"
        or old.witness.ordering != (1, 1)
        or old_context.inventory_generation != 1
        or old.witness.checkpoint_digest != checkpoint.checkpoint_sha256
        or old.witness.release_heads_sha256 != checkpoint.release_heads_sha256
        or old.witness.checkpoint_settlement_position_sha256
        != checkpoint.settlement_position_sha256
    ):
        raise ValueError("continued quarantine predecessor binding is invalid")
    inventory_payload = _verify_compact(
        successor_inventory,
        expected_kid=root_key_id,
        public_key=root_public,
        expected_typ=RECOVERY_WITNESS_INVENTORY_TYP,
    )
    if (
        inventory_payload.get("inventory_generation") != 2
        or inventory_payload.get("previous_inventory_digest")
        != hashlib.sha256(predecessor_inventory).hexdigest()
    ):
        raise ValueError("continued quarantine inventory chain is invalid")
    new_context = verify_recovery_witness_inventory(
        successor_inventory,
        root_key_id=root_key_id,
        root_public_key=root_public,
        identity=identity,
        witness_key_id=str(package["witness_key_id"]),
        now=now,
    )
    if (
        new_context.public_key.public_bytes_raw() == old_context.public_key.public_bytes_raw()
        or new_context.key_id == old_context.key_id
    ):
        raise ValueError("continued quarantine requires a fresh witness identity")
    new = RecoveryAnchorRecordDecoder(new_context, root_key_id, root_public)(
        successor_transition, successor_witness
    )
    validate_anchor_successor(old, new)
    if (
        new.transition_version != 2
        or new.continuity != "quarantined"
        or new.beacon is not None
        or new.witness.status != "quarantined"
        or new.witness.ordering != (2, 1)
        or new.witness.checkpoint_digest != checkpoint.checkpoint_sha256
        or new.witness.release_heads_sha256 != checkpoint.release_heads_sha256
        or new.witness.checkpoint_settlement_position_sha256
        != checkpoint.settlement_position_sha256
        or not new.witness.valid_at(now)
    ):
        raise ValueError("continued quarantine successor authority is invalid")
    return identity, old, new, ContinuedQuarantineSuccessorDecoder(old, new)


def verify_bootstrap_package(
    package: dict[str, object], *, now: datetime, expected_root_public_sha256: str
) -> tuple[RecoveryAnchorIdentity, VerifiedAnchorTransition]:
    """Strictly reconstruct and verify an offline package before any online write."""

    expected = {
        "format_version",
        "environment",
        "ledger_id",
        "storage_epoch",
        "root_key_id",
        "root_public_key_b64",
        "root_public_key_sha256",
        "witness_key_id",
        "inventory_jws_b64",
        "witness_jws_b64",
        "transition_jws_b64",
        "transition_sha256",
        "checkpoint",
    }
    if set(package) != expected or package.get("format_version") != "1":
        raise ValueError("recovery bootstrap package shape is invalid")
    try:
        identity = RecoveryAnchorIdentity(
            str(package["environment"]),
            canonical_uuid4(str(package["ledger_id"])),
            canonical_uuid4(str(package["storage_epoch"])),
        )
        root_key_id = str(package["root_key_id"])
        witness_key_id = str(package["witness_key_id"])
        public_bytes = base64.b64decode(str(package["root_public_key_b64"]), validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        inventory_jws = base64.b64decode(str(package["inventory_jws_b64"]), validate=True)
        witness_jws = base64.b64decode(str(package["witness_jws_b64"]), validate=True)
        transition_jws = base64.b64decode(str(package["transition_jws_b64"]), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("recovery bootstrap package encoding is invalid") from exc
    observed_root_digest = hashlib.sha256(public_bytes).hexdigest()
    if (
        observed_root_digest != package["root_public_key_sha256"]
        or observed_root_digest != expected_root_public_sha256
    ):
        raise ValueError("recovery bootstrap root trust pin is invalid")
    if hashlib.sha256(transition_jws).hexdigest() != package["transition_sha256"]:
        raise ValueError("recovery bootstrap transition digest is invalid")
    context = verify_recovery_witness_inventory(
        inventory_jws,
        root_key_id=root_key_id,
        root_public_key=public_key,
        identity=identity,
        witness_key_id=witness_key_id,
        now=now,
    )
    decoder = RecoveryAnchorRecordDecoder(context, root_key_id, public_key)
    transition = decoder(transition_jws, witness_jws)
    checkpoint_raw = package["checkpoint"]
    if not isinstance(checkpoint_raw, dict):
        raise ValueError("recovery bootstrap checkpoint is invalid")
    checkpoint = construct_recovery_checkpoint(checkpoint_raw, identity=identity)
    require_day_zero_quarantine_checkpoint(checkpoint)
    if transition.transition_version != 1 or transition.previous_transition_sha256 is not None:
        raise ValueError("recovery bootstrap must be the unique first transition")
    if transition.continuity != "quarantined" or transition.witness.status != "quarantined":
        raise ValueError("recovery bootstrap must fail closed in quarantine")
    if (
        transition.witness.recovery_generation != 1
        or transition.witness.witness_revision != 1
        or context.inventory_generation != 1
        or transition.witness.checkpoint_digest != checkpoint.checkpoint_sha256
        or transition.witness.release_heads_sha256 != checkpoint.release_heads_sha256
        or transition.witness.checkpoint_settlement_position_sha256
        != checkpoint.settlement_position_sha256
    ):
        raise ValueError("recovery bootstrap checkpoint binding is invalid")
    return identity, transition


def build_quarantined_bootstrap(
    *,
    identity: RecoveryAnchorIdentity,
    root_key_id: str,
    root_private_key: Ed25519PrivateKey,
    witness_key_id: str,
    witness_private_key: Ed25519PrivateKey,
    checkpoint: dict[str, object],
    now: datetime,
    validity: timedelta = timedelta(hours=12),
) -> tuple[RecoveryBootstrapArtifacts, VerifiedAnchorTransition]:
    """Build and self-verify the unique version-one quarantined bootstrap package."""

    current = now.astimezone(UTC).replace(microsecond=0)
    if not timedelta(minutes=1) <= validity <= timedelta(hours=24):
        raise ValueError("recovery witness validity must be between one minute and 24 hours")
    if (
        not root_key_id
        or not witness_key_id
        or root_key_id == witness_key_id
        or root_private_key.private_bytes_raw() == witness_private_key.private_bytes_raw()
    ):
        raise ValueError("recovery root and witness signing authority must be purpose-distinct")
    verified_checkpoint = construct_recovery_checkpoint(checkpoint, identity=identity)
    require_day_zero_quarantine_checkpoint(verified_checkpoint)
    public_b64 = base64.b64encode(witness_private_key.public_key().public_bytes_raw()).decode()
    root_public_b64 = base64.b64encode(root_private_key.public_key().public_bytes_raw()).decode()
    until = current + validity
    inventory_payload: dict[str, object] = {
        "format_version": "1",
        "inventory_generation": 1,
        "previous_inventory_digest": None,
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
                "public_key_b64": public_b64,
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
    inventory_context = verify_recovery_witness_inventory(
        inventory_jws,
        root_key_id=root_key_id,
        root_public_key=root_private_key.public_key(),
        identity=identity,
        witness_key_id=witness_key_id,
        now=current,
    )
    witness_payload: dict[str, object] = {
        "format_version": "1",
        "witness_id": str(uuid4()),
        "issuer": "stoin:control",
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 1,
        "witness_revision": 1,
        "status": "quarantined",
        "issued_at": _timestamp(current),
        "not_before": _timestamp(current),
        "not_after": _timestamp(until),
        "inventory_generation": 1,
        "inventory_jws_sha256": inventory_context.inventory_jws_sha256,
        "release_heads_sha256": verified_checkpoint.release_heads_sha256,
        "checkpoint_settlement_position_sha256": verified_checkpoint.settlement_position_sha256,
        "checkpoint_digest": verified_checkpoint.checkpoint_sha256,
    }
    witness_jws = _sign_compact(
        witness_payload,
        key_id=witness_key_id,
        typ=RECOVERY_WITNESS_TYP,
        private_key=witness_private_key,
    )
    witness = verify_recovery_witness(witness_jws, context=inventory_context)
    transition_payload: dict[str, object] = {
        "format_version": "1",
        "transition_version": 1,
        "previous_transition_sha256": None,
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 1,
        "witness_revision": 1,
        "witness_jws_sha256": witness.exact_sha256,
        "continuity": "quarantined",
        "beacon": None,
    }
    transition_jws = _sign_compact(
        transition_payload,
        key_id=root_key_id,
        typ=ANCHOR_TRANSITION_TYP,
        private_key=root_private_key,
    )
    transition = verify_anchor_transition(
        transition_jws,
        root_key_id=root_key_id,
        root_public_key=root_private_key.public_key(),
        witness=witness,
    )
    return (
        RecoveryBootstrapArtifacts(
            root_key_id=root_key_id,
            root_public_key_b64=root_public_b64,
            witness_key_id=witness_key_id,
            inventory_jws=inventory_jws,
            witness_jws=witness_jws,
            transition_jws=transition_jws,
            checkpoint=verified_checkpoint,
        ),
        transition,
    )


def build_continued_quarantine_successor(
    *,
    predecessor: RecoveryBootstrapArtifacts,
    identity: RecoveryAnchorIdentity,
    root_private_key: Ed25519PrivateKey,
    witness_key_id: str,
    witness_private_key: Ed25519PrivateKey,
    predecessor_verified_at: datetime,
    now: datetime,
    validity: timedelta = timedelta(hours=24),
) -> tuple[ContinuedQuarantineSuccessorArtifacts, VerifiedAnchorTransition]:
    """Build a quarantine-only v2 successor after an expired v1 bootstrap witness.

    ``predecessor_verified_at`` is intentionally explicit: the old inventory may no longer be
    current now, but its signed bytes must still be verifiable at the previously recorded
    commissioning instant.  This routine never opens a serving path.
    """

    current = now.astimezone(UTC).replace(microsecond=0)
    historical = predecessor_verified_at.astimezone(UTC).replace(microsecond=0)
    if not timedelta(minutes=1) <= validity <= timedelta(hours=24):
        raise ValueError("recovery witness validity must be between one minute and 24 hours")
    if (
        not witness_key_id
        or witness_key_id == predecessor.root_key_id
        or root_private_key.public_key().public_bytes_raw()
        != base64.b64decode(predecessor.root_public_key_b64, validate=True)
        or root_private_key.private_bytes_raw() == witness_private_key.private_bytes_raw()
    ):
        raise ValueError("continued quarantine signer authority is invalid")
    root_public_key = root_private_key.public_key()
    old_context = verify_recovery_witness_inventory(
        predecessor.inventory_jws,
        root_key_id=predecessor.root_key_id,
        root_public_key=root_public_key,
        identity=identity,
        witness_key_id=predecessor.witness_key_id,
        now=historical,
    )
    old_transition = RecoveryAnchorRecordDecoder(
        old_context, predecessor.root_key_id, root_public_key
    )(predecessor.transition_jws, predecessor.witness_jws)
    if (
        witness_private_key.public_key().public_bytes_raw()
        == old_context.public_key.public_bytes_raw()
    ):
        raise ValueError("continued quarantine requires a replacement witness key")
    if (
        old_transition.transition_version != 1
        or old_transition.previous_transition_sha256 is not None
        or old_transition.continuity != "quarantined"
        or old_transition.witness.status != "quarantined"
        or old_transition.witness.ordering != (1, 1)
    ):
        raise ValueError("continued quarantine requires the original quarantined bootstrap")
    require_day_zero_quarantine_checkpoint(predecessor.checkpoint)
    if (
        old_transition.witness.checkpoint_digest != predecessor.checkpoint.checkpoint_sha256
        or old_transition.witness.release_heads_sha256
        != predecessor.checkpoint.release_heads_sha256
        or old_transition.witness.checkpoint_settlement_position_sha256
        != predecessor.checkpoint.settlement_position_sha256
    ):
        raise ValueError("continued quarantine predecessor checkpoint binding is invalid")
    until = current + validity
    witness_public_b64 = base64.b64encode(
        witness_private_key.public_key().public_bytes_raw()
    ).decode("ascii")
    inventory_payload: dict[str, object] = {
        "format_version": "1",
        "inventory_generation": 2,
        "previous_inventory_digest": old_context.inventory_jws_sha256,
        "issued_at": _timestamp(current),
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "root_key_id": predecessor.root_key_id,
        "keys": [
            {
                "kid": witness_key_id,
                "issuer": "stoin:control",
                "environment": identity.environment,
                "purpose": "policy_notary_v13",
                "use": "tiamat-recovery-witness",
                "algorithm": "EdDSA",
                "public_key_b64": witness_public_b64,
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
        key_id=predecessor.root_key_id,
        typ=RECOVERY_WITNESS_INVENTORY_TYP,
        private_key=root_private_key,
    )
    context = verify_recovery_witness_inventory(
        inventory_jws,
        root_key_id=predecessor.root_key_id,
        root_public_key=root_public_key,
        identity=identity,
        witness_key_id=witness_key_id,
        now=current,
    )
    if (
        context.inventory_generation != 2
        or context.inventory_jws_sha256 != hashlib.sha256(inventory_jws).hexdigest()
    ):
        raise RuntimeError("continued quarantine inventory self-verification failed")
    witness_payload: dict[str, object] = {
        "format_version": "1",
        "witness_id": str(uuid4()),
        "issuer": "stoin:control",
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 2,
        "witness_revision": 1,
        "status": "quarantined",
        "issued_at": _timestamp(current),
        "not_before": _timestamp(current),
        "not_after": _timestamp(until),
        "inventory_generation": 2,
        "inventory_jws_sha256": context.inventory_jws_sha256,
        "release_heads_sha256": predecessor.checkpoint.release_heads_sha256,
        "checkpoint_settlement_position_sha256": predecessor.checkpoint.settlement_position_sha256,
        "checkpoint_digest": predecessor.checkpoint.checkpoint_sha256,
    }
    witness_jws = _sign_compact(
        witness_payload,
        key_id=witness_key_id,
        typ=RECOVERY_WITNESS_TYP,
        private_key=witness_private_key,
    )
    witness = verify_recovery_witness(witness_jws, context=context)
    transition_jws = _sign_compact(
        {
            "format_version": "1",
            "transition_version": 2,
            "previous_transition_sha256": old_transition.exact_sha256,
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "recovery_generation": 2,
            "witness_revision": 1,
            "witness_jws_sha256": witness.exact_sha256,
            "continuity": "quarantined",
            "beacon": None,
        },
        key_id=predecessor.root_key_id,
        typ=ANCHOR_TRANSITION_TYP,
        private_key=root_private_key,
    )
    transition = verify_anchor_transition(
        transition_jws,
        root_key_id=predecessor.root_key_id,
        root_public_key=root_public_key,
        witness=witness,
    )
    return (
        ContinuedQuarantineSuccessorArtifacts(
            predecessor=predecessor,
            witness_key_id=witness_key_id,
            inventory_jws=inventory_jws,
            witness_jws=witness_jws,
            transition_jws=transition_jws,
            predecessor_verified_at=historical,
        ),
        transition,
    )


def _sign_compact(
    payload: dict[str, object],
    *,
    key_id: str,
    typ: str,
    private_key: Ed25519PrivateKey,
) -> bytes:
    header = {"alg": "EdDSA", "kid": key_id, "typ": typ}
    protected = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = protected + b"." + encoded_payload
    return signing_input + b"." + _b64url(private_key.sign(signing_input))


def _b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_uuid4(value: str) -> UUID:
    parsed = UUID(value)
    if str(parsed) != value or parsed.version != 4:
        raise ValueError("recovery bootstrap identity must use canonical UUID v4")
    return parsed
