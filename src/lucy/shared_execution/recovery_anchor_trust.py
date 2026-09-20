"""Assemble a verifying external anchor reader from pinned, content-free trust material.

A launcher never learns trust from the record it is about to verify. The root public key and its
independent digest pin come from deployment configuration; the root-signed witness inventory is
verified against that pinned root before any stored transition is decoded. Nothing here signs,
installs or mutates an anchor record, and no credential is accepted as application configuration.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_dynamodb import (
    DynamoDbExternalRecoveryAnchor,
    dynamodb_recovery_anchor_from_environment,
)
from lucy.shared_execution.recovery_witness_jws import (
    RecoveryAnchorRecordDecoder,
    verify_recovery_witness_inventory,
)

_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TRUST_FIELDS = (
    "environment",
    "ledger_id",
    "storage_epoch",
    "root_key_id",
    "root_public_key_b64",
    "root_public_key_sha256",
    "witness_key_id",
    "inventory_jws_b64",
)


class AnchorTrustRejected(RuntimeError):
    """Configured anchor trust material is unusable, so nothing may be decoded with it."""


@dataclass(frozen=True)
class AnchorTrustConfiguration:
    """The exact public trust material a deployment pins for one ledger.

    These are the only fields of a published bootstrap package which establish trust. The signed
    transition and witness bytes in that package are evidence of one historical install, never
    configuration, and are deliberately absent here.
    """

    identity: RecoveryAnchorIdentity
    root_key_id: str
    root_public_key_b64: str
    root_public_key_sha256: str
    witness_key_id: str
    inventory_jws_b64: str

    def __post_init__(self) -> None:
        if (
            _KEY_ID.fullmatch(self.root_key_id) is None
            or _KEY_ID.fullmatch(self.witness_key_id) is None
            or self.root_key_id == self.witness_key_id
            or _HEX_DIGEST.fullmatch(self.root_public_key_sha256) is None
            or not self.root_public_key_b64
            or not self.inventory_jws_b64
        ):
            raise ValueError("anchor trust configuration is invalid")

    @property
    def root_public_key(self) -> Ed25519PublicKey:
        """Decode the configured root key only after its independent digest pin matches."""

        raw = _decode(self.root_public_key_b64, "root public key")
        if hashlib.sha256(raw).hexdigest() != self.root_public_key_sha256:
            raise AnchorTrustRejected("recovery_anchor_root_trust_pin_mismatch")
        try:
            return Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise AnchorTrustRejected("recovery_anchor_root_key_invalid") from exc

    @property
    def inventory_jws(self) -> bytes:
        return _decode(self.inventory_jws_b64, "witness inventory")


def load_anchor_trust(document: Mapping[str, object]) -> AnchorTrustConfiguration:
    """Read pinned trust from a published package or a trust-only configuration document.

    A published bootstrap package carries more than trust, so extra members are ignored rather
    than rejected. Every member actually used is required, and none of them is optional.
    """

    missing = [field for field in _TRUST_FIELDS if field not in document]
    if missing:
        raise AnchorTrustRejected("recovery_anchor_trust_incomplete")
    try:
        identity = RecoveryAnchorIdentity(
            str(document["environment"]),
            UUID(str(document["ledger_id"])),
            UUID(str(document["storage_epoch"])),
        )
        configuration = AnchorTrustConfiguration(
            identity=identity,
            root_key_id=str(document["root_key_id"]),
            root_public_key_b64=str(document["root_public_key_b64"]),
            root_public_key_sha256=str(document["root_public_key_sha256"]),
            witness_key_id=str(document["witness_key_id"]),
            inventory_jws_b64=str(document["inventory_jws_b64"]),
        )
    except (TypeError, ValueError) as exc:
        raise AnchorTrustRejected("recovery_anchor_trust_invalid") from exc
    return configuration


def verified_anchor_reader(
    configuration: AnchorTrustConfiguration,
    *,
    now: datetime,
    environment: Mapping[str, str] | None = None,
    client_factory: Any | None = None,
) -> DynamoDbExternalRecoveryAnchor:
    """Build the read/compare-and-swap adapter which verifies exact signed bytes on every read.

    ``now`` verifies the configured inventory's own validity. The adapter it returns re-verifies
    each stored record against this pinned root, so an unsigned or foreign record fails closed
    rather than becoming authority.
    """

    if now.tzinfo is None:
        raise ValueError("anchor trust time must be aware")
    root_public_key = configuration.root_public_key
    try:
        context = verify_recovery_witness_inventory(
            configuration.inventory_jws,
            root_key_id=configuration.root_key_id,
            root_public_key=root_public_key,
            identity=configuration.identity,
            witness_key_id=configuration.witness_key_id,
            now=now,
        )
    except Exception as exc:  # noqa: BLE001 - every inventory rejection is one fail-closed outcome
        raise AnchorTrustRejected("recovery_anchor_witness_inventory_rejected") from exc
    decoder = RecoveryAnchorRecordDecoder(context, configuration.root_key_id, root_public_key)
    try:
        return dynamodb_recovery_anchor_from_environment(
            decoder,
            environment=environment,
            client_factory=client_factory,
        )
    except ValueError as exc:
        raise AnchorTrustRejected("recovery_anchor_store_configuration_invalid") from exc


def _decode(value: str, description: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        reason = f"recovery_anchor_{description.replace(' ', '_')}_invalid"
        raise AnchorTrustRejected(reason) from exc
