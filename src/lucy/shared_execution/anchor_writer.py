"""M4: the validating sole writer of the external recovery anchor.

This is the only principal that may write the anchor table. Callers - the recovery coordinator
and its tools - may only ask it to install a transition. For every request it:

1. strong-reads the current head itself, never accepting a head from the caller;
2. verifies the candidate's exact signed bytes - transition, witness and the witness inventory
   carried in the request - against a root public key held in its own configuration for that
   anchor key, at its own clock;
3. verifies the head it read against the same pinned root. A head whose witness has since
   expired, or was signed under an earlier inventory, is verified as of the instant its witness
   was issued: signatures do not expire, and a forged head cannot be made to verify at any
   instant;
4. applies the shared successor rules, including the continuity-state rules, then writes
   conditionally on the exact prior version and digest;
5. strong-rereads and reports the digest it read back; and
6. treats a request for the bytes already at the head as success, so a caller that saw an
   ambiguous response can retry the identical request.

The caller supplies trust material only as bytes that must verify against the writer's pinned
root; nothing the caller asserts is believed on its own.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
)
from lucy.shared_execution.recovery_anchor_dynamodb import (
    DynamoDbClient,
    DynamoDbExternalRecoveryAnchor,
)
from lucy.shared_execution.recovery_witness_jws import (
    RecoveryAnchorRecordDecoder,
    verify_recovery_witness_inventory,
)


class AnchorWriteRefused(RuntimeError):
    """The writer refused the request; ``str(exc)`` is the content-free reason code."""


@dataclass(frozen=True)
class WriterRoot:
    """The anchor root the writer trusts for one anchor key. A reviewed configuration change."""

    root_key_id: str
    root_public_key_b64: str
    root_public_key_sha256: str

    @property
    def public_key(self) -> Ed25519PublicKey:
        try:
            raw = base64.b64decode(self.root_public_key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AnchorWriteRefused("recovery_anchor_writer_root_invalid") from exc
        if hashlib.sha256(raw).hexdigest() != self.root_public_key_sha256:
            raise AnchorWriteRefused("recovery_anchor_writer_root_pin_mismatch")
        try:
            return Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise AnchorWriteRefused("recovery_anchor_writer_root_invalid") from exc


@dataclass(frozen=True)
class AnchorWriteRequest:
    anchor_key: str
    transition_jws: bytes
    witness_jws: bytes
    inventory_jws: bytes
    # The inventory the current head's witness was signed under, when it differs from the
    # candidate's. It is trusted only if it verifies against the pinned root.
    head_inventory_jws: bytes | None = None


@dataclass(frozen=True)
class AnchorWriteResult:
    outcome: Literal["installed", "already_installed"]
    transition_sha256: str
    transition_version: int


class AnchorWriter:
    def __init__(
        self,
        *,
        roots: Mapping[str, WriterRoot],
        client: DynamoDbClient,
        table_name: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not roots or not table_name:
            raise ValueError("anchor writer configuration is incomplete")
        self._roots = dict(roots)
        self._client = client
        self._table_name = table_name
        self._clock = clock

    def write(self, request: AnchorWriteRequest) -> AnchorWriteResult:
        root = self._roots.get(request.anchor_key)
        if root is None:
            raise AnchorWriteRefused("recovery_anchor_writer_key_not_configured")
        now = self._clock()
        if now.tzinfo is None:
            raise AnchorWriteRefused("recovery_anchor_writer_clock_invalid")

        candidate = self._verify(
            root, request.transition_jws, request.witness_jws, request.inventory_jws, at=now
        )
        if _storage_key(candidate.witness.identity) != request.anchor_key:
            raise AnchorWriteRefused("recovery_anchor_identity_mismatch")

        stored = self._strong_read(request.anchor_key)
        if stored is not None and stored == (candidate.exact_jws, candidate.witness.exact_jws):
            # The identical bytes are already the head: an ambiguous earlier response, retried.
            return self._confirm(request.anchor_key, candidate, "already_installed")
        head: VerifiedAnchorTransition | None = None
        if stored is not None:
            head = self._verify_historical(
                root,
                *stored,
                request.head_inventory_jws or request.inventory_jws,
                head_inventory_supplied=request.head_inventory_jws is not None,
            )

        anchor = DynamoDbExternalRecoveryAnchor(
            client=self._client,
            table_name=self._table_name,
            decode_transition=_Pinned(candidate, head),
        )
        try:
            anchor.install(
                candidate,
                expected_transition_sha256=None if head is None else head.exact_sha256,
                now=now,
            )
        except RecoveryAnchorRejected as exc:
            if self._strong_read(request.anchor_key) != stored:
                # The head moved after this request read it: another write won the race.
                raise AnchorWriteRefused("recovery_anchor_compare_failed") from exc
            raise AnchorWriteRefused(str(exc)) from exc
        return self._confirm(request.anchor_key, candidate, "installed")

    def _verify(
        self,
        root: WriterRoot,
        transition_jws: bytes,
        witness_jws: bytes,
        inventory_jws: bytes,
        *,
        at: datetime,
    ) -> VerifiedAnchorTransition:
        """Verify exact bytes through inventory, witness and transition against the pinned root."""

        try:
            claims, header = _claims(witness_jws)
            identity = RecoveryAnchorIdentity(
                str(claims["environment"]),
                UUID(str(claims["ledger_id"])),
                UUID(str(claims["storage_epoch"])),
            )
            context = verify_recovery_witness_inventory(
                inventory_jws,
                root_key_id=root.root_key_id,
                root_public_key=root.public_key,
                identity=identity,
                witness_key_id=str(header["kid"]),
                now=at,
            )
            return RecoveryAnchorRecordDecoder(context, root.root_key_id, root.public_key)(
                transition_jws, witness_jws
            )
        except AnchorWriteRefused:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise AnchorWriteRefused("recovery_anchor_record_invalid") from exc

    def _verify_historical(
        self,
        root: WriterRoot,
        transition_jws: bytes,
        witness_jws: bytes,
        inventory_jws: bytes,
        *,
        head_inventory_supplied: bool,
    ) -> VerifiedAnchorTransition:
        """Verify the stored head as of the instant its witness was issued.

        ``issued_at`` is signed and, by the witness rules, always falls inside its key's issuance
        window, so a genuine head always verifies there. ``not_before`` need not: a witness issued
        late in the window may start after it closes, and would otherwise wedge the anchor.
        """

        try:
            claims, _ = _claims(witness_jws)
            instant = datetime.strptime(str(claims["issued_at"]), "%Y-%m-%dT%H:%M:%SZ")
        except (KeyError, TypeError, ValueError) as exc:
            # Not even a well-formed witness: the head is junk, whatever inventory is offered.
            raise AnchorWriteRefused("recovery_anchor_record_invalid") from exc
        try:
            return self._verify(
                root, transition_jws, witness_jws, inventory_jws, at=instant.replace(tzinfo=UTC)
            )
        except AnchorWriteRefused as exc:
            if not head_inventory_supplied and str(exc) == "recovery_anchor_record_invalid":
                # A well-formed head that did not verify under the candidate's inventory, and
                # the caller did not send the one it was signed under: say what is missing.
                raise AnchorWriteRefused("recovery_anchor_head_inventory_required") from exc
            raise

    def _strong_read(self, anchor_key: str) -> tuple[bytes, bytes] | None:
        try:
            response = self._client.get_item(
                TableName=self._table_name,
                Key={"anchor_key": {"S": anchor_key}},
                ConsistentRead=True,
            )
        except (BotoCoreError, ClientError) as exc:
            raise AnchorWriteRefused("recovery_anchor_unavailable") from exc
        item = response.get("Item")
        if item is None:
            return None
        try:
            return bytes(item["transition_jws"]["B"]), bytes(item["witness_jws"]["B"])
        except (KeyError, TypeError) as exc:
            raise AnchorWriteRefused("recovery_anchor_record_invalid") from exc

    def _confirm(
        self,
        anchor_key: str,
        candidate: VerifiedAnchorTransition,
        outcome: Literal["installed", "already_installed"],
    ) -> AnchorWriteResult:
        stored = self._strong_read(anchor_key)
        if stored != (candidate.exact_jws, candidate.witness.exact_jws):
            raise AnchorWriteRefused("recovery_anchor_compare_failed")
        return AnchorWriteResult(
            outcome=outcome,
            transition_sha256=hashlib.sha256(stored[0]).hexdigest(),
            transition_version=candidate.transition_version,
        )


@dataclass(frozen=True)
class _Pinned:
    """Decode exactly the two records this write already verified, and nothing else."""

    candidate: VerifiedAnchorTransition
    head: VerifiedAnchorTransition | None

    def __call__(
        self, exact_transition_jws: bytes, exact_witness_jws: bytes
    ) -> VerifiedAnchorTransition:
        for transition in (self.candidate, self.head):
            if (
                transition is not None
                and exact_transition_jws == transition.exact_jws
                and exact_witness_jws == transition.witness.exact_jws
            ):
                return transition
        raise ValueError("record is not one this write verified")


def _claims(exact_jws: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read a compact JWS's header and payload without trusting them.

    Only used to choose which key and which instant to verify with; the verification that
    follows is what decides whether the bytes are believed.
    """

    parts = exact_jws.split(b".")
    if len(parts) != 3:
        raise ValueError("compact JWS is malformed")

    def segment(value: bytes) -> dict[str, Any]:
        decoded = json.loads(base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4)))
        if not isinstance(decoded, dict):
            raise ValueError("compact JWS segment is not an object")
        return decoded

    return segment(parts[1]), segment(parts[0])


def _storage_key(identity: RecoveryAnchorIdentity) -> str:
    return f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}"
