"""M4: the validating sole anchor writer, against genuinely signed transitions.

The fake table enforces the conditional write the writer relies on, so a compare-and-swap that
should fail does fail. Every transition here is really signed by the builders the offline
ceremonies use.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution import anchor_writer_lambda
from lucy.shared_execution.anchor_writer import (
    AnchorWriter,
    AnchorWriteRefused,
    AnchorWriteRequest,
    WriterRoot,
)
from lucy.shared_execution.anchor_writer_lambda import (
    LambdaAnchorWriterClient,
    writer_from_environment,
)
from lucy.shared_execution.recovery_anchor import (
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
    validate_anchor_successor,
)
from lucy.shared_execution.recovery_anchor_commissioning import (
    RecoveryBootstrapArtifacts,
    build_continued_quarantine_successor,
    build_quarantined_bootstrap,
)

NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)
ROOT_KEY_ID = "tiamat-recovery-root.test.1"


class ConditionalTable:
    """A one-table DynamoDB fake that evaluates the writer's two condition forms."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.puts = 0
        self.interfere: dict[str, Any] | None = None
        self.interfere_on_read: dict[str, Any] | None = None
        self.reads = 0

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["ConsistentRead"] is True
        key = kwargs["Key"]["anchor_key"]["S"]
        self.reads += 1
        if self.interfere_on_read is not None and self.reads >= 2:
            # Another write lands after the writer's own first read of this request.
            self.items[key], self.interfere_on_read = self.interfere_on_read, None
        item = self.items.get(key)
        return {} if item is None else {"Item": item}

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.puts += 1
        item = kwargs["Item"]
        key = item["anchor_key"]["S"]
        if self.interfere is not None:
            # Another write lands between the writer's read and its conditional put.
            self.items[key], self.interfere = self.interfere, None
        current = self.items.get(key)
        condition = kwargs["ConditionExpression"]
        if condition == "attribute_not_exists(#anchor_key)":
            holds = current is None
        else:
            values = kwargs["ExpressionAttributeValues"]
            holds = (
                current is not None
                and current["transition_sha256"]["S"] == values[":expected_digest"]["S"]
                and current["transition_version"]["N"] == values[":expected_version"]["N"]
            )
        if not holds:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "no"}},
                "PutItem",
            )
        self.items[key] = item
        return {}


def _checkpoint(identity: RecoveryAnchorIdentity) -> dict[str, object]:
    return {
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 1,
        "release_inventory": {"state": "not_installed"},
        "release_heads": [],
        "settlement_position": [],
    }


def _root(private: Ed25519PrivateKey) -> WriterRoot:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return WriterRoot(
        root_key_id=ROOT_KEY_ID,
        root_public_key_b64=base64.b64encode(raw).decode(),
        root_public_key_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _key(identity: RecoveryAnchorIdentity) -> str:
    return f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}"


def _bootstrap(
    identity: RecoveryAnchorIdentity, root: Ed25519PrivateKey
) -> RecoveryBootstrapArtifacts:
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id=ROOT_KEY_ID,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.test.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint=_checkpoint(identity),
        now=NOW,
        validity=timedelta(hours=12),
    )
    return artifacts


def _request(
    identity: RecoveryAnchorIdentity,
    artifacts: Any,
    *,
    head_inventory: bytes | None = None,
) -> AnchorWriteRequest:
    return AnchorWriteRequest(
        anchor_key=_key(identity),
        transition_jws=artifacts.transition_jws,
        witness_jws=artifacts.witness_jws,
        inventory_jws=artifacts.inventory_jws,
        head_inventory_jws=head_inventory,
    )


def _writer(
    table: ConditionalTable,
    identity: RecoveryAnchorIdentity,
    root: Ed25519PrivateKey,
    *,
    now: datetime = NOW,
) -> AnchorWriter:
    return AnchorWriter(
        roots={_key(identity): _root(root)},
        client=table,
        table_name="tiamat-recovery-anchor",
        clock=lambda: now,
    )


@pytest.fixture
def world() -> tuple[RecoveryAnchorIdentity, Ed25519PrivateKey, ConditionalTable]:
    return RecoveryAnchorIdentity("test", uuid4(), uuid4()), Ed25519PrivateKey.generate(), (
        ConditionalTable()
    )


def test_a_first_transition_is_installed_and_read_back(world: Any) -> None:
    identity, root, table = world
    bootstrap = _bootstrap(identity, root)

    result = _writer(table, identity, root).write(_request(identity, bootstrap))

    assert result.outcome == "installed"
    assert result.transition_sha256 == bootstrap.transition_sha256
    assert result.transition_version == 1
    assert table.items[_key(identity)]["transition_jws"]["B"] == bootstrap.transition_jws


def test_an_identical_retry_succeeds_without_writing_again(world: Any) -> None:
    """C4(vii): after an ambiguous response the caller retries the same bytes."""

    identity, root, table = world
    bootstrap = _bootstrap(identity, root)
    writer = _writer(table, identity, root)
    writer.write(_request(identity, bootstrap))

    retried = writer.write(_request(identity, bootstrap))

    assert retried.outcome == "already_installed"
    assert table.puts == 1


def test_a_successor_under_a_rotated_witness_key_is_installed(world: Any) -> None:
    """The head expired and was signed under an earlier inventory; it still verifies as history."""

    identity, root, table = world
    bootstrap = _bootstrap(identity, root)
    _writer(table, identity, root).write(_request(identity, bootstrap))
    later = NOW + timedelta(hours=13)
    successor, _ = build_continued_quarantine_successor(
        predecessor=bootstrap,
        identity=identity,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.test.2",
        witness_private_key=Ed25519PrivateKey.generate(),
        predecessor_verified_at=NOW,
        now=later,
    )

    result = _writer(table, identity, root, now=later).write(
        _request(identity, successor, head_inventory=bootstrap.inventory_jws)
    )

    assert (result.outcome, result.transition_version) == ("installed", 2)
    assert table.items[_key(identity)]["transition_sha256"]["S"] == successor.transition_sha256


def test_a_head_is_not_verified_under_an_inventory_that_never_signed_it(world: Any) -> None:
    identity, root, table = world
    bootstrap = _bootstrap(identity, root)
    _writer(table, identity, root).write(_request(identity, bootstrap))
    later = NOW + timedelta(hours=13)
    successor, _ = build_continued_quarantine_successor(
        predecessor=bootstrap,
        identity=identity,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.test.2",
        witness_private_key=Ed25519PrivateKey.generate(),
        predecessor_verified_at=NOW,
        now=later,
    )

    # Omitted: the writer says what is missing rather than calling the head junk.
    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_head_inventory_required"):
        _writer(table, identity, root, now=later).write(_request(identity, successor))
    # Supplied, but not the inventory that signed the head: refused as unverifiable.
    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_record_invalid"):
        _writer(table, identity, root, now=later).write(
            _request(identity, successor, head_inventory=successor.inventory_jws)
        )
    assert table.puts == 1


def test_a_head_that_moves_after_the_writer_read_it_loses_the_compare(world: Any) -> None:
    """The read/read race: the head changes between the writer's read and the install's."""

    identity, root, table = world
    bootstrap = _bootstrap(identity, root)
    _writer(table, identity, root).write(_request(identity, bootstrap))
    later = NOW + timedelta(hours=13)
    successor, _ = build_continued_quarantine_successor(
        predecessor=bootstrap,
        identity=identity,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.test.2",
        witness_private_key=Ed25519PrivateKey.generate(),
        predecessor_verified_at=NOW,
        now=later,
    )
    table.reads = 0
    table.interfere_on_read = {
        **table.items[_key(identity)],
        "transition_jws": {"B": b"someone-else"},
        "witness_jws": {"B": b"someone-else"},
        "transition_sha256": {"S": "2" * 64},
    }

    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_compare_failed"):
        _writer(table, identity, root, now=later).write(
            _request(identity, successor, head_inventory=bootstrap.inventory_jws)
        )
    assert table.puts == 1


def test_a_candidate_under_another_root_is_refused(world: Any) -> None:
    identity, root, table = world
    impostor = _bootstrap(identity, Ed25519PrivateKey.generate())

    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_record_invalid"):
        _writer(table, identity, root).write(_request(identity, impostor))
    assert table.puts == 0


def test_altered_candidate_bytes_are_refused(world: Any) -> None:
    identity, root, table = world
    bootstrap = _bootstrap(identity, root)
    altered = replace(
        _request(identity, bootstrap),
        transition_jws=bootstrap.transition_jws[:-4] + b"AAAA",
    )

    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_record_invalid"):
        _writer(table, identity, root).write(altered)
    assert table.puts == 0


def test_an_unconfigured_anchor_key_is_refused(world: Any) -> None:
    identity, root, table = world
    other = RecoveryAnchorIdentity("test", uuid4(), uuid4())
    bootstrap = _bootstrap(other, root)

    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_writer_key_not_configured"):
        _writer(table, identity, root).write(_request(other, bootstrap))


def test_a_candidate_for_another_ledger_under_this_key_is_refused(world: Any) -> None:
    identity, root, table = world
    other = RecoveryAnchorIdentity("test", uuid4(), uuid4())
    bootstrap = _bootstrap(other, root)
    request = replace(_request(other, bootstrap), anchor_key=_key(identity))

    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_identity_mismatch"):
        _writer(table, identity, root).write(request)
    assert table.puts == 0


def test_a_raw_malformed_head_is_refused_and_not_overwritten(world: Any) -> None:
    """C4(v): junk at the head blocks the writer; it does not paper over it."""

    identity, root, table = world
    table.items[_key(identity)] = {
        "anchor_key": {"S": _key(identity)},
        "transition_jws": {"B": b"junk"},
        "witness_jws": {"B": b"junk"},
        "transition_sha256": {"S": "0" * 64},
        "transition_version": {"N": "1"},
    }

    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_record_invalid"):
        _writer(table, identity, root).write(_request(identity, _bootstrap(identity, root)))
    assert table.puts == 0


def test_a_second_first_transition_is_refused(world: Any) -> None:
    """C4(iii): a different version-one transition cannot replace the installed one."""

    identity, root, table = world
    _writer(table, identity, root).write(_request(identity, _bootstrap(identity, root)))

    with pytest.raises(AnchorWriteRefused):
        _writer(table, identity, root).write(_request(identity, _bootstrap(identity, root)))
    assert table.puts == 1


def test_a_write_racing_another_loses_the_compare(world: Any) -> None:
    """C4(i): between the writer's read and its put, another write lands; the put must fail."""

    identity, root, table = world
    bootstrap = _bootstrap(identity, root)
    table.interfere = {
        "anchor_key": {"S": _key(identity)},
        "transition_jws": {"B": b"someone-else"},
        "witness_jws": {"B": b"someone-else"},
        "transition_sha256": {"S": "1" * 64},
        "transition_version": {"N": "1"},
    }

    with pytest.raises(AnchorWriteRefused, match="recovery_anchor_compare_failed"):
        _writer(table, identity, root).write(_request(identity, bootstrap))


# ---------------------------------------------------------------- G9, shared by every adapter


def _transition(
    identity: RecoveryAnchorIdentity,
    continuity: str,
    *,
    version: int,
    previous: VerifiedAnchorTransition | None = None,
    witness: VerifiedRecoveryWitness | None = None,
    generation: int = 2,
) -> VerifiedAnchorTransition:
    witness = witness or VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=generation,
        witness_revision=1,
        status="quarantined" if continuity == "quarantined" else "reconciled",
        checkpoint_digest="a" * 64,
        release_heads_sha256="c" * 64,
        checkpoint_settlement_position_sha256="d" * 64,
        witness_inventory_digest="b" * 64,
        exact_jws=f"witness-{generation}-{version}".encode(),
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
    )
    return VerifiedAnchorTransition(
        witness=witness,
        transition_version=version,
        previous_transition_sha256=None if previous is None else previous.exact_sha256,
        continuity=continuity,  # type: ignore[arg-type]
        # Only established continuity asserts a database position.
        beacon=(
            PostgresContinuityBeacon("system-1", 1, f"0/{version:02X}", "a" * 64)
            if continuity == "continuity_established"
            else None
        ),
        exact_jws=f"transition-{continuity}-{version}".encode(),
    )


def test_quarantine_cannot_skip_recovery_pending() -> None:
    """C4(x), G9."""

    identity = RecoveryAnchorIdentity("test", uuid4(), uuid4())
    quarantined = _transition(identity, "quarantined", version=1, generation=1)
    established = _transition(identity, "continuity_established", version=2, previous=quarantined)
    with pytest.raises(RecoveryAnchorRejected, match="recovery_continuity_requires_pending"):
        validate_anchor_successor(quarantined, established)


def test_establishing_continuity_confirms_the_pending_witness_exactly() -> None:
    identity = RecoveryAnchorIdentity("test", uuid4(), uuid4())
    quarantined = _transition(identity, "quarantined", version=1, generation=1)
    pending = _transition(identity, "recovery_pending", version=2, previous=quarantined)
    validate_anchor_successor(quarantined, pending)

    confirmed = _transition(
        identity, "continuity_established", version=3, previous=pending, witness=pending.witness
    )
    validate_anchor_successor(pending, confirmed)

    reminted = _transition(
        identity, "continuity_established", version=3, previous=pending, generation=3
    )
    with pytest.raises(RecoveryAnchorRejected, match="recovery_continuity_witness_changed"):
        validate_anchor_successor(pending, reminted)


# ---------------------------------------------------------------- Lambda handler and client


class _Payload:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body


class _InvokesHandler:
    """A Lambda client whose invocation runs the real handler in-process."""

    def __init__(self, writer: AnchorWriter) -> None:
        self.writer = writer
        self.invocations = 0

    def invoke(self, **kwargs: Any) -> dict[str, Any]:
        self.invocations += 1
        assert kwargs["InvocationType"] == "RequestResponse"
        anchor_writer_lambda._writer = self.writer
        answer = anchor_writer_lambda.handler(json.loads(kwargs["Payload"]), None)
        return {"Payload": _Payload(json.dumps(answer).encode())}


def test_the_client_installs_through_the_handler(world: Any) -> None:
    identity, root, table = world
    bootstrap = _bootstrap(identity, root)
    client = LambdaAnchorWriterClient(
        function_name="tiamat-anchor-writer", client=_InvokesHandler(_writer(table, identity, root))
    )

    first = client.write(_request(identity, bootstrap))
    again = client.write(_request(identity, bootstrap))

    assert (first.outcome, again.outcome) == ("installed", "already_installed")
    assert first.transition_sha256 == bootstrap.transition_sha256
    assert table.puts == 1


def test_a_refusal_reaches_the_caller_as_its_reason_code(world: Any) -> None:
    identity, root, table = world
    impostor = _bootstrap(identity, Ed25519PrivateKey.generate())
    client = LambdaAnchorWriterClient(
        function_name="tiamat-anchor-writer", client=_InvokesHandler(_writer(table, identity, root))
    )

    with pytest.raises(RecoveryAnchorRejected, match="recovery_anchor_record_invalid"):
        client.write(_request(identity, impostor))


def test_the_handler_refuses_a_malformed_request_and_leaks_no_detail() -> None:
    assert anchor_writer_lambda.handler({"anchor_key": "x"}, None) == {
        "status": "refused",
        "reason": "recovery_anchor_writer_request_invalid",
    }

    class _Exploding:
        def write(self, _request: Any) -> None:
            raise RuntimeError("internal detail that must not leave the function")

    anchor_writer_lambda._writer = _Exploding()  # type: ignore[assignment]
    answer = anchor_writer_lambda.handler(
        {
            "anchor_key": "x",
            "transition_jws_b64": "",
            "witness_jws_b64": "",
            "inventory_jws_b64": "",
        },
        None,
    )
    anchor_writer_lambda._writer = None
    assert answer == {"status": "refused", "reason": "recovery_anchor_writer_failed"}


def test_an_unknown_invocation_outcome_is_unavailable_not_success() -> None:
    class _FunctionError:
        def invoke(self, **_kwargs: Any) -> dict[str, Any]:
            return {"FunctionError": "Unhandled", "Payload": _Payload(b"{}")}

    client = LambdaAnchorWriterClient(function_name="tiamat-anchor-writer", client=_FunctionError())
    request = AnchorWriteRequest("x", b"t", b"w", b"i")
    with pytest.raises(RecoveryAnchorRejected, match="recovery_anchor_writer_unavailable"):
        client.write(request)


@pytest.mark.parametrize(
    "roots",
    [
        "",
        "{}",
        '{"ENV#a#LEDGER#b": {"root_key_id": "k"}}',
        '{"ENV#a#LEDGER#b": {"root_key_id": "k", "root_public_key_b64": "x", '
        '"root_public_key_sha256": "y", "extra": "z"}}',
    ],
)
def test_the_writer_refuses_incomplete_configuration(roots: str) -> None:
    with pytest.raises(ValueError, match="configuration is invalid"):
        writer_from_environment(_environment(roots), client=ConditionalTable())


def _environment(roots: str, *, digest: str | None = None) -> dict[str, str]:
    return {
        "TIAMAT_RECOVERY_ANCHOR_TABLE": "t",
        "AWS_REGION": "us-east-1",
        "TIAMAT_ANCHOR_WRITER_ROOTS": roots,
        "TIAMAT_ANCHOR_WRITER_ROOTS_SHA256": (
            digest if digest is not None else hashlib.sha256(roots.encode()).hexdigest()
        ),
    }


def test_the_writer_starts_only_on_the_reviewed_roots(world: Any) -> None:
    """The version names the roots digest; configuration that does not hash to it is refused."""

    identity, root, _ = world
    entry = _root(root)
    roots = json.dumps(
        {
            _key(identity): {
                "root_key_id": entry.root_key_id,
                "root_public_key_b64": entry.root_public_key_b64,
                "root_public_key_sha256": entry.root_public_key_sha256,
            }
        }
    )
    assert writer_from_environment(_environment(roots), client=ConditionalTable()) is not None
    with pytest.raises(ValueError, match="configuration is invalid"):
        writer_from_environment(_environment(roots, digest="0" * 64), client=ConditionalTable())
