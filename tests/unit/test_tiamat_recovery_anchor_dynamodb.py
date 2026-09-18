from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from lucy.shared_execution.recovery_anchor import (
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
    RecoveryAnchorRuntimeGate,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)
from lucy.shared_execution.recovery_anchor_dynamodb import (
    DynamoDbExternalRecoveryAnchor,
    dynamodb_recovery_anchor_from_environment,
)

NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)


def make_transition(
    identity: RecoveryAnchorIdentity,
    *,
    version: int = 1,
    previous: VerifiedAnchorTransition | None = None,
) -> VerifiedAnchorTransition:
    witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=1,
        witness_revision=version,
        status="reconciled",
        checkpoint_digest="a" * 64,
        release_heads_sha256="c" * 64,
        checkpoint_settlement_position_sha256="d" * 64,
        witness_inventory_digest="b" * 64,
        exact_jws=f"witness-{version}".encode(),
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
    )
    return VerifiedAnchorTransition(
        witness=witness,
        transition_version=version,
        previous_transition_sha256=None if previous is None else previous.exact_sha256,
        continuity="continuity_established",
        beacon=PostgresContinuityBeacon("system-1", 1, f"0/{version:02X}", "a" * 64),
        exact_jws=f"transition-{version}".encode(),
    )


class FakeDynamoDb:
    def __init__(self) -> None:
        self.item: dict[str, Any] | None = None
        self.get_calls: list[dict[str, Any]] = []
        self.put_calls: list[dict[str, Any]] = []
        self.failure: Exception | None = None
        self.fail_after_put = False

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(kwargs)
        if self.failure is not None:
            raise self.failure
        return {} if self.item is None else {"Item": self.item}

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.put_calls.append(kwargs)
        if self.failure is not None:
            raise self.failure
        self.item = kwargs["Item"]
        if self.fail_after_put:
            raise EndpointConnectionError(endpoint_url="https://dynamodb.invalid")
        return {}


class Decoder:
    def __init__(self, *transitions: VerifiedAnchorTransition) -> None:
        self.transitions = {
            (transition.exact_jws, transition.witness.exact_jws): transition
            for transition in transitions
        }
        self.calls: list[tuple[bytes, bytes]] = []

    def __call__(self, transition_jws: bytes, witness_jws: bytes) -> VerifiedAnchorTransition:
        self.calls.append((transition_jws, witness_jws))
        try:
            return self.transitions[(transition_jws, witness_jws)]
        except KeyError as exc:
            raise RecoveryAnchorRejected("signature_invalid") from exc


def adapter(
    client: FakeDynamoDb, decoder: Decoder
) -> DynamoDbExternalRecoveryAnchor:
    return DynamoDbExternalRecoveryAnchor(
        client=client, table_name="tiamat-recovery-anchor", decode_transition=decoder
    )


def test_bootstrap_stores_exact_signed_bytes_with_conditional_create() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    decoder = Decoder(first)

    adapter(client, decoder).install(first, expected_transition_sha256=None, now=NOW)

    request = client.put_calls[0]
    assert request["ConditionExpression"] == "attribute_not_exists(#anchor_key)"
    assert request["ExpressionAttributeNames"] == {"#anchor_key": "anchor_key"}
    assert request["Item"]["transition_jws"] == {"B": first.exact_jws}
    assert request["Item"]["witness_jws"] == {"B": first.witness.exact_jws}
    assert decoder.calls == [(first.exact_jws, first.witness.exact_jws)]


def test_read_is_strongly_consistent_and_reverifies_exact_bytes() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    decoder = Decoder(first)
    store = adapter(client, decoder)
    store.install(first, expected_transition_sha256=None, now=NOW)

    assert store.read(identity.key) == first
    assert client.get_calls[-1]["ConsistentRead"] is True
    assert decoder.calls[-1] == (first.exact_jws, first.witness.exact_jws)


def test_successor_uses_exact_digest_and_version_compare_and_swap() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    second = make_transition(identity, version=2, previous=first)
    client = FakeDynamoDb()
    store = adapter(client, Decoder(first, second))
    store.install(first, expected_transition_sha256=None, now=NOW)

    store.install(second, expected_transition_sha256=first.exact_sha256, now=NOW)

    request = client.put_calls[-1]
    assert "#transition_sha256 = :expected_digest" in request["ConditionExpression"]
    assert request["ExpressionAttributeNames"] == {
        "#anchor_key": "anchor_key",
        "#transition_sha256": "transition_sha256",
        "#transition_version": "transition_version",
    }
    assert request["ExpressionAttributeValues"] == {
        ":expected_digest": {"S": first.exact_sha256},
        ":expected_version": {"N": "1"},
    }


def test_conditional_failure_is_fail_closed() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    client.failure = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "lost race"}},
        "PutItem",
    )

    with pytest.raises(RecoveryAnchorRejected, match="compare_failed"):
        adapter(client, Decoder(first)).install(
            first, expected_transition_sha256=None, now=NOW
        )


@pytest.mark.parametrize("operation", ["read", "write"])
def test_aws_unavailability_fails_closed(operation: str) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    client.failure = EndpointConnectionError(endpoint_url="https://dynamodb.invalid")
    store = adapter(client, Decoder(first))

    with pytest.raises(RecoveryAnchorRejected, match="unavailable"):
        if operation == "read":
            store.read(identity.key)
        else:
            store.install(first, expected_transition_sha256=None, now=NOW)


def test_unsigned_metadata_or_signed_byte_mutation_is_rejected() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    store = adapter(client, Decoder(first))
    store.install(first, expected_transition_sha256=None, now=NOW)
    assert client.item is not None
    client.item["transition_version"] = {"N": "99"}

    with pytest.raises(RecoveryAnchorRejected, match="record_invalid"):
        store.read(identity.key)


def test_ambiguous_write_never_reports_success_and_is_resolved_by_strong_read() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    store = adapter(client, Decoder(first))
    client.fail_after_put = True

    with pytest.raises(RecoveryAnchorRejected, match="unavailable"):
        store.install(first, expected_transition_sha256=None, now=NOW)

    client.fail_after_put = False
    assert store.read(identity.key) == first


def test_caller_object_must_match_verified_signed_bytes() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    forged = VerifiedAnchorTransition(
        witness=first.witness,
        transition_version=first.transition_version,
        previous_transition_sha256=None,
        continuity="recovery_pending",
        beacon=None,
        exact_jws=first.exact_jws,
    )

    with pytest.raises(RecoveryAnchorRejected, match="signed_bytes_mismatch"):
        adapter(FakeDynamoDb(), Decoder(first)).install(
            forged, expected_transition_sha256=None, now=NOW
        )


def test_startup_requires_aws_but_running_outage_uses_only_unexpired_cached_authority() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    store = adapter(client, Decoder(first))
    gate = RecoveryAnchorRuntimeGate(store, identity)

    client.failure = EndpointConnectionError(endpoint_url="https://dynamodb.invalid")
    with pytest.raises(RecoveryAnchorRejected, match="unavailable"):
        gate.start()

    client.failure = None
    store.install(first, expected_transition_sha256=None, now=NOW)
    gate.start()
    client.failure = EndpointConnectionError(endpoint_url="https://dynamodb.invalid")
    assert gate.refresh() is False
    observed = PostgresContinuityBeacon("system-1", 1, "0/02", "a" * 64)
    assert gate.require_dispatch_authority(observed_beacon=observed, now=NOW) == first.witness
    with pytest.raises(RecoveryAnchorRejected, match="dispatch_not_authorized"):
        gate.require_dispatch_authority(
            observed_beacon=observed, now=NOW + timedelta(hours=2)
        )


def test_known_quarantine_immediately_replaces_cached_dispatch_authority() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    quarantined_witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=2,
        witness_revision=1,
        status="quarantined",
        checkpoint_digest="c" * 64,
        release_heads_sha256="e" * 64,
        checkpoint_settlement_position_sha256="f" * 64,
        witness_inventory_digest="d" * 64,
        exact_jws=b"witness-quarantined",
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
    )
    quarantined = VerifiedAnchorTransition(
        witness=quarantined_witness,
        transition_version=2,
        previous_transition_sha256=first.exact_sha256,
        continuity="quarantined",
        beacon=None,
        exact_jws=b"transition-quarantined",
    )
    client = FakeDynamoDb()
    store = adapter(client, Decoder(first, quarantined))
    store.install(first, expected_transition_sha256=None, now=NOW)
    gate = RecoveryAnchorRuntimeGate(store, identity)
    gate.start()
    store.install(quarantined, expected_transition_sha256=first.exact_sha256, now=NOW)

    assert gate.refresh() is True
    with pytest.raises(RecoveryAnchorRejected, match="continuity_not_established"):
        gate.require_dispatch_authority(
            observed_beacon=PostgresContinuityBeacon("system-1", 1, "0/02", "a" * 64),
            now=NOW,
        )


def test_environment_factory_uses_sdk_machine_identity_without_credential_settings() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = make_transition(identity)
    client = FakeDynamoDb()
    calls: list[tuple[str, str]] = []

    def client_factory(service: str, *, region_name: str) -> FakeDynamoDb:
        calls.append((service, region_name))
        return client

    store = dynamodb_recovery_anchor_from_environment(
        Decoder(first),
        environment={
            "TIAMAT_RECOVERY_ANCHOR_TABLE": "stoin-staging-tiamat-recovery-anchor-v1",
            "AWS_REGION": "us-east-1",
        },
        client_factory=client_factory,
    )

    assert calls == [("dynamodb", "us-east-1")]
    store.install(first, expected_transition_sha256=None, now=NOW)


@pytest.mark.parametrize(
    "environment",
    [
        {"AWS_REGION": "us-east-1"},
        {"TIAMAT_RECOVERY_ANCHOR_TABLE": "valid-table"},
        {
            "TIAMAT_RECOVERY_ANCHOR_TABLE": "bad/table",
            "AWS_REGION": "us-east-1",
        },
        {
            "TIAMAT_RECOVERY_ANCHOR_TABLE": "valid-table",
            "AWS_REGION": "not-a-region",
        },
    ],
)
def test_environment_factory_rejects_missing_or_invalid_deployment_binding(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        dynamodb_recovery_anchor_from_environment(Decoder(), environment=environment)
