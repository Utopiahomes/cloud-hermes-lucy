from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

import lucy.recovery_acknowledgement as acknowledgement_module
from lucy.authority_recovery import (
    AuthorityTransitionResultV1,
    PendingAuthorityEventV1,
)
from lucy.cost_admission import ProviderAttemptAdmissionV1
from lucy.cost_recovery import PendingCostEventV1
from lucy.recovery_acknowledgement import (
    AuthorityAcknowledgementReceiver,
    CostAcknowledgementReceiver,
    HttpRecoveryAcknowledgementClient,
)
from lucy.recovery_journal import (
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryJournalHeadV1,
    RecoveryStreamKind,
)


class FakeHttpResponse:
    def __init__(self, body: dict[str, object], status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(body).encode("utf-8")

    def read(self, _maximum: int) -> bytes:
        return self._body


class FakeHttpConnection:
    response: FakeHttpResponse
    request_values: tuple[tuple[object, ...], dict[str, object]] | None = None

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        assert (host, port, timeout) == ("lucy-recovery", 8080, 15)

    def request(self, *values: object, **kwargs: object) -> None:
        type(self).request_values = values, kwargs

    def getresponse(self) -> FakeHttpResponse:
        return type(self).response

    def close(self) -> None:
        pass


class FakeJournal:
    def __init__(self, acknowledgement: RecoveryAppendAcknowledgementV1 | None) -> None:
        self.acknowledgement = acknowledgement

    def exact_acknowledgement(
        self, event_id: UUID
    ) -> RecoveryAppendAcknowledgementV1 | None:
        if self.acknowledgement is not None:
            assert event_id == self.acknowledgement.event_id
        return self.acknowledgement


class FakeAuthorityStore:
    def __init__(self, pending: PendingAuthorityEventV1) -> None:
        self.value = pending
        self.received: dict[str, object] | None = None

    def pending(self, event_id: UUID) -> PendingAuthorityEventV1:
        assert event_id == self.value.event_id
        return self.value

    def acknowledge(self, **kwargs: object) -> AuthorityTransitionResultV1:
        self.received = kwargs
        return AuthorityTransitionResultV1(
            **self.value.model_dump(
                exclude={
                    "idempotency_key",
                    "occurred_at",
                    "source_authority_ref",
                    "source_authority_digest",
                }
            ),
            state="DURABLY_RECORDED",
            journal_head_digest=str(kwargs["journal_head_digest"]),
            replayed=False,
        )


class FakeCostStore:
    def __init__(self, pending: PendingCostEventV1) -> None:
        self.value = pending
        self.route: str | None = None

    def pending(self, event_id: UUID) -> PendingCostEventV1:
        assert event_id == self.value.event_id
        return self.value

    def acknowledge(self, **kwargs: object) -> ProviderAttemptAdmissionV1:
        self.route = "reservation"
        return self._result(kwargs)

    def acknowledge_outcome(self, **kwargs: object) -> ProviderAttemptAdmissionV1:
        self.route = "outcome"
        return self._result(kwargs)

    def _result(self, values: dict[str, object]) -> ProviderAttemptAdmissionV1:
        assert values["event_id"] == self.value.event_id
        return ProviderAttemptAdmissionV1(
            attempt_id=self.value.attempt_id,
            policy_id=self.value.policy_id,
            policy_version=self.value.policy_version,
            state="ADMITTED" if self.value.event_type == "reservation" else "SETTLED",
            reserved_microusd=self.value.maximum_microusd,
            unresolved_microusd=(
                self.value.maximum_microusd if self.value.event_type == "reservation" else 0
            ),
            event_id=self.value.event_id,
            replayed=False,
        )


def test_authority_receiver_requires_and_reconciles_exact_durable_ack() -> None:
    pending = _authority_pending()
    acknowledgement = _ack(
        pending.event_id, RecoveryStreamKind.AUTHORITY, stream_id=pending.stream_id
    )
    store = FakeAuthorityStore(pending)
    result = AuthorityAcknowledgementReceiver(store, FakeJournal(acknowledgement)).receive(
        pending.event_id
    )
    assert result.state == "DURABLY_RECORDED"
    assert store.received == {
        "event_id": pending.event_id,
        "journal_sequence": 1,
        "journal_event_digest": "b" * 64,
        "journal_head_digest": "b" * 64,
    }


@pytest.mark.parametrize(
    "event_type,route", [("reservation", "reservation"), ("settlement", "outcome")]
)
def test_cost_receiver_selects_only_the_prepared_event_route(
    event_type: str, route: str
) -> None:
    pending = _cost_pending(event_type)
    store = FakeCostStore(pending)
    result = CostAcknowledgementReceiver(
        store, FakeJournal(_ack(pending.event_id, RecoveryStreamKind.COST))
    ).receive(pending.event_id)
    assert result.event_id == pending.event_id
    assert store.route == route


def test_receiver_rejects_missing_wrong_kind_or_substituted_digest() -> None:
    pending = _authority_pending()
    store = FakeAuthorityStore(pending)
    with pytest.raises(RecoveryJournalError, match="unavailable"):
        AuthorityAcknowledgementReceiver(store, FakeJournal(None)).receive(pending.event_id)
    for acknowledgement in (
        _ack(pending.event_id, RecoveryStreamKind.COST),
        _ack(
            pending.event_id,
            RecoveryStreamKind.AUTHORITY,
            digest="c" * 64,
            stream_id=pending.stream_id,
        ),
    ):
        with pytest.raises(RecoveryJournalError, match="unavailable"):
            AuthorityAcknowledgementReceiver(store, FakeJournal(acknowledgement)).receive(
                pending.event_id
            )
    assert store.received is None


def test_http_client_sends_only_empty_path_request_and_validates_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = uuid4()
    FakeHttpConnection.response = FakeHttpResponse(
        {"event_id": str(event_id), "stream_kind": "cost", "state": "ADMITTED"}
    )
    monkeypatch.setattr(
        acknowledgement_module.http.client, "HTTPConnection", FakeHttpConnection
    )
    client = HttpRecoveryAcknowledgementClient("lucy-recovery:8080", "synthetic")
    result = client.acknowledge(
        attempt_id=uuid4(), event_id=event_id, head_digest="a" * 64
    )
    assert result.state == "ADMITTED"
    assert FakeHttpConnection.request_values is not None
    values, kwargs = FakeHttpConnection.request_values
    assert values == (
        "POST",
        f"/v1/recovery/cost/acknowledgements/{event_id}",
    )
    assert kwargs["body"] == b""
    assert kwargs["headers"] == {
        "Authorization": "Bearer synthetic",
        "Content-Length": "0",
    }


def test_http_client_rejects_substituted_or_wrong_state_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = uuid4()
    monkeypatch.setattr(
        acknowledgement_module.http.client, "HTTPConnection", FakeHttpConnection
    )
    client = HttpRecoveryAcknowledgementClient("lucy-recovery:8080", "synthetic")
    FakeHttpConnection.response = FakeHttpResponse(
        {"event_id": str(uuid4()), "stream_kind": "cost", "state": "ADMITTED"}
    )
    with pytest.raises(RecoveryJournalError, match="differs"):
        client.acknowledge(
            attempt_id=uuid4(), event_id=event_id, head_digest="a" * 64
        )
    FakeHttpConnection.response = FakeHttpResponse(
        {"event_id": str(event_id), "stream_kind": "cost", "state": "SETTLED"}
    )
    with pytest.raises(RecoveryJournalError, match="reservation.*incomplete"):
        client.acknowledge(
            attempt_id=uuid4(), event_id=event_id, head_digest="a" * 64
        )


def _authority_pending() -> PendingAuthorityEventV1:
    return PendingAuthorityEventV1(
        event_id=uuid4(),
        idempotency_key=f"authority:{uuid4()}",
        stream_id=uuid4(),
        authority_epoch=1,
        event_type="membership_revoked",
        security_realm_id=uuid4(),
        workspace_id=uuid4(),
        subject_id=uuid4(),
        previous_generation=1,
        new_generation=2,
        source_authority_ref=f"owner:{uuid4()}",
        source_authority_digest="a" * 64,
        transition_digest="d" * 64,
        occurred_at=datetime.now(UTC),
        journal_sequence=1,
        journal_previous_digest="0" * 64,
        journal_event_digest="b" * 64,
    )


def _cost_pending(event_type: str) -> PendingCostEventV1:
    outcome = event_type != "reservation"
    return PendingCostEventV1.model_validate(
        {
            "event_id": uuid4(),
            "attempt_id": uuid4(),
            "idempotency_key": f"cost:{uuid4()}",
            "event_type": event_type,
            "node_id": uuid4(),
            "channel_binding_id": uuid4(),
            "policy_id": uuid4(),
            "policy_version": 1,
            "rate_version": "synthetic-v1",
            "accounting_period": datetime.now(UTC),
            "maximum_microusd": 5_000,
            "incurred_microusd": 2_000 if outcome else 0,
            "unresolved_microusd": 0 if outcome else 5_000,
            "request_commitment": "e" * 64,
            "provider_reference_commitment": "f" * 64 if outcome else None,
            "source_authority_ref": f"policy:{uuid4()}",
            "source_authority_digest": "a" * 64,
            "occurred_at": datetime.now(UTC),
            "journal_sequence": 1,
            "journal_previous_digest": "0" * 64,
            "journal_event_digest": "b" * 64,
        }
    )


def _ack(
    event_id: UUID,
    kind: RecoveryStreamKind,
    *,
    digest: str = "b" * 64,
    stream_id: UUID | None = None,
) -> RecoveryAppendAcknowledgementV1:
    return RecoveryAppendAcknowledgementV1(
        event_id=event_id,
        event_digest=digest,
        resulting_head=RecoveryJournalHeadV1(
            stream_kind=kind,
            stream_id=stream_id or uuid4(),
            authority_epoch=1,
            independent_store_id="arn:aws:dynamodb:us-east-1:429870640638:table/synthetic",
            binding_manifest_digest="9" * 64,
            sequence=1,
            event_digest=digest,
        ),
        acknowledged_at=datetime.now(UTC),
    )
