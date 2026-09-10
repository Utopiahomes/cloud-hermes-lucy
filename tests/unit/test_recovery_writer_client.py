from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

import lucy.recovery_writer_client as writer_module
from lucy.cost_admission import ProviderAttemptAdmissionV1, ProviderAttemptRequestV1
from lucy.recovery_journal import RecoveryJournalError, RecoveryStreamKind
from lucy.recovery_writer_client import HttpRecoveryJournalWriterClient


class FakeHttpResponse:
    def __init__(self, body: dict[str, object], status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(body).encode()

    def read(self, _maximum: int) -> bytes:
        return self._body


class FakeHttpConnection:
    response: FakeHttpResponse
    request_values: tuple[tuple[object, ...], dict[str, object]] | None = None

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        assert (host, port, timeout) == ("lucy-cost-writer", 8080, 15)

    def request(self, *values: object, **kwargs: object) -> None:
        type(self).request_values = values, kwargs

    def getresponse(self) -> FakeHttpResponse:
        return type(self).response

    def close(self) -> None:
        pass


def _admission(state: str) -> ProviderAttemptAdmissionV1:
    return ProviderAttemptAdmissionV1.model_validate(
        {
            "attempt_id": uuid4(),
            "policy_id": uuid4(),
            "policy_version": 1,
            "state": state,
            "reserved_microusd": 100,
            "unresolved_microusd": 100,
            "event_id": uuid4(),
            "replayed": False,
        }
    )


def _attempt(admission: ProviderAttemptAdmissionV1) -> ProviderAttemptRequestV1:
    return ProviderAttemptRequestV1(
        attempt_id=admission.attempt_id,
        idempotency_key=f"public:{admission.attempt_id}",
        node_id=uuid4(),
        channel_binding_id=uuid4(),
        provider="openrouter",
        model="synthetic/model",
        rate_version="synthetic-v1",
        request_commitment="a" * 64,
        session_commitment="b" * 64,
        ip_commitment="c" * 64,
        maximum_microusd=100,
        input_tokens=10,
        output_tokens=10,
        request_bytes=100,
        timeout_seconds=10,
        requested_at=datetime.now(UTC),
    )


def test_client_sends_only_event_identifier_and_validates_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = uuid4()
    FakeHttpConnection.response = FakeHttpResponse(
        {
            "event_id": str(event_id),
            "stream_kind": "cost",
            "sequence": 3,
            "event_digest": "d" * 64,
        }
    )
    monkeypatch.setattr(writer_module.http.client, "HTTPConnection", FakeHttpConnection)
    client = HttpRecoveryJournalWriterClient(
        RecoveryStreamKind.COST, "lucy-cost-writer:8080", "cost-only"
    )
    result = client.append_pending(event_id)
    assert result.event_digest == "d" * 64
    assert FakeHttpConnection.request_values is not None
    values, kwargs = FakeHttpConnection.request_values
    assert values == ("POST", f"/v1/recovery/events/{event_id}")
    assert kwargs["body"] == b""
    assert kwargs["headers"] == {
        "Authorization": "Bearer cost-only",
        "Content-Length": "0",
    }

    FakeHttpConnection.response = FakeHttpResponse(
        {
            "event_id": str(event_id),
            "stream_kind": "authority",
            "sequence": 3,
            "event_digest": "d" * 64,
        }
    )
    with pytest.raises(RecoveryJournalError, match="response differs"):
        client.append_pending(event_id)


def test_cost_gateway_validates_workflow_before_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = _admission("PERSISTENCE_PENDING")
    FakeHttpConnection.response = FakeHttpResponse(
        {
            "event_id": str(admission.event_id),
            "stream_kind": "cost",
            "sequence": 1,
            "event_digest": "e" * 64,
        }
    )
    monkeypatch.setattr(writer_module.http.client, "HTTPConnection", FakeHttpConnection)
    client = HttpRecoveryJournalWriterClient(
        RecoveryStreamKind.COST, "lucy-cost-writer:8080", "cost-only"
    )
    assert client.append_reservation(admission) == "e" * 64
    with pytest.raises(RecoveryJournalError, match="not pending"):
        client.append_reservation(admission.model_copy(update={"state": "ADMITTED"}))

    settlement = admission.model_copy(update={"state": "SETTLEMENT_PENDING"})
    assert (
        client.append_outcome(
            attempt=_attempt(settlement),
            admission=settlement,
            incurred_microusd=50,
            provider_reference_commitment="f" * 64,
        )
        == "e" * 64
    )
