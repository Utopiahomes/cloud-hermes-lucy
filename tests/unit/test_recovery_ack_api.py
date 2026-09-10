from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import lucy.recovery_ack_api as api
import lucy.recovery_ack_runtime as runtime
from lucy.recovery_acknowledgement import (
    AuthorityAcknowledgementReceiver,
    CostAcknowledgementReceiver,
)


class FakeJournal:
    def __init__(self) -> None:
        self.head_reads = 0

    def head(self) -> object:
        self.head_reads += 1
        return object()


def _dependencies() -> api.RecoveryAckDependencies:
    authority = AuthorityAcknowledgementReceiver(
        object(), object()  # type: ignore[arg-type]
    )
    cost = CostAcknowledgementReceiver(object(), object())  # type: ignore[arg-type]
    return api.RecoveryAckDependencies(
        authority=authority,
        cost=cost,
        authority_journal=FakeJournal(),  # type: ignore[arg-type]
        cost_journal=FakeJournal(),  # type: ignore[arg-type]
    )


def test_private_endpoint_accepts_only_bearer_and_path_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = uuid4()
    monkeypatch.setenv("LUCY_AUTHORITY_RECOVERY_ACK_TOKEN", "authority-only")
    monkeypatch.setenv("LUCY_COST_RECOVERY_ACK_TOKEN", "cost-only")
    monkeypatch.setattr(api, "_dependencies", _dependencies)
    monkeypatch.setattr(
        AuthorityAcknowledgementReceiver,
        "receive",
        lambda _self, received: SimpleNamespace(
            event_id=received, state="DURABLY_RECORDED"
        ),
    )
    client = TestClient(api.app)

    path = f"/v1/recovery/authority/acknowledgements/{event_id}"
    assert client.post(path).status_code == 401
    headers = {"Authorization": "Bearer authority-only"}
    prohibited = client.post(
        path,
        headers=headers,
        json={"head_digest": "caller-controlled"},
    )
    assert prohibited.status_code == 400
    accepted = client.post(path, headers=headers)
    assert accepted.status_code == 200
    assert accepted.json() == {
        "event_id": str(event_id),
        "stream_kind": "authority",
        "state": "DURABLY_RECORDED",
    }
    assert client.post(path, headers={"Authorization": "Bearer cost-only"}).status_code == 401


def test_ready_exact_reads_the_bound_journal(monkeypatch: pytest.MonkeyPatch) -> None:
    dependencies = _dependencies()
    monkeypatch.setattr(api, "_dependencies", lambda: dependencies)
    response = TestClient(api.app).get("/ready")
    assert response.status_code == 200
    assert dependencies.authority_journal.head_reads == 1  # type: ignore[attr-defined]
    assert dependencies.cost_journal.head_reads == 1  # type: ignore[attr-defined]


def test_runtime_requires_production_v13_capture_off_and_pinned_hermes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false")
    monkeypatch.setenv("LUCY_OBSERVED_HERMES_COMMIT", "a" * 40)
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    dependencies = _dependencies()
    monkeypatch.setattr(runtime, "_dependencies", lambda: dependencies)
    calls: list[str] = []
    monkeypatch.setattr(
        runtime.uvicorn, "run", lambda app, **_kwargs: calls.append(app.title)
    )
    runtime.main()
    assert calls == ["Lucy Recovery Acknowledgement API"]
    assert dependencies.authority_journal.head_reads == 1  # type: ignore[attr-defined]
    assert dependencies.cost_journal.head_reads == 1  # type: ignore[attr-defined]

    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true")
    with pytest.raises(SystemExit, match="startup gate failed"):
        runtime.main()
