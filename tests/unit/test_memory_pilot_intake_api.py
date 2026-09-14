from __future__ import annotations

import base64

from fastapi.testclient import TestClient
from test_memory_pilot_transport import NOW, _authorization

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_pilot_intake_api import (
    MemoryPilotIntakeConfigurationV1,
    create_memory_pilot_execution_app,
    create_memory_pilot_intake_app,
)
from lucy.memory_pilot_transport import (
    MemoryPilotTransportAdmissionReceiptV1,
    MemoryPilotTransportBatchV1,
    prepare_memory_pilot_transport,
)
from lucy.memory_pilot_transport_runner import (
    MemoryPilotTransportExecutionReceiptV1,
    MemoryPilotTransportExecutionResult,
)


class _Admission:
    def __init__(self) -> None:
        self.calls = 0

    def admit(self, batch: object, *, capability_token: bytes) -> object:
        self.calls += 1
        assert capability_token == b"c" * 32
        return MemoryPilotTransportAdmissionReceiptV1(
            batch_id=batch.batch_id,  # type: ignore[attr-defined]
            admitted_at=NOW,
            replayed=self.calls > 1,
        )


class _Executor:
    def execute(self, batch: object, *, capability_token: bytes) -> object:
        assert capability_token == b"c" * 32
        return MemoryPilotTransportExecutionResult(
            MemoryPilotTransportExecutionReceiptV1(
                campaign_id=batch.campaign_id,  # type: ignore[attr-defined]
                batch_id=batch.batch_id,  # type: ignore[attr-defined]
                extraction_job_id=batch.dispatch.extraction_job_id,  # type: ignore[attr-defined]
                reservation_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                state="succeeded",
                archived_source_count=len(batch.records),  # type: ignore[attr-defined]
                billed_microusd=0,
                candidate_count=0,
            ),
            None,
        )


def _request() -> tuple[str, dict[str, object]]:
    build, authorization = _authorization()
    prepared = prepare_memory_pilot_transport(
        build,
        authorization,
        expected_bundle_digest=authorization.bundle_digest,
        transfer_key=b"t" * 32,
        capability_token=b"c" * 32,
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
        expires_at=NOW.replace(hour=1),
        now=NOW,
    )
    batch = prepared.batches[0]
    return str(batch.batch_id), batch.model_dump(mode="json")


def _post(client: TestClient, path: str, body: dict[str, object], token: str):
    batch = MemoryPilotTransportBatchV1.model_validate(body)
    return client.post(
        path,
        content=canonical_json_bytes(batch),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )


def test_exact_batch_admits_synchronously_and_replays() -> None:
    admission = _Admission()
    client = TestClient(create_memory_pilot_intake_app(admission))  # type: ignore[arg-type]
    batch_id, body = _request()
    token = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    first = _post(client, f"/v1/private-memory/pilot/batches/{batch_id}", body, token)
    replay = _post(client, f"/v1/private-memory/pilot/batches/{batch_id}", body, token)
    assert first.status_code == 200 and first.json()["replayed"] is False
    assert replay.status_code == 200 and replay.json()["replayed"] is True


def test_missing_capability_wrong_path_and_oversized_body_fail_closed() -> None:
    admission = _Admission()
    client = TestClient(create_memory_pilot_intake_app(admission))  # type: ignore[arg-type]
    batch_id, body = _request()
    token = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    assert client.post(f"/v1/private-memory/pilot/batches/{batch_id}", json=body).status_code == 401
    wrong = "00000000-0000-4000-8000-000000000001"
    assert (
        _post(client, f"/v1/private-memory/pilot/batches/{wrong}", body, token).status_code == 403
    )
    limited = TestClient(
        create_memory_pilot_intake_app(
            admission,  # type: ignore[arg-type]
            configuration=MemoryPilotIntakeConfigurationV1(maximum_request_bytes=200),
        )
    )
    assert (
        _post(limited, f"/v1/private-memory/pilot/batches/{batch_id}", body, token).status_code
        == 413
    )
    assert admission.calls == 0


def test_execution_intake_returns_no_store_content_free_status() -> None:
    client = TestClient(create_memory_pilot_execution_app(_Executor()))  # type: ignore[arg-type]
    batch_id, body = _request()
    token = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    response = _post(client, f"/v1/private-memory/pilot/batches/{batch_id}", body, token)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["receipt"]["state"] == "succeeded"
    assert response.json()["review_artifact"] is None
    assert "private synthetic history" not in response.text


def test_wire_body_headers_and_errors_are_fail_closed_and_no_store() -> None:
    admission = _Admission()
    client = TestClient(create_memory_pilot_intake_app(admission))  # type: ignore[arg-type]
    batch_id, body = _request()
    token = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    noncanonical = client.post(
        f"/v1/private-memory/pilot/batches/{batch_id}", json=body, headers=headers
    )
    compressed = client.post(
        f"/v1/private-memory/pilot/batches/{batch_id}",
        content=canonical_json_bytes(MemoryPilotTransportBatchV1.model_validate(body)),
        headers={**headers, "Content-Encoding": "gzip"},
    )
    wrong_type = client.post(
        f"/v1/private-memory/pilot/batches/{batch_id}",
        content=canonical_json_bytes(MemoryPilotTransportBatchV1.model_validate(body)),
        headers={**headers, "Content-Type": "text/plain"},
    )

    assert noncanonical.status_code == 403
    assert compressed.status_code == 415
    assert wrong_type.status_code == 415
    assert all(
        response.headers["cache-control"] == "no-store"
        for response in (noncanonical, compressed, wrong_type)
    )
    assert client.get("/health").json() == {"status": "ok"}
    assert admission.calls == 0


def test_private_executor_requires_gateway_and_separate_campaign_capability() -> None:
    client = TestClient(
        create_memory_pilot_execution_app(
            _Executor(),  # type: ignore[arg-type]
            configuration=MemoryPilotIntakeConfigurationV1(
                gateway_bearer_token="g" * 32
            ),
        )
    )
    batch_id, body = _request()
    batch = MemoryPilotTransportBatchV1.model_validate(body)
    capability = "Bearer " + base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    path = f"/v1/private-memory/pilot/batches/{batch_id}"
    headers = {"Content-Type": "application/json"}

    assert client.post(
        path,
        content=canonical_json_bytes(batch),
        headers={**headers, "Authorization": capability},
    ).status_code == 401
    accepted = client.post(
        path,
        content=canonical_json_bytes(batch),
        headers={
            **headers,
            "Authorization": "Bearer " + "g" * 32,
            "X-Lucy-Pilot-Capability": capability,
        },
    )
    assert accepted.status_code == 200
