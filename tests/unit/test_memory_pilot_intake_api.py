from __future__ import annotations

import base64

from fastapi.testclient import TestClient
from test_memory_pilot_transport import NOW, _authorization

from lucy.memory_pilot_intake_api import (
    MemoryPilotIntakeConfigurationV1,
    create_memory_pilot_intake_app,
)
from lucy.memory_pilot_transport import (
    MemoryPilotTransportAdmissionReceiptV1,
    prepare_memory_pilot_transport,
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


def test_exact_batch_admits_synchronously_and_replays() -> None:
    admission = _Admission()
    client = TestClient(create_memory_pilot_intake_app(admission))  # type: ignore[arg-type]
    batch_id, body = _request()
    token = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    first = client.post(
        f"/v1/private-memory/pilot/batches/{batch_id}",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    replay = client.post(
        f"/v1/private-memory/pilot/batches/{batch_id}",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert first.status_code == 200 and first.json()["replayed"] is False
    assert replay.status_code == 200 and replay.json()["replayed"] is True


def test_missing_capability_wrong_path_and_oversized_body_fail_closed() -> None:
    admission = _Admission()
    client = TestClient(create_memory_pilot_intake_app(admission))  # type: ignore[arg-type]
    batch_id, body = _request()
    token = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    assert client.post(f"/v1/private-memory/pilot/batches/{batch_id}", json=body).status_code == 401
    wrong = "00000000-0000-4000-8000-000000000001"
    assert client.post(
        f"/v1/private-memory/pilot/batches/{wrong}",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 403
    limited = TestClient(
        create_memory_pilot_intake_app(
            admission,  # type: ignore[arg-type]
            configuration=MemoryPilotIntakeConfigurationV1(maximum_request_bytes=200),
        )
    )
    assert limited.post(
        f"/v1/private-memory/pilot/batches/{batch_id}",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 413
    assert admission.calls == 0
