from __future__ import annotations

import base64
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from test_memory_pilot_intake_api import _request

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_pilot_intake_api import MemoryPilotExecutionResponseV1
from lucy.memory_pilot_proxy_api import (
    MemoryPilotProxyConfigurationV1,
    create_memory_pilot_proxy_app,
)
from lucy.memory_pilot_transport import MemoryPilotTransportBatchV1
from lucy.memory_pilot_transport_runner import MemoryPilotTransportExecutionReceiptV1


class _Transport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes, str, str, int]] = []

    def __call__(
        self,
        url: str,
        body: bytes,
        gateway_authorization: str,
        capability_authorization: str,
        timeout_seconds: int,
    ) -> bytes:
        self.calls.append(
            (url, body, gateway_authorization, capability_authorization, timeout_seconds)
        )
        batch = MemoryPilotTransportBatchV1.model_validate_json(body)
        return (
            MemoryPilotExecutionResponseV1(
                receipt=MemoryPilotTransportExecutionReceiptV1(
                    campaign_id=batch.campaign_id,
                    batch_id=batch.batch_id,
                    extraction_job_id=batch.dispatch.extraction_job_id,
                    reservation_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    state="succeeded",
                    archived_source_count=len(batch.records),
                    billed_microusd=0,
                    candidate_count=0,
                ),
                review_artifact=None,
            )
            .model_dump_json()
            .encode()
        )


def _configuration() -> MemoryPilotProxyConfigurationV1:
    return MemoryPilotProxyConfigurationV1(
        private_executor_hostport="raymond-lucy-evidence:10000",
        gateway_bearer_token="g" * 32,
    )


def test_proxy_forwards_exact_batch_over_fixed_private_binding() -> None:
    transport = _Transport()
    client = TestClient(create_memory_pilot_proxy_app(_configuration(), transport=transport))
    batch_id, body = _request()
    batch = MemoryPilotTransportBatchV1.model_validate(body)
    capability = "Bearer " + base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")

    response = client.post(
        f"/v1/private-memory/pilot/batches/{batch_id}",
        content=canonical_json_bytes(batch),
        headers={"Authorization": capability, "Content-Type": "application/json"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert transport.calls == [
        (
            f"http://raymond-lucy-evidence:10000/v1/private-memory/pilot/batches/{batch_id}",
            canonical_json_bytes(batch),
            "Bearer " + "g" * 32,
            capability,
            180,
        )
    ]


def test_proxy_rejects_noncanonical_or_wrong_response_identity() -> None:
    transport = _Transport()
    client = TestClient(create_memory_pilot_proxy_app(_configuration(), transport=transport))
    batch_id, body = _request()
    capability = "Bearer " + base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    noncanonical = client.post(
        f"/v1/private-memory/pilot/batches/{batch_id}",
        json=body,
        headers={"Authorization": capability},
    )
    assert noncanonical.status_code == 503
    assert noncanonical.headers["cache-control"] == "no-store"
    assert transport.calls == []


def test_proxy_configuration_rejects_non_private_host_binding() -> None:
    configuration = MemoryPilotProxyConfigurationV1(
        private_executor_hostport="https://example.com",
        gateway_bearer_token="g" * 32,
    )
    with pytest.raises(ValueError, match="host binding"):
        configuration.private_url(UUID("00000000-0000-4000-8000-000000000001"))
