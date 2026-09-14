from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import SecretStr

from lucy.internal_admission import InternalAdmissionDenied
from lucy.workspaces_admission import (
    WorkspacesRoomAdmissionReceiptV1,
    WorkspacesRoomAdmissionRequestV1,
)
from lucy.workspaces_admission_api import (
    WorkspacesAdmissionAPISettingsV1,
    create_workspaces_admission_app,
)

ZERO = UUID("00000000-0000-4000-8000-000000000000")
ONE = UUID("00000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 9, 12, 18, 0, tzinfo=UTC)
TOKEN = "private-workspaces-token-32-characters"


class SyntheticGateway:
    def __init__(self) -> None:
        self.received_credential: str | None = None
        self.deny = False
        self.executed_capabilities: list[str] = []

    def preflight(
        self,
        *,
        lucy_authority_credential: SecretStr,
        request: WorkspacesRoomAdmissionRequestV1,
        checked_at: datetime,
    ) -> WorkspacesRoomAdmissionReceiptV1:
        del checked_at
        self.received_credential = lucy_authority_credential.get_secret_value()
        if self.deny:
            raise InternalAdmissionDenied("sensitive detail")
        return WorkspacesRoomAdmissionReceiptV1(
            admission_id=ONE,
            request_id=request.request_id,
            room_id=request.room_id,
            authority_mode="approved_knowledge",
            authority_ref="utopia-sales-approved-v1",
            admitted_capabilities=request.requested_capabilities,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )

    def execute(self, **values: object):
        capability = values["capability"]
        effect = values["effect"]
        assert isinstance(capability, str)
        assert callable(effect)
        self.executed_capabilities.append(capability)
        return effect(object())


class SyntheticOperations:
    def query_knowledge(self, **values: object) -> tuple[str, str, int, str]:
        assert values["question"] == "What homes are available?"
        return ("Shamrock House is available.", "approved-faq", 3, "a" * 64)

    def delegate_task(self, **values: object) -> UUID:
        assert values["instruction"] == "Draft a viewing plan"
        assert values["room_id"] == ONE
        return UUID("00000000-0000-4000-8000-000000000003")


def _client(
    gateway: SyntheticGateway, operations: SyntheticOperations | None = None
) -> TestClient:
    return TestClient(
        create_workspaces_admission_app(
            settings=WorkspacesAdmissionAPISettingsV1(
                transport_token=TOKEN,
                lucy_authority_credential="server-held-identity-token",
            ),
            gateway=gateway,
            operations=operations,
        )
    )


def _request() -> dict[str, object]:
    return {
        "request_id": str(ZERO),
        "room_id": str(ONE),
        "requested_capabilities": ["memory.read", "task.delegate"],
    }


def test_private_api_uses_server_held_authority_credential() -> None:
    gateway = SyntheticGateway()
    response = _client(gateway).post(
        "/v1/workspaces/rooms/admit",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json=_request(),
    )

    assert response.status_code == 200
    assert gateway.received_credential == "server-held-identity-token"
    assert response.json()["authority_ref"] == "utopia-sales-approved-v1"
    assert response.json()["usable_as_bearer"] is False


def test_private_api_rejects_missing_transport_auth_before_admission() -> None:
    gateway = SyntheticGateway()
    response = _client(gateway).post(
        "/v1/workspaces/rooms/admit",
        content=b"this is deliberately not json",
    )

    assert response.status_code == 401
    assert gateway.received_credential is None


def test_private_api_rejects_credentials_and_authority_selectors_in_body() -> None:
    gateway = SyntheticGateway()
    response = _client(gateway).post(
        "/v1/workspaces/rooms/admit",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={**_request(), "credential": "attendee-token", "node_id": str(ONE)},
    )

    assert response.status_code == 422
    assert gateway.received_credential is None


def test_private_api_returns_content_free_denial() -> None:
    gateway = SyntheticGateway()
    gateway.deny = True
    response = _client(gateway).post(
        "/v1/workspaces/rooms/admit",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json=_request(),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "request not authorized"}


def test_private_api_exposes_only_health_and_admission() -> None:
    paths = {route.path for route in _client(SyntheticGateway()).app.routes}
    assert paths == {
        "/health",
        "/v1/workspaces/rooms/admit",
        "/v1/workspaces/rooms/{room_id}/knowledge/query",
        "/v1/workspaces/rooms/{room_id}/tasks",
    }


def test_operations_use_fresh_capability_admission() -> None:
    gateway = SyntheticGateway()
    client = _client(gateway, SyntheticOperations())
    headers = {"Authorization": f"Bearer {TOKEN}"}
    knowledge = client.post(
        f"/v1/workspaces/rooms/{ONE}/knowledge/query",
        headers=headers,
        json={"request_id": str(ZERO), "question": "What homes are available?"},
    )
    task = client.post(
        f"/v1/workspaces/rooms/{ONE}/tasks",
        headers=headers,
        json={"request_id": str(ZERO), "instruction": "Draft a viewing plan"},
    )

    assert knowledge.status_code == 200
    assert knowledge.json()["snapshot_digest"] == "a" * 64
    assert task.status_code == 202
    assert task.json()["status"] == "accepted"
    assert gateway.executed_capabilities == ["memory.read", "task.delegate"]
