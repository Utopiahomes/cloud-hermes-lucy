from __future__ import annotations

from uuid import UUID

import pytest
from fastapi import HTTPException

from lucy import api
from lucy import interpreted_recall_http as recall_http
from lucy.interpreted_recall_http import (
    InterpretedPolicyLookupV1,
    InterpretedPolicyResultV1,
    InterpretedRecallUnavailable,
)


def test_raymond_policy_route_requires_mode_flag_identity_and_gateway_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = InterpretedPolicyLookupV1(
        query="past plan", owner_interaction_ref=UUID("00000000-0000-4000-8000-000000000001")
    )
    monkeypatch.setenv("LUCY_SERVICE_MODE", "policy")
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_EXPECTED_DATABASE_LOGIN", "lucy_raymond_policy")
    monkeypatch.setenv("LUCY_POLICY_GATEWAY_TOKEN", "raymond-gateway-test")
    monkeypatch.delenv("LUCY_PERSONAL_INTERPRETED_RECALL_ENABLED", raising=False)
    monkeypatch.setattr(api, "_ready_sessions", lambda: pytest.fail("database not needed"))
    with pytest.raises(HTTPException) as disabled:
        api.policy_interpreted_memory_context(request, "Bearer raymond-gateway-test")
    assert disabled.value.status_code == 404
    monkeypatch.setenv("LUCY_PERSONAL_INTERPRETED_RECALL_ENABLED", "true")
    with pytest.raises(HTTPException) as wrong_token:
        api.policy_interpreted_memory_context(request, "Bearer wrong")
    assert wrong_token.value.status_code == 401
    monkeypatch.setenv("LUCY_EXPECTED_DATABASE_LOGIN", "lucy_utopia_policy")
    with pytest.raises(HTTPException) as wrong_realm:
        api.policy_interpreted_memory_context(request, "Bearer raymond-gateway-test")
    assert wrong_realm.value.status_code == 404


def test_raymond_policy_route_uses_protected_recall_with_audited_owner_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = InterpretedPolicyLookupV1(
        query="past plan", owner_interaction_ref=UUID("00000000-0000-4000-8000-000000000001")
    )
    monkeypatch.setenv("LUCY_SERVICE_MODE", "policy")
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_EXPECTED_DATABASE_LOGIN", "lucy_raymond_policy")
    monkeypatch.setenv("LUCY_POLICY_GATEWAY_TOKEN", "raymond-gateway-test")
    monkeypatch.setenv("LUCY_PERSONAL_INTERPRETED_RECALL_ENABLED", "true")
    monkeypatch.setattr(api, "_ready_sessions", lambda: object())
    monkeypatch.setattr(api, "GovernedMemoryPolicy", lambda sessions: object())

    def recall(policy: object, query: str, **kwargs: object) -> tuple[()]:
        assert query == request.query
        assert kwargs["owner_interaction_ref"] == request.owner_interaction_ref
        assert kwargs["reason_code"] == "raymond_telegram_owner_interpreted_recall"
        assert kwargs["campaign_id"] == api.RAYMOND_INTERPRETED_CAMPAIGN_ID
        return ()

    monkeypatch.setattr(api, "recall_interpreted_answer_context", recall)
    result = api.policy_interpreted_memory_context(request, "Bearer raymond-gateway-test")
    assert result == InterpretedPolicyResultV1(contexts=(), read_only=True)


def test_raymond_routine_route_requires_adapter_and_relays_private_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = api.RaymondInterpretedLookupInput(
        query="past plan", source_conversation_id="telegram:owner", source_turn_id="turn-1"
    )
    monkeypatch.setenv("LUCY_SERVICE_MODE", "routine")
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_EXPECTED_DATABASE_LOGIN", "lucy_raymond_routine")
    monkeypatch.setenv("LUCY_PERSONAL_INTERPRETED_RECALL_ENABLED", "true")
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "raymond-adapter-test")
    monkeypatch.setenv("LUCY_POLICY_HOSTPORT", "raymond-lucy-policy:10000")
    monkeypatch.setenv("LUCY_POLICY_GATEWAY_TOKEN", "raymond-gateway-test")
    with pytest.raises(HTTPException) as denied:
        api.raymond_interpreted_memory_lookup(request, "Bearer wrong")
    assert denied.value.status_code == 401

    class Client:
        def __init__(self, hostport: str, token: str) -> None:
            assert hostport == "raymond-lucy-policy:10000"
            assert token == "raymond-gateway-test"

        def lookup(self, value: InterpretedPolicyLookupV1) -> InterpretedPolicyResultV1:
            assert value.query == "past plan"
            assert value.owner_interaction_ref.version == 5
            return InterpretedPolicyResultV1(contexts=(), read_only=True)

    monkeypatch.setattr(api, "HttpInterpretedRecallClient", Client)
    assert api.raymond_interpreted_memory_lookup(request, "Bearer raymond-adapter-test") == {
        "query": "past plan", "contexts": [], "read_only": True
    }


@pytest.mark.parametrize(
    ("status", "payload"),
    [(403, b"{}"), (200, b'{"contexts":[],"read_only":false}'), (200, b"not-json")],
)
def test_private_client_rejects_policy_denial_or_invalid_response(
    monkeypatch: pytest.MonkeyPatch, status: int, payload: bytes,
) -> None:
    class Connection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            assert (host, port, timeout) == ("raymond-policy", 10000, 10)

        def request(self, method: str, path: str, **kwargs: object) -> None:
            assert (method, path) == ("POST", "/internal/v1/memory/interpreted-context")

        def getresponse(self) -> object:
            class Response:
                def __init__(self) -> None:
                    self.status = status

                def read(self, limit: int) -> bytes:
                    assert limit == 131_073
                    return payload

            return Response()

        def close(self) -> None:
            pass

    monkeypatch.setattr(recall_http.http.client, "HTTPConnection", Connection)
    client = recall_http.HttpInterpretedRecallClient("raymond-policy:10000", "private-token")
    with pytest.raises(InterpretedRecallUnavailable):
        client.lookup(InterpretedPolicyLookupV1(
            query="plan", owner_interaction_ref=UUID("00000000-0000-4000-8000-000000000001")
        ))
