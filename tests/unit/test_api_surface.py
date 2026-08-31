from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import lucy.api as api
from lucy.api import app
from lucy.authorization import GatewaySensitiveActionPermitRequest, SensitiveAction
from lucy.proposals import GatewayMemoryProposalInput, MemoryProposalInput


def test_adapter_surface_has_no_approval_or_apply_route() -> None:
    exposed = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if route.path.startswith("/v1/")
    }
    assert exposed == {
        ("POST", "/v1/evidence/retrieve"),
        ("POST", "/v1/memory/lookup"),
        ("POST", "/v1/memory/proposals"),
    }


def test_internal_surface_only_exposes_model_budget_bridge() -> None:
    exposed = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if route.path.startswith("/internal/")
    }
    assert exposed == {
        ("POST", "/internal/v1/conversations/accept-turn"),
        ("GET", "/internal/v1/conversations/capture-mode"),
        ("GET", "/internal/v1/conversations/latest-retained-evidence"),
        ("POST", "/internal/v1/conversations/capture-mode"),
        ("POST", "/internal/v1/conversations/forget-last"),
        ("POST", "/internal/v1/conversations/messages"),
        ("POST", "/internal/v1/model-executions/begin"),
        ("POST", "/internal/v1/model-executions/settle"),
        ("POST", "/internal/v1/sensitive-action-permits"),
    }


def test_memory_proposal_maps_missing_evidence_to_controlled_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "test-token")
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true")
    monkeypatch.setattr(api, "_ready_sessions", lambda: object())

    def missing(*_args: object, **_kwargs: object) -> None:
        raise LookupError("internal detail must not escape")

    monkeypatch.setattr(api.MemoryProposalService, "submit", missing)
    candidate = GatewayMemoryProposalInput(
        source_conversation_id="synthetic-session", source_turn_id="synthetic-turn",
        evidence_id=uuid4(),
        subject="Lucy",
        predicate="likes",
        object="tea",
        confidence=0.9,
    )
    with pytest.raises(HTTPException) as caught:
        api.propose_memory(candidate, "Bearer test-token", f"hermes-memory-proposal:{uuid4()}")
    assert caught.value.status_code == 404
    assert caught.value.detail == "immutable evidence does not exist"


def test_memory_proposal_rejects_blank_idempotency_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "test-token")
    candidate = MemoryProposalInput(
        evidence_id=uuid4(),
        subject="Lucy",
        predicate="likes",
        object="tea",
        confidence=0.9,
    )
    with pytest.raises(HTTPException) as caught:
        api.propose_memory(candidate, "Bearer test-token", "   ")
    assert caught.value.status_code == 400


@pytest.mark.parametrize("enabled", [None, "", "false", "True", "1"])
def test_capture_gate_rejects_missing_or_nonexact_activation(
    monkeypatch: pytest.MonkeyPatch, enabled: str | None,
) -> None:
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "test-token")
    if enabled is None:
        monkeypatch.delenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", raising=False)
    else:
        monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", enabled)
    monkeypatch.setattr(api, "_ready_sessions", lambda: pytest.fail("database not needed"))
    request = GatewayMemoryProposalInput(
        source_conversation_id="s", source_turn_id="t", evidence_id=uuid4(),
        subject="owner", predicate="likes", object="tea", confidence=0.9,
    )
    with pytest.raises(HTTPException) as caught:
        api.propose_memory(request, "Bearer test-token", f"hermes-memory-proposal:{uuid4()}")
    assert caught.value.status_code == 403


def test_gateway_bearer_cannot_mint_owner_evidence_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SERVICE_MODE", "policy")
    monkeypatch.setenv("LUCY_POLICY_GATEWAY_TOKEN", "gateway-only")
    monkeypatch.setattr(api, "_ready_sessions", lambda: pytest.fail("must not issue permit"))
    request = GatewaySensitiveActionPermitRequest(
        action=SensitiveAction.EVIDENCE_RETRIEVE, platform="telegram",
        source_conversation_id="fabricated", source_turn_id="fabricated",
        evidence_ids=(uuid4(),), reason="resolve_ambiguity",
    )
    with pytest.raises(HTTPException) as caught:
        api.issue_gateway_sensitive_action_permit(request, "Bearer gateway-only", "fake:permit")
    assert caught.value.status_code == 403
    assert caught.value.detail == "verified owner interaction required"


def test_empty_adapter_token_does_not_authorize_empty_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "")
    with pytest.raises(HTTPException) as caught:
        api._authorize("Bearer ")
    assert caught.value.status_code == 401


def test_recall_text_is_sent_in_body_not_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "test-token")
    monkeypatch.setenv("LUCY_SERVICE_MODE", "routine")
    monkeypatch.setattr(api, "_ready_sessions", lambda: object())
    monkeypatch.setattr(api.MemoryService, "build_context", lambda *_: type(
        "Projection", (), {"claims": []},
    )())
    client = TestClient(app)
    response = client.post("/v1/memory/lookup", json={"query": "synthetic private query"},
                           headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    assert str(response.request.url).endswith("/v1/memory/lookup")
    assert client.get("/v1/memory/lookup").status_code == 405
