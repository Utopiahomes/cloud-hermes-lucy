from uuid import uuid4

import pytest
from fastapi import HTTPException

import lucy.api as api
from lucy.api import app
from lucy.proposals import MemoryProposalInput


def test_adapter_surface_has_no_approval_or_apply_route() -> None:
    exposed = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if route.path.startswith("/v1/")
    }
    assert exposed == {
        ("POST", "/v1/evidence/retrieve"),
        ("GET", "/v1/memory/lookup"),
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
        ("GET", "/internal/v1/conversations/capture-mode"),
        ("POST", "/internal/v1/conversations/capture-mode"),
        ("POST", "/internal/v1/conversations/forget-last"),
        ("POST", "/internal/v1/conversations/messages"),
        ("POST", "/internal/v1/model-executions/begin"),
        ("POST", "/internal/v1/model-executions/settle"),
    }


def test_memory_proposal_maps_missing_evidence_to_controlled_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "test-token")
    monkeypatch.setattr(api, "_ready_sessions", lambda: object())

    def missing(*_args: object, **_kwargs: object) -> None:
        raise LookupError("internal detail must not escape")

    monkeypatch.setattr(api.MemoryProposalService, "submit", missing)
    candidate = MemoryProposalInput(
        evidence_id=uuid4(),
        subject="Lucy",
        predicate="likes",
        object="tea",
        confidence=0.9,
    )
    with pytest.raises(HTTPException) as caught:
        api.propose_memory(candidate, "Bearer test-token", "proposal-key")
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
