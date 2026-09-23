from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

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
        ("POST", "/v1/memory/interpreted-lookup"),
        ("POST", "/v1/memory/proposals"),
    }


def test_internal_surface_is_an_exact_reviewed_allowlist() -> None:
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
        ("POST", "/internal/v1/conversations/capture-mode-and-accept"),
        ("POST", "/internal/v1/conversations/forget-last"),
        ("POST", "/internal/v1/conversations/messages"),
        ("POST", "/internal/v1/model-executions/begin"),
        ("POST", "/internal/v1/model-executions/settle"),
        ("POST", "/internal/v1/memory/interpreted-context"),
        ("POST", "/internal/v1/telegram-stage1/events/claim"),
        ("POST", "/internal/v1/telegram-stage1/events/transition"),
        ("POST", "/internal/v1/telegram-stage1/lease/acquire"),
        ("POST", "/internal/v1/telegram-stage1/lease/heartbeat"),
        ("POST", "/internal/v1/telegram-stage1/lease/release"),
        ("POST", "/internal/v1/sensitive-action-permits"),
        ("POST", "/internal/v2/evidence/{operation_id}/delivery"),
        ("POST", "/internal/v2/security/deletion-manifests"),
        ("POST", "/internal/v2/security/operations/{operation_id}/grant"),
        (
            "POST",
            "/internal/v2/security/operations/{operation_id}/receipt-attestation",
        ),
            ("POST", "/internal/v3/security/operations/{operation_id}/grant"),
            ("POST", "/internal/v3/security/operations/{operation_id}/grant-v2"),
            ("POST", "/internal/v3/security/memory-outcomes/recovery-grant"),
        (
            "POST",
            "/internal/v3/security/operations/{operation_id}/deletion-manifest",
        ),
        (
            "POST",
            "/internal/v3/security/operations/{operation_id}/deletion-manifest-v2",
        ),
        (
            "POST",
            "/internal/v3/security/operations/{operation_id}/receipt-attestation",
        ),
        (
            "POST",
            "/internal/v3/security/operations/{operation_id}/receipt-attestation-v2",
        ),
    }


def test_r1_owner_surface_is_exact_and_deferred_r2_r3_routes_are_absent() -> None:
    paths = {route.path for route in app.routes}
    assert {path for path in paths if path.startswith("/owner/")} == {
        "/owner/v1/evidence/retrieve",
        "/owner/v1/evidence/{evidence_id}/delete",
        "/owner/v1/sensitive-action-permits",
        "/owner/v2/evidence/retrieve",
        "/owner/v2/evidence/{evidence_id}/delete",
        "/owner/v2/security/permits",
        "/owner/v3/evidence/retrieve",
        "/owner/v3/evidence/{evidence_id}/delete",
    }
    deferred_route_fragments = {
        "/jobs",
        "/wallets",
        "/credits",
        "/consulting",
        "/grants",
        "/runners",
        "/exports",
        "/rehost",
        "/transfer",
        "/stoinnet",
    }
    assert not {
        path
        for path in paths
        if any(fragment in path.lower() for fragment in deferred_route_fragments)
    }


def test_archive_service_selects_v13_realm_runtime_only_for_exact_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = object()
    monkeypatch.setenv("LUCY_ARCHIVE_BACKEND", "aws-kms-dynamodb-v13")
    monkeypatch.setattr(api, "realm_conversation_archive_from_environment", lambda: marker)
    api._archive_service.cache_clear()
    try:
        assert api._archive_service() is marker
        assert api._archive_service() is marker
        assert api._archive_service.cache_info().misses == 1
    finally:
        api._archive_service.cache_clear()


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


def test_production_v12_hides_superseded_sensitive_v1_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SECURITY_ENVIRONMENT", "production")
    with pytest.raises(HTTPException) as caught:
        api._require_legacy_sensitive_api_allowed()
    assert caught.value.status_code == 404


def test_v13_hides_all_v12_sensitive_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SECURITY_ENVIRONMENT", "development")
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")

    with pytest.raises(HTTPException) as legacy:
        api._require_legacy_sensitive_api_allowed()
    with pytest.raises(HTTPException) as v12:
        api._require_v12_sensitive_api()

    assert legacy.value.status_code == 404
    assert v12.value.status_code == 404


def test_v13_grant_route_is_hidden_from_v12_and_uses_policy_identity_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation_id = uuid4()
    monkeypatch.setenv("LUCY_SERVICE_MODE", "policy")
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.2")
    with pytest.raises(HTTPException) as hidden:
        api.grant_sensitive_operation_v3(operation_id, "Bearer policy-token")
    assert hidden.value.status_code == 404

    marker = object()

    class Grants:
        def issue_grant(self, candidate: object) -> object:
            assert candidate == operation_id
            return marker

    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")
    monkeypatch.setenv("LUCY_POLICY_GATEWAY_TOKEN", "policy-token")
    monkeypatch.setattr(
        api, "_realm_policy_services", lambda: (Grants(), object(), object())
    )
    assert api.grant_sensitive_operation_v3(operation_id, "Bearer policy-token") is marker


def test_memory_outcome_grant_route_is_v13_policy_only_and_gateway_authenticated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = type(
        "Request",
        (),
        {"authorization": object(), "package": object()},
    )()
    monkeypatch.setenv("LUCY_SERVICE_MODE", "policy")
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.2")
    with pytest.raises(HTTPException) as hidden:
        api.grant_memory_outcome_recovery_v1(
            request, "Bearer policy-token"  # type: ignore[arg-type]
        )
    assert hidden.value.status_code == 404

    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")
    monkeypatch.setenv("LUCY_POLICY_GATEWAY_TOKEN", "policy-token")
    with pytest.raises(HTTPException) as unauthorized:
        api.grant_memory_outcome_recovery_v1(request, "Bearer wrong")  # type: ignore[arg-type]
    assert unauthorized.value.status_code == 401

    marker = object()

    class Issuer:
        def issue(self, **values: object) -> object:
            assert values["authorization"] is request.authorization
            assert values["package"] is request.package
            assert values["now"] is not None
            return marker

    monkeypatch.setattr(api, "_memory_outcome_grant_issuer", lambda: Issuer())
    assert (
        api.grant_memory_outcome_recovery_v1(
            request, "Bearer policy-token"  # type: ignore[arg-type]
        )
        is marker
    )


def test_v13_receipt_route_rejects_path_body_identity_mismatch_before_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SERVICE_MODE", "policy")
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")
    monkeypatch.setenv("LUCY_POLICY_GATEWAY_TOKEN", "policy-token")
    monkeypatch.setattr(
        api,
        "_realm_policy_services",
        lambda: pytest.fail("mismatched receipt must not reach policy"),
    )
    receipt = type("Receipt", (), {"operation_id": uuid4()})()
    with pytest.raises(HTTPException) as caught:
        api.attest_executor_receipt_v3(
            uuid4(), receipt, "Bearer policy-token"  # type: ignore[arg-type]
        )
    assert caught.value.status_code == 400


def test_v13_deletion_route_rejects_path_permit_mismatch_before_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SERVICE_MODE", "deletion")
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")
    monkeypatch.setenv("LUCY_OWNER_TOKEN", "owner-token")
    monkeypatch.setattr(
        api,
        "_ready_sessions",
        lambda: pytest.fail("mismatched evidence must not reach workflow storage"),
    )
    permit = type(
        "Permit",
        (),
        {"resource_selector": type("Selector", (), {"object_id": uuid4()})()},
    )()
    request = type("Request", (), {"permit": permit})()
    with pytest.raises(HTTPException) as caught:
        api.owner_delete_evidence_v3(
            uuid4(),
            request,  # type: ignore[arg-type]
            "Bearer owner-token",
            "delete-once",
        )
    assert caught.value.status_code == 400


def test_policy_storage_failure_logging_uses_only_an_allowlisted_code() -> None:
    class Diagnostic:
        message_primary = "authorization environment or epoch mismatch"

    class Original:
        diag = Diagnostic()

    error = SQLAlchemyError()
    error.orig = Original()  # type: ignore[attr-defined]
    assert api._policy_permit_storage_failure_code(error) == "authorization_epoch_mismatch"

    Diagnostic.message_primary = "synthetic detail that must not enter logs"
    assert api._policy_permit_storage_failure_code(error) == "unclassified_database_error"


def test_policy_value_failure_logging_uses_only_an_allowlisted_code() -> None:
    assert (
        api._policy_permit_value_failure_code(
            ValueError("security workflow function returned no result")
        )
        == "permit_store_no_result"
    )
    assert (
        api._policy_permit_value_failure_code(
            ValueError("synthetic detail that must not enter logs")
        )
        == "unclassified_value_error"
    )


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
