from __future__ import annotations

import base64
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import lucy.public_model_api as api
from lucy.public_contracts import PublicKnowledgeEntry, PublicRetrievalResult
from lucy.public_model_service import (
    PublicModelServiceRequest,
    PublicModelServiceResponse,
    PublicModelServiceUnavailable,
)
from lucy.publication import knowledge_snapshot, snapshot_digest

TOKEN = "private-model-api-token-that-is-long-enough"
REQUEST_ID = UUID("24512180-a368-4ad0-a167-44082ae66c66")


def _environment() -> dict[str, str]:
    encoded = base64.b64encode(b"k" * 32).decode()
    return {
        "LUCY_ENVIRONMENT": "production",
        "LUCY_PUBLIC_MODEL_DATABASE_URL": (
            "postgresql://lucy_utopia_cost_admission:synthetic@dpg-example-a/lucy_example"
        ),
        "LUCY_PUBLIC_MODEL_EXPECTED_DATABASE_LOGIN": "lucy_utopia_cost_admission",
        "LUCY_PUBLIC_MODEL_TOKEN": TOKEN,
        "LUCY_PUBLIC_MODEL_ALLOWED_SNAPSHOT_DIGESTS": "a" * 64,
        "LUCY_PUBLIC_MODEL_NODE_ID": "eb181c78-1314-456b-b5c9-675495ddc896",
        "LUCY_PUBLIC_MODEL_CHANNEL_BINDING_ID": "be91f214-c314-4d05-88dc-3d541922f72f",
        "LUCY_PUBLIC_MODEL_ID": "google/gemini-3.1-flash-lite",
        "LUCY_PUBLIC_MODEL_ALLOWED_PROVIDERS": "Google",
        "LUCY_PUBLIC_MODEL_RATE_VERSION": "openrouter-2026-09-13",
        "OPENROUTER_API_KEY": "o" * 32,
        "LUCY_PUBLIC_MODEL_MAX_PROMPT_USD_PER_MILLION": "0.8",
        "LUCY_PUBLIC_MODEL_MAX_COMPLETION_USD_PER_MILLION": "4",
        "LUCY_PUBLIC_MODEL_GENERATOR_MAX_MICROUSD": "30000",
        "LUCY_PUBLIC_MODEL_VERIFIER_MAX_MICROUSD": "15000",
        "LUCY_PUBLIC_MODEL_GENERATOR_MAX_TOKENS": "700",
        "LUCY_PUBLIC_MODEL_VERIFIER_MAX_TOKENS": "300",
        "LUCY_PUBLIC_MODEL_TIMEOUT_SECONDS": "12",
        "LUCY_PUBLIC_MODEL_MAX_REQUEST_BYTES": "200000",
        "LUCY_PUBLIC_MODEL_REQUEST_COMMITMENT_KEY_B64": encoded,
        "LUCY_PUBLIC_MODEL_PROVIDER_REFERENCE_KEY_B64": encoded,
        "LUCY_COST_WRITER_HOSTPORT": "lucy-cost-writer:10000",
        "LUCY_COST_WRITER_TOKEN": "w" * 32,
        "LUCY_RECOVERY_ACK_HOSTPORT": "lucy-recovery-coordinator:10000",
        "LUCY_RECOVERY_ACK_TOKEN": "r" * 32,
    }


def _entry() -> PublicKnowledgeEntry:
    return PublicKnowledgeEntry.model_validate(
        {
            "id": "about-utopia",
            "service_line": "general",
            "kind": "description",
            "title": "About Utopia",
            "approved_text": "Utopia Homes creates distinctive group stays.",
            "aliases": [],
            "topics": ["about"],
            "route": "about",
            "property_slug": None,
            "property_facts": None,
            "source": {
                "id": "about-page",
                "label": "About Utopia Homes",
                "href": "https://www.utopiahomes.com/about",
            },
            "links": [],
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "direct_answer": True,
        }
    )


def _request() -> PublicModelServiceRequest:
    entry = _entry()
    digest = snapshot_digest(knowledge_snapshot([entry.model_dump(mode="json")]))
    return PublicModelServiceRequest(
        contract="lucy.public-model-request.v1",
        request_id=REQUEST_ID,
        snapshot_digest=digest,
        session_commitment="b" * 64,
        ip_commitment="c" * 64,
        question="What is Utopia?",
        entries=(entry,),
    )


@pytest.fixture(autouse=True)
def reset_dependencies() -> None:
    api._dependencies.cache_clear()
    yield
    api._dependencies.cache_clear()


def test_configuration_requires_exact_cost_identity_and_private_provider_pin() -> None:
    config = api.PublicModelApiConfiguration.from_environment(_environment())
    assert config.expected_database_login == "lucy_utopia_cost_admission"
    assert config.model == "google/gemini-3.1-flash-lite"
    assert config.allowed_providers == ("Google",)

    for key in (
        "LUCY_PUBLIC_MODEL_DATABASE_URL",
        "LUCY_PUBLIC_MODEL_TOKEN",
        "OPENROUTER_API_KEY",
        "LUCY_PUBLIC_MODEL_ALLOWED_PROVIDERS",
    ):
        values = {**_environment(), key: ""}
        with pytest.raises(api.PublicModelApiConfigurationError):
            api.PublicModelApiConfiguration.from_environment(values)

    wrong_login = {
        **_environment(),
        "LUCY_PUBLIC_MODEL_EXPECTED_DATABASE_LOGIN": "lucy_utopia_public",
    }
    with pytest.raises(api.PublicModelApiConfigurationError, match="identity"):
        api.PublicModelApiConfiguration.from_environment(wrong_login)

    generic_cost_role = {
        **_environment(),
        "LUCY_PUBLIC_MODEL_DATABASE_URL": (
            "postgresql://lucy_cost_admission:synthetic@dpg-example-a/lucy_example"
        ),
        "LUCY_PUBLIC_MODEL_EXPECTED_DATABASE_LOGIN": "lucy_cost_admission",
    }
    with pytest.raises(api.PublicModelApiConfigurationError, match="identity"):
        api.PublicModelApiConfiguration.from_environment(generic_cost_role)


def test_diagnostics_require_an_exact_model_release() -> None:
    enabled = {**_environment(), "LUCY_PUBLIC_DIAGNOSTICS_ENABLED": "true"}
    with pytest.raises(api.PublicModelApiConfigurationError, match="release"):
        api.PublicModelApiConfiguration.from_environment(enabled)

    config = api.PublicModelApiConfiguration.from_environment(
        {**enabled, "LUCY_PUBLIC_MODEL_RELEASE_ID": "d" * 40}
    )
    assert config.diagnostics_enabled is True
    assert config.release_id == "d" * 40


def test_private_api_authenticates_bounds_and_returns_no_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    answer = PublicRetrievalResult(outcome="answered", answer="Synthetic approved answer.")
    response = PublicModelServiceResponse(
        contract="lucy.public-model-response.v1",
        request_id=request.request_id,
        snapshot_digest=request.snapshot_digest,
        answer=answer,
    )
    calls: list[PublicModelServiceRequest] = []
    handler = SimpleNamespace(
        answer=lambda item: (calls.append(item), response)[1]
    )
    config = SimpleNamespace(api_token=TOKEN, maximum_request_bytes=200_000)
    monkeypatch.setattr(
        api,
        "_dependencies",
        lambda: SimpleNamespace(config=config, handler=handler),
    )
    client = TestClient(api.app)

    assert client.post("/v1/public-model/answer", json={}).status_code == 401
    success = client.post(
        "/v1/public-model/answer",
        content=request.model_dump_json(),
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
    )
    assert success.status_code == 200
    assert success.headers["cache-control"] == "no-store"
    assert success.json()["answer"]["answer"] == "Synthetic approved answer."
    assert calls == [request]


def test_private_api_conceals_handler_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _request()

    def fail(_request: PublicModelServiceRequest) -> None:
        raise PublicModelServiceUnavailable("sensitive upstream detail")

    config = SimpleNamespace(api_token=TOKEN, maximum_request_bytes=200_000)
    monkeypatch.setattr(
        api,
        "_dependencies",
        lambda: SimpleNamespace(
            config=config,
            handler=SimpleNamespace(answer=fail),
        ),
    )
    response = TestClient(api.app).post(
        "/v1/public-model/answer",
        content=request.model_dump_json(),
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 503
    assert "sensitive" not in response.text
