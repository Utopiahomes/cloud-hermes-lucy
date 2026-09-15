from __future__ import annotations

import base64
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

import lucy.public_api as api
from lucy.public_contracts import PublicKnowledgeEntry, PublicReference
from lucy.public_model_service import (
    PublicModelCallDiagnostic,
    PublicModelDiagnostic,
    PublicModelServiceResponse,
)
from lucy.publication import PublicAnswer, PublicKnowledgeProjection
from lucy.readiness import ReadinessError
from lucy.tenancy import ScopeNotFound

SESSION = "1db886ff-7d89-4aa7-b9a1-083a98b80702"
EPOCH = "4f1d7615-6d73-4dc8-9d87-e17113e0a56c"
DIGEST = "6" * 64
TOKEN = "public-api-test-token-that-is-long-enough"


def _environment() -> dict[str, str]:
    return {
        "LUCY_DATABASE_URL": (
            "postgresql://lucy_utopia_public:synthetic@dpg-example-a/lucy_example"
        ),
        "LUCY_EXPECTED_DATABASE_LOGIN": "lucy_utopia_public",
        "LUCY_PUBLIC_API_TOKEN": TOKEN,
        "LUCY_PUBLIC_ALLOWED_ORIGIN": "https://www.utopiahomes.com",
        "LUCY_PUBLIC_SITE_HOSTNAME": "www.utopiahomes.com",
        "LUCY_PUBLIC_SNAPSHOT_DIGEST": DIGEST,
        "LUCY_STORAGE_EPOCH": EPOCH,
        "LUCY_PUBLIC_MAX_REQUEST_BYTES": "8192",
        "LUCY_PUBLIC_REQUESTS_PER_IP_PER_MINUTE": "20",
        "LUCY_PUBLIC_REQUESTS_PER_SESSION_PER_MINUTE": "30",
        "LUCY_PUBLIC_SESSION_TTL_SECONDS": "3600",
    }


def _headers(**changes: str) -> dict[str, str]:
    values = {
        "Authorization": f"Bearer {TOKEN}",
        "Origin": "https://www.utopiahomes.com",
        "X-Lucy-Public-Host": "www.utopiahomes.com",
        "X-Lucy-Public-Session": SESSION,
    }
    values.update(changes)
    return values


@pytest.fixture(autouse=True)
def reset_api(monkeypatch: pytest.MonkeyPatch) -> None:
    cached_reader = api._reader
    cached_model_client = api._model_client
    for key, value in _environment().items():
        monkeypatch.setenv(key, value)
    api._configuration.cache_clear()
    api._reader.cache_clear()
    cached_model_client.cache_clear()
    api._diagnostic_store.cache_clear()
    monkeypatch.setattr(api, "_limiter", api._OpaqueRateLimiter(commitment_key=b"k" * 32))
    monkeypatch.setattr(api, "_exercise_limiter", api._ExerciseLimiter())
    yield
    api._configuration.cache_clear()
    cached_reader.cache_clear()
    cached_model_client.cache_clear()
    api._diagnostic_store.cache_clear()


def test_public_api_exposes_only_health_and_exact_answer_route() -> None:
    surface = {
        (method, route.path) for route in api.app.routes for method in (route.methods or set())
    }
    assert surface == {
        ("GET", "/health"),
        ("GET", "/v1/operations/public-diagnostic/{trace_id}"),
        ("POST", "/v1/public/answer"),
    }


def test_configuration_binds_exact_public_login_origin_hostname_and_epoch() -> None:
    config = api.PublicApiConfiguration.from_environment(_environment())
    assert config.site_hostname == "www.utopiahomes.com"
    assert config.storage_epoch == UUID(EPOCH)

    for key in (
        "LUCY_DATABASE_URL",
        "LUCY_PUBLIC_API_TOKEN",
        "LUCY_PUBLIC_SNAPSHOT_DIGEST",
        "LUCY_STORAGE_EPOCH",
    ):
        candidate = _environment()
        candidate[key] = ""
        with pytest.raises(api.PublicApiConfigurationError):
            api.PublicApiConfiguration.from_environment(candidate)

    candidate = _environment()
    candidate["LUCY_EXPECTED_DATABASE_LOGIN"] = "lucy_utopia_routine"
    with pytest.raises(api.PublicApiConfigurationError, match="identity"):
        api.PublicApiConfiguration.from_environment(candidate)
    candidate = {**_environment(), "LUCY_ENVIRONMENT": "production"}
    candidate["LUCY_DATABASE_URL"] = (
        "postgresql://lucy_utopia_public:synthetic@public.example/lucy_example"
    )
    with pytest.raises(api.PublicApiConfigurationError, match="boundary"):
        api.PublicApiConfiguration.from_environment(candidate)


def test_answer_requires_bearer_origin_hostname_and_canonical_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = SimpleNamespace(answer_admitted=lambda **_kwargs: pytest.fail("reader called"))
    monkeypatch.setattr(api, "_reader", lambda: reader)
    client = TestClient(api.app)

    assert client.post("/v1/public/answer", json={"question": "Question"}).status_code == 401
    assert (
        client.post(
            "/v1/public/answer",
            json={"question": "Question"},
            headers=_headers(Origin="https://foreign.example"),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/public/answer",
            json={"question": "Question"},
            headers=_headers(**{"X-Lucy-Public-Host": "foreign.example"}),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/public/answer",
            json={"question": "Question"},
            headers=_headers(**{"X-Lucy-Public-Session": "not-a-uuid"}),
        ).status_code
        == 400
    )


def test_conversational_answer_uses_temporary_history_after_public_scope_is_established(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_PUBLIC_CONVERSATION_ENABLED", "true")
    api._configuration.cache_clear()
    source = PublicReference(
        id="buttercup-source",
        label="Buttercup Beauty",
        href="https://www.utopiahomes.com/stays/buttercup-beauty",
    )
    projection = PublicKnowledgeProjection(
        entries=(
            PublicKnowledgeEntry.model_validate(
                {
                    "id": "buttercup-parking",
                    "service_line": "homes",
                    "kind": "fact",
                    "title": "Buttercup parking",
                    "approved_text": (
                        "Buttercup Beauty’s published parking guidance allows four cars."
                    ),
                    "aliases": ["cars", "driveway"],
                    "topics": ["parking"],
                        "route": "property",
                        "property_slug": "buttercup-beauty",
                        "property_facts": {
                            "max_guests": 22,
                            "parking_spaces": 4,
                            "has_pool": True,
                            "has_hot_tub": True,
                            "bedrooms": 7,
                            "bathrooms": 3.5,
                            "pets_allowed": True,
                        },
                        "source": source,
                    "links": [],
                    "effective_from": "2026-01-01T00:00:00Z",
                    "effective_until": None,
                    "direct_answer": True,
                }
            ),
        ),
        version=2,
        snapshot_digest=DIGEST,
    )
    calls: list[object] = []

    def knowledge_admitted(**kwargs: object) -> PublicKnowledgeProjection:
        calls.append(kwargs)
        return projection

    reader = SimpleNamespace(knowledge_admitted=knowledge_admitted)
    monkeypatch.setattr(api, "_reader", lambda: reader)
    client = TestClient(api.app)
    payload = {
        "question": "How many cars fit?",
        "page_context": {"route": "other_public"},
        "history": [
            {"role": "visitor", "content": "Tell me about Buttercup."},
            {"role": "lucy", "content": "Buttercup is in Wildwood Crest."},
        ],
    }

    denied = client.post("/v1/public/answer", json=payload)
    assert denied.status_code == 401
    assert calls == []

    response = client.post("/v1/public/answer", json=payload, headers=_headers())
    assert response.status_code == 200
    assert response.json() == {
        "contract": "lucy.public-answer.v2",
        "outcome": "answered",
        "answer": "Buttercup Beauty’s published parking guidance allows four cars.",
        "sources": [source.model_dump(mode="json")],
        "links": [],
        "version": 2,
        "snapshot_digest": DIGEST,
    }
    assert len(calls) == 1


def test_model_route_receives_only_approved_projection_and_keyed_commitments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_PUBLIC_CONVERSATION_ENABLED", "true")
    monkeypatch.setenv("LUCY_PUBLIC_MODEL_ENABLED", "true")
    monkeypatch.setenv("LUCY_PUBLIC_MODEL_HOSTPORT", "lucy-public-model:10000")
    monkeypatch.setenv("LUCY_PUBLIC_MODEL_TOKEN", "model-service-token-that-is-long-enough")
    monkeypatch.setenv(
        "LUCY_PUBLIC_COST_COMMITMENT_KEY_B64",
        base64.b64encode(b"m" * 32).decode(),
    )
    api._configuration.cache_clear()
    source = PublicReference(
        id="buttercup-source",
        label="Buttercup Beauty",
        href="https://www.utopiahomes.com/stays/buttercup-beauty",
    )
    entry = PublicKnowledgeEntry.model_validate(
        {
            "id": "buttercup-parking",
            "service_line": "homes",
            "kind": "fact",
            "title": "Buttercup parking",
            "approved_text": "Buttercup Beauty has parking for 4 cars.",
            "aliases": [],
            "topics": ["parking"],
            "route": "property",
            "property_slug": "buttercup-beauty",
            "property_facts": {
                "max_guests": 22,
                "parking_spaces": 4,
                "has_pool": True,
                "has_hot_tub": True,
                "bedrooms": 7,
                "bathrooms": 3.5,
                "pets_allowed": True,
            },
            "source": source,
            "links": [],
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "direct_answer": True,
        }
    )
    projection = PublicKnowledgeProjection(
        entries=(entry,), version=2, snapshot_digest=DIGEST
    )
    monkeypatch.setattr(
        api,
        "_reader",
        lambda: SimpleNamespace(knowledge_admitted=lambda **_kwargs: projection),
    )
    requests: list[object] = []

    def model_answer(request):
        requests.append(request)
        return PublicModelServiceResponse(
            contract="lucy.public-model-response.v1",
            request_id=request.request_id,
            snapshot_digest=request.snapshot_digest,
            answer={
                "outcome": "answered",
                "answer": "Buttercup Beauty has parking for 4 cars.",
                "sources": [source.model_dump(mode="json")],
                "evidence_ids": ["buttercup-parking"],
            },
        )

    monkeypatch.setattr(
        api, "_model_client", lambda: SimpleNamespace(answer=model_answer)
    )
    response = TestClient(api.app).post(
        "/v1/public/answer",
        json={"question": "How many cars fit?"},
        headers=_headers(),
    )

    assert response.status_code == 200
    assert response.json()["answer"] == "Buttercup Beauty has parking for 4 cars."
    sent = requests[0]
    assert sent.entries == (entry,)
    assert sent.snapshot_digest == DIGEST
    assert sent.session_commitment != SESSION
    assert sent.ip_commitment != "testclient"
    assert len(sent.session_commitment) == len(sent.ip_commitment) == 64


def test_diagnostic_trace_is_header_visible_and_operator_receipt_is_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostic_token = "diagnostic-operator-token-that-is-long-enough"
    for key, value in {
        "LUCY_PUBLIC_CONVERSATION_ENABLED": "true",
        "LUCY_PUBLIC_MODEL_ENABLED": "true",
        "LUCY_PUBLIC_MODEL_HOSTPORT": "lucy-public-model-staging:10000",
        "LUCY_PUBLIC_MODEL_TOKEN": "model-service-token-that-is-long-enough",
        "LUCY_PUBLIC_COST_COMMITMENT_KEY_B64": base64.b64encode(b"m" * 32).decode(),
        "LUCY_PUBLIC_DIAGNOSTICS_ENABLED": "true",
        "LUCY_PUBLIC_DIAGNOSTIC_TOKEN": diagnostic_token,
        "LUCY_PUBLIC_RELEASE_ID": "c" * 40,
        "LUCY_PUBLIC_DEPLOYMENT_TIER": "staging",
        "LUCY_PUBLIC_EXERCISE_MODE": "true",
        "LUCY_PUBLIC_EXERCISE_CONCURRENCY_LIMIT": "2",
        "LUCY_PUBLIC_EXERCISE_SESSION_REQUEST_LIMIT": "20",
        "LUCY_PUBLIC_EXERCISE_TOTAL_REQUEST_LIMIT": "40",
    }.items():
        monkeypatch.setenv(key, value)
    api._configuration.cache_clear()
    api._diagnostic_store.cache_clear()
    source = PublicReference(
        id="about-source",
        label="About Utopia Homes",
        href="https://www.utopiahomes.com/about",
    )
    entry = PublicKnowledgeEntry.model_validate(
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
            "source": source,
            "links": [],
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "direct_answer": True,
        }
    )
    projection = PublicKnowledgeProjection(
        entries=(entry,), version=2, snapshot_digest=DIGEST
    )
    monkeypatch.setattr(
        api,
        "_reader",
        lambda: SimpleNamespace(knowledge_admitted=lambda **_kwargs: projection),
    )

    def model_answer(request):
        calls = tuple(
            PublicModelCallDiagnostic(
                purpose=purpose,
                attempt_id=UUID(
                    "24512180-a368-4ad0-a167-44082ae66c66"
                    if purpose == "answer"
                    else "f5050bb0-766e-48d9-bf7b-2986e2e1443f"
                ),
                configured_model="google/gemini-3.1-flash-lite",
                observed_model="google/gemini-3.1-flash-lite",
                configured_providers=("Google",),
                observed_provider="Google-Vertex",
                rate_version="openrouter-2026-09-13",
                prompt_tokens=100,
                completion_tokens=20,
                maximum_microusd=30_000 if purpose == "answer" else 15_000,
                incurred_microusd=100 if purpose == "answer" else 50,
            )
            for purpose in ("answer", "verify")
        )
        return PublicModelServiceResponse(
            contract="lucy.public-model-response.v1",
            request_id=request.request_id,
            snapshot_digest=request.snapshot_digest,
            answer={
                "outcome": "answered",
                "answer": "Utopia Homes creates distinctive group stays.",
                "sources": [source.model_dump(mode="json")],
                "evidence_ids": ["about-utopia"],
            },
            diagnostic=PublicModelDiagnostic(
                contract="lucy.public-model-diagnostic.v1",
                request_id=request.request_id,
                model_release_id="d" * 40,
                answer_policy_digest="e" * 64,
                verifier_policy_digest="f" * 64,
                validation_outcome="supported",
                model_latency_ms=200,
                calls=calls,
            ),
        )

    monkeypatch.setattr(api, "_model_client", lambda: SimpleNamespace(answer=model_answer))
    client = TestClient(api.app)
    question = "What makes a Utopia stay different?"
    response = client.post(
        "/v1/public/answer", json={"question": question}, headers=_headers()
    )

    assert response.status_code == 200
    trace_id = response.headers["x-lucy-trace-id"]
    assert UUID(trace_id).version == 4
    assert response.headers["x-lucy-cloud-release"] == "c" * 40
    assert response.headers["x-lucy-snapshot-version"] == "2"
    assert response.headers["x-lucy-snapshot-digest"] == DIGEST
    assert client.get(f"/v1/operations/public-diagnostic/{trace_id}").status_code == 401

    receipt = client.get(
        f"/v1/operations/public-diagnostic/{trace_id}",
        headers={"Authorization": f"Bearer {diagnostic_token}"},
    )
    assert receipt.status_code == 200
    assert receipt.json()["model"]["validation_outcome"] == "supported"
    assert receipt.json()["model"]["calls"][0]["incurred_microusd"] == 100
    assert question not in receipt.text
    assert response.json()["answer"] not in receipt.text


def test_model_configuration_rejects_a_non_private_hostport_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment()
    environment.update(
        {
            "LUCY_PUBLIC_CONVERSATION_ENABLED": "true",
            "LUCY_PUBLIC_MODEL_ENABLED": "true",
            "LUCY_PUBLIC_MODEL_HOSTPORT": "https://lucy-public-model.example/path",
            "LUCY_PUBLIC_MODEL_TOKEN": "model-service-token-that-is-long-enough",
            "LUCY_PUBLIC_COST_COMMITMENT_KEY_B64": base64.b64encode(b"m" * 32).decode(),
        }
    )

    with pytest.raises(api.PublicApiConfigurationError, match="destination is invalid"):
        api.PublicApiConfiguration.from_environment(environment)


def test_answer_is_bounded_strict_and_uses_only_fixed_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def answer_admitted(**kwargs: object) -> PublicAnswer:
        calls.append(kwargs)
        return PublicAnswer(
            answer="Utopia creates distinctive group stays.",
            source="content://utopia/public/approved-v0",
            version=1,
            snapshot_digest=DIGEST,
        )

    monkeypatch.setattr(api, "_reader", lambda: SimpleNamespace(answer_admitted=answer_admitted))
    response = TestClient(api.app).post(
        "/v1/public/answer",
        json={"question": "  What   is Utopia?  "},
        headers=_headers(),
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "answer": "Utopia creates distinctive group stays.",
        "source": "content://utopia/public/approved-v0",
        "version": 1,
        "snapshot_digest": DIGEST,
    }
    assert calls == [
        {
            "hostname": "www.utopiahomes.com",
            "question": "What is Utopia?",
            "storage_epoch": UUID(EPOCH),
        }
    ]

    extra = TestClient(api.app).post(
        "/v1/public/answer",
        json={"question": "Question", "transcript": "forbidden"},
        headers=_headers(),
    )
    assert extra.status_code == 400


def test_snapshot_and_storage_failures_close_without_leaking_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(api.app)
    monkeypatch.setattr(
        api,
        "_reader",
        lambda: SimpleNamespace(
            answer_admitted=lambda **_kwargs: PublicAnswer("answer", "source", 2, "7" * 64)
        ),
    )
    assert (
        client.post(
            "/v1/public/answer", json={"question": "Question"}, headers=_headers()
        ).status_code
        == 503
    )

    def failing_reader(error: Exception) -> SimpleNamespace:
        def fail(**_kwargs: object) -> None:
            raise error

        return SimpleNamespace(answer_admitted=fail)

    for error, status in (
        (ScopeNotFound("missing"), 404),
        (ReadinessError("quarantined"), 503),
        (SQLAlchemyError("secret"), 503),
    ):
        reader = failing_reader(error)
        monkeypatch.setattr(api, "_reader", lambda reader=reader: reader)
        response = client.post(
            "/v1/public/answer", json={"question": "Question"}, headers=_headers()
        )
        assert response.status_code == status
        assert "secret" not in response.text


def test_limiter_retains_only_commitments_and_enforces_both_ceilings() -> None:
    now = [0.0]
    limiter = api._OpaqueRateLimiter(clock=lambda: now[0], commitment_key=b"z" * 32)
    config = api.PublicApiConfiguration.from_environment(
        {
            **_environment(),
            "LUCY_PUBLIC_REQUESTS_PER_IP_PER_MINUTE": "2",
            "LUCY_PUBLIC_REQUESTS_PER_SESSION_PER_MINUTE": "1",
        }
    )
    first = UUID(SESSION)
    second = UUID("f8092d4c-3514-428a-887f-73e5a6ad033b")
    assert limiter.allow("203.0.113.8", first, config)
    assert not limiter.allow("203.0.113.8", first, config)
    assert not limiter.allow("203.0.113.8", second, config)
    assert "203.0.113.8" not in repr(limiter._windows)
    assert SESSION not in repr(limiter._sessions)


def test_exercise_limiter_enforces_concurrency_session_and_total_bounds() -> None:
    now = [0.0]
    limiter = api._ExerciseLimiter(clock=lambda: now[0])
    config = api.PublicApiConfiguration.from_environment(
        {
            **_environment(),
            "LUCY_PUBLIC_CONVERSATION_ENABLED": "true",
            "LUCY_PUBLIC_MODEL_ENABLED": "true",
            "LUCY_PUBLIC_MODEL_HOSTPORT": "lucy-public-model-staging:10000",
            "LUCY_PUBLIC_MODEL_TOKEN": "model-service-token-that-is-long-enough",
            "LUCY_PUBLIC_COST_COMMITMENT_KEY_B64": base64.b64encode(b"m" * 32).decode(),
            "LUCY_PUBLIC_DIAGNOSTICS_ENABLED": "true",
            "LUCY_PUBLIC_DIAGNOSTIC_TOKEN": "diagnostic-token-that-is-long-enough",
            "LUCY_PUBLIC_RELEASE_ID": "c" * 40,
            "LUCY_PUBLIC_DEPLOYMENT_TIER": "staging",
            "LUCY_PUBLIC_EXERCISE_MODE": "true",
            "LUCY_PUBLIC_EXERCISE_CONCURRENCY_LIMIT": "2",
            "LUCY_PUBLIC_EXERCISE_SESSION_REQUEST_LIMIT": "2",
            "LUCY_PUBLIC_EXERCISE_TOTAL_REQUEST_LIMIT": "3",
        }
    )
    first = UUID(SESSION)
    second = UUID("f8092d4c-3514-428a-887f-73e5a6ad033b")

    assert limiter.acquire(first, config)
    assert limiter.acquire(second, config)
    assert not limiter.acquire(first, config)
    limiter.release()
    limiter.release()
    assert limiter.acquire(first, config)
    limiter.release()
    assert not limiter.acquire(second, config)


def test_declared_and_streamed_oversize_requests_are_rejected() -> None:
    client = TestClient(api.app)
    declared = client.post(
        "/v1/public/answer",
        content=b"{}",
        headers={**_headers(), "Content-Type": "application/json", "Content-Length": "9000"},
    )
    assert declared.status_code == 413
    streamed = client.post(
        "/v1/public/answer",
        content=b"x" * 9000,
        headers={**_headers(), "Content-Type": "application/json"},
    )
    assert streamed.status_code == 413
