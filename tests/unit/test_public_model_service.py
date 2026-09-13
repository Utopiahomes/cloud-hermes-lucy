from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from lucy.public_contracts import PublicKnowledgeEntry, PublicRetrievalResult
from lucy.public_model_service import (
    HttpPublicModelClient,
    PublicModelServiceHandler,
    PublicModelServiceRequest,
    PublicModelServiceResponse,
    PublicModelServiceUnavailable,
)
from lucy.publication import knowledge_snapshot, snapshot_digest

REQUEST_ID = UUID("24512180-a368-4ad0-a167-44082ae66c66")


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


def _request(*, digest: str | None = None) -> PublicModelServiceRequest:
    entry = _entry()
    actual = snapshot_digest(knowledge_snapshot([entry.model_dump(mode="json")]))
    return PublicModelServiceRequest(
        contract="lucy.public-model-request.v1",
        request_id=REQUEST_ID,
        snapshot_digest=digest or actual,
        session_commitment="a" * 64,
        ip_commitment="b" * 64,
        question="What is Utopia?",
        entries=(entry,),
        page_context=None,
        history=(),
    )


def _answer() -> PublicRetrievalResult:
    return PublicRetrievalResult(
        outcome="answered",
        answer="Utopia Homes creates distinctive group stays.",
    )


def test_handler_revalidates_digest_before_model_execution() -> None:
    request = _request()
    calls: list[str] = []

    def engine_factory(_request: PublicModelServiceRequest):
        calls.append("factory")
        return SimpleNamespace(
            answer=lambda **_kwargs: SimpleNamespace(answer=_answer())
        )

    handler = PublicModelServiceHandler((request.snapshot_digest,), engine_factory)
    response = handler.answer(request)

    assert response.request_id == REQUEST_ID
    assert response.answer.answer.startswith("Utopia Homes")
    assert calls == ["factory"]

    with pytest.raises(PublicModelServiceUnavailable, match="snapshot"):
        PublicModelServiceHandler(("c" * 64,), engine_factory).answer(request)
    assert calls == ["factory"]


class FakeHttpResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, _: int) -> bytes:
        return self._body


class FakeHttpConnection:
    response: FakeHttpResponse
    observed: dict[str, object] = {}

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        self.observed.update(host=host, port=port, timeout=timeout)

    def request(self, method: str, path: str, **kwargs: object) -> None:
        self.observed.update(method=method, path=path, **kwargs)

    def getresponse(self) -> FakeHttpResponse:
        return self.response

    def close(self) -> None:
        self.observed["closed"] = True


def test_http_client_binds_private_response_without_exposing_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    response = PublicModelServiceResponse(
        contract="lucy.public-model-response.v1",
        request_id=request.request_id,
        snapshot_digest=request.snapshot_digest,
        answer=_answer(),
    )
    FakeHttpConnection.response = FakeHttpResponse(200, response.model_dump_json().encode())
    FakeHttpConnection.observed = {}
    monkeypatch.setattr(
        "lucy.public_model_service.http.client.HTTPConnection", FakeHttpConnection
    )

    result = HttpPublicModelClient("lucy-public-model:10000", "k" * 32).answer(request)

    assert result == response
    assert FakeHttpConnection.observed["path"] == "/v1/public-model/answer"
    headers = FakeHttpConnection.observed["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == f"Bearer {'k' * 32}"
    sent = json.loads(FakeHttpConnection.observed["body"])
    assert sent["session_commitment"] == "a" * 64
    assert "203.0.113" not in str(sent)


def test_http_client_rejects_wrong_binding_and_never_returns_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    wrong = PublicModelServiceResponse(
        contract="lucy.public-model-response.v1",
        request_id=UUID("f5050bb0-766e-48d9-bf7b-2986e2e1443f"),
        snapshot_digest=request.snapshot_digest,
        answer=_answer(),
    )
    FakeHttpConnection.observed = {}
    FakeHttpConnection.response = FakeHttpResponse(200, wrong.model_dump_json().encode())
    monkeypatch.setattr(
        "lucy.public_model_service.http.client.HTTPConnection", FakeHttpConnection
    )
    with pytest.raises(PublicModelServiceUnavailable, match="binding") as error:
        HttpPublicModelClient("lucy-public-model:10000", "k" * 32).answer(request)
    assert "distinctive" not in str(error.value)

    FakeHttpConnection.response = FakeHttpResponse(503, b'{"detail":"secret"}')
    with pytest.raises(PublicModelServiceUnavailable, match="rejected") as error:
        HttpPublicModelClient("lucy-public-model:10000", "k" * 32).answer(request)
    assert "secret" not in str(error.value)
