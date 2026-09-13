from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any
from urllib.error import HTTPError
from uuid import UUID

import pytest

import lucy.memory_openrouter as memory_openrouter
from lucy.memory_extraction import MemoryExtractionDispatchV1, memory_extraction_job_id
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV2
from lucy.memory_openrouter import (
    MemoryOpenRouterUnavailable,
    OpenRouterMemoryPolicyV1,
    OpenRouterMemoryProvider,
    UrllibOpenRouterTransport,
    build_openrouter_memory_request,
)

NOW = datetime(2026, 9, 12, 23, 0, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


class TransportSpy:
    def __init__(self, response: Mapping[str, Any]) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def post_json(self, **values: object) -> Mapping[str, Any]:
        self.calls.append(values)
        return self.response


def _manifest(**changes: object) -> ImportManifestV2:
    values: dict[str, object] = {
        "campaign_id": CAMPAIGN,
        "destination_content_scope_id": SCOPE,
        "source_namespace": "raymond-private/chatgpt-export",
        "source_conversation_id": "pilot:selection",
        "parser_version": "parser-v1",
        "extractor_version": "extractor-v1",
        "prompt_version": "prompt-v1",
        "provider_policy_id": "private-zdr-v1",
        "model_route": "openai/gpt-oss-20b",
        "token_accounting_version": "canonical-json-byte-upper-bound-v1",
        "records": (
            ImportManifestRecordV1(
                source_record_id="conversation:node:message",
                content_commitment="a" * 64,
                byte_length=17,
                estimated_tokens=6,
                source_revision=1,
                role="owner",
                displayed=True,
            ),
        ),
        "max_records": 1,
        "max_bytes": 17,
        "max_source_estimated_tokens": 6,
        "max_request_input_tokens": 100_000,
        "max_request_output_tokens": 200,
        "max_request_total_tokens": 100_200,
        "max_model_spend_microusd": 10_000,
        "max_attempts": 3,
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return ImportManifestV2.model_validate(values)


def _dispatch(**changes: object) -> MemoryExtractionDispatchV1:
    prompt = "Extract from exact synthetic history."
    attempt_key = "pilot:batch-1:attempt-1"
    request = build_openrouter_memory_request(
        model_route="openai/gpt-oss-20b", prompt=prompt, output_tokens=100
    )
    values: dict[str, object] = {
        "extraction_job_id": memory_extraction_job_id(
            CAMPAIGN,
            attempt_key=attempt_key,
            request_commitment=request.request_commitment,
        ),
        "attempt_key": attempt_key,
        "source_record_ids": ("conversation:node:message",),
        "prompt": prompt,
        "input_tokens": request.input_token_upper_bound,
        "output_tokens": 100,
        "request_bytes": request.request_bytes,
        "request_commitment": request.request_commitment,
        "maximum_microusd": 5_000,
        "timeout_seconds": 30,
    }
    values.update(changes)
    return MemoryExtractionDispatchV1.model_validate(values)


def _response(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": "gen-private-memory-1",
        "model": "openai/gpt-oss-20b",
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {"contract_version": "1", "candidates": []}
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 400, "completion_tokens": 20, "cost": "0.0012341"},
    }
    values.update(changes)
    return values


def _provider(
    transport: TransportSpy,
    *,
    policy: OpenRouterMemoryPolicyV1 | None = None,
) -> OpenRouterMemoryProvider:
    return OpenRouterMemoryProvider(
        api_key="synthetic-openrouter-key",
        policy=policy
        or OpenRouterMemoryPolicyV1(
            provider_policy_id="private-zdr-v1",
            model_route="openai/gpt-oss-20b",
            maximum_output_tokens=200,
            maximum_response_bytes=100_000,
        ),
        provider_reference_commitment_key=b"r" * 32,
        transport=transport,
    )


def test_private_request_is_strict_zdr_bounded_and_cost_accounted() -> None:
    transport = TransportSpy(_response())
    outcome = _provider(transport).infer(manifest=_manifest(), dispatch=_dispatch())

    assert outcome.billed_microusd == 1_235
    assert outcome.provider_policy_id == "private-zdr-v1"
    assert outcome.model_route == "openai/gpt-oss-20b"
    assert len(outcome.provider_reference_commitment) == 64
    assert json.loads(outcome.output) == {"contract_version": "1", "candidates": []}
    call = transport.calls[0]
    assert call["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert call["timeout_seconds"] == 30
    assert call["maximum_response_bytes"] == 100_000
    body = call["body"]
    assert isinstance(body, dict)
    assert body["model"] == "openai/gpt-oss-20b"
    assert body["max_tokens"] == 100
    assert body["stream"] is False
    assert body["provider"] == {
        "zdr": True,
        "data_collection": "deny",
        "require_parameters": True,
    }
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert "tools" not in body and "plugins" not in body
    assert "synthetic-openrouter-key" not in json.dumps(body)


def test_manifest_policy_or_output_cap_mismatch_never_dispatches() -> None:
    for manifest, dispatch in (
        (_manifest(provider_policy_id="other-policy"), _dispatch()),
        (_manifest(model_route="other/model"), _dispatch()),
        (_manifest(), _dispatch(output_tokens=201)),
    ):
        transport = TransportSpy(_response())
        with pytest.raises(MemoryOpenRouterUnavailable):
            _provider(transport).infer(manifest=manifest, dispatch=dispatch)
        assert transport.calls == []


def test_complete_request_accounting_rejects_forged_counts_before_network() -> None:
    exact = _dispatch()
    for dispatch in (
        exact.model_copy(update={"input_tokens": exact.input_tokens - 1}),
        exact.model_copy(update={"request_bytes": exact.request_bytes - 1}),
        exact.model_copy(update={"request_commitment": "0" * 64}),
    ):
        transport = TransportSpy(_response())
        with pytest.raises(MemoryOpenRouterUnavailable, match="accounting differs"):
            _provider(transport).infer(manifest=_manifest(), dispatch=dispatch)
        assert transport.calls == []

    request = build_openrouter_memory_request(
        model_route="openai/gpt-oss-20b",
        prompt="café",
        output_tokens=100,
    )
    assert request.input_token_upper_bound > len("café".encode())
    assert b"json_schema" in request.serialized_body
    assert b"untrusted historical text" in request.serialized_body


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"model": "other/model"}, "unapproved model"),
        ({"id": ""}, "generation identity"),
        ({"usage": {}}, "billed cost"),
        (
            {"usage": {"completion_tokens": 20, "cost": "NaN"}},
            "billed cost",
        ),
        (
            {"usage": {"completion_tokens": 20, "cost": 0}},
            "input usage",
        ),
        (
            {
                "usage": {
                    "prompt_tokens": 999_999,
                    "completion_tokens": 20,
                    "cost": 0,
                }
            },
            "input usage",
        ),
        (
            {
                "usage": {
                    "prompt_tokens": 400,
                    "completion_tokens": 101,
                    "cost": 0,
                }
            },
            "token ceiling",
        ),
        ({"choices": []}, "candidate content"),
        (
            {"choices": [{"message": {"content": "not-json"}}]},
            "valid v1 contract",
        ),
    ],
)
def test_malformed_or_policy_divergent_response_fails_closed(
    changes: dict[str, object], message: str
) -> None:
    transport = TransportSpy(_response(**changes))
    with pytest.raises((MemoryOpenRouterUnavailable, ValueError), match=message):
        _provider(transport).infer(manifest=_manifest(), dispatch=_dispatch())


def test_generation_reference_is_keyed_and_not_returned_raw() -> None:
    first = _provider(TransportSpy(_response(id="guessable-generation"))).infer(
        manifest=_manifest(), dispatch=_dispatch()
    )
    second = _provider(TransportSpy(_response(id="other-generation"))).infer(
        manifest=_manifest(), dispatch=_dispatch()
    )
    assert first.provider_reference_commitment != second.provider_reference_commitment
    assert "guessable" not in first.provider_reference_commitment


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = BytesIO(body)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self._body.read(size)


def test_network_transport_bounds_response_and_sanitizes_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = UrllibOpenRouterTransport()
    call = {
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "headers": {"Authorization": "Bearer synthetic"},
        "body": {"model": "synthetic/model"},
        "timeout_seconds": 1,
        "maximum_response_bytes": 5,
    }
    monkeypatch.setattr(
        memory_openrouter, "urlopen", lambda *_args, **_kwargs: _Response(b"123456")
    )
    with pytest.raises(MemoryOpenRouterUnavailable, match="byte ceiling"):
        transport.post_json(**call)

    def rejected(*_args: object, **_kwargs: object) -> object:
        raise HTTPError(
            call["url"],
            400,
            "bad request",
            {},
            BytesIO(b"sensitive upstream detail"),
        )

    monkeypatch.setattr(memory_openrouter, "urlopen", rejected)
    with pytest.raises(MemoryOpenRouterUnavailable) as failure:
        transport.post_json(**call)
    assert "sensitive upstream detail" not in str(failure.value)
