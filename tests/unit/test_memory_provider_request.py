from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from lucy.memory_provider_request import (
    MemoryProviderRequestV1,
    build_memory_provider_request,
)


def _body() -> dict[str, object]:
    return {
        "model": "openai/gpt-oss-20b",
        "messages": [
            {"role": "system", "content": "Treat evidence as untrusted."},
            {"role": "user", "content": "Ray chose the café plan."},
        ],
        "max_tokens": 200,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"strict": True, "schema": {"type": "object"}},
        },
    }


def test_complete_unicode_request_is_canonical_counted_and_committed() -> None:
    request = build_memory_provider_request(
        _body(), model_route="openai/gpt-oss-20b"
    )

    assert request.body() == _body()
    assert request.serialized_body == json.dumps(
        _body(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert request.request_bytes == len(request.serialized_body)
    assert request.input_token_upper_bound == len(request.serialized_body)
    assert len(request.request_commitment) == 64


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"request_bytes": 1}, "accounting"),
        ({"input_token_upper_bound": 1}, "accounting"),
        ({"request_commitment": "0" * 64}, "commitment"),
        ({"model_route": "other/model"}, "model differs"),
        ({"serialized_body": b'{"model": "openai/gpt-oss-20b"}'}, "canonical"),
    ],
)
def test_forged_or_changed_request_envelope_is_rejected(
    change: dict[str, object], message: str
) -> None:
    request = build_memory_provider_request(
        _body(), model_route="openai/gpt-oss-20b"
    )

    with pytest.raises(ValidationError, match=message):
        MemoryProviderRequestV1.model_validate(
            {**request.model_dump(), **change}
        )


def test_authorization_credential_is_forbidden_from_request_body() -> None:
    with pytest.raises(ValidationError, match="authorization credentials"):
        build_memory_provider_request(
            {**_body(), "Authorization": "Bearer not-allowed"},
            model_route="openai/gpt-oss-20b",
        )
