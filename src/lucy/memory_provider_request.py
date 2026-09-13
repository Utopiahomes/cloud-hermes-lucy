"""Immutable, exactly accounted provider-request envelopes for memory extraction."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import canonical_json_bytes

_REQUEST_PREFIX = b"LUCY-MEMORY-PROVIDER-REQUEST-V1\x00"
_MAX_REQUEST_BYTES = 10_000_000


class MemoryProviderRequestV1(BaseModel):
    """Canonical request body whose byte length is a conservative token bound."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    model_route: str = Field(min_length=1, max_length=200)
    token_accounting_version: Literal["canonical-json-byte-upper-bound-v1"]
    serialized_body: bytes = Field(min_length=1, max_length=_MAX_REQUEST_BYTES)
    request_bytes: int = Field(ge=1, le=_MAX_REQUEST_BYTES)
    input_token_upper_bound: int = Field(ge=1, le=_MAX_REQUEST_BYTES)
    request_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_accounting(self) -> MemoryProviderRequestV1:
        try:
            body = json.loads(self.serialized_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("provider request body is not valid JSON") from None
        if not isinstance(body, dict) or canonical_json_bytes(body) != self.serialized_body:
            raise ValueError("provider request body is not canonical JSON")
        if body.get("model") != self.model_route:
            raise ValueError("provider request model differs from its envelope")
        if "authorization" in {str(key).lower() for key in body}:
            raise ValueError("provider request body must not contain authorization credentials")
        exact_bytes = len(self.serialized_body)
        if self.request_bytes != exact_bytes or self.input_token_upper_bound != exact_bytes:
            raise ValueError("provider request accounting is not exact")
        expected = hashlib.sha256(_REQUEST_PREFIX + self.serialized_body).hexdigest()
        if self.request_commitment != expected:
            raise ValueError("provider request commitment is invalid")
        return self

    def body(self) -> dict[str, Any]:
        value = json.loads(self.serialized_body)
        if not isinstance(value, dict):  # pragma: no cover - guaranteed by validation
            raise RuntimeError("validated provider request body changed type")
        return value


def build_memory_provider_request(
    body: Mapping[str, Any], *, model_route: str
) -> MemoryProviderRequestV1:
    """Freeze the full model-visible request before admission or network access."""

    serialized = canonical_json_bytes(dict(body))
    exact_bytes = len(serialized)
    return MemoryProviderRequestV1(
        model_route=model_route,
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        serialized_body=serialized,
        request_bytes=exact_bytes,
        input_token_upper_bound=exact_bytes,
        request_commitment=hashlib.sha256(_REQUEST_PREFIX + serialized).hexdigest(),
    )
