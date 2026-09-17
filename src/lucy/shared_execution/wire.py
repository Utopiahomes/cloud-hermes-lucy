"""Strict RC1 request and response models for the local Tiamat executor."""

from __future__ import annotations

import math
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.shared_execution.canonical import canonical_json_bytes

BUNDLE_DIGEST = "5185680e2cb9ac9aff6006c9abc6a582b67933db077d5c7bd5dcc596f574cb85"
CONTRACT_DIGEST = "a010c2cd5d501dd5586be3e1c54753ed7bf82505b9971d19c007e227bb9a75a8"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Message(StrictModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=65_536)


class TextOutput(StrictModel):
    mode: Literal["text"]


class JsonSchemaOutput(StrictModel):
    mode: Literal["json_schema"]
    name: str = Field(pattern=r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$", max_length=128)
    schema_: dict[str, Any] = Field(alias="schema")

    @model_validator(mode="after")
    def schema_is_restricted(self) -> JsonSchemaOutput:
        canonical = canonical_json_bytes(self.schema_)
        if len(canonical) > 32_768 or not restricted_schema_is_valid(self.schema_):
            raise ValueError("JSON Schema output contract is outside the RC1 subset")
        return self


OutputRequest = Annotated[TextOutput | JsonSchemaOutput, Field(discriminator="mode")]


class Limits(StrictModel):
    max_output_tokens: int = Field(ge=1, le=4096)
    max_cost_microusd: int = Field(ge=1, le=1_000_000)


class ExecutionRequest(StrictModel):
    contract: Literal["stoin.inference.execute.request.v1"]
    execution_profile_id: str = Field(
        pattern=r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$", max_length=128
    )
    messages: tuple[Message, ...] = Field(min_length=2, max_length=32)
    output: OutputRequest
    limits: Limits

    @model_validator(mode="after")
    def messages_follow_rc1(self) -> ExecutionRequest:
        roles = tuple(message.role for message in self.messages)
        if roles[0] != "system" or roles.count("system") != 1 or roles[-1] != "user":
            raise ValueError("messages must have one first system role and end with user")
        expected = tuple(
            "user" if index % 2 == 0 else "assistant"
            for index in range(len(roles) - 1)
        )
        if roles[1:] != expected:
            raise ValueError("messages after system must alternate user and assistant")
        total_bytes = sum(len(message.content.encode("utf-8")) for message in self.messages)
        if total_bytes > 196_608:
            raise ValueError("total message content exceeds the RC1 byte bound")
        return self


class OutputResult(StrictModel):
    mode: Literal["text", "json_schema"]
    content: str | dict[str, Any]


class Usage(StrictModel):
    input_tokens: int = Field(ge=0)
    generated_tokens: int = Field(ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def breakdown_is_exact(self) -> Usage:
        if (self.output_tokens is None) != (self.reasoning_tokens is None):
            raise ValueError("usage breakdown fields must both be integers or both be null")
        if (
            self.output_tokens is not None
            and self.reasoning_tokens is not None
            and self.output_tokens + self.reasoning_tokens != self.generated_tokens
        ):
            raise ValueError("usage breakdown must sum to generated_tokens")
        return self


class CostReceipt(StrictModel):
    reserved_microusd: int = Field(ge=1, le=1_000_000)
    settled_microusd: int | None = Field(default=None, ge=0)
    settlement_status: Literal[
        "settled", "pending_reconciliation", "reservation_forfeited", "settlement_overrun"
    ]

    @model_validator(mode="after")
    def settlement_is_coherent(self) -> CostReceipt:
        if self.settlement_status == "settled":
            if self.settled_microusd is None or self.settled_microusd > self.reserved_microusd:
                raise ValueError("settled cost must be present and no greater than the reservation")
        elif self.settlement_status == "settlement_overrun":
            if self.settled_microusd is None or self.settled_microusd <= self.reserved_microusd:
                raise ValueError("settlement overrun must exceed the reservation")
        elif self.settled_microusd is not None:
            raise ValueError("unsettled cost must not claim a settled amount")
        return self


class ExecutionResponse(StrictModel):
    contract: Literal["stoin.inference.execute.response.v1"]
    request_id: UUID
    execution_id: UUID
    replayed: bool
    execution_profile_id: str
    profile_release_id: str = Field(min_length=1, max_length=128)
    output: OutputResult
    finish_reason: Literal["stop"]
    usage: Usage
    cost: CostReceipt


def restricted_schema_is_valid(
    schema: object, *, depth: int = 1, count: list[int] | None = None
) -> bool:
    """Validate the closed RC1 subset needed before a provider call can be admitted."""

    if not isinstance(schema, dict) or depth > 8:
        return False
    if count is None:
        count = [0]
    allowed = {
        "type", "properties", "required", "additionalProperties", "items", "enum", "const",
        "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems",
    }
    if not set(schema) <= allowed:
        return False
    schema_type = schema.get("type")
    if depth == 1 and schema_type != "object":
        return False
    simple = {"object", "array", "string", "integer", "number", "boolean", "null"}
    if isinstance(schema_type, list):
        if (
            len(schema_type) != 2
            or len(set(schema_type)) != 2
            or "null" not in schema_type
            or not set(schema_type) <= simple
        ):
            return False
        non_null_type = next(item for item in schema_type if item != "null")
    elif schema_type in simple:
        non_null_type = schema_type
    else:
        return False
    if not _numeric_literals_are_valid(schema):
        return False
    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or len(enum) > 64 or not _enum_is_unique(enum):
            return False
        if isinstance(schema_type, list) and sum(item is None for item in enum) != 1:
            return False
    if "const" in schema and isinstance(schema_type, list) and schema["const"] is not None:
        return False
    if non_null_type == "object":
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or schema.get("additionalProperties") is not False
            or set(required) != set(properties)
            or len(required) != len(set(required))
        ):
            return False
        count[0] += len(properties)
        return count[0] <= 128 and all(
            restricted_schema_is_valid(child, depth=depth + 1, count=count)
            for child in properties.values()
        )
    if non_null_type == "array":
        return "items" in schema and restricted_schema_is_valid(
            schema["items"], depth=depth + 1, count=count
        )
    return True


def _numeric_literals_are_valid(schema: dict[str, Any]) -> bool:
    for key in ("minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"):
        if key not in schema:
            continue
        value = schema[key]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        if not math.isfinite(float(value)) or abs(value) > 2**53 - 1:
            return False
        if key in {"minLength", "maxLength", "minItems", "maxItems"} and not isinstance(
            value, int
        ):
            return False
        if key.startswith("min") and value < 0:
            return False
    literals = list(schema.get("enum", []))
    if "const" in schema:
        literals.append(schema["const"])
    for value in literals:
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not math.isfinite(float(value)) or abs(value) > 2**53 - 1)
        ):
            return False
    for smaller, larger in (
        ("minimum", "maximum"),
        ("minLength", "maxLength"),
        ("minItems", "maxItems"),
    ):
        if smaller in schema and larger in schema and schema[smaller] > schema[larger]:
            return False
    return True


def _enum_is_unique(values: list[Any]) -> bool:
    encoded = [
        canonical_json_bytes(value).decode("utf-8")
        for value in values
    ]
    return len(encoded) == len(set(encoded))
