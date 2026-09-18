from __future__ import annotations

from typing import Any

import pytest
from jsonschema import Draft202012Validator

from lucy.shared_execution.output_validation import validate_output


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        ({"type": "number", "enum": [1]}, 1.0),
        ({"type": "integer"}, 1.0),
        ({"type": "integer"}, 1.5),
        ({"type": "number", "minimum": -1, "maximum": 1}, -0.0),
        ({"type": "string", "minLength": 2, "maxLength": 3}, "ab"),
        ({"type": "string", "minLength": 2, "maxLength": 3}, "a"),
        ({"type": "string", "const": "fixed"}, "other"),
        ({"type": "boolean", "const": True}, True),
        ({"type": "null"}, None),
        ({"type": ["string", "null"], "enum": ["answer", None]}, None),
        (
            {
                "type": "array",
                "items": {"type": "boolean"},
                "minItems": 1,
                "maxItems": 2,
            },
            [True],
        ),
        (
            {
                "type": "array",
                "items": {"type": "boolean"},
                "minItems": 1,
                "maxItems": 2,
            },
            [True, False, True],
        ),
        (
            {
                "type": "object",
                "properties": {"count": {"type": "integer", "minimum": 0}},
                "required": ["count"],
                "additionalProperties": False,
            },
            {"count": 2},
        ),
        (
            {
                "type": "object",
                "properties": {"count": {"type": "integer"}},
                "required": ["count"],
                "additionalProperties": False,
            },
            {"count": 2, "extra": True},
        ),
    ],
)
def test_restricted_evaluator_matches_independent_jsonschema(
    schema: dict[str, Any], value: object
) -> None:
    expected = Draft202012Validator(schema).is_valid(value)
    assert validate_output(schema, value) is expected


@pytest.mark.parametrize(
    "value",
    [
        2**53,
        -(2**53),
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_numeric_values_outside_canonical_domain_fail_closed(value: int | float) -> None:
    assert not validate_output({"type": "number"}, value)


def test_invalid_unicode_scalar_fails_closed_at_nested_depth() -> None:
    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {"type": "string"},
            }
        },
    }
    assert not validate_output(schema, {"items": ["valid", "\ud800"]})


def test_boolean_never_equals_numeric_enum_member() -> None:
    assert not validate_output({"type": "boolean", "enum": [1]}, True)


def test_nested_boolean_never_equals_numeric_enum_member() -> None:
    schema = {
        "type": "object",
        "properties": {"value": {"type": "boolean"}},
        "enum": [{"value": 1}],
    }
    assert not validate_output(schema, {"value": True})
