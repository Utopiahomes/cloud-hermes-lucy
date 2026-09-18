"""Executor-side validation for the caller-owned RC1 restricted JSON Schema subset."""

from __future__ import annotations

import math
from typing import Any, TypeGuard


def validate_output(schema: dict[str, Any], value: object) -> bool:
    """Return whether a parsed provider value satisfies the admitted restricted schema."""

    schema_type = schema.get("type")
    if not _matches_type(schema_type, value):
        return False
    if "const" in schema and not _json_equal(value, schema["const"]):
        return False
    if "enum" in schema and not any(_json_equal(value, candidate) for candidate in schema["enum"]):
        return False
    if value is None:
        return True
    if isinstance(value, str):
        if _has_invalid_scalar(value):
            return False
        if "minLength" in schema and len(value) < schema["minLength"]:
            return False
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False
    if _is_number(value):
        if not _number_in_canonical_domain(value):
            return False
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        return all(validate_output(schema["items"], item) for item in value)
    if isinstance(value, dict):
        properties = schema["properties"]
        if set(value) != set(properties):
            return False
        return all(validate_output(properties[key], item) for key, item in value.items())
    return True


def _matches_type(schema_type: object, value: object) -> bool:
    allowed = schema_type if isinstance(schema_type, list) else [schema_type]
    return any(_matches_single_type(item, value) for item in allowed)


def _matches_single_type(schema_type: object, value: object) -> bool:
    if schema_type == "null":
        return value is None
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "integer":
        return _is_number(value) and (
            isinstance(value, int) or (isinstance(value, float) and value.is_integer())
        )
    if schema_type == "number":
        return _is_number(value)
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "object":
        return isinstance(value, dict)
    return False


def _is_number(value: object) -> TypeGuard[int | float]:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _json_equal(left: object, right: object) -> bool:
    if _is_number(left) and _is_number(right):
        return (
            _number_in_canonical_domain(left)
            and _number_in_canonical_domain(right)
            and left == right
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(_json_equal(left[key], right[key]) for key in left)
    if type(left) is not type(right):
        return False
    return left == right


def _number_in_canonical_domain(value: int | float) -> bool:
    if isinstance(value, int):
        return abs(value) <= 2**53 - 1
    return math.isfinite(value)


def _has_invalid_scalar(value: str) -> bool:
    return "\x00" in value or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
