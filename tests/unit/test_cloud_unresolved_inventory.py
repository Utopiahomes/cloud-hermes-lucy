from __future__ import annotations

from typing import Any

import pytest

from deploy.postgres.inspect_unresolved_cloud_v1_2 import (
    _CAPTURE_SAFETY_QUERY,
    AUTHORIZATION,
    InventoryConfig,
    InventoryError,
    sanitize_row,
)


def environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_UNRESOLVED_DIAGNOSTIC_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MAINTENANCE_DATABASE_URL": ("postgresql://lucy_migration:secret@dpg-example-a/lucy"),
        "LUCY_DIAGNOSTIC_TOKEN": "x" * 32,
        "PORT": "10000",
    }


def test_inventory_config_requires_exact_quarantined_render_boundary() -> None:
    parsed = InventoryConfig.from_environment(environment())
    assert parsed.migration_url.username == "lucy_migration"
    assert parsed.port == 10000

    for key, value in {
        "RENDER": "false",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
        "LUCY_UNRESOLVED_DIAGNOSTIC_AUTHORIZATION": "wrong",
        "LUCY_MAINTENANCE_DATABASE_URL": "postgresql://x:y@example.com/other",
        "LUCY_DIAGNOSTIC_TOKEN": "short",
        "PORT": "0",
    }.items():
        changed = environment() | {key: value}
        with pytest.raises(InventoryError):
            InventoryConfig.from_environment(changed)


def test_inventory_sanitizes_idempotency_and_omits_sensitive_values() -> None:
    row: list[Any] = [
        "00000000-0000-4000-8000-000000000001",
        "cloud-acceptance-retrieve:00000000-0000-4000-8000-000000000002",
        "pending",
        "created",
        None,
        ["operation.started"],
        0,
        0,
        0,
        0,
        "evidence.retrieve",
        "EXECUTING",
        True,
        1,
        0,
        None,
        0,
        0,
        True,
        True,
    ]
    result = sanitize_row(row)
    assert result["idempotency_class"] == "cloud-acceptance-sensitive"
    assert len(result["idempotency_sha256"]) == 64
    serialized = repr(result)
    assert row[1] not in serialized
    for forbidden in ("encrypted_package", "serialized_permit", "ciphertext", "wrapped_key"):
        assert forbidden not in result


def test_inventory_capture_gate_rejects_non_synthetic_historical_receipts() -> None:
    query = " ".join(_CAPTURE_SAFETY_QUERY.split())
    assert "WHERE r.capture_enabled AND NOT" in query
    assert "^cloud-acceptance-" in query
    assert "source_turn_id=regexp_replace" in query
    assert "e.source_conversation_id='telegram:' || r.source_conversation_id" in query
