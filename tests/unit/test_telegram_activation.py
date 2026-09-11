from __future__ import annotations

from typing import cast
from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.telegram_activation import (
    TelegramStage1ActivationManifest,
    TelegramStage2ActivationManifest,
)


def _manifest() -> dict[str, object]:
    return {
        "contract": "lucy.telegram.private.stage1.activation.v1",
        "environment": "production",
        "realm_slug": "utopia",
        "activation_decision_id": "owner-approved-stage-1",
        "artifacts": {
            "source_commit": "1" * 40,
            "rollback_commit": "2" * 40,
            "gateway_dockerfile_sha256": "3" * 64,
            "profile_sha256": "4" * 64,
            "hermes_release": "v2026.8.19",
            "hermes_version": "0.20.5",
            "hermes_source_commit": "fcbd1076a93841fa88855acce810e342a5b78101",
            "hermes_manifest_digest": (
                "3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09"
            ),
            "hermes_platform_digest": (
                "f3cba556e7b35dbe20a67d32b715090d9babd5907798c79721380757d9a12bb6"
            ),
            "target_platform": "linux/amd64",
            "schema_revision": "0053_r1_telegram_authority",
        },
        "realm": {
            "node_id": str(uuid4()),
            "security_realm_id": str(uuid4()),
            "content_scope_id": str(uuid4()),
            "channel_binding_id": str(uuid4()),
            "routine_render_service_id": "srv-routine1",
            "gateway_render_service_id": "srv-gateway1",
        },
        "bot_id": 123,
        "owner_telegram_user_id": 456,
        "one_active_gateway": True,
        "unauthorized_dm_behavior": "ignore",
        "budget": {
            "provider": "openrouter",
            "model": "openai/gpt-oss-20b",
            "reservation_microusd": 5000,
            "max_output_tokens": 1024,
            "realm_daily_limit_microusd": 1000000,
        },
        "transcript_capture_enabled": False,
        "automatic_memory_writes_enabled": False,
        "raw_evidence_retrieval_enabled": False,
        "rollback_preserves_authority_and_deletion_history": True,
    }


def test_manifest_accepts_only_the_bounded_stage1_shape() -> None:
    assert TelegramStage1ActivationManifest.model_validate(_manifest()).one_active_gateway


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("transcript_capture_enabled", True),
        ("automatic_memory_writes_enabled", True),
        ("raw_evidence_retrieval_enabled", True),
        ("one_active_gateway", False),
    ],
)
def test_manifest_rejects_scope_expansion(key: str, value: bool) -> None:
    candidate = _manifest()
    candidate[key] = value
    with pytest.raises(ValidationError):
        TelegramStage1ActivationManifest.model_validate(candidate)


def _stage2_manifest() -> dict[str, object]:
    candidate = _manifest()
    candidate.update(
        {
            "contract": "lucy.telegram.private.stage2.activation.v1",
            "transcript_capture_enabled": True,
            "encrypted_evidence_archive_enabled": True,
            "authoritative_two_message_commit": True,
            "off_record_history_rotation": True,
            "sensitive_gateway_tools_enabled": False,
        }
    )
    artifacts = cast(dict[str, object], candidate["artifacts"]).copy()
    artifacts["schema_revision"] = "0054_stage2_scoped_turn_commit"
    candidate["artifacts"] = artifacts
    return candidate


def test_stage2_manifest_requires_all_capture_safety_boundaries() -> None:
    manifest = TelegramStage2ActivationManifest.model_validate(_stage2_manifest())
    assert manifest.transcript_capture_enabled
    assert manifest.authoritative_two_message_commit


@pytest.mark.parametrize(
    "key",
    [
        "encrypted_evidence_archive_enabled",
        "authoritative_two_message_commit",
        "off_record_history_rotation",
        "one_active_gateway",
    ],
)
def test_stage2_manifest_rejects_missing_required_boundary(key: str) -> None:
    candidate = _stage2_manifest()
    candidate[key] = False
    with pytest.raises(ValidationError):
        TelegramStage2ActivationManifest.model_validate(candidate)


@pytest.mark.parametrize(
    "key",
    [
        "automatic_memory_writes_enabled",
        "raw_evidence_retrieval_enabled",
        "sensitive_gateway_tools_enabled",
    ],
)
def test_stage2_manifest_rejects_gateway_authority_expansion(key: str) -> None:
    candidate = _stage2_manifest()
    candidate[key] = True
    with pytest.raises(ValidationError):
        TelegramStage2ActivationManifest.model_validate(candidate)
