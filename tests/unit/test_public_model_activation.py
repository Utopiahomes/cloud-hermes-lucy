from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from deploy.render.validate_public_model_activation_v2 import validate
from lucy.public_model_activation import UtopiaPublicModelActivationManifestV2


def valid_manifest() -> dict[str, object]:
    return {
        "contract": "lucy.utopia.public-model.activation-manifest.v2",
        "environment": "production",
        "realm_slug": "utopia",
        "release_state": "staged-disabled",
        "release_decision_id": "model-release-review-1",
        "artifacts": {
            "cloud_source_commit": "a" * 40,
            "cloud_rollback_commit": "b" * 40,
            "website_source_commit": "c" * 40,
            "website_rollback_commit": "d" * 40,
            "image_digest": "1" * 64,
            "base_image_digest": "2" * 64,
            "schema_revision": "0071_memory_import_job_replay",
            "aws_realm_template_sha256": "3" * 64,
            "aws_recovery_template_sha256": "4" * 64,
        },
        "ingress": {
            "website_origin": "https://www.utopiahomes.com",
            "website_api_path": "/api/lucy",
            "public_service": "lucy-public",
            "model_service": "lucy-public-model",
            "model_service_private_only": True,
            "trust_forwarded_host": False,
            "max_browser_request_bytes": 8_192,
            "max_model_request_bytes": 200_000,
            "requests_per_ip_per_minute": 20,
            "requests_per_session_per_minute": 30,
        },
        "routing": {
            "provider": "openrouter",
            "model": "google/gemini-3.1-flash-lite",
            "allowed_providers": ["reviewed-provider"],
            "rate_version": "2026-09-13",
            "credential_scope_reference": "render:lucy-public-model:OPENROUTER_API_KEY",
            "zero_data_retention": True,
            "data_collection": "deny",
            "allow_fallbacks": False,
            "max_prompt_usd_per_million": 0.8,
            "max_completion_usd_per_million": 4.0,
        },
        "cost_policy": {
            "kill_state": "disabled",
            "platform_daily_cap_microusd": 10_000_000,
            "node_daily_cap_microusd": 1_000_000,
            "site_daily_cap_microusd": 1_000_000,
            "provider_daily_cap_microusd": 1_000_000,
            "outstanding_cap_microusd": 90_000,
            "per_attempt_cap_microusd": 30_000,
            "per_conversation_cap_microusd": 45_000,
            "concurrency_limit": 2,
            "requests_per_minute": 60,
            "session_requests_per_minute": 30,
            "ip_requests_per_minute": 20,
        },
        "execution": {
            "generator_max_microusd": 30_000,
            "verifier_max_microusd": 15_000,
            "generator_max_output_tokens": 700,
            "verifier_max_output_tokens": 300,
            "max_input_tokens": 20_000,
            "provider_timeout_seconds": 6,
            "public_to_model_timeout_seconds": 15,
            "website_to_public_timeout_seconds": 18,
        },
        "history": {
            "storage": "browser-memory-only",
            "max_turns": 6,
            "max_characters": 4_000,
            "expires_after_seconds": 1_800,
            "clears_on_refresh": True,
            "clears_on_close": True,
            "prior_messages_are_evidence": False,
        },
        "publication": {
            "active_snapshot_sha256": "5" * 64,
            "rollback_snapshot_sha256": "6" * 64,
            "model_allowed_snapshot_sha256": ["5" * 64],
            "withdrawn_snapshot_sha256": [],
            "source_lineage": ["approved-public-knowledge-r1"],
        },
        "model_traffic_enabled": False,
        "transcript_capture_enabled": False,
        "permitted_data_classes": [
            "approved-public-knowledge",
            "temporary-browser-conversation-context",
        ],
        "permitted_actions": ["public-read-only-model-answer"],
        "operations_contact": "operations@example.com",
        "rollback_owner": "owner@example.com",
    }


def test_disabled_staging_manifest_is_accepted() -> None:
    manifest = UtopiaPublicModelActivationManifestV2.model_validate(valid_manifest())
    assert manifest.release_state == "staged-disabled"
    assert manifest.model_traffic_enabled is False
    assert manifest.cost_policy.kill_state == "disabled"
    assert manifest.artifacts.schema_revision == "0071_memory_import_job_replay"


def test_staging_test_and_active_are_distinct_states() -> None:
    staging = valid_manifest()
    staging["release_state"] = "staging-test"
    staging["cost_policy"]["kill_state"] = "enabled"  # type: ignore[index]
    staged = UtopiaPublicModelActivationManifestV2.model_validate(staging)
    assert staged.model_traffic_enabled is False

    active = valid_manifest()
    active["release_state"] = "active"
    active["model_traffic_enabled"] = True
    active["cost_policy"]["kill_state"] = "enabled"  # type: ignore[index]
    activated = UtopiaPublicModelActivationManifestV2.model_validate(active)
    assert activated.model_traffic_enabled is True


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("artifacts", "schema_revision"), "0070_memory_pilot_transport_admission"),
        (("routing", "zero_data_retention"), False),
        (("routing", "data_collection"), "allow"),
        (("routing", "allow_fallbacks"), True),
        (("ingress", "model_service_private_only"), False),
        (("transcript_capture_enabled",), True),
    ],
)
def test_release_cannot_relax_pinned_security_boundaries(
    path: tuple[str, ...], value: object
) -> None:
    candidate = valid_manifest()
    target = candidate
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        UtopiaPublicModelActivationManifestV2.model_validate(candidate)


def test_active_release_requires_eligible_snapshot_and_enabled_cost_policy() -> None:
    candidate = valid_manifest()
    candidate["release_state"] = "active"
    candidate["model_traffic_enabled"] = True
    candidate["cost_policy"]["kill_state"] = "enabled"  # type: ignore[index]
    candidate["publication"]["model_allowed_snapshot_sha256"] = ["7" * 64]  # type: ignore[index]
    with pytest.raises(ValidationError, match="eligible active snapshot"):
        UtopiaPublicModelActivationManifestV2.model_validate(candidate)


def test_withdrawn_snapshot_cannot_remain_eligible_or_be_rollback() -> None:
    for withdrawn in (["5" * 64], ["6" * 64]):
        candidate = valid_manifest()
        candidate["publication"]["withdrawn_snapshot_sha256"] = withdrawn  # type: ignore[index]
        with pytest.raises(ValidationError, match="eligibility is inconsistent"):
            UtopiaPublicModelActivationManifestV2.model_validate(candidate)


def test_cost_and_timeout_envelopes_cover_both_model_calls() -> None:
    candidate = valid_manifest()
    candidate["execution"]["verifier_max_microusd"] = 15_001  # type: ignore[index]
    with pytest.raises(ValidationError, match="per-conversation"):
        UtopiaPublicModelActivationManifestV2.model_validate(candidate)

    candidate = valid_manifest()
    candidate["execution"]["public_to_model_timeout_seconds"] = 11  # type: ignore[index]
    with pytest.raises(ValidationError, match="timeouts are incoherent"):
        UtopiaPublicModelActivationManifestV2.model_validate(candidate)


def test_content_free_validator_reports_only_release_state(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(valid_manifest()), encoding="utf-8")
    result = validate(path)
    assert result == {
        "contract": "lucy.public-model-activation-validation.v2",
        "status": "passed",
        "release_state": "staged-disabled",
        "model_traffic_enabled": False,
        "cost_policy_enabled": False,
        "capture_enabled": False,
        "model_snapshot_count": 1,
    }

    path.write_text("{}", encoding="utf-8")
    assert validate(path) == {
        "contract": "lucy.public-model-activation-validation.v2",
        "status": "failed",
    }
