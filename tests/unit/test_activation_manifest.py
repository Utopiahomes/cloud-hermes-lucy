from __future__ import annotations

import pytest
from pydantic import ValidationError

from lucy.activation_manifest import UtopiaActivationManifestV1


def valid_manifest() -> dict[str, object]:
    return {
        "contract": "lucy.utopia.r1.activation-manifest.v1",
        "environment": "production",
        "realm_slug": "utopia",
        "activation_decision_id": "owner-approval-1",
        "artifacts": {
            "source_commit": "a" * 40,
            "rollback_commit": "b" * 40,
            "image_digest": "c" * 64,
            "base_image_digest": "d" * 64,
            "schema_revision": "0053_r1_telegram_authority",
            "aws_realm_template_sha256": "e" * 64,
            "aws_recovery_template_sha256": "f" * 64,
        },
        "customer_identity": {
            "issuer": "https://identity.example/",
            "audience": "lucy-utopia",
            "owner_subjects": ["owner-1"],
            "strong_auth_claim": "acr",
            "strong_auth_values": ["mfa"],
        },
        "ingress": {
            "public_hostnames": ["lucy.utopiahomes.com"],
            "private_hostnames": ["internal-lucy.utopiahomes.com"],
            "allowed_origins": ["https://lucy.utopiahomes.com"],
            "trust_forwarded_host": False,
            "max_request_bytes": 65536,
            "requests_per_ip_per_minute": 20,
            "requests_per_session_per_minute": 30,
            "session_ttl_seconds": 3600,
        },
        "paid_inference_enabled": False,
        "paid_inference": None,
        "transcript_capture_enabled": False,
        "public_seed": {"snapshot_sha256": "1" * 64, "source_lineage": ["faq-v1"]},
        "permitted_data_classes": ["approved-public-faq"],
        "permitted_actions": ["public-read-only-answer"],
        "operations_contact": "security@example.com",
        "rollback_owner": "owner@example.com",
    }


def test_capture_off_activation_manifest_is_accepted() -> None:
    manifest = UtopiaActivationManifestV1.model_validate(valid_manifest())
    assert manifest.transcript_capture_enabled is False
    assert manifest.paid_inference is None


def test_public_only_manifest_requires_no_private_identity_or_ingress() -> None:
    candidate = valid_manifest()
    candidate["activation_scope"] = "public_only"
    candidate["customer_identity"] = None
    candidate["ingress"]["private_hostnames"] = []  # type: ignore[index]
    manifest = UtopiaActivationManifestV1.model_validate(candidate)
    assert manifest.activation_scope == "public_only"
    assert manifest.customer_identity is None


@pytest.mark.parametrize("private_value", [["private.example"], []])
def test_public_only_manifest_rejects_private_surface(private_value: list[str]) -> None:
    candidate = valid_manifest()
    candidate["activation_scope"] = "public_only"
    candidate["customer_identity"] = None
    candidate["ingress"]["private_hostnames"] = private_value  # type: ignore[index]
    if not private_value:
        candidate["customer_identity"] = valid_manifest()["customer_identity"]
    with pytest.raises(ValidationError):
        UtopiaActivationManifestV1.model_validate(candidate)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("transcript_capture_enabled",), True),
        (("ingress", "trust_forwarded_host"), True),
        (("ingress", "allowed_origins"), ["https://foreign.example"]),
        (("artifacts", "source_commit"), "main"),
    ],
)
def test_unsafe_or_moving_activation_inputs_fail(
    path: tuple[str, ...], value: object
) -> None:
    candidate = valid_manifest()
    target = candidate
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        UtopiaActivationManifestV1.model_validate(candidate)


def test_paid_inference_requires_complete_limits() -> None:
    candidate = valid_manifest()
    candidate["paid_inference_enabled"] = True
    with pytest.raises(ValidationError):
        UtopiaActivationManifestV1.model_validate(candidate)


def test_per_request_cost_cannot_exceed_enclosing_cap() -> None:
    candidate = valid_manifest()
    candidate["paid_inference_enabled"] = True
    candidate["paid_inference"] = {
        "provider": "openrouter",
        "model": "provider/model",
        "rate_version": "2026-09-11",
        "credential_scope_reference": "render:utopia-openrouter-v1",
        "platform_daily_cap_microusd": 1_000_000,
        "realm_daily_cap_microusd": 1_000_000,
        "site_daily_cap_microusd": 100_000,
        "provider_daily_cap_microusd": 1_000_000,
        "outstanding_cap_microusd": 100_000,
        "per_request_cap_microusd": 100_001,
        "concurrency_cap": 1,
        "max_input_tokens": 4096,
        "max_output_tokens": 1024,
        "timeout_seconds": 60,
    }
    with pytest.raises(ValidationError):
        UtopiaActivationManifestV1.model_validate(candidate)
