from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    DeletionArtifactClass,
    DeletionArtifactClassV3,
    DeletionDisposition,
    DeletionTargetManifestV3,
    DeletionTargetReferenceV3,
    OriginScopeV1,
    V13SigningKeyPurpose,
    deletion_targets_digest_v3,
    security_v1_3_json_schemas,
)

ZERO = UUID("00000000-0000-4000-8000-000000000000")
ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")
THREE = UUID("00000000-0000-4000-8000-000000000003")
FOUR = UUID("00000000-0000-4000-8000-000000000004")
FIVE = UUID("00000000-0000-4000-8000-000000000005")
SIX = UUID("00000000-0000-4000-8000-000000000006")
NOW = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64


def _scope() -> OriginScopeV1:
    return OriginScopeV1(
        tenant_account_id=ZERO,
        node_id=ONE,
        node_tenure_id=TWO,
        tenure_epoch=1,
        security_realm_id=THREE,
        storage_epoch=1,
    )


def _targets() -> tuple[DeletionTargetReferenceV3, ...]:
    return (
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.ENCRYPTED_ARCHIVE,
            artifact_id=ZERO,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=ONE,
            wrapped_key_ref=TWO,
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_CANDIDATE,
            artifact_id=THREE,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.INVALIDATE,
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_CANDIDATE,
            artifact_id=THREE,
            artifact_version=2,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.INVALIDATE,
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_CLAIM,
            artifact_id=FOUR,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.INVALIDATE,
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_IMPORT_PROVIDER_OUTCOME,
            artifact_id=FIVE,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=SIX,
            wrapped_key_ref=SIX,
            key_registry_id=FOUR,
        ),
    )


def _manifest(
    targets: tuple[DeletionTargetReferenceV3, ...] | None = None,
    **changes: object,
) -> DeletionTargetManifestV3:
    exact_targets = targets or _targets()
    values: dict[str, object] = {
        "signing_key_purpose": V13SigningKeyPurpose.POLICY_NOTARY,
        "key_id": "policy-v13-test",
        "issuer": "lucy-policy-v13-test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW,
        "manifest_id": SIX,
        "permit_id": ONE,
        "permit_digest": DIGEST,
        "operation_id": TWO,
        "target_scope": _scope(),
        "workspace_id": FOUR,
        "root_evidence_id": ZERO,
        "root_representation_id": ONE,
        "owner_assertion_id": THREE,
        "owner_assertion_digest": DIGEST,
        "idempotency_key": "delete-root-zero-v3",
        "closure_version": 3,
        "targets": exact_targets,
        "target_count": len(exact_targets),
        "targets_digest": deletion_targets_digest_v3(exact_targets),
        "tombstone_policy_version": 3,
        "finality_policy_version": 3,
        "permit_claim_deadline": NOW + timedelta(seconds=60),
        "execution_completion_deadline": NOW + timedelta(seconds=120),
        "nonce": "n" * 32,
    }
    values.update(changes)
    return DeletionTargetManifestV3.model_validate(values)


def test_v3_freezes_candidate_versions_and_exact_encrypted_outcome_key() -> None:
    manifest = _manifest()

    assert manifest.contract_version == "3"
    assert manifest.object_type == "lucy.deletion-target-manifest.v3"
    assert manifest.target_count == 5
    assert manifest.targets[-1].key_registry_id == FOUR


def test_v3_identity_includes_artifact_version_but_rejects_exact_duplicate() -> None:
    targets = _targets()
    assert _manifest().targets[1].artifact_version == 1
    duplicate = tuple(sorted((*targets, targets[1]), key=lambda target: (
        target.artifact_class.value,
        str(target.artifact_id),
        target.artifact_version,
        str(target.representation_id or ZERO),
    )))

    with pytest.raises(ValidationError, match="duplicate artifact versions"):
        _manifest(duplicate)


def test_v3_key_authority_is_limited_to_exact_encrypted_classes() -> None:
    with pytest.raises(ValidationError, match="exact key registry"):
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_IMPORT_PROVIDER_OUTCOME,
            artifact_id=FIVE,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=SIX,
            wrapped_key_ref=SIX,
        )
    with pytest.raises(ValidationError, match="wrapped-key authority"):
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_CANDIDATE,
            artifact_id=THREE,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=SIX,
            wrapped_key_ref=SIX,
            key_registry_id=FOUR,
        )


def test_v3_is_additive_and_does_not_reinterpret_v2_schema() -> None:
    schemas = security_v1_3_json_schemas()

    assert schemas["DeletionTargetManifestV3"]["additionalProperties"] is False
    assert "MEMORY_CANDIDATE" not in DeletionArtifactClass.__members__
    assert "MEMORY_CANDIDATE" in DeletionArtifactClassV3.__members__
    assert "key_registry_id" not in schemas["DeletionTargetReferenceV2"]["properties"]
    assert "key_registry_id" in schemas["DeletionTargetReferenceV3"]["properties"]

