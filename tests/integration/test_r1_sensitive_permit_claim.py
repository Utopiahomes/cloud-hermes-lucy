from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from lucy.archive import ConversationMessageArchiveInput, TurnCaptureInput
from lucy.authorized_deletion_recovery import (
    AuthorizedDeletionRecoveryProofV2,
    build_authorized_deletion_recovery_contract_v2,
)
from lucy.contracts.canonical import canonical_json_bytes, canonical_sha256
from lucy.contracts.security_v1_2 import (
    DeletionRecoveryInventoryV1,
    DeploymentEnvironment,
    ExecutorResult,
    SensitiveActionV2,
    SensitiveReasonCode,
)
from lucy.contracts.security_v1_3 import (
    DeletionArtifactClass,
    DeletionDisposition,
    DeletionTargetManifestV2,
    DeletionTargetReferenceV2,
    Ed25519V13Signer,
    EncryptedEvidencePackageV2,
    EvidencePayloadBindingV2,
    EvidenceWrapperBindingV2,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    ExecutorReceiptV2,
    KmsEncryptionContextV2,
    OriginScopeV1,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13SigningKeyPurpose,
    deletion_targets_digest_v2,
)
from lucy.db import create_session_factory
from lucy.db.models import (
    RealmBindingRow,
    RealmContentScopeRow,
    RealmExecutorBindingV2Row,
    RealmSensitiveActorBindingRow,
    RealmServiceBindingRow,
)
from lucy.realm_archive import (
    GeneratedDataKeyV1,
    RealmArchiveEncryptor,
    RealmArchiveEnvelopeV1,
    RealmArchiveIdentityV1,
)
from lucy.realm_archive_commit import (
    PostgresRealmArchiveCommitStore,
    RealmArchiveCommitService,
    RealmConversationArchiveService,
)
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
POLICY_URL = os.getenv("LUCY_TEST_UTOPIA_POLICY_DATABASE_URL")
WORKFLOW_URL = os.getenv("LUCY_TEST_UTOPIA_WORKFLOW_DATABASE_URL")
ARCHIVE_URL = os.getenv("LUCY_TEST_UTOPIA_DATABASE_URL")
RAYMOND_WORKFLOW_URL = os.getenv("LUCY_TEST_RAYMOND_WORKFLOW_DATABASE_URL")
FINALITY_URL = os.getenv("LUCY_TEST_UTOPIA_FINALITY_DATABASE_URL")
pytestmark = pytest.mark.skipif(not APP_URL, reason="requires PostgreSQL integration database")


@pytest.fixture(autouse=True)
def clean_sensitive_tables() -> None:
    assert OWNER_URL is not None
    parsed = make_url(OWNER_URL)
    if (parsed.database, parsed.host, parsed.port) != ("lucy_test", "127.0.0.1", 54329):
        raise RuntimeError("refusing to clear a non-synthetic database")
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.scoped_authorized_deletion_recovery_targets_v2, "
                "lucy.scoped_archive_reconciliations_v1, "
                "lucy.scoped_archive_aws_outcomes_v1, lucy.scoped_archive_intents_v1, "
                "lucy.scoped_recovery_deletion_fences_v2, "
                "lucy.scoped_authorized_deletion_recoveries_v2, "
                "lucy.scoped_capture_receipts_v1, lucy.scoped_capture_transitions_v1, "
                "lucy.scoped_capture_states_v1, "
                "lucy.scoped_finality_observations_v2, "
                "lucy.scoped_evidence_deletion_fences_v2, "
                "lucy.scoped_deletion_manifest_targets_v2, "
                "lucy.scoped_deletion_manifests_v2, "
                "lucy.scoped_memory_claim_sources_v2, "
                "lucy.executor_receipt_attestations_v2, "
                "lucy.sensitive_execution_grants_v2, "
                "lucy.realm_executor_bindings_v2, lucy.sensitive_operation_packages_v2, "
                "lucy.scoped_evidence_wrappers_v2, lucy.scoped_evidence_payloads_v2, "
                "lucy.scoped_evidence_records_v2, lucy.sensitive_operation_events_v2, "
                "lucy.sensitive_operations_v2, lucy.sensitive_action_permits_v3, "
                "lucy.realm_sensitive_actor_bindings_v1, lucy.scoped_memory_events_v1, "
                "lucy.scoped_memory_claims_v1, lucy.realm_service_bindings_v1, "
                "lucy.realm_content_scopes_v1, lucy.public_projection_events, "
                "lucy.public_projection_routes, lucy.public_projection_versions, "
                "lucy.public_projection_approvals, lucy.public_projection_candidates, "
                "lucy.lucy_instances, lucy.node_memberships, lucy.channel_bindings, "
                "lucy.wallet_registrations, lucy.workspaces, lucy.realm_bindings, "
                "lucy.node_tenures, lucy.security_realms, lucy.nodes, "
                "lucy.tenant_accounts, lucy.principals CASCADE"
            )
        )
        connection.execute(
            text(
                "GRANT EXECUTE ON FUNCTION lucy.issue_sensitive_action_permit_v3(jsonb,text) "
                "TO lucy_utopia_policy; "
                "GRANT EXECUTE ON FUNCTION "
                "lucy.claim_sensitive_operation_v2(uuid,text) "
                "TO lucy_utopia_sensitive_workflow, lucy_raymond_sensitive_workflow; "
                "GRANT EXECUTE ON FUNCTION "
                "lucy.register_scoped_evidence_v2(jsonb,jsonb,text,jsonb,text) "
                "TO lucy_utopia_routine; "
                "GRANT EXECUTE ON FUNCTION lucy.set_scoped_capture_mode_v1(text,boolean,text), "
                "lucy.get_scoped_capture_mode_v1(text), "
                "lucy.accept_scoped_capture_turn_v1(text,text), "
                "lucy.register_capturable_scoped_evidence_v2("
                "text,text,jsonb,jsonb,text,jsonb,text) TO lucy_utopia_routine; "
                "GRANT EXECUTE ON FUNCTION "
                "lucy.claim_capturable_scoped_archive_v1(text,text,text,text,text,jsonb), "
                "lucy.record_scoped_archive_aws_outcome_v1(uuid,jsonb,text), "
                "lucy.reconcile_capturable_scoped_archive_v1(uuid) "
                "TO lucy_utopia_routine; "
                "GRANT EXECUTE ON FUNCTION lucy.freeze_claimed_evidence_package_v2(uuid) "
                "TO lucy_utopia_sensitive_workflow, lucy_raymond_sensitive_workflow; "
                "GRANT EXECUTE ON FUNCTION lucy.store_sensitive_execution_grant_v2(uuid,jsonb) "
                "TO lucy_utopia_policy; "
                "GRANT EXECUTE ON FUNCTION lucy.attest_executor_receipt_v2(uuid,jsonb) "
                "TO lucy_utopia_policy; "
                "GRANT EXECUTE ON FUNCTION lucy.reconcile_sensitive_operation_v2(uuid) "
                "TO lucy_utopia_sensitive_workflow, lucy_raymond_sensitive_workflow; "
                "GRANT EXECUTE ON FUNCTION lucy.write_evidence_derived_memory_claim_v2("
                "text,text,text,text,bigint,uuid[]) TO lucy_utopia_routine; "
                "GRANT EXECUTE ON FUNCTION lucy.search_scoped_memory_v1(text,integer) "
                "TO lucy_utopia_routine; "
                "GRANT EXECUTE ON FUNCTION lucy.store_scoped_deletion_manifest_v2(uuid,jsonb) "
                "TO lucy_utopia_policy; "
                "GRANT EXECUTE ON FUNCTION lucy.store_deletion_execution_grant_v2(uuid,jsonb) "
                "TO lucy_utopia_policy; "
                "GRANT EXECUTE ON FUNCTION "
                "lucy.attest_deletion_executor_receipt_v2(uuid,jsonb) "
                "TO lucy_utopia_policy; "
                "GRANT EXECUTE ON FUNCTION lucy.reconcile_scoped_deletion_v2(uuid) "
                "TO lucy_utopia_sensitive_workflow, lucy_raymond_sensitive_workflow; "
                "GRANT EXECUTE ON FUNCTION lucy.record_scoped_finality_inventory_v2(uuid,jsonb) "
                "TO lucy_utopia_finality"
            )
        )
    engine.dispose()


@pytest.fixture
def realm() -> dict[str, UUID]:
    assert APP_URL is not None and OWNER_URL is not None
    app_sessions = create_session_factory(APP_URL)
    owner_sessions = create_session_factory(OWNER_URL)
    tenancy = TenancyService(app_sessions)
    owner_id = tenancy.create_principal(
        issuer="https://identity.test",
        subject="ray-subject",
        kind="human",
        display_name="Ray",
    )
    foundation = tenancy.create_node_foundation(
        account_slug="utopia",
        account_name="Utopia",
        node_slug="utopia",
        node_name="Utopia",
        node_kind="organization",
        realm_slug="utopia-realm",
        workspace_slug="operations",
        hostname="internal.utopia.test",
        workspace_kind="private",
        channel_kind="internal",
    )
    tenancy.grant_workspace_membership(
        principal_id=owner_id, workspace_id=foundation.workspace_id, role="owner"
    )
    evidence_id = tenancy.create_principal(
        issuer="https://workload.test",
        subject="render:utopia:evidence",
        kind="service",
        display_name="Utopia evidence",
    )
    policy_id = tenancy.create_principal(
        issuer="https://workload.test",
        subject="render:utopia:policy",
        kind="service",
        display_name="Utopia policy",
    )
    workflow_id = tenancy.create_principal(
        issuer="https://workload.test",
        subject="render:utopia:sensitive-workflow",
        kind="service",
        display_name="Utopia sensitive workflow",
    )
    finality_id = tenancy.create_principal(
        issuer="https://workload.test",
        subject="render:utopia:finality",
        kind="service",
        display_name="Utopia finality verifier",
    )
    with app_sessions() as session:
        realm_binding = session.execute(
            select(RealmBindingRow).where(
                RealmBindingRow.tenure_id == foundation.tenure_id,
                RealmBindingRow.realm_id == foundation.realm_id,
            )
        ).scalar_one()
    scope_id, service_binding_id = uuid4(), uuid4()
    policy_binding_id, workflow_binding_id, archive_binding_id = uuid4(), uuid4(), uuid4()
    finality_binding_id = uuid4()
    executor_binding_id, deletion_executor_binding_id = uuid4(), uuid4()
    deployment_id = uuid4()
    now = datetime.now(UTC)
    with owner_sessions.begin() as session:
        session.add(
            RealmContentScopeRow(
                id=scope_id,
                tenant_account_id=foundation.account_id,
                node_id=foundation.node_id,
                node_tenure_id=foundation.tenure_id,
                tenure_epoch=1,
                security_realm_id=foundation.realm_id,
                storage_epoch=1,
                realm_binding_id=realm_binding.id,
                workspace_id=foundation.workspace_id,
                deployment_id=deployment_id,
                created_at=now,
            )
        )
        session.flush()
        session.add(
            RealmServiceBindingRow(
                id=service_binding_id,
                session_login="lucy_utopia_routine",
                service_principal_id=evidence_id,
                content_scope_id=scope_id,
                service_role="realm_evidence",
                allowed_actions=[
                    "evidence.archive",
                    "evidence.retrieve",
                    "evidence.delete",
                    "memory.read",
                    "memory.write",
                ],
                binding_generation=1,
                node_authz_epoch=1,
                policy_version=1,
                active=True,
                created_at=now,
            )
        )
        session.flush()
        session.add_all(
            [
                RealmSensitiveActorBindingRow(
                    id=archive_binding_id,
                    session_login="lucy_utopia_routine",
                    actor_principal_id=evidence_id,
                    target_service_binding_id=service_binding_id,
                    content_scope_id=scope_id,
                    actor_role="archive_writer",
                    allowed_actions=["evidence.archive"],
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
                RealmSensitiveActorBindingRow(
                    id=finality_binding_id,
                    session_login="lucy_utopia_finality",
                    actor_principal_id=finality_id,
                    target_service_binding_id=service_binding_id,
                    content_scope_id=scope_id,
                    actor_role="finality_verifier",
                    allowed_actions=["sensitive.finality.record"],
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
                RealmSensitiveActorBindingRow(
                    id=policy_binding_id,
                    session_login="lucy_utopia_policy",
                    actor_principal_id=policy_id,
                    target_service_binding_id=service_binding_id,
                    content_scope_id=scope_id,
                    actor_role="policy_notary",
                    allowed_actions=[
                        "sensitive.permit.issue",
                        "sensitive.grant.issue",
                        "sensitive.receipt.attest",
                        "sensitive.deletion_manifest.issue",
                    ],
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
                RealmSensitiveActorBindingRow(
                    id=workflow_binding_id,
                    session_login="lucy_utopia_sensitive_workflow",
                    actor_principal_id=workflow_id,
                    target_service_binding_id=service_binding_id,
                    content_scope_id=scope_id,
                    actor_role="sensitive_workflow",
                    allowed_actions=[
                        "sensitive.operation.claim",
                        "sensitive.operation.reconcile",
                    ],
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
            ]
        )
        session.add_all(
            [
                RealmExecutorBindingV2Row(
                id=executor_binding_id,
                content_scope_id=scope_id,
                action="evidence.retrieve",
                caller_identity="arn:aws:iam::123456789012:role/utopia-evidence-workflow",
                executor_identity="lucy-utopia-evidence-executor-v13",
                executor_alias_arn=(
                    "arn:aws:lambda:us-east-1:123456789012:"
                    "function:lucy-utopia-evidence-executor-v13:production"
                ),
                executor_version=1,
                receipt_key_id="utopia-retrieval-receipt-v13-test",
                binding_generation=1,
                node_authz_epoch=1,
                policy_version=1,
                active=True,
                created_at=now,
                ),
                RealmExecutorBindingV2Row(
                    id=deletion_executor_binding_id,
                    content_scope_id=scope_id,
                    action="evidence.delete",
                    caller_identity=(
                        "arn:aws:iam::123456789012:role/utopia-deletion-workflow"
                    ),
                    executor_identity="lucy-utopia-deletion-executor-v13",
                    executor_alias_arn=(
                        "arn:aws:lambda:us-east-1:123456789012:"
                        "function:lucy-utopia-deletion-executor-v13:production"
                    ),
                    executor_version=1,
                    receipt_key_id="utopia-deletion-receipt-v13-test",
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
            ]
        )
    return {
        "account": foundation.account_id,
        "node": foundation.node_id,
        "tenure": foundation.tenure_id,
        "realm": foundation.realm_id,
        "workspace": foundation.workspace_id,
        "channel": foundation.channel_binding_id,
        "owner": owner_id,
        "evidence": evidence_id,
        "scope": scope_id,
        "service_binding": service_binding_id,
        "deployment": deployment_id,
    }


def _scope(realm: dict[str, UUID]) -> OriginScopeV1:
    return OriginScopeV1(
        tenant_account_id=realm["account"],
        node_id=realm["node"],
        node_tenure_id=realm["tenure"],
        tenure_epoch=1,
        security_realm_id=realm["realm"],
        storage_epoch=1,
    )


def _permit(
    realm: dict[str, UUID],
    *,
    permit_id: UUID | None = None,
    evidence_id: UUID | None = None,
    action: SensitiveActionV2 = SensitiveActionV2.EVIDENCE_RETRIEVE,
) -> SensitiveActionPermitV3:
    now = datetime.now(UTC)
    unsigned = SensitiveActionPermitV3(
        key_id="policy-v13-test",
        issuer="lucy-policy-v13-test",
        environment=DeploymentEnvironment.TEST,
        issued_at=now,
        permit_id=permit_id or uuid4(),
        action=action,
        reason=(
            SensitiveReasonCode.OWNER_REQUEST
            if action == SensitiveActionV2.EVIDENCE_DELETE
            else SensitiveReasonCode.OWNER_REVIEW
        ),
        principal_id=realm["owner"],
        service_principal_id=realm["evidence"],
        service_binding_id=realm["service_binding"],
        service_binding_generation=1,
        operation_id=uuid4(),
        target_scope=_scope(realm),
        workspace_id=realm["workspace"],
        resource_selector=ExactObjectSelectorV1(
            object_id=evidence_id or uuid4(), object_version=1
        ),
        execution_binding=ExecutionBindingV1(
            deployment_id=realm["deployment"],
            active_realm_id=realm["realm"],
            active_storage_epoch=1,
            realm_binding_generation=1,
            node_authz_epoch=1,
        ),
        owner_assertion_id=uuid4(),
        owner_assertion_digest="1" * 64,
        approval_digest="2" * 64,
        policy_version=1,
        membership_generation=1,
        channel_binding_id=realm["channel"],
        channel_generation=1,
        permit_claim_deadline=now + timedelta(seconds=60),
        execution_completion_deadline=now + timedelta(minutes=2),
        max_records=90 if action == SensitiveActionV2.EVIDENCE_DELETE else 1,
        max_bytes=131_072 if action == SensitiveActionV2.EVIDENCE_DELETE else 65_536,
        nonce=uuid4().hex,
    )
    return Ed25519V13Signer(
        ed25519.Ed25519PrivateKey.generate(),
        key_id="policy-v13-test",
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
    ).sign(unsigned)


def test_policy_issues_then_workflow_claims_exact_realm_permit(realm: dict[str, UUID]) -> None:
    assert POLICY_URL and WORKFLOW_URL and RAYMOND_WORKFLOW_URL and OWNER_URL
    permit = _permit(realm)
    policy = create_engine(POLICY_URL)
    workflow = create_engine(WORKFLOW_URL)
    raymond = create_engine(RAYMOND_WORKFLOW_URL)
    owner = create_engine(OWNER_URL)
    with policy.begin() as connection:
        issued = connection.execute(
            text("SELECT lucy.issue_sensitive_action_permit_v3(:permit,:key)"),
            {"permit": permit.model_dump_json(), "key": "issue-one"},
        ).scalar_one()
        replayed = connection.execute(
            text("SELECT lucy.issue_sensitive_action_permit_v3(:permit,:key)"),
            {"permit": permit.model_dump_json(), "key": "issue-one"},
        ).scalar_one()
    assert issued == replayed == permit.permit_id
    with workflow.begin() as connection:
        first = connection.execute(
            text("SELECT lucy.claim_sensitive_operation_v2(:permit,:key)"),
            {"permit": permit.permit_id, "key": "claim-one"},
        ).scalar_one()
        replay = connection.execute(
            text("SELECT lucy.claim_sensitive_operation_v2(:permit,:key)"),
            {"permit": permit.permit_id, "key": "claim-one"},
        ).scalar_one()
    assert first == {"operation_id": str(permit.operation_id), "replayed": False}
    assert replay == {"operation_id": str(permit.operation_id), "replayed": True}
    with owner.connect() as connection:
        stored_digest = connection.execute(
            text("SELECT permit_digest FROM lucy.sensitive_action_permits_v3 WHERE id=:id"),
            {"id": permit.permit_id},
        ).scalar_one()
        event_types = connection.execute(
            text(
                "SELECT event_type FROM lucy.sensitive_operation_events_v2 "
                "WHERE operation_id=:id ORDER BY occurred_at"
            ),
            {"id": permit.operation_id},
        ).scalars().all()
    assert stored_digest == permit.unsigned_digest_hex()
    assert event_types == ["sensitive.permit_issued", "sensitive.operation_claimed"]
    with pytest.raises(DBAPIError, match="claim unavailable"), raymond.begin() as connection:
        connection.execute(
            text("SELECT lucy.claim_sensitive_operation_v2(:permit,:key)"),
            {"permit": permit.permit_id, "key": "foreign"},
        )
    with pytest.raises(DBAPIError, match="permission denied"), workflow.begin() as connection:
        connection.execute(
            text("INSERT INTO lucy.sensitive_action_permits_v3(id) VALUES (:id)"),
            {"id": uuid4()},
        )


def test_current_authority_is_required_at_issue_and_claim(realm: dict[str, UUID]) -> None:
    assert POLICY_URL and WORKFLOW_URL and OWNER_URL
    policy = create_engine(POLICY_URL)
    workflow = create_engine(WORKFLOW_URL)
    owner = create_engine(OWNER_URL)
    permit = _permit(realm)
    with policy.begin() as connection:
        connection.execute(
            text("SELECT lucy.issue_sensitive_action_permit_v3(:permit,:key)"),
            {"permit": permit.model_dump_json(), "key": "issue-before-revocation"},
        )
    with owner.begin() as connection:
        connection.execute(
            text(
                "UPDATE lucy.node_memberships SET status='revoked', generation=generation+1 "
                "WHERE principal_id=:owner AND workspace_id=:workspace"
            ),
            {"owner": realm["owner"], "workspace": realm["workspace"]},
        )
    with pytest.raises(DBAPIError, match="authority is stale"), workflow.begin() as connection:
        connection.execute(
            text("SELECT lucy.claim_sensitive_operation_v2(:permit,:key)"),
            {"permit": permit.permit_id, "key": "claim-after-revocation"},
        )
    with pytest.raises(DBAPIError, match="authority is unavailable"), policy.begin() as connection:
        later = _permit(realm)
        connection.execute(
            text("SELECT lucy.issue_sensitive_action_permit_v3(:permit,:key)"),
            {"permit": later.model_dump_json(), "key": "issue-after-revocation"},
        )


def test_scoped_off_record_receipts_fail_closed_across_transitions(
    realm: dict[str, UUID],
) -> None:
    assert ARCHIVE_URL and OWNER_URL
    archive = create_engine(ARCHIVE_URL)
    owner = create_engine(OWNER_URL)
    conversation = "synthetic-utopia-conversation"
    scope = _scope(realm)
    evidence_id, representation_id, key_ref = uuid4(), uuid4(), uuid4()
    ciphertext = b"synthetic-capturable-realm-ciphertext"
    digest = hashlib.sha256(ciphertext).hexdigest()
    payload = EvidencePayloadBindingV2(
        evidence_id=evidence_id,
        original_scope=scope,
        record_version=1,
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        content_nonce_b64=base64.b64encode(b"123456789012").decode("ascii"),
        authenticated_header_b64=base64.b64encode(b"synthetic-aad").decode("ascii"),
        payload_ciphertext_digest=digest,
    )
    wrapper = EvidenceWrapperBindingV2(
        representation_id=representation_id,
        wrapping_scope=scope,
        wrapped_key_ref=key_ref,
        encryption_context=KmsEncryptionContextV2(
            tenant_account_id=scope.tenant_account_id,
            node_id=scope.node_id,
            node_tenure_id=scope.node_tenure_id,
            tenure_epoch=scope.tenure_epoch,
            security_realm_id=scope.security_realm_id,
            storage_epoch=scope.storage_epoch,
            evidence_id=evidence_id,
        ),
        payload_ciphertext_digest=digest,
    )

    def accept(turn: str) -> dict[str, object]:
        with archive.begin() as connection:
            return connection.execute(
                text("SELECT lucy.accept_scoped_capture_turn_v1(:conversation,:turn)"),
                {"conversation": conversation, "turn": turn},
            ).scalar_one()

    def set_mode(enabled: bool, key: str) -> dict[str, object]:
        with archive.begin() as connection:
            return connection.execute(
                text("SELECT lucy.set_scoped_capture_mode_v1(:conversation,:enabled,:key)"),
                {"conversation": conversation, "enabled": enabled, "key": key},
            ).scalar_one()

    assert accept("before-off") == {"capture_enabled": True, "version": 0, "replayed": False}
    assert set_mode(False, "off-transition") == {
        "capture_enabled": False,
        "version": 1,
        "replayed": False,
    }
    assert set_mode(False, "off-transition")["replayed"] is True
    with pytest.raises(DBAPIError, match="idempotency conflict"), archive.begin() as connection:
        connection.execute(
            text("SELECT lucy.set_scoped_capture_mode_v1(:conversation,true,:key)"),
            {"conversation": conversation, "key": "off-transition"},
        )
    assert accept("while-off")["capture_enabled"] is False
    for turn in ("before-off", "while-off"):
        with (
            pytest.raises(DBAPIError, match="not authorized for retention"),
            archive.begin() as connection,
        ):
            connection.execute(
                text(
                    "SELECT lucy.register_capturable_scoped_evidence_v2("
                    ":conversation,:turn,:payload,:wrapper,'owner_conversation','[]',:key)"
                ),
                {
                    "conversation": conversation,
                    "turn": turn,
                    "payload": payload.model_dump_json(),
                    "wrapper": wrapper.model_dump_json(),
                    "key": f"blocked-{turn}",
                },
            )
    assert set_mode(True, "on-transition")["version"] == 2
    assert accept("after-on")["capture_enabled"] is True
    with archive.begin() as connection:
        archived = connection.execute(
            text(
                "SELECT lucy.register_capturable_scoped_evidence_v2("
                ":conversation,'after-on',:payload,:wrapper,'owner_conversation','[]',:key)"
            ),
            {
                "conversation": conversation,
                "payload": payload.model_dump_json(),
                "wrapper": wrapper.model_dump_json(),
                "key": "allowed-after-on",
            },
        ).scalar_one()
    assert archived == {
        "evidence_id": str(evidence_id),
        "representation_id": str(representation_id),
        "replayed": False,
    }
    with pytest.raises(DBAPIError, match="permission denied"), archive.begin() as connection:
        connection.execute(text("SELECT * FROM lucy.scoped_capture_receipts_v1"))
    with owner.connect() as connection:
        receipts = connection.execute(
            text(
                "SELECT source_turn_id,capture_enabled,capture_version FROM "
                "lucy.scoped_capture_receipts_v1 ORDER BY source_turn_id"
            )
        ).all()
    assert receipts == [
        ("after-on", True, 2),
        ("before-off", True, 0),
        ("while-off", False, 1),
    ]


def test_archive_commit_protocol_is_retry_safe_and_rechecks_capture(
    realm: dict[str, UUID],
) -> None:
    assert ARCHIVE_URL and OWNER_URL and RAYMOND_WORKFLOW_URL
    archive = create_engine(ARCHIVE_URL)
    owner = create_engine(OWNER_URL)
    foreign = create_engine(RAYMOND_WORKFLOW_URL)
    conversation = "synthetic-archive-commit"
    request_commitment = canonical_sha256({"plaintext": "synthetic owner message"})

    with archive.begin() as connection:
        receipt = connection.execute(
            text("SELECT lucy.accept_scoped_capture_turn_v1(:conversation,'turn-1')"),
            {"conversation": conversation},
        ).scalar_one()
        assert receipt["capture_enabled"] is True
        assert connection.execute(
            text("SELECT lucy.get_scoped_capture_mode_v1(:conversation)"),
            {"conversation": conversation},
        ).scalar_one() == {"capture_enabled": True, "version": 0, "replayed": False}
        claim = connection.execute(
            text(
                "SELECT lucy.claim_capturable_scoped_archive_v1("
                ":conversation,'turn-1','archive-op-1',:commitment,"
                "'owner_conversation','[]')"
            ),
            {"conversation": conversation, "commitment": request_commitment},
        ).scalar_one()
        replay = connection.execute(
            text(
                "SELECT lucy.claim_capturable_scoped_archive_v1("
                ":conversation,'turn-1','archive-op-1',:commitment,"
                "'owner_conversation','[]')"
            ),
            {"conversation": conversation, "commitment": request_commitment},
        ).scalar_one()
    assert claim["stage"] == "INTENT_RECORDED"
    assert claim["replayed"] is False
    assert replay == {**claim, "replayed": True}

    with (
        pytest.raises(DBAPIError, match="idempotency conflict"),
        archive.begin() as connection,
    ):
        connection.execute(
            text(
                "SELECT lucy.claim_capturable_scoped_archive_v1("
                ":conversation,'turn-1','archive-op-1',:commitment,"
                "'owner_conversation','[]')"
            ),
            {"conversation": conversation, "commitment": "f" * 64},
        )

    ciphertext = b"synthetic-realm-archive-ciphertext"
    ciphertext_digest = hashlib.sha256(ciphertext).hexdigest()
    scope = _scope(realm)
    payload = EvidencePayloadBindingV2(
        evidence_id=UUID(claim["evidence_id"]),
        original_scope=scope,
        record_version=1,
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        content_nonce_b64=base64.b64encode(b"123456789012").decode("ascii"),
        authenticated_header_b64=base64.b64encode(b"synthetic-aad").decode("ascii"),
        payload_ciphertext_digest=ciphertext_digest,
    )
    wrapper = EvidenceWrapperBindingV2(
        representation_id=UUID(claim["representation_id"]),
        wrapping_scope=scope,
        wrapped_key_ref=UUID(claim["wrapped_key_ref"]),
        encryption_context=KmsEncryptionContextV2(
            tenant_account_id=scope.tenant_account_id,
            node_id=scope.node_id,
            node_tenure_id=scope.node_tenure_id,
            tenure_epoch=scope.tenure_epoch,
            security_realm_id=scope.security_realm_id,
            storage_epoch=scope.storage_epoch,
            evidence_id=UUID(claim["evidence_id"]),
        ),
        payload_ciphertext_digest=ciphertext_digest,
    )
    envelope = RealmArchiveEnvelopeV1(
        payload_binding=payload,
        wrapper_binding=wrapper,
        keyed_commitment="a" * 64,
        request_commitment=request_commitment,
        kms_request_id="synthetic-kms-request",
    ).model_dump(mode="json")
    envelope_digest = canonical_sha256(envelope)

    with archive.begin() as connection:
        outcome = connection.execute(
            text(
                "SELECT lucy.record_scoped_archive_aws_outcome_v1("
                ":operation_id,:envelope,:digest)"
            ),
            {
                "operation_id": claim["operation_id"],
                "envelope": json.dumps(envelope),
                "digest": envelope_digest,
            },
        ).scalar_one()
        outcome_replay = connection.execute(
            text(
                "SELECT lucy.record_scoped_archive_aws_outcome_v1("
                ":operation_id,:envelope,:digest)"
            ),
            {
                "operation_id": claim["operation_id"],
                "envelope": json.dumps(envelope),
                "digest": envelope_digest,
            },
        ).scalar_one()
        reconciled = connection.execute(
            text("SELECT lucy.reconcile_capturable_scoped_archive_v1(:operation_id)"),
            {"operation_id": claim["operation_id"]},
        ).scalar_one()
        reconciled_replay = connection.execute(
            text("SELECT lucy.reconcile_capturable_scoped_archive_v1(:operation_id)"),
            {"operation_id": claim["operation_id"]},
        ).scalar_one()
    assert outcome["replayed"] is False
    assert outcome_replay == {**outcome, "replayed": True}
    assert reconciled["replayed"] is False
    assert reconciled_replay == {**reconciled, "replayed": True}
    assert reconciled["evidence_id"] == claim["evidence_id"]

    with pytest.raises(DBAPIError, match="permission denied"), archive.connect() as connection:
        connection.execute(text("SELECT * FROM lucy.scoped_archive_intents_v1"))
    with pytest.raises(DBAPIError, match="permission denied"), foreign.begin() as connection:
        connection.execute(
            text("SELECT lucy.reconcile_capturable_scoped_archive_v1(:operation_id)"),
            {"operation_id": claim["operation_id"]},
        )
    with owner.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT count(*) FROM lucy.scoped_evidence_records_v2 "
                "WHERE id=:evidence_id"
            ),
            {"evidence_id": claim["evidence_id"]},
        ) == 1

    with archive.begin() as connection:
        connection.execute(
            text("SELECT lucy.accept_scoped_capture_turn_v1(:conversation,'turn-2')"),
            {"conversation": conversation},
        )
        pending = connection.execute(
            text(
                "SELECT lucy.claim_capturable_scoped_archive_v1("
                ":conversation,'turn-2','archive-op-2',:commitment,"
                "'owner_conversation','[]')"
            ),
            {"conversation": conversation, "commitment": "b" * 64},
        ).scalar_one()
        pending_envelope = {
            **envelope,
            "payload_binding": {
                **envelope["payload_binding"],
                "evidence_id": pending["evidence_id"],
            },
            "wrapper_binding": {
                **envelope["wrapper_binding"],
                "representation_id": pending["representation_id"],
                "wrapped_key_ref": pending["wrapped_key_ref"],
                "encryption_context": {
                    **envelope["wrapper_binding"]["encryption_context"],
                    "evidence_id": pending["evidence_id"],
                },
            },
            "request_commitment": "b" * 64,
        }
        connection.execute(
            text(
                "SELECT lucy.record_scoped_archive_aws_outcome_v1("
                ":operation_id,:envelope,:digest)"
            ),
            {
                "operation_id": pending["operation_id"],
                "envelope": json.dumps(pending_envelope),
                "digest": canonical_sha256(pending_envelope),
            },
        )
        connection.execute(
            text("SELECT lucy.set_scoped_capture_mode_v1(:conversation,false,'withdraw-1')"),
            {"conversation": conversation},
        )
        assert connection.execute(
            text("SELECT lucy.get_scoped_capture_mode_v1(:conversation)"),
            {"conversation": conversation},
        ).scalar_one() == {"capture_enabled": False, "version": 1, "replayed": False}
    with (
        pytest.raises(DBAPIError, match="not authorized for retention"),
        archive.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.reconcile_capturable_scoped_archive_v1(:operation_id)"),
            {"operation_id": pending["operation_id"]},
        )
    archive.dispose()
    owner.dispose()
    foreign.dispose()


def test_realm_runtime_preserves_existing_hermes_archive_contract(
    realm: dict[str, UUID],
) -> None:
    assert ARCHIVE_URL and OWNER_URL

    class Backend:
        def __init__(self) -> None:
            self.envelopes: dict[UUID, RealmArchiveEnvelopeV1] = {}
            self.generate_calls = 0

        def generate_data_key(
            self, *, key_arn: str, encryption_context: dict[str, str]
        ) -> GeneratedDataKeyV1:
            self.generate_calls += 1
            return GeneratedDataKeyV1(
                b"d" * 32, b"synthetic-wrapped-dek", key_arn, "synthetic-kms-request"
            )

        def load_archive_envelope(self, key_ref: UUID) -> RealmArchiveEnvelopeV1 | None:
            return self.envelopes.get(key_ref)

        def put_archive_envelope(
            self,
            *,
            envelope: RealmArchiveEnvelopeV1,
            wrapped_key: bytes,
            key_arn: str,
        ) -> None:
            assert wrapped_key and key_arn
            self.envelopes[envelope.wrapper_binding.wrapped_key_ref] = envelope

    sessions = create_session_factory(ARCHIVE_URL)
    store = PostgresRealmArchiveCommitStore(sessions)
    backend = Backend()
    encryptor = RealmArchiveEncryptor(
        backend,
        RealmArchiveIdentityV1(
            target_scope=_scope(realm),
            evidence_key_arn=(
                "arn:aws:kms:us-east-1:123456789012:"
                "key/11111111-1111-4111-8111-111111111111"
            ),
            record_version=1,
        ),
        commitment_key=b"c" * 32,
    )
    runtime = RealmConversationArchiveService(
        store,
        RealmArchiveCommitService(store, encryptor, request_commitment_key=b"r" * 32),
        capture_authorized=True,
    )
    assert runtime.accept_turn(
        TurnCaptureInput(
            platform="telegram",
            source_conversation_id="runtime-conversation",
            source_turn_id="runtime-turn",
        )
    ).capture_enabled
    request = ConversationMessageArchiveInput(
        platform="telegram",
        source_conversation_id="runtime-conversation",
        source_turn_id="runtime-turn",
        source_message_id="runtime-message",
        role="user",
        content="synthetic owner message",
    )
    first = runtime.preserve_message("runtime-archive-1", request)
    replay = runtime.preserve_message("runtime-archive-1", request)
    assert first.archived and first.capture_enabled and not first.replayed
    assert replay.evidence_id == first.evidence_id and replay.replayed
    assert backend.generate_calls == 1
    assert len(backend.envelopes) == 1

    owner = create_engine(OWNER_URL)
    with owner.connect() as connection:
        assert connection.scalar(
            text("SELECT count(*) FROM lucy.scoped_evidence_records_v2 WHERE id=:id"),
            {"id": first.evidence_id},
        ) == 1
    owner.dispose()


def test_archive_registers_and_workflow_freezes_exact_claimed_package(
    realm: dict[str, UUID],
) -> None:
    assert (
        ARCHIVE_URL
        and POLICY_URL
        and WORKFLOW_URL
        and RAYMOND_WORKFLOW_URL
        and FINALITY_URL
        and OWNER_URL
    )
    evidence_id, representation_id, key_ref = uuid4(), uuid4(), uuid4()
    ciphertext = b"synthetic-realm-ciphertext-and-gcm-tag"
    digest = hashlib.sha256(ciphertext).hexdigest()
    scope = _scope(realm)
    payload = EvidencePayloadBindingV2(
        evidence_id=evidence_id,
        original_scope=scope,
        record_version=1,
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        content_nonce_b64=base64.b64encode(b"123456789012").decode("ascii"),
        authenticated_header_b64=base64.b64encode(b"synthetic-aad").decode("ascii"),
        payload_ciphertext_digest=digest,
    )
    wrapper = EvidenceWrapperBindingV2(
        representation_id=representation_id,
        wrapping_scope=scope,
        wrapped_key_ref=key_ref,
        encryption_context=KmsEncryptionContextV2(
            tenant_account_id=scope.tenant_account_id,
            node_id=scope.node_id,
            node_tenure_id=scope.node_tenure_id,
            tenure_epoch=scope.tenure_epoch,
            security_realm_id=scope.security_realm_id,
            storage_epoch=scope.storage_epoch,
            evidence_id=evidence_id,
        ),
        payload_ciphertext_digest=digest,
    )
    archive = create_engine(ARCHIVE_URL)
    policy = create_engine(POLICY_URL)
    workflow = create_engine(WORKFLOW_URL)
    owner = create_engine(OWNER_URL)
    with archive.begin() as connection:
        first = connection.execute(
            text(
                "SELECT lucy.register_scoped_evidence_v2("
                ":payload,:wrapper,:classification,:lineage,:key)"
            ),
            {
                "payload": payload.model_dump_json(),
                "wrapper": wrapper.model_dump_json(),
                "classification": "owner_conversation",
                "lineage": "[]",
                "key": "archive-one",
            },
        ).scalar_one()
        replay = connection.execute(
            text(
                "SELECT lucy.register_scoped_evidence_v2("
                ":payload,:wrapper,:classification,:lineage,:key)"
            ),
            {
                "payload": payload.model_dump_json(),
                "wrapper": wrapper.model_dump_json(),
                "classification": "owner_conversation",
                "lineage": "[]",
                "key": "archive-one",
            },
        ).scalar_one()
    assert first["replayed"] is False
    assert replay["replayed"] is True
    foreign_wrapper = wrapper.model_copy(
        update={
            "wrapping_scope": scope.model_copy(
                update={"security_realm_id": uuid4()}
            )
        }
    )
    with (
        pytest.raises(DBAPIError, match="scoped evidence realm binding is unavailable"),
        archive.begin() as connection,
    ):
        connection.execute(
            text(
                "SELECT lucy.register_scoped_evidence_v2("
                ":payload,:wrapper,:classification,:lineage,:key)"
            ),
            {
                "payload": payload.model_dump_json(),
                "wrapper": foreign_wrapper.model_dump_json(),
                "classification": "owner_conversation",
                "lineage": "[]",
                "key": "foreign-archive",
            },
        )
    with pytest.raises(DBAPIError, match="permission denied"), archive.begin() as connection:
        connection.execute(text("SELECT * FROM lucy.scoped_evidence_payloads_v2"))
    with archive.begin() as connection:
        derived = connection.execute(
            text(
                "SELECT lucy.write_evidence_derived_memory_claim_v2("
                ":key,:subject,:predicate,:object,:confidence,:sources)"
            ),
            {
                "key": "derived-memory-one",
                "subject": "Ray",
                "predicate": "prefers",
                "object": "durable provenance",
                "confidence": 900_000,
                "sources": [evidence_id],
            },
        ).scalar_one()
        derived_replay = connection.execute(
            text(
                "SELECT lucy.write_evidence_derived_memory_claim_v2("
                ":key,:subject,:predicate,:object,:confidence,:sources)"
            ),
            {
                "key": "derived-memory-one",
                "subject": "Ray",
                "predicate": "prefers",
                "object": "durable provenance",
                "confidence": 900_000,
                "sources": [evidence_id],
            },
        ).scalar_one()
    assert derived["replayed"] is False
    assert derived_replay == {**derived, "replayed": True}
    with (
        pytest.raises(DBAPIError, match="scoped evidence derivation unavailable"),
        archive.begin() as connection,
    ):
        connection.execute(
            text(
                "SELECT lucy.write_evidence_derived_memory_claim_v2("
                ":key,:subject,:predicate,:object,:confidence,:sources)"
            ),
            {
                "key": "foreign-derived-memory",
                "subject": "Ray",
                "predicate": "prefers",
                "object": "foreign evidence",
                "confidence": 900_000,
                "sources": [uuid4()],
            },
        )
    permit = _permit(realm, evidence_id=evidence_id)
    with policy.begin() as connection:
        connection.execute(
            text("SELECT lucy.issue_sensitive_action_permit_v3(:permit,:key)"),
            {"permit": permit.model_dump_json(), "key": "issue-archived"},
        )
    with workflow.begin() as connection:
        connection.execute(
            text("SELECT lucy.claim_sensitive_operation_v2(:permit,:key)"),
            {"permit": permit.permit_id, "key": "claim-archived"},
        )
        frozen = connection.execute(
            text("SELECT lucy.freeze_claimed_evidence_package_v2(:operation)"),
            {"operation": permit.operation_id},
        ).scalar_one()
        frozen_replay = connection.execute(
            text("SELECT lucy.freeze_claimed_evidence_package_v2(:operation)"),
            {"operation": permit.operation_id},
        ).scalar_one()
    package = EncryptedEvidencePackageV2.model_validate(frozen["package"])
    assert package.operation_id == permit.operation_id
    assert package.permit_id == permit.permit_id
    assert package.payload_binding.evidence_id == evidence_id
    assert package.wrapper_binding.representation_id == representation_id
    assert frozen["package_digest"] == package.package_digest_hex()
    assert frozen_replay["package_digest"] == frozen["package_digest"]
    assert frozen_replay["replayed"] is True
    with owner.connect() as connection:
        claimed_at = connection.execute(
            text("SELECT claimed_at FROM lucy.sensitive_operations_v2 WHERE id=:id"),
            {"id": permit.operation_id},
        ).scalar_one()
    unsigned_grant = SensitiveExecutionGrantV2(
        key_id="policy-v13-test",
        issuer="lucy-policy-v13-test",
        environment=DeploymentEnvironment.TEST,
        issued_at=datetime.now(UTC),
        grant_id=uuid4(),
        action=permit.action,
        permit_id=permit.permit_id,
        permit_digest=permit.unsigned_digest_hex(),
        operation_id=permit.operation_id,
        caller_identity="arn:aws:iam::123456789012:role/utopia-evidence-workflow",
        target_scope=permit.target_scope,
        workspace_id=permit.workspace_id,
        resource_selector=permit.resource_selector,
        execution_binding=permit.execution_binding,
        encrypted_package_digest=package.package_digest_hex(),
        package_size_bytes=len(canonical_json_bytes(package)),
        idempotency_key="claim-archived",
        executor_identity="lucy-utopia-evidence-executor-v13",
        executor_alias_arn=(
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-utopia-evidence-executor-v13:production"
        ),
        executor_version=1,
        permit_claimed_at=claimed_at,
        permit_claim_deadline=permit.permit_claim_deadline,
        execution_completion_deadline=permit.execution_completion_deadline,
        max_records=1,
        max_bytes=permit.max_bytes,
        nonce=uuid4().hex,
    )
    signer = Ed25519V13Signer(
        ed25519.Ed25519PrivateKey.generate(),
        key_id="policy-v13-test",
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
    )
    wrong_grant = signer.sign(
        unsigned_grant.model_copy(
            update={
                "executor_alias_arn": (
                    "arn:aws:lambda:us-east-1:123456789012:"
                    "function:lucy-utopia-evidence-executor-v13:wrong"
                )
            }
        )
    )
    with (
        pytest.raises(DBAPIError, match="execution grant differs from claimed authority"),
        policy.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.store_sensitive_execution_grant_v2(:operation,:grant)"),
            {"operation": permit.operation_id, "grant": wrong_grant.model_dump_json()},
        )
    grant = signer.sign(unsigned_grant)
    with policy.begin() as connection:
        grant_digest = connection.execute(
            text("SELECT lucy.store_sensitive_execution_grant_v2(:operation,:grant)"),
            {"operation": permit.operation_id, "grant": grant.model_dump_json()},
        ).scalar_one()
        grant_replay = connection.execute(
            text("SELECT lucy.store_sensitive_execution_grant_v2(:operation,:grant)"),
            {"operation": permit.operation_id, "grant": grant.model_dump_json()},
        ).scalar_one()
    assert grant_digest == grant_replay == grant.unsigned_digest_hex()
    completed_at = datetime.now(UTC)
    unsigned_receipt = ExecutorReceiptV2(
        key_id="utopia-retrieval-receipt-v13-test",
        issuer="lucy-utopia-retrieval-executor-v13-test",
        environment=DeploymentEnvironment.TEST,
        issued_at=completed_at,
        signing_key_purpose=V13SigningKeyPurpose.RETRIEVAL_RECEIPT,
        receipt_id=uuid4(),
        action=permit.action,
        executor_identity=grant.executor_identity,
        executor_alias_arn=grant.executor_alias_arn,
        executor_version=grant.executor_version,
        caller_identity=grant.caller_identity,
        target_scope=grant.target_scope,
        execution_binding=grant.execution_binding,
        operation_id=permit.operation_id,
        permit_id=permit.permit_id,
        permit_digest=permit.unsigned_digest_hex(),
        execution_grant_id=grant.grant_id,
        execution_grant_digest=grant.unsigned_digest_hex(),
        package_digest=package.package_digest_hex(),
        result=ExecutorResult.RETRIEVAL_SUCCEEDED,
        lambda_request_id="synthetic-lambda-request",
        kms_request_id="synthetic-kms-request",
        execution_completion_deadline=permit.execution_completion_deadline,
        completed_at=completed_at,
        record_version=1,
        journal_ref=f"retrieval/{permit.operation_id}",
        finality_state="not_applicable",
    )
    receipt = unsigned_receipt.model_copy(
        update={"signature": base64.b64encode(b"synthetic-ecdsa-signature").decode("ascii")}
    )
    wrong_receipt = receipt.model_copy(update={"package_digest": "f" * 64})
    with (
        pytest.raises(DBAPIError, match="verified executor receipt differs from stored grant"),
        policy.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.attest_executor_receipt_v2(:operation,:receipt)"),
            {"operation": permit.operation_id, "receipt": wrong_receipt.model_dump_json()},
        )
    with owner.begin() as connection:
        connection.execute(
            text(
                "UPDATE lucy.realm_executor_bindings_v2 SET active=false, "
                "binding_generation=binding_generation+1 WHERE content_scope_id=:scope "
                "AND action='evidence.retrieve'"
            ),
            {"scope": realm["scope"]},
        )
    with policy.begin() as connection:
        receipt_digest = connection.execute(
            text("SELECT lucy.attest_executor_receipt_v2(:operation,:receipt)"),
            {"operation": permit.operation_id, "receipt": receipt.model_dump_json()},
        ).scalar_one()
        receipt_replay = connection.execute(
            text("SELECT lucy.attest_executor_receipt_v2(:operation,:receipt)"),
            {"operation": permit.operation_id, "receipt": receipt.model_dump_json()},
        ).scalar_one()
    assert receipt_digest == receipt_replay == receipt.unsigned_digest_hex()
    raymond = create_engine(RAYMOND_WORKFLOW_URL)
    with (
        pytest.raises(DBAPIError, match="sensitive reconciliation unavailable"),
        raymond.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.reconcile_sensitive_operation_v2(:operation)"),
            {"operation": permit.operation_id},
        )
    with workflow.begin() as connection:
        reconciled = connection.execute(
            text("SELECT lucy.reconcile_sensitive_operation_v2(:operation)"),
            {"operation": permit.operation_id},
        ).scalar_one()
        reconcile_replay = connection.execute(
            text("SELECT lucy.reconcile_sensitive_operation_v2(:operation)"),
            {"operation": permit.operation_id},
        ).scalar_one()
    assert reconciled == {
        "operation_id": str(permit.operation_id),
        "state": "RECONCILED",
        "result": "retrieval_succeeded",
        "receipt_digest": receipt.unsigned_digest_hex(),
        "replayed": False,
    }
    assert reconcile_replay == {**reconciled, "replayed": True}
    deletion_permit = _permit(
        realm,
        evidence_id=evidence_id,
        action=SensitiveActionV2.EVIDENCE_DELETE,
    )
    with policy.begin() as connection:
        connection.execute(
            text("SELECT lucy.issue_sensitive_action_permit_v3(:permit,:key)"),
            {"permit": deletion_permit.model_dump_json(), "key": "issue-delete-one"},
        )
    with workflow.begin() as connection:
        connection.execute(
            text("SELECT lucy.claim_sensitive_operation_v2(:permit,:key)"),
            {"permit": deletion_permit.permit_id, "key": "claim-delete-one"},
        )
    deletion_targets = (
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.ENCRYPTED_ARCHIVE,
            artifact_id=evidence_id,
            artifact_version=1,
            root_evidence_id=evidence_id,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=representation_id,
            wrapped_key_ref=key_ref,
        ),
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.MEMORY_CLAIM,
            artifact_id=UUID(derived["claim_id"]),
            artifact_version=1,
            root_evidence_id=evidence_id,
            disposition=DeletionDisposition.INVALIDATE,
        ),
    )
    unsigned_manifest = DeletionTargetManifestV2(
        key_id="policy-v13-test",
        issuer="lucy-policy-v13-test",
        environment=DeploymentEnvironment.TEST,
        issued_at=deletion_permit.issued_at,
        manifest_id=uuid4(),
        permit_id=deletion_permit.permit_id,
        permit_digest=deletion_permit.unsigned_digest_hex(),
        operation_id=deletion_permit.operation_id,
        target_scope=deletion_permit.target_scope,
        workspace_id=deletion_permit.workspace_id,
        root_evidence_id=evidence_id,
        root_representation_id=representation_id,
        owner_assertion_id=deletion_permit.owner_assertion_id,
        owner_assertion_digest=deletion_permit.owner_assertion_digest,
        idempotency_key="delete-root-one",
        closure_version=1,
        targets=deletion_targets,
        target_count=len(deletion_targets),
        targets_digest=deletion_targets_digest_v2(deletion_targets),
        tombstone_policy_version=1,
        finality_policy_version=1,
        permit_claim_deadline=deletion_permit.permit_claim_deadline,
        execution_completion_deadline=deletion_permit.execution_completion_deadline,
        nonce=uuid4().hex,
    )
    manifest = Ed25519V13Signer(
        ed25519.Ed25519PrivateKey.generate(),
        key_id="policy-v13-test",
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
    ).sign(unsigned_manifest)
    wrong_manifest = Ed25519V13Signer(
        ed25519.Ed25519PrivateKey.generate(),
        key_id="policy-v13-test",
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
    ).sign(
        unsigned_manifest.model_copy(
            update={
                "targets": (deletion_targets[0],),
                "target_count": 1,
                "targets_digest": deletion_targets_digest_v2((deletion_targets[0],)),
            }
        )
    )
    with (
        pytest.raises(DBAPIError, match="scoped deletion closure is not exact"),
        policy.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.store_scoped_deletion_manifest_v2(:operation,:manifest)"),
            {
                "operation": deletion_permit.operation_id,
                "manifest": wrong_manifest.model_dump_json(),
            },
        )
    with policy.begin() as connection:
        frozen_manifest = connection.execute(
            text("SELECT lucy.store_scoped_deletion_manifest_v2(:operation,:manifest)"),
            {
                "operation": deletion_permit.operation_id,
                "manifest": manifest.model_dump_json(),
            },
        ).scalar_one()
        manifest_replay = connection.execute(
            text("SELECT lucy.store_scoped_deletion_manifest_v2(:operation,:manifest)"),
            {
                "operation": deletion_permit.operation_id,
                "manifest": manifest.model_dump_json(),
            },
        ).scalar_one()
    assert frozen_manifest["target_count"] == 2
    assert frozen_manifest["manifest_digest"] == manifest.unsigned_digest_hex()
    assert manifest_replay == {**frozen_manifest, "replayed": True}
    with owner.connect() as connection:
        deletion_claimed_at = connection.execute(
            text("SELECT claimed_at FROM lucy.sensitive_operations_v2 WHERE id=:id"),
            {"id": deletion_permit.operation_id},
        ).scalar_one()
    unsigned_deletion_grant = SensitiveExecutionGrantV2(
        key_id="policy-v13-test",
        issuer="lucy-policy-v13-test",
        environment=DeploymentEnvironment.TEST,
        issued_at=datetime.now(UTC),
        grant_id=uuid4(),
        action=deletion_permit.action,
        permit_id=deletion_permit.permit_id,
        permit_digest=deletion_permit.unsigned_digest_hex(),
        operation_id=deletion_permit.operation_id,
        caller_identity="arn:aws:iam::123456789012:role/utopia-deletion-workflow",
        target_scope=deletion_permit.target_scope,
        workspace_id=deletion_permit.workspace_id,
        resource_selector=deletion_permit.resource_selector,
        execution_binding=deletion_permit.execution_binding,
        deletion_manifest_id=manifest.manifest_id,
        deletion_manifest_digest=manifest.unsigned_digest_hex(),
        encrypted_package_digest=manifest.unsigned_digest_hex(),
        package_size_bytes=len(canonical_json_bytes(manifest)),
        idempotency_key="claim-delete-one",
        executor_identity="lucy-utopia-deletion-executor-v13",
        executor_alias_arn=(
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-utopia-deletion-executor-v13:production"
        ),
        executor_version=1,
        permit_claimed_at=deletion_claimed_at,
        permit_claim_deadline=deletion_permit.permit_claim_deadline,
        execution_completion_deadline=deletion_permit.execution_completion_deadline,
        max_records=deletion_permit.max_records,
        max_bytes=deletion_permit.max_bytes,
        nonce=uuid4().hex,
    )
    deletion_grant = signer.sign(unsigned_deletion_grant)
    wrong_deletion_grant = signer.sign(
        unsigned_deletion_grant.model_copy(
            update={
                "grant_id": uuid4(),
                "deletion_manifest_digest": "f" * 64,
                "nonce": uuid4().hex,
            }
        )
    )
    with (
        pytest.raises(DBAPIError, match="deletion grant differs from frozen authority"),
        policy.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.store_deletion_execution_grant_v2(:operation,:grant)"),
            {
                "operation": deletion_permit.operation_id,
                "grant": wrong_deletion_grant.model_dump_json(),
            },
        )
    with policy.begin() as connection:
        deletion_grant_digest = connection.execute(
            text("SELECT lucy.store_deletion_execution_grant_v2(:operation,:grant)"),
            {
                "operation": deletion_permit.operation_id,
                "grant": deletion_grant.model_dump_json(),
            },
        ).scalar_one()
        deletion_grant_replay = connection.execute(
            text("SELECT lucy.store_deletion_execution_grant_v2(:operation,:grant)"),
            {
                "operation": deletion_permit.operation_id,
                "grant": deletion_grant.model_dump_json(),
            },
        ).scalar_one()
    assert deletion_grant_digest == deletion_grant_replay
    assert deletion_grant_digest == deletion_grant.unsigned_digest_hex()
    deletion_completed_at = datetime.now(UTC)
    unsigned_deletion_receipt = ExecutorReceiptV2(
        key_id="utopia-deletion-receipt-v13-test",
        issuer="lucy-utopia-deletion-executor-v13-test",
        environment=DeploymentEnvironment.TEST,
        issued_at=deletion_completed_at,
        signing_key_purpose=V13SigningKeyPurpose.DELETION_RECEIPT,
        receipt_id=uuid4(),
        action=deletion_permit.action,
        executor_identity=deletion_grant.executor_identity,
        executor_alias_arn=deletion_grant.executor_alias_arn,
        executor_version=deletion_grant.executor_version,
        caller_identity=deletion_grant.caller_identity,
        target_scope=deletion_grant.target_scope,
        execution_binding=deletion_grant.execution_binding,
        operation_id=deletion_permit.operation_id,
        permit_id=deletion_permit.permit_id,
        permit_digest=deletion_permit.unsigned_digest_hex(),
        execution_grant_id=deletion_grant.grant_id,
        execution_grant_digest=deletion_grant.unsigned_digest_hex(),
        deletion_manifest_id=manifest.manifest_id,
        deletion_manifest_digest=manifest.unsigned_digest_hex(),
        package_digest=manifest.unsigned_digest_hex(),
        result=ExecutorResult.DELETION_SUCCEEDED,
        lambda_request_id="synthetic-deletion-lambda-request",
        transaction_client_token=f"delete-{deletion_permit.operation_id}",
        execution_completion_deadline=deletion_permit.execution_completion_deadline,
        completed_at=deletion_completed_at,
        record_version=1,
        journal_ref=f"deletion/{deletion_permit.operation_id}",
        finality_state="operationally_deleted",
    )
    deletion_receipt = unsigned_deletion_receipt.model_copy(
        update={"signature": base64.b64encode(b"synthetic-ecdsa-signature").decode("ascii")}
    )
    wrong_deletion_receipt = deletion_receipt.model_copy(
        update={"deletion_manifest_digest": "e" * 64}
    )
    with (
        pytest.raises(DBAPIError, match="verified deletion receipt differs from stored grant"),
        policy.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.attest_deletion_executor_receipt_v2(:operation,:receipt)"),
            {
                "operation": deletion_permit.operation_id,
                "receipt": wrong_deletion_receipt.model_dump_json(),
            },
        )
    with policy.begin() as connection:
        deletion_receipt_digest = connection.execute(
            text("SELECT lucy.attest_deletion_executor_receipt_v2(:operation,:receipt)"),
            {
                "operation": deletion_permit.operation_id,
                "receipt": deletion_receipt.model_dump_json(),
            },
        ).scalar_one()
        deletion_receipt_replay = connection.execute(
            text("SELECT lucy.attest_deletion_executor_receipt_v2(:operation,:receipt)"),
            {
                "operation": deletion_permit.operation_id,
                "receipt": deletion_receipt.model_dump_json(),
            },
        ).scalar_one()
    assert deletion_receipt_digest == deletion_receipt_replay
    assert deletion_receipt_digest == deletion_receipt.unsigned_digest_hex()
    with (
        pytest.raises(DBAPIError, match="sensitive reconciliation unavailable"),
        workflow.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.reconcile_sensitive_operation_v2(:operation)"),
            {"operation": deletion_permit.operation_id},
        )
    with (
        pytest.raises(DBAPIError, match="scoped deletion reconciliation unavailable"),
        raymond.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.reconcile_scoped_deletion_v2(:operation)"),
            {"operation": deletion_permit.operation_id},
        )
    with workflow.begin() as connection:
        deletion_reconciled = connection.execute(
            text("SELECT lucy.reconcile_scoped_deletion_v2(:operation)"),
            {"operation": deletion_permit.operation_id},
        ).scalar_one()
        deletion_reconcile_replay = connection.execute(
            text("SELECT lucy.reconcile_scoped_deletion_v2(:operation)"),
            {"operation": deletion_permit.operation_id},
        ).scalar_one()
    assert deletion_reconciled["state"] == "FINALITY_PENDING"
    assert deletion_reconciled["result"] == "deletion_succeeded"
    assert deletion_reconciled["finality_not_before"] is not None
    assert deletion_reconcile_replay == {**deletion_reconciled, "replayed": True}
    with owner.connect() as connection:
        deletion_effective_at = connection.execute(
            text(
                "SELECT effective_at FROM lucy.scoped_deletion_effects_v2 "
                "WHERE operation_id=:operation"
            ),
            {"operation": deletion_permit.operation_id},
        ).scalar_one()
    observed_at = datetime.now(UTC)
    recovery_inventory = DeletionRecoveryInventoryV1(
        operation_id=deletion_permit.operation_id,
        metadata_observed_at=observed_at,
        pitr_status="ENABLED",
        pitr_recovery_period_days=30,
        pitr_earliest_restorable_at=deletion_effective_at - timedelta(seconds=1),
        pitr_latest_restorable_at=observed_at,
        on_demand_backup_count=0,
        aws_backup_recovery_point_count=0,
        export_count=0,
        import_count=0,
        global_replica_count=0,
        quarantine_table_count=0,
        stream_enabled=False,
        metadata_inventory_digest="a" * 64,
    )
    finality = create_engine(FINALITY_URL)
    with finality.begin() as connection:
        finality_extended = connection.execute(
            text("SELECT lucy.record_scoped_finality_inventory_v2(:operation,:inventory)"),
            {
                "operation": deletion_permit.operation_id,
                "inventory": recovery_inventory.model_dump_json(),
            },
        ).scalar_one()
        finality_replay = connection.execute(
            text("SELECT lucy.record_scoped_finality_inventory_v2(:operation,:inventory)"),
            {
                "operation": deletion_permit.operation_id,
                "inventory": recovery_inventory.model_dump_json(),
            },
        ).scalar_one()
    assert finality_extended["status"] == "EXTENDED"
    assert finality_extended["recoverable_copy_count"] == 1
    assert finality_extended["replayed"] is False
    assert finality_replay == {**finality_extended, "replayed": True}
    with (
        pytest.raises(DBAPIError, match="scoped finality operation unavailable"),
        finality.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.record_scoped_finality_inventory_v2(:operation,:inventory)"),
            {
                "operation": permit.operation_id,
                "inventory": recovery_inventory.model_copy(
                    update={"operation_id": permit.operation_id}
                ).model_dump_json(),
            },
        )
    with pytest.raises(DBAPIError, match="permission denied"), finality.begin() as connection:
        connection.execute(text("SELECT * FROM lucy.scoped_deletion_effects_v2"))
    with archive.connect() as connection:
        assert connection.execute(
            text("SELECT lucy.search_scoped_memory_v1(:query,:limit)"),
            {"query": "durable", "limit": 10},
        ).scalar_one() == []
    late_retrieval_permit = _permit(realm, evidence_id=evidence_id)
    with policy.begin() as connection:
        connection.execute(
            text("SELECT lucy.issue_sensitive_action_permit_v3(:permit,:key)"),
            {
                "permit": late_retrieval_permit.model_dump_json(),
                "key": "issue-retrieval-after-delete-fence",
            },
        )
    with workflow.begin() as connection:
        connection.execute(
            text("SELECT lucy.claim_sensitive_operation_v2(:permit,:key)"),
            {
                "permit": late_retrieval_permit.permit_id,
                "key": "claim-retrieval-after-delete-fence",
            },
        )
    with (
        pytest.raises(DBAPIError, match="scoped evidence is deletion fenced"),
        workflow.begin() as connection,
    ):
        connection.execute(
            text("SELECT lucy.freeze_claimed_evidence_package_v2(:operation)"),
            {"operation": late_retrieval_permit.operation_id},
        )
    with (
        pytest.raises(DBAPIError, match="scoped evidence derivation unavailable"),
        archive.begin() as connection,
    ):
        connection.execute(
            text(
                "SELECT lucy.write_evidence_derived_memory_claim_v2("
                ":key,:subject,:predicate,:object,:confidence,:sources)"
            ),
            {
                "key": "derived-after-fence",
                "subject": "Ray",
                "predicate": "prefers",
                "object": "late derivation",
                "confidence": 900_000,
                "sources": [evidence_id],
            },
        )
    with pytest.raises(DBAPIError, match="permission denied"), workflow.begin() as connection:
        connection.execute(text("SELECT * FROM lucy.scoped_evidence_payloads_v2"))
    with owner.connect() as connection:
        assert connection.execute(
            text("SELECT count(*) FROM lucy.sensitive_operation_packages_v2")
        ).scalar_one() == 1
        assert connection.execute(
            text("SELECT count(*) FROM lucy.sensitive_execution_grants_v2")
        ).scalar_one() == 2
        assert connection.execute(
            text("SELECT count(*) FROM lucy.executor_receipt_attestations_v2")
        ).scalar_one() == 2
        assert connection.execute(
            text("SELECT count(*) FROM lucy.scoped_memory_claim_sources_v2")
        ).scalar_one() == 1
        assert connection.execute(
            text("SELECT count(*) FROM lucy.scoped_deletion_manifest_targets_v2")
        ).scalar_one() == 2
        assert connection.execute(
            text("SELECT count(*) FROM lucy.scoped_deletion_effects_v2")
        ).scalar_one() == 1
        assert connection.execute(
            text("SELECT count(*) FROM lucy.scoped_finality_observations_v2")
        ).scalar_one() == 1
        operation_state = connection.execute(
            text(
                "SELECT state,executor_result,executor_receipt_digest "
                "FROM lucy.sensitive_operations_v2 WHERE id=:id"
            ),
            {"id": permit.operation_id},
        ).one()
        assert operation_state == (
            "RECONCILED",
            "retrieval_succeeded",
            receipt.unsigned_digest_hex(),
        )
        deletion_operation_state = connection.execute(
            text(
                "SELECT state,executor_result,executor_receipt_digest "
                "FROM lucy.sensitive_operations_v2 WHERE id=:id"
            ),
            {"id": deletion_permit.operation_id},
        ).one()
        assert deletion_operation_state == (
            "FINALITY_PENDING",
            "deletion_succeeded",
            deletion_receipt.unsigned_digest_hex(),
        )
    with owner.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role='replica'"))
        connection.execute(
            text(
                "DELETE FROM lucy.scoped_evidence_deletion_fences_v2 "
                "WHERE operation_id=:operation"
            ),
            {"operation": deletion_permit.operation_id},
        )
    with archive.connect() as connection:
        assert len(
            connection.execute(
                text("SELECT lucy.search_scoped_memory_v1(:query,:limit)"),
                {"query": "durable", "limit": 10},
            ).scalar_one()
        ) == 1
    scope_digest = canonical_sha256(
        deletion_permit.target_scope,
        prefix=b"lucy:authorized-deletion-recovery-scope:v2\0",
    )
    recovery_bindings = {
        "operation_id": str(deletion_permit.operation_id),
        "permit_digest": deletion_permit.unsigned_digest_hex(),
        "manifest_digest": manifest.unsigned_digest_hex(),
        "grant_digest": deletion_grant.unsigned_digest_hex(),
        "receipt_digest": deletion_receipt.unsigned_digest_hex(),
        "targets_digest": manifest.targets_digest,
        "scope_digest": scope_digest,
    }
    recovery_proof = AuthorizedDeletionRecoveryProofV2(
        operation_id=str(deletion_permit.operation_id),
        permit_id=str(deletion_permit.permit_id),
        manifest_id=str(manifest.manifest_id),
        permit_digest=deletion_permit.unsigned_digest_hex(),
        manifest_digest=manifest.unsigned_digest_hex(),
        grant_digest=deletion_grant.unsigned_digest_hex(),
        receipt_digest=deletion_receipt.unsigned_digest_hex(),
        targets_digest=manifest.targets_digest,
        target_count=manifest.target_count,
        scope_digest=scope_digest,
        completed_at=deletion_receipt.completed_at.isoformat(),
        recovery_digest=canonical_sha256(
            recovery_bindings,
            prefix=b"lucy:authorized-deletion-recovery:v2\0",
        ),
    )
    recovery_contract = build_authorized_deletion_recovery_contract_v2(
        proof=recovery_proof,
        permit=deletion_permit,
        manifest=manifest,
        grant=deletion_grant,
        receipt=deletion_receipt,
        authority_evidence_digest="b" * 64,
    )
    with owner.begin() as connection:
        recovered = connection.execute(
            text(
                "SELECT lucy.apply_scoped_authorized_deletion_recovery_v2("
                "CAST(:recovery AS jsonb))"
            ),
            {"recovery": json.dumps(recovery_contract, separators=(",", ":"))},
        ).scalar_one()
        recovery_replay = connection.execute(
            text(
                "SELECT lucy.apply_scoped_authorized_deletion_recovery_v2("
                "CAST(:recovery AS jsonb))"
            ),
            {"recovery": json.dumps(recovery_contract, separators=(",", ":"))},
        ).scalar_one()
    assert recovered["state"] == "FINALITY_PENDING"
    assert recovered["replayed"] is False
    assert recovered["derived_summary"]["claims_suppressed"] == 1
    assert recovery_replay == {**recovered, "replayed": True}
    wrong_scope_recovery = {
        **recovery_contract,
        "target_scope": {
            **recovery_contract["target_scope"],
            "security_realm_id": str(uuid4()),
        },
    }
    with (
        pytest.raises(DBAPIError, match="scope digest is invalid"),
        owner.begin() as connection,
    ):
        connection.execute(
            text(
                "SELECT lucy.apply_scoped_authorized_deletion_recovery_v2("
                "CAST(:recovery AS jsonb))"
            ),
            {"recovery": json.dumps(wrong_scope_recovery, separators=(",", ":"))},
        )
    with owner.begin() as connection:
        connection.execute(
            text(
                "UPDATE lucy.runtime_admission SET state='ready',storage_epoch=:epoch,"
                "updated_at=now() WHERE singleton"
            ),
            {"epoch": uuid4()},
        )
    with (
        pytest.raises(DBAPIError, match="requires quarantined capture-off storage"),
        owner.begin() as connection,
    ):
        connection.execute(
            text(
                "SELECT lucy.apply_scoped_authorized_deletion_recovery_v2("
                "CAST(:recovery AS jsonb))"
            ),
            {"recovery": json.dumps(recovery_contract, separators=(",", ":"))},
        )
    with owner.begin() as connection:
        connection.execute(
            text(
                "UPDATE lucy.runtime_admission SET state='quarantined',storage_epoch=NULL,"
                "updated_at=now() WHERE singleton"
            )
        )
    with archive.connect() as connection:
        assert connection.execute(
            text("SELECT lucy.search_scoped_memory_v1(:query,:limit)"),
            {"query": "durable", "limit": 10},
        ).scalar_one() == []
    with (
        pytest.raises(DBAPIError, match="scoped evidence derivation unavailable"),
        archive.begin() as connection,
    ):
        connection.execute(
            text(
                "SELECT lucy.write_evidence_derived_memory_claim_v2("
                ":key,:subject,:predicate,:object,:confidence,:sources)"
            ),
            {
                "key": "derived-after-recovery-fence",
                "subject": "Ray",
                "predicate": "prefers",
                "object": "resurrected memory",
                "confidence": 900_000,
                "sources": [evidence_id],
            },
        )
    with owner.connect() as connection:
        assert connection.execute(
            text("SELECT count(*) FROM lucy.scoped_authorized_deletion_recoveries_v2")
        ).scalar_one() == 1
        assert connection.execute(
            text("SELECT count(*) FROM lucy.scoped_recovery_deletion_fences_v2")
        ).scalar_one() == 1
