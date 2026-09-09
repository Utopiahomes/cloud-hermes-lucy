from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from lucy.contracts.security_v1_2 import (
    DeploymentEnvironment,
    SensitiveActionV2,
    SensitiveReasonCode,
)
from lucy.contracts.security_v1_3 import (
    Ed25519V13Signer,
    EncryptedEvidencePackageV2,
    EvidencePayloadBindingV2,
    EvidenceWrapperBindingV2,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    KmsEncryptionContextV2,
    OriginScopeV1,
    SensitiveActionPermitV3,
    V13SigningKeyPurpose,
)
from lucy.db import create_session_factory
from lucy.db.models import (
    RealmBindingRow,
    RealmContentScopeRow,
    RealmSensitiveActorBindingRow,
    RealmServiceBindingRow,
)
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
POLICY_URL = os.getenv("LUCY_TEST_UTOPIA_POLICY_DATABASE_URL")
WORKFLOW_URL = os.getenv("LUCY_TEST_UTOPIA_WORKFLOW_DATABASE_URL")
ARCHIVE_URL = os.getenv("LUCY_TEST_UTOPIA_DATABASE_URL")
RAYMOND_WORKFLOW_URL = os.getenv("LUCY_TEST_RAYMOND_WORKFLOW_DATABASE_URL")
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
                "TRUNCATE lucy.sensitive_operation_packages_v2, "
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
                "GRANT EXECUTE ON FUNCTION lucy.freeze_claimed_evidence_package_v2(uuid) "
                "TO lucy_utopia_sensitive_workflow, lucy_raymond_sensitive_workflow"
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
    with app_sessions() as session:
        realm_binding = session.execute(
            select(RealmBindingRow).where(
                RealmBindingRow.tenure_id == foundation.tenure_id,
                RealmBindingRow.realm_id == foundation.realm_id,
            )
        ).scalar_one()
    scope_id, service_binding_id = uuid4(), uuid4()
    policy_binding_id, workflow_binding_id, archive_binding_id = uuid4(), uuid4(), uuid4()
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
                allowed_actions=["evidence.archive", "evidence.retrieve"],
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
                    id=policy_binding_id,
                    session_login="lucy_utopia_policy",
                    actor_principal_id=policy_id,
                    target_service_binding_id=service_binding_id,
                    content_scope_id=scope_id,
                    actor_role="policy_notary",
                    allowed_actions=["sensitive.permit.issue"],
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
                    allowed_actions=["sensitive.operation.claim"],
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
) -> SensitiveActionPermitV3:
    now = datetime.now(UTC)
    unsigned = SensitiveActionPermitV3(
        key_id="policy-v13-test",
        issuer="lucy-policy-v13-test",
        environment=DeploymentEnvironment.TEST,
        issued_at=now,
        permit_id=permit_id or uuid4(),
        action=SensitiveActionV2.EVIDENCE_RETRIEVE,
        reason=SensitiveReasonCode.OWNER_REVIEW,
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
        max_records=1,
        max_bytes=65_536,
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


def test_archive_registers_and_workflow_freezes_exact_claimed_package(
    realm: dict[str, UUID],
) -> None:
    assert ARCHIVE_URL and POLICY_URL and WORKFLOW_URL and OWNER_URL
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
    with pytest.raises(DBAPIError, match="permission denied"), workflow.begin() as connection:
        connection.execute(text("SELECT * FROM lucy.scoped_evidence_payloads_v2"))
    with owner.connect() as connection:
        assert connection.execute(
            text("SELECT count(*) FROM lucy.sensitive_operation_packages_v2")
        ).scalar_one() == 1
