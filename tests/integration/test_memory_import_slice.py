from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from lucy.archive_crypto import EnvelopeCipher, MemoryArchiveKeyStore
from lucy.chatgpt_manifest import (
    AuthorizedPilotManifestV1,
    LocalChatGPTConversationV1,
    LocalChatGPTMessageV1,
    LocalPilotBuildV1,
    PilotManifestBundleV1,
    manifest_record_for_local_message,
)
from lucy.contracts.canonical import canonical_json_bytes, canonical_sha256
from lucy.contracts.memory_outcome_recovery_v1 import MemoryOutcomeRecoveryPackageV1
from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    DeletionArtifactClassV3,
    DeletionTargetManifestV3,
    DeletionTargetReferenceV3,
    Ed25519V13Signer,
    ExecutionBindingV1,
    OriginScopeV1,
    V13SigningKeyPurpose,
    deletion_targets_digest_v3,
)
from lucy.db import create_session_factory
from lucy.db.models import (
    MemoryImportCampaignV1Row,
    RealmBindingRow,
    RealmContentScopeRow,
    RealmSensitiveActorBindingRow,
    RealmServiceBindingRow,
    ScopedEvidencePayloadV2Row,
    ScopedEvidenceRecordV2Row,
)
from lucy.governed_memory import (
    GovernedMemoryArchive,
    GovernedMemoryExtractor,
    GovernedMemoryPolicy,
    GovernedMemoryReader,
    GovernedMemoryUnavailable,
)
from lucy.governed_memory_outcome import PostgresMemoryOutcomeStore
from lucy.memory_candidate_extraction import (
    ExtractedCandidateDraftV1,
    ExtractedSourceQuoteV1,
    MemoryExtractionOutputV1,
)
from lucy.memory_extraction import memory_extraction_job_id
from lucy.memory_import import (
    AssertionStatus,
    EpistemicStatus,
    ImportManifestV2,
    MemoryCandidatePayloadV1,
    MemoryKind,
    ProtectionClass,
    SourceSpanV1,
    build_archive_requests,
    build_synthetic_manifest,
    extract_synthetic_candidate,
    load_synthetic_conversation,
)
from lucy.memory_outcome import (
    EncryptedMemoryOutcomeJournal,
    MemoryOutcomeBindingV1,
    MemoryOutcomeEnvelopeV1,
    MemoryOutcomeUnavailable,
    memory_outcome_encryption_id,
)
from lucy.memory_outcome_recovery import (
    DurableMemoryOutcomeGrantIssuer,
    MemoryOutcomeGrantRequestV1,
    MemoryOutcomeRecoveryPolicy,
    PostgresMemoryOutcomePolicyStore,
)
from lucy.memory_pilot_transport import (
    MemoryPilotTransportUnavailable,
    PostgresMemoryPilotTransportAdmission,
    prepare_memory_pilot_transport,
)
from lucy.memory_pilot_transport_runner import (
    DeterministicFakeMemoryImportProvider,
    VerifiedMemoryPilotBatchExecutor,
)
from lucy.realm_archive import (
    GeneratedDataKeyV1,
    RealmArchiveEncryptor,
    RealmArchiveEnvelopeV1,
    RealmArchiveIdentityV1,
)
from lucy.scoped_deletion import (
    PostgresScopedDeletionManifestStoreV3,
    ScopedDeletionUnavailable,
)
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
RAYMOND_URL = os.getenv("LUCY_TEST_RAYMOND_DATABASE_URL")
POLICY_URL = os.getenv("LUCY_TEST_RAYMOND_POLICY_DATABASE_URL")
WORKFLOW_URL = os.getenv("LUCY_TEST_RAYMOND_WORKFLOW_DATABASE_URL")
pytestmark = pytest.mark.skipif(not APP_URL, reason="requires PostgreSQL integration database")
TEST_CAMPAIGN_ID = UUID("00000000-0000-4000-8000-000000000055")
TEST_MANIFEST_DIGEST = "c" * 64
TEST_KMS_ARN = (
    "arn:aws:kms:us-east-1:123456789012:"
    "key/11111111-1111-4111-8111-111111111111"
)


class _ImportArchiveBackend:
    def __init__(self) -> None:
        self.envelopes: dict[UUID, RealmArchiveEnvelopeV1] = {}
        self.generate_calls = 0

    def generate_data_key(
        self, *, key_arn: str, encryption_context: dict[str, str]
    ) -> GeneratedDataKeyV1:
        assert encryption_context["purpose"] == "EVIDENCE_DEK"
        self.generate_calls += 1
        return GeneratedDataKeyV1(b"d" * 32, b"synthetic-wrapped", key_arn, "synthetic-kms")

    def load_archive_envelope(self, key_ref: UUID) -> RealmArchiveEnvelopeV1 | None:
        return self.envelopes.get(key_ref)

    def put_archive_envelope(
        self,
        *,
        envelope: RealmArchiveEnvelopeV1,
        wrapped_key: bytes,
        key_arn: str,
    ) -> None:
        assert wrapped_key == b"synthetic-wrapped" and key_arn == TEST_KMS_ARN
        self.envelopes[envelope.wrapper_binding.wrapped_key_ref] = envelope


@pytest.fixture(autouse=True)
def clean_private_realm() -> None:
    assert OWNER_URL is not None
    parsed = make_url(OWNER_URL)
    if (parsed.database, parsed.host, parsed.port) != ("lucy_test", "127.0.0.1", 54329):
        raise RuntimeError("refusing to clear a non-synthetic database")
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.scoped_memory_events_v1,lucy.scoped_memory_claims_v1,"
                "lucy.realm_service_bindings_v1,lucy.realm_content_scopes_v1,"
                "lucy.public_projection_events,lucy.public_projection_routes,"
                "lucy.public_projection_versions,lucy.public_projection_approvals,"
                "lucy.public_projection_candidates,lucy.lucy_instances,"
                "lucy.node_memberships,lucy.channel_bindings,lucy.wallet_registrations,"
                "lucy.workspaces,lucy.realm_bindings,lucy.node_tenures,"
                "lucy.security_realms,lucy.nodes,lucy.tenant_accounts,lucy.principals CASCADE"
            )
        )
    engine.dispose()


def _provision() -> tuple[object, object]:
    assert all((APP_URL, OWNER_URL, RAYMOND_URL, POLICY_URL))
    app = create_session_factory(APP_URL)
    owner = create_session_factory(OWNER_URL)
    tenancy = TenancyService(app)
    foundation = tenancy.create_node_foundation(
        account_slug="raymond",
        account_name="Raymond",
        node_slug="raymond-private",
        node_name="Raymond Private",
        node_kind="person",
        realm_slug="raymond-private-realm",
        workspace_slug="private",
        hostname="raymond.private.test",
        workspace_kind="private",
        channel_kind="internal",
    )
    routine_principal = tenancy.create_principal(
        issuer="https://workload.invalid",
        subject="render:raymond:routine",
        kind="service",
        display_name="Raymond routine",
    )
    policy_principal = tenancy.create_principal(
        issuer="https://workload.invalid",
        subject="render:raymond:policy",
        kind="service",
        display_name="Raymond policy",
    )
    owner_principal = tenancy.create_principal(
        issuer="https://owner.invalid",
        subject="raymond-owner",
        kind="human",
        display_name="Raymond owner",
    )
    tenancy.grant_workspace_membership(
        principal_id=owner_principal,
        workspace_id=foundation.workspace_id,
        role="owner",
    )
    with app() as session:
        realm_binding_id = session.execute(
            select(RealmBindingRow.id).where(
                RealmBindingRow.tenure_id == foundation.tenure_id,
                RealmBindingRow.realm_id == foundation.realm_id,
            )
        ).scalar_one()
    scope_id = uuid4()
    service_id = uuid4()
    archive_actor_id = uuid4()
    policy_actor_id = uuid4()
    workflow_actor_id = uuid4()
    evidence_ids = (uuid4(), uuid4())
    now = datetime.now(UTC)
    with owner.begin() as session:
        session.add(
            RealmContentScopeRow(
                id=scope_id,
                tenant_account_id=foundation.account_id,
                node_id=foundation.node_id,
                node_tenure_id=foundation.tenure_id,
                tenure_epoch=1,
                security_realm_id=foundation.realm_id,
                storage_epoch=1,
                realm_binding_id=realm_binding_id,
                workspace_id=foundation.workspace_id,
                deployment_id=uuid4(),
                created_at=now,
            )
        )
        session.flush()
        session.add(
            RealmServiceBindingRow(
                id=service_id,
                session_login="lucy_raymond_routine",
                service_principal_id=routine_principal,
                content_scope_id=scope_id,
                service_role="realm_evidence",
                allowed_actions=["evidence.archive", "memory.read", "memory.propose"],
                binding_generation=1,
                node_authz_epoch=1,
                policy_version=1,
                active=True,
                created_at=now,
            )
        )
        session.flush()
        session.add_all(
            (
                RealmSensitiveActorBindingRow(
                    id=archive_actor_id,
                    session_login="lucy_raymond_routine",
                    actor_principal_id=routine_principal,
                    target_service_binding_id=service_id,
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
                    id=policy_actor_id,
                    session_login="lucy_raymond_policy",
                    actor_principal_id=policy_principal,
                    target_service_binding_id=service_id,
                    content_scope_id=scope_id,
                    actor_role="policy_notary",
                    allowed_actions=[
                        "memory.candidate.approve",
                        "memory.candidate.promote",
                        "memory.outcome.recover",
                        "memory.protected.read",
                        "sensitive.deletion_manifest.issue",
                        "sensitive.grant.issue",
                        "sensitive.receipt.attest",
                    ],
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
                RealmSensitiveActorBindingRow(
                    id=workflow_actor_id,
                    session_login="lucy_raymond_sensitive_workflow",
                    actor_principal_id=policy_principal,
                    target_service_binding_id=service_id,
                    content_scope_id=scope_id,
                    actor_role="sensitive_workflow",
                    allowed_actions=["sensitive.operation.reconcile"],
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
            )
        )
        session.execute(
            text(
                "INSERT INTO lucy.realm_executor_bindings_v2("
                "id,content_scope_id,action,caller_identity,executor_identity,"
                "executor_alias_arn,executor_version,receipt_key_id,binding_generation,"
                "node_authz_epoch,policy_version,active,created_at) VALUES("
                ":id,:scope,'evidence.delete',:caller,:executor,:alias,1,:receipt,1,1,1,true,:now)"
            ),
            {
                "id": uuid4(),
                "scope": scope_id,
                "caller": "arn:aws:iam::123456789012:role/lucy-raymond-deletion",
                "executor": "lucy-raymond-deletion-executor",
                "alias": (
                    "arn:aws:lambda:us-east-1:123456789012:function:"
                    "lucy-raymond-deletion-executor-v13:realm-v13"
                ),
                "receipt": (
                    "arn:aws:kms:us-east-1:123456789012:key/"
                    "22222222-2222-4222-8222-222222222222"
                ),
                "now": now,
            },
        )
        session.flush()
        session.add(
            MemoryImportCampaignV1Row(
                id=TEST_CAMPAIGN_ID,
                content_scope_id=scope_id,
                policy_actor_binding_id=policy_actor_id,
                manifest_digest=TEST_MANIFEST_DIGEST,
                serialized_manifest={
                    "provider_policy_id": "synthetic-private-zdr-v1",
                    "token_accounting_version": "canonical-json-byte-upper-bound-v1",
                    "max_request_input_tokens": 100,
                    "max_request_output_tokens": 100,
                    "max_request_total_tokens": 200,
                    "records": [
                        {
                            "source_record_id": f"synthetic-record-{index}",
                            "source_revision": 1,
                            "included": True,
                        }
                        for index in range(len(evidence_ids))
                    ]
                },
                extractor_version="synthetic-extractor-v1",
                prompt_version="synthetic-prompt-v1",
                model_route="none",
                max_model_spend_microusd=0,
                max_attempts=2,
                expires_at=now + timedelta(hours=1),
                created_at=now,
            )
        )
        session.flush()
        for index, evidence_id in enumerate(evidence_ids):
            synthetic_ciphertext = bytes([index + 1]) * 80
            session.add(
                ScopedEvidenceRecordV2Row(
                    id=evidence_id,
                    content_scope_id=scope_id,
                    archive_actor_binding_id=archive_actor_id,
                    content_classification="synthetic.private",
                    lineage_refs=[],
                    idempotency_key=(
                        f"memory-import:{TEST_MANIFEST_DIGEST}:"
                        f"synthetic-record-{index}:r1"
                    ),
                    status="active",
                    created_at=now,
                )
            )
            session.flush()
            session.add(
                ScopedEvidencePayloadV2Row(
                    evidence_id=evidence_id,
                    record_version=1,
                    payload_ciphertext_digest=hashlib.sha256(
                        synthetic_ciphertext
                    ).hexdigest(),
                    serialized_payload={
                        "ciphertext_b64": base64.b64encode(
                            synthetic_ciphertext
                        ).decode("ascii")
                    },
                    created_at=now,
                )
            )
        session.execute(
            text(
                "GRANT EXECUTE ON FUNCTION "
                "lucy.stage_memory_import_candidate_v1(jsonb),"
                "lucy.register_memory_import_evidence_v1(uuid,text,jsonb,jsonb),"
                "lucy.search_governed_scoped_memory_v1(text,integer),"
                "lucy.reserve_memory_import_attempt_v1(uuid,text,bigint),"
                "lucy.settle_memory_import_attempt_v1(uuid,bigint,text),"
                "lucy.require_memory_import_sources_v1(uuid,text,jsonb) "
                ",lucy.register_memory_import_job_v1(jsonb) "
                ",lucy.record_memory_import_provider_outcome_v1(jsonb) "
                ",lucy.load_memory_import_provider_outcome_v1(uuid) "
                ",lucy.read_memory_pilot_transport_admission_v1(text,uuid) "
                ",lucy.admit_memory_pilot_transport_v1(text,uuid,text,bigint,uuid,text) "
                "TO lucy_raymond_routine; "
                "GRANT EXECUTE ON FUNCTION "
                "lucy.approve_scoped_memory_candidate_v1(uuid,bigint,text,uuid,text),"
                "lucy.promote_scoped_memory_candidate_v1(uuid,text),"
                "lucy.search_protected_scoped_memory_v1(text,integer,uuid,text) "
                ",lucy.authorize_memory_import_campaign_v1("
                "uuid,jsonb,text,bigint,bigint,timestamptz,text,text,text) "
                ",lucy.build_scoped_deletion_targets_v3(uuid) "
                ",lucy.read_claimed_deletion_authority_v2(uuid) "
                ",lucy.store_scoped_deletion_manifest_v4(uuid,jsonb) "
                ",lucy.read_claimed_sensitive_authority_v2(uuid) "
                ",lucy.store_deletion_execution_grant_v3(uuid,jsonb) "
                ",lucy.attest_deletion_executor_receipt_v3(uuid,jsonb) "
                ",lucy.reconcile_scoped_deletion_v3(uuid) "
                ",lucy.admit_memory_outcome_recovery_v1(jsonb,jsonb,text,text) "
                ",lucy.read_memory_outcome_recovery_grant_v1(text) "
                ",lucy.record_memory_outcome_recovery_grant_v1(text,text,jsonb) "
                "TO lucy_raymond_policy; "
                "GRANT EXECUTE ON FUNCTION lucy.reconcile_scoped_deletion_v3(uuid) "
                "TO lucy_raymond_sensitive_workflow"
            )
        )
    return scope_id, evidence_ids


def _candidate(scope_id, evidence_ids, *, protection, version=1, object_text="Use plan B"):
    return MemoryCandidatePayloadV1(
        candidate_id=uuid4(),
        candidate_version=version,
        campaign_id=TEST_CAMPAIGN_ID,
        manifest_digest=TEST_MANIFEST_DIGEST,
        extraction_job_id=uuid4(),
        extractor_version="synthetic-extractor-v1",
        prompt_version="synthetic-prompt-v1",
        model_route="none",
        destination_content_scope_id=scope_id,
        subject="Ray",
        predicate="selected_architecture",
        object=object_text,
        confidence_millionths=950_000,
        memory_kind=MemoryKind.ASSERTION,
        assertion_status=AssertionStatus.DECISION,
        epistemic_status=EpistemicStatus.CURRENT,
        protection_class=protection,
        domain_tags=("cloud-lucy",),
        sources=tuple(
            SourceSpanV1(
                source_record_id=f"synthetic-record-{index}",
                evidence_id=evidence_id,
                record_version=1,
                byte_start=0,
                byte_end=10,
            )
            for index, evidence_id in enumerate(evidence_ids)
        ),
    )


def _make_source_unavailable(evidence_id: object) -> None:
    assert OWNER_URL is not None
    owner = create_session_factory(OWNER_URL)
    with owner.begin() as session:
        session.execute(
            text(
                "ALTER TABLE lucy.scoped_evidence_payloads_v2 "
                "DISABLE TRIGGER scoped_evidence_payloads_v2_immutable"
            )
        )
        session.execute(
            text("DELETE FROM lucy.scoped_evidence_payloads_v2 WHERE evidence_id=:id"),
            {"id": evidence_id},
        )
        session.execute(
            text(
                "ALTER TABLE lucy.scoped_evidence_payloads_v2 "
                "ENABLE TRIGGER scoped_evidence_payloads_v2_immutable"
            )
        )


def _prepare_deletion_operation(scope_id: object, evidence_id: object) -> UUID:
    assert OWNER_URL is not None
    operation_id = uuid4()
    permit_id = uuid4()
    representation_id = uuid4()
    wrapped_key_ref = uuid4()
    owner_assertion_id = uuid4()
    now = datetime.now(UTC)
    owner = create_session_factory(OWNER_URL)
    with owner.begin() as session:
        payload_digest = session.execute(
            text(
                "SELECT payload_ciphertext_digest "
                "FROM lucy.scoped_evidence_payloads_v2 WHERE evidence_id=:evidence"
            ),
            {"evidence": evidence_id},
        ).scalar_one()
        scope = session.execute(
            text(
                "SELECT tenant_account_id,node_id,node_tenure_id,tenure_epoch,"
                "security_realm_id,storage_epoch,workspace_id,deployment_id "
                "FROM lucy.realm_content_scopes_v1 WHERE id=:scope"
            ),
            {"scope": scope_id},
        ).mappings().one()
        serialized_permit = json.dumps(
            {
                "workspace_id": str(scope["workspace_id"]),
                "owner_assertion_id": str(owner_assertion_id),
                "owner_assertion_digest": "b" * 64,
                "target_scope": {
                    "tenant_account_id": str(scope["tenant_account_id"]),
                    "node_id": str(scope["node_id"]),
                    "node_tenure_id": str(scope["node_tenure_id"]),
                    "tenure_epoch": scope["tenure_epoch"],
                    "security_realm_id": str(scope["security_realm_id"]),
                    "storage_epoch": scope["storage_epoch"],
                },
                "resource_selector": {
                    "object_id": str(evidence_id),
                    "object_version": 1,
                },
                "execution_binding": {
                    "deployment_id": str(scope["deployment_id"]),
                    "active_realm_id": str(scope["security_realm_id"]),
                    "active_storage_epoch": scope["storage_epoch"],
                    "realm_binding_generation": 1,
                    "node_authz_epoch": 1,
                },
                "membership_generation": 1,
                "channel_generation": 1,
                "service_binding_generation": 1,
                "max_records": 90,
                "max_bytes": 131_072,
            },
            separators=(",", ":"),
        )
        session.execute(
            text(
                "INSERT INTO lucy.scoped_evidence_wrappers_v2("
                "representation_id,evidence_id,content_scope_id,wrapped_key_ref,"
                "payload_ciphertext_digest,serialized_wrapper,current,created_at) "
                "VALUES (:representation,:evidence,:scope,:key,:digest,'{}',true,:now)"
            ),
            {
                "representation": representation_id,
                "evidence": evidence_id,
                "scope": scope_id,
                "key": wrapped_key_ref,
                "digest": payload_digest,
                "now": now,
            },
        )
        session.execute(
            text(
                "INSERT INTO lucy.sensitive_action_permits_v3("
                "id,operation_id,content_scope_id,policy_actor_binding_id,"
                "target_service_binding_id,principal_id,channel_binding_id,action,"
                "resource_object_id,resource_object_version,permit_digest,"
                "serialized_permit,nonce,issuance_idempotency_key,issued_at,"
                "permit_claim_deadline,execution_completion_deadline,state,"
                "claim_idempotency_key,claimed_at,created_at) "
                "SELECT :permit,:operation,p.content_scope_id,p.id,"
                "p.target_service_binding_id,m.principal_id,c.id,'evidence.delete',"
                ":evidence,1,:digest,CAST(:serialized AS jsonb),:nonce,:issue_key,"
                ":now,:claim_deadline,"
                ":completion_deadline,'CLAIMED',:claim_key,:now,:now "
                "FROM lucy.realm_sensitive_actor_bindings_v1 p "
                "JOIN lucy.realm_content_scopes_v1 s ON s.id=p.content_scope_id "
                "JOIN lucy.node_memberships m ON m.workspace_id=s.workspace_id "
                "AND m.role='owner' AND m.status='active' "
                "CROSS JOIN LATERAL (SELECT id FROM lucy.channel_bindings LIMIT 1) c "
                "WHERE p.content_scope_id=:scope AND p.actor_role='policy_notary'"
            ),
            {
                "permit": permit_id,
                "operation": operation_id,
                "evidence": evidence_id,
                "digest": hashlib.sha256(permit_id.bytes).hexdigest(),
                "serialized": serialized_permit,
                "nonce": f"synthetic-{permit_id.hex}",
                "issue_key": f"synthetic-issue-{permit_id}",
                "claim_key": f"synthetic-claim-{permit_id}",
                "now": now,
                "claim_deadline": now + timedelta(seconds=60),
                "completion_deadline": now + timedelta(seconds=120),
                "scope": scope_id,
            },
        )
        session.execute(
            text(
                "INSERT INTO lucy.sensitive_operations_v2("
                "id,permit_id,content_scope_id,workflow_actor_binding_id,"
                "target_service_binding_id,action,resource_object_id,"
                "resource_object_version,claim_idempotency_key,state,claimed_at) "
                "SELECT :operation,:permit,p.content_scope_id,p.id,"
                "p.target_service_binding_id,'evidence.delete',:evidence,1,"
                ":claim_key,'CLAIMED',:now "
                "FROM lucy.realm_sensitive_actor_bindings_v1 p "
                "WHERE p.content_scope_id=:scope AND p.actor_role='sensitive_workflow'"
            ),
            {
                "operation": operation_id,
                "permit": permit_id,
                "evidence": evidence_id,
                "claim_key": f"synthetic-operation-{operation_id}",
                "now": now,
                "scope": scope_id,
            },
        )
    return operation_id


def test_fixture_drives_exact_manifest_candidates_and_governed_recall() -> None:
    assert all((RAYMOND_URL, POLICY_URL))
    scope_id, _ = _provision()
    conversation = load_synthetic_conversation(
        Path(__file__).parents[1] / "fixtures" / "synthetic_memory_conversation.v1.json"
    )
    fingerprint_key = b"f" * 32
    manifest = build_synthetic_manifest(
        conversation,
        campaign_id=uuid4(),
        destination_content_scope_id=scope_id,
        fingerprint_key=fingerprint_key,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        max_model_spend_microusd=0,
        max_attempts=1,
    )
    policy = GovernedMemoryPolicy(create_session_factory(POLICY_URL))
    policy.authorize_campaign(manifest)
    assert OWNER_URL is not None
    owner = create_session_factory(OWNER_URL)
    with owner() as session:
        scope = session.get(RealmContentScopeRow, scope_id)
        assert scope is not None
        origin_scope = OriginScopeV1(
            tenant_account_id=scope.tenant_account_id,
            node_id=scope.node_id,
            node_tenure_id=scope.node_tenure_id,
            tenure_epoch=scope.tenure_epoch,
            security_realm_id=scope.security_realm_id,
            storage_epoch=scope.storage_epoch,
        )
    backend = _ImportArchiveBackend()
    archive = GovernedMemoryArchive(
        create_session_factory(RAYMOND_URL),
        RealmArchiveEncryptor(
            backend,
            RealmArchiveIdentityV1(
                target_scope=origin_scope,
                evidence_key_arn=TEST_KMS_ARN,
                record_version=1,
            ),
            commitment_key=b"c" * 32,
        ),
        request_commitment_key=b"r" * 32,
    )
    requests = build_archive_requests(
        conversation, manifest, fingerprint_key=fingerprint_key
    )
    evidence: dict[str, UUID] = {}
    for record, request in zip(manifest.records, requests, strict=True):
        result = archive.preserve(manifest, record, request)
        replay = archive.preserve(manifest, record, request)
        assert replay.evidence_id == result.evidence_id and replay.replayed
        evidence[record.source_record_id] = result.evidence_id
    assert backend.generate_calls == len(manifest.records)
    job_id = uuid4()
    prefix = f"{conversation.conversation_id}:"
    ordinary = extract_synthetic_candidate(
        conversation,
        manifest,
        fingerprint_key=fingerprint_key,
        evidence_by_source_record_id=evidence,
        candidate_id=uuid4(),
        extraction_job_id=job_id,
        subject="synthetic project",
        predicate="current plan",
        object_text="Plan B supersedes Plan A",
        memory_kind=MemoryKind.ASSERTION,
        assertion_status=AssertionStatus.DECISION,
        epistemic_status=EpistemicStatus.CURRENT,
        protection_class=ProtectionClass.ORDINARY_PRIVATE,
        source_quotes=(
            (f"{prefix}m5", "Plan B is now current"),
            (f"{prefix}m6", "Plan B supersedes Plan A"),
        ),
        domain_tags=("synthetic-project",),
    )
    protected_episode = extract_synthetic_candidate(
        conversation,
        manifest,
        fingerprint_key=fingerprint_key,
        evidence_by_source_record_id=evidence,
        candidate_id=uuid4(),
        extraction_job_id=job_id,
        subject="synthetic project",
        predicate="decision history",
        object_text="Ray first selected Plan A and later reversed to Plan B.",
        memory_kind=MemoryKind.EPISODE,
        assertion_status=AssertionStatus.REPORT,
        epistemic_status=EpistemicStatus.HISTORICAL,
        protection_class=ProtectionClass.PROTECTED,
        source_quotes=(
            (f"{prefix}m1", "choose Plan A"),
            (f"{prefix}m5", "Reverse the earlier decision"),
        ),
        domain_tags=("synthetic-project",),
    )
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    reader = GovernedMemoryReader(create_session_factory(RAYMOND_URL))
    mismatched_source = ordinary.model_copy(
        update={
            "candidate_id": uuid4(),
            "sources": (
                ordinary.sources[0].model_copy(
                    update={"source_record_id": f"{prefix}m7"}
                ),
            ),
        }
    )
    with pytest.raises(GovernedMemoryUnavailable, match="staging"):
        extractor.stage(mismatched_source)
    for candidate in (ordinary, protected_episode):
        extractor.stage(candidate)
        approval = policy.approve(
            candidate,
            owner_approval_ref=uuid4(),
            owner_actor_id="raymond-owner",
        )
        policy.promote(approval.approval_id, expected_digest=candidate.digest)
    assert len(reader.ordinary_recall("Plan B")) == 1
    assert reader.ordinary_recall("decision history") == ()
    protected = policy.protected_recall(
        "decision history",
        owner_interaction_ref=uuid4(),
        reason_code="synthetic_acceptance",
    )
    assert len(protected) == 1
    assert len(protected[0].source_evidence_ids) == 2


def test_v2_executable_manifest_round_trips_through_exact_campaign_authorization() -> None:
    assert all((OWNER_URL, POLICY_URL))
    scope_id, _ = _provision()
    conversation = load_synthetic_conversation(
        Path(__file__).parents[1] / "fixtures" / "synthetic_memory_conversation.v1.json"
    )
    base = build_synthetic_manifest(
        conversation,
        campaign_id=uuid4(),
        destination_content_scope_id=scope_id,
        fingerprint_key=b"f" * 32,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        max_model_spend_microusd=10_000,
        max_attempts=2,
        provider_policy_id="private-zdr-v1",
        model_route="openai/gpt-oss-20b",
    )
    values = base.model_dump(exclude={"contract_version", "max_input_tokens"})
    source_tokens = sum(record.estimated_tokens for record in base.records if record.included)
    manifest = ImportManifestV2.model_validate(
        {
            **values,
            "token_accounting_version": "canonical-json-byte-upper-bound-v1",
            "max_source_estimated_tokens": source_tokens,
            "max_request_input_tokens": 100_000,
            "max_request_output_tokens": 2_000,
            "max_request_total_tokens": 102_000,
        }
    )
    policy = GovernedMemoryPolicy(create_session_factory(POLICY_URL))

    assert not policy.authorize_campaign(manifest).replayed
    assert policy.authorize_campaign(manifest).replayed
    with pytest.raises(GovernedMemoryUnavailable, match="authorization"):
        policy.authorize_campaign(
            manifest.model_copy(update={"max_request_total_tokens": 102_001})
        )

    owner = create_session_factory(OWNER_URL)
    with owner() as session:
        stored = session.execute(
            text(
                "SELECT serialized_manifest,manifest_digest "
                "FROM lucy.memory_import_campaigns_v1 WHERE id=:campaign"
            ),
            {"campaign": manifest.campaign_id},
        ).one()
    assert stored.serialized_manifest["contract_version"] == "2"
    assert stored.serialized_manifest["max_request_total_tokens"] == 102_000
    assert stored.manifest_digest == manifest.digest


def test_governed_ordinary_and_protected_memory_cycle() -> None:
    assert all((OWNER_URL, RAYMOND_URL, POLICY_URL))
    scope_id, evidence_ids = _provision()
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    reader = GovernedMemoryReader(create_session_factory(RAYMOND_URL))
    policy = GovernedMemoryPolicy(create_session_factory(POLICY_URL))

    ordinary = _candidate(
        scope_id, evidence_ids, protection=ProtectionClass.ORDINARY_PRIVATE
    )
    staged = extractor.stage(ordinary)
    assert staged.candidate_digest == ordinary.digest and not staged.replayed
    assert extractor.stage(ordinary).replayed

    out_of_bounds = ordinary.model_copy(
        update={
            "candidate_id": uuid4(),
            "sources": (
                ordinary.sources[0].model_copy(update={"byte_end": 65}),
            ),
        }
    )
    with pytest.raises(GovernedMemoryUnavailable, match="staging"):
        extractor.stage(out_of_bounds)

    changed = ordinary.model_copy(update={"object": "Unreviewed replacement"})
    with pytest.raises(GovernedMemoryUnavailable, match="approval"):
        policy.approve(
            changed,
            owner_approval_ref=uuid4(),
            owner_actor_id="raymond-owner",
        )

    approval = policy.approve(
        ordinary,
        owner_approval_ref=uuid4(),
        owner_actor_id="raymond-owner",
    )
    promoted = policy.promote(approval.approval_id, expected_digest=ordinary.digest)
    restarted_policy = GovernedMemoryPolicy(create_session_factory(POLICY_URL))
    assert restarted_policy.promote(
        approval.approval_id, expected_digest=ordinary.digest
    ).replayed
    recalled = reader.ordinary_recall("plan B")
    assert recalled[0].claim_id == promoted.claim_id
    assert set(recalled[0].source_evidence_ids) == set(evidence_ids)

    protected = _candidate(
        scope_id,
        evidence_ids[:1],
        protection=ProtectionClass.PROTECTED,
        object_text="Sensitive passage",
    )
    pending_episode = protected.model_copy(
        update={
            "candidate_id": uuid4(),
            "memory_kind": MemoryKind.EPISODE,
            "assertion_status": AssertionStatus.REPORT,
            "object": "Ray reversed the synthetic decision from Plan A to Plan B.",
        }
    )
    extractor.stage(pending_episode)
    extractor.stage(protected)
    protected_approval = policy.approve(
        protected,
        owner_approval_ref=uuid4(),
        owner_actor_id="raymond-owner",
    )
    policy.promote(protected_approval.approval_id, expected_digest=protected.digest)
    assert reader.ordinary_recall("Sensitive passage") == ()
    protected_result = policy.protected_recall(
        "Sensitive passage",
        owner_interaction_ref=uuid4(),
        reason_code="owner_memory_review",
    )
    assert len(protected_result) == 1

    owner = create_session_factory(OWNER_URL)
    with owner() as session:
        access = session.execute(
            text(
                "SELECT query_commitment,returned_claim_ids FROM "
                "lucy.scoped_protected_memory_accesses_v1"
            )
        ).one()
        assert len(access.query_commitment) == 64
        assert len(access.returned_claim_ids) == 1
        pending_approval_count = session.scalar(
            text(
                "SELECT count(*) FROM lucy.scoped_memory_candidate_approvals_v1 "
                "WHERE candidate_id=:candidate"
            ),
            {"candidate": pending_episode.candidate_id},
        )
        assert pending_approval_count == 0

    _make_source_unavailable(evidence_ids[0])
    restarted_reader = GovernedMemoryReader(create_session_factory(RAYMOND_URL))
    restarted_policy = GovernedMemoryPolicy(create_session_factory(POLICY_URL))
    assert restarted_reader.ordinary_recall("plan B") == ()
    assert restarted_policy.protected_recall(
        "Sensitive passage",
        owner_interaction_ref=uuid4(),
        reason_code="owner_memory_review",
    ) == ()


def test_ordinary_runtime_cannot_bypass_promotion_or_approve() -> None:
    assert all((OWNER_URL, RAYMOND_URL))
    scope_id, evidence_ids = _provision()
    candidate = _candidate(
        scope_id, evidence_ids, protection=ProtectionClass.ORDINARY_PRIVATE
    )
    GovernedMemoryExtractor(create_session_factory(RAYMOND_URL)).stage(candidate)
    for database_url in (RAYMOND_URL, APP_URL):
        ordinary_identity = create_session_factory(database_url)
        for statement, values in (
            (
                "SELECT lucy.write_scoped_memory_claim_v1("
                "'bypass','Ray','decided','X',1)",
                {},
            ),
            (
                "SELECT lucy.write_evidence_derived_memory_claim_v2("
                "'bypass','Ray','decided','X',1,:sources)",
                {"sources": list(evidence_ids)},
            ),
            (
                "SELECT lucy.approve_scoped_memory_candidate_v1("
                ":candidate,1,:digest,:owner_ref,'forged-owner')",
                {
                    "candidate": candidate.candidate_id,
                    "digest": candidate.digest,
                    "owner_ref": uuid4(),
                },
            ),
            ("SELECT * FROM lucy.scoped_memory_candidate_versions_v1", {}),
        ):
            with (
                pytest.raises(DBAPIError, match="permission denied|unavailable"),
                ordinary_identity.begin() as session,
            ):
                session.execute(text(statement), values)


def test_deleted_or_revised_source_fences_stale_promotion() -> None:
    assert all((OWNER_URL, RAYMOND_URL, POLICY_URL))
    scope_id, evidence_ids = _provision()
    candidate = _candidate(scope_id, evidence_ids, protection=ProtectionClass.PROTECTED)
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    policy = GovernedMemoryPolicy(create_session_factory(POLICY_URL))
    extractor.stage(candidate)
    approval = policy.approve(
        candidate,
        owner_approval_ref=uuid4(),
        owner_actor_id="raymond-owner",
    )
    _make_source_unavailable(evidence_ids[0])
    with pytest.raises(GovernedMemoryUnavailable, match="promotion"):
        policy.promote(approval.approval_id, expected_digest=candidate.digest)


def test_campaign_cap_charges_retries_and_survives_client_restart() -> None:
    assert all((OWNER_URL, RAYMOND_URL, POLICY_URL))
    scope_id, _ = _provision()
    conversation = load_synthetic_conversation(
        Path(__file__).parents[1] / "fixtures" / "synthetic_memory_conversation.v1.json"
    )
    manifest = build_synthetic_manifest(
        conversation,
        campaign_id=uuid4(),
        destination_content_scope_id=scope_id,
        fingerprint_key=b"f" * 32,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        max_model_spend_microusd=10_000,
        max_attempts=2,
    )
    policy = GovernedMemoryPolicy(create_session_factory(POLICY_URL))
    assert not policy.authorize_campaign(manifest).replayed
    assert policy.authorize_campaign(manifest).replayed

    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    first = extractor.reserve_attempt(
        manifest.campaign_id, attempt_key="attempt-1", reserved_microusd=6_000
    )
    assert not first.replayed
    assert not extractor.settle_attempt(
        first.reservation_id, billed_microusd=5_000, result="failed"
    ).replayed

    restarted = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    assert restarted.reserve_attempt(
        manifest.campaign_id, attempt_key="attempt-1", reserved_microusd=6_000
    ).replayed
    second = restarted.reserve_attempt(
        manifest.campaign_id, attempt_key="attempt-2", reserved_microusd=4_000
    )
    restarted.settle_attempt(
        second.reservation_id, billed_microusd=4_000, result="succeeded"
    )
    with pytest.raises(GovernedMemoryUnavailable, match="reservation"):
        restarted.reserve_attempt(
            manifest.campaign_id, attempt_key="attempt-3", reserved_microusd=1
        )

    runtime = create_session_factory(RAYMOND_URL)
    with pytest.raises(DBAPIError, match="permission denied"), runtime.begin() as session:
        session.execute(text("SELECT * FROM lucy.memory_import_campaigns_v1"))


def test_source_eligibility_is_exact_realm_bound_and_deletion_aware() -> None:
    assert RAYMOND_URL is not None
    _, evidence_ids = _provision()
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))

    extractor.require_eligible(
        campaign_id=TEST_CAMPAIGN_ID,
        manifest_digest=TEST_MANIFEST_DIGEST,
        source_record_ids=("synthetic-record-0", "synthetic-record-1"),
        phase="pre_dispatch",
    )
    for sources in (
        ("synthetic-record-0", "synthetic-record-0"),
        ("outside-manifest",),
    ):
        with pytest.raises(GovernedMemoryUnavailable, match="eligibility"):
            extractor.require_eligible(
                campaign_id=TEST_CAMPAIGN_ID,
                manifest_digest=TEST_MANIFEST_DIGEST,
                source_record_ids=sources,
                phase="pre_dispatch",
            )

    _make_source_unavailable(evidence_ids[0])
    with pytest.raises(GovernedMemoryUnavailable, match="eligibility"):
        extractor.require_eligible(
            campaign_id=TEST_CAMPAIGN_ID,
            manifest_digest=TEST_MANIFEST_DIGEST,
            source_record_ids=("synthetic-record-0",),
            phase="post_dispatch",
        )


def test_deleted_source_blocks_new_candidate_approval() -> None:
    assert all((RAYMOND_URL, POLICY_URL))
    scope_id, evidence_ids = _provision()
    candidate = _candidate(
        scope_id,
        evidence_ids,
        protection=ProtectionClass.PROTECTED,
    )
    GovernedMemoryExtractor(create_session_factory(RAYMOND_URL)).stage(candidate)
    _make_source_unavailable(evidence_ids[0])

    with pytest.raises(GovernedMemoryUnavailable, match="approval"):
        GovernedMemoryPolicy(create_session_factory(POLICY_URL)).approve(
            candidate,
            owner_approval_ref=uuid4(),
            owner_actor_id="raymond-owner",
        )


def test_extraction_job_binds_exact_reservation_request_and_sources() -> None:
    assert RAYMOND_URL is not None
    scope_id, evidence_ids = _provision()
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    reservation = extractor.reserve_attempt(
        TEST_CAMPAIGN_ID,
        attempt_key="pilot:batch:1:attempt:1",
        reserved_microusd=0,
    )
    request_commitment = "d" * 64
    job_id = memory_extraction_job_id(
        TEST_CAMPAIGN_ID,
        attempt_key="pilot:batch:1:attempt:1",
        request_commitment=request_commitment,
    )
    job = {
        "contract_version": "1",
        "extraction_job_id": str(job_id),
        "reservation_id": str(reservation.reservation_id),
        "campaign_id": str(TEST_CAMPAIGN_ID),
        "manifest_digest": TEST_MANIFEST_DIGEST,
        "attempt_key": "pilot:batch:1:attempt:1",
        "source_record_ids": ["synthetic-record-0"],
        "request_commitment": request_commitment,
        "request_bytes": 50,
        "input_token_upper_bound": 50,
        "maximum_output_tokens": 50,
        "token_accounting_version": "canonical-json-byte-upper-bound-v1",
        "provider_policy_id": "synthetic-private-zdr-v1",
        "model_route": "none",
        "maximum_microusd": 0,
    }
    sessions = create_session_factory(RAYMOND_URL)
    with sessions.begin() as session:
        first = session.execute(
            text("SELECT lucy.register_memory_import_job_v1(CAST(:job AS jsonb))"),
            {"job": json.dumps(job, separators=(",", ":"))},
        ).scalar_one()
        replay = session.execute(
            text("SELECT lucy.register_memory_import_job_v1(CAST(:job AS jsonb))"),
            {"job": json.dumps(job, separators=(",", ":"))},
        ).scalar_one()
    assert first == {"extraction_job_id": str(job_id), "replayed": False}
    assert replay == {"extraction_job_id": str(job_id), "replayed": True}

    outcome_store = PostgresMemoryOutcomeStore(sessions)
    envelope = MemoryOutcomeEnvelopeV1(
        binding=MemoryOutcomeBindingV1(
            extraction_job_id=job_id,
            reservation_id=reservation.reservation_id,
            campaign_id=TEST_CAMPAIGN_ID,
            destination_content_scope_id=scope_id,
            manifest_digest=TEST_MANIFEST_DIGEST,
            attempt_key="pilot:batch:1:attempt:1",
            source_record_ids=("synthetic-record-0",),
            request_commitment=request_commitment,
            provider_policy_id="synthetic-private-zdr-v1",
            model_route="none",
            maximum_microusd=0,
        ),
        encryption_id=uuid4(),
        registry_id=uuid4(),
        algorithm="AES-256-GCM+AES-KW-GCM",
        encryption_context_version=1,
        record_version=1,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        ciphertext_b64=base64.b64encode(b"encrypted outcome").decode("ascii"),
        content_nonce_b64=base64.b64encode(b"n" * 12).decode("ascii"),
        keyed_commitment="f" * 64,
        billed_microusd=0,
        provider_reference_commitment="a" * 64,
    )
    assert outcome_store.put(envelope) == envelope
    assert outcome_store.put(envelope) == envelope
    assert outcome_store.load(job_id) == envelope
    assert outcome_store.load(uuid4()) is None
    with pytest.raises(MemoryOutcomeUnavailable, match="outcome write unavailable"):
        outcome_store.put(envelope.model_copy(update={"billed_microusd": 1}))
    with pytest.raises(DBAPIError, match="permission denied"), sessions.begin() as session:
        session.execute(text("SELECT * FROM lucy.memory_import_provider_outcomes_v1"))

    for changed in (
        {**job, "source_record_ids": ["synthetic-record-1"]},
        {**job, "request_commitment": "e" * 64},
    ):
        with pytest.raises(DBAPIError), sessions.begin() as session:
            session.execute(
                text("SELECT lucy.register_memory_import_job_v1(CAST(:job AS jsonb))"),
                {"job": json.dumps(changed, separators=(",", ":"))},
            ).scalar_one()
    _make_source_unavailable(evidence_ids[0])
    with pytest.raises(MemoryOutcomeUnavailable, match="lookup unavailable"):
        outcome_store.load(job_id)


def test_v3_deletion_closure_finds_candidate_claim_and_encrypted_outcome() -> None:
    assert all((OWNER_URL, RAYMOND_URL, POLICY_URL, WORKFLOW_URL))
    scope_id, evidence_ids = _provision()
    raymond_sessions = create_session_factory(RAYMOND_URL)
    policy_sessions = create_session_factory(POLICY_URL)
    extractor = GovernedMemoryExtractor(raymond_sessions)
    policy = GovernedMemoryPolicy(policy_sessions)
    candidate = _candidate(
        scope_id,
        evidence_ids,
        protection=ProtectionClass.PROTECTED,
    )
    extractor.stage(candidate)
    candidate_v2 = candidate.model_copy(
        update={
            "candidate_version": 2,
            "object": "Use plan B after review",
            "supersedes_candidate_id": candidate.candidate_id,
        }
    )
    extractor.stage(candidate_v2)
    approval = policy.approve(
        candidate,
        owner_approval_ref=uuid4(),
        owner_actor_id="raymond-owner",
    )
    policy.promote(approval.approval_id, expected_digest=candidate.digest)

    reservation = extractor.reserve_attempt(
        TEST_CAMPAIGN_ID,
        attempt_key="v3-deletion-outcome",
        reserved_microusd=0,
    )
    request_commitment = "7" * 64
    job_id = memory_extraction_job_id(
        TEST_CAMPAIGN_ID,
        attempt_key="v3-deletion-outcome",
        request_commitment=request_commitment,
    )
    job = {
        "contract_version": "1",
        "extraction_job_id": str(job_id),
        "reservation_id": str(reservation.reservation_id),
        "campaign_id": str(TEST_CAMPAIGN_ID),
        "manifest_digest": TEST_MANIFEST_DIGEST,
        "attempt_key": "v3-deletion-outcome",
        "source_record_ids": ["synthetic-record-0"],
        "request_commitment": request_commitment,
        "request_bytes": 50,
        "input_token_upper_bound": 50,
        "maximum_output_tokens": 50,
        "token_accounting_version": "canonical-json-byte-upper-bound-v1",
        "provider_policy_id": "synthetic-private-zdr-v1",
        "model_route": "none",
        "maximum_microusd": 0,
    }
    with raymond_sessions.begin() as session:
        session.execute(
            text("SELECT lucy.register_memory_import_job_v1(CAST(:job AS jsonb))"),
            {"job": json.dumps(job, separators=(",", ":"))},
        ).scalar_one()
    encryption_id = uuid4()
    registry_id = uuid4()
    envelope = MemoryOutcomeEnvelopeV1(
        binding=MemoryOutcomeBindingV1(
            extraction_job_id=job_id,
            reservation_id=reservation.reservation_id,
            campaign_id=TEST_CAMPAIGN_ID,
            destination_content_scope_id=scope_id,
            manifest_digest=TEST_MANIFEST_DIGEST,
            attempt_key="v3-deletion-outcome",
            source_record_ids=("synthetic-record-0",),
            request_commitment=request_commitment,
            provider_policy_id="synthetic-private-zdr-v1",
            model_route="none",
            maximum_microusd=0,
        ),
        encryption_id=encryption_id,
        registry_id=registry_id,
        algorithm="AES-256-GCM+AES-KW-GCM",
        encryption_context_version=1,
        record_version=1,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        ciphertext_b64=base64.b64encode(b"encrypted outcome").decode("ascii"),
        content_nonce_b64=base64.b64encode(b"n" * 12).decode("ascii"),
        keyed_commitment="8" * 64,
        billed_microusd=0,
        provider_reference_commitment="9" * 64,
    )
    PostgresMemoryOutcomeStore(raymond_sessions).put(envelope)

    late_reservation = extractor.reserve_attempt(
        TEST_CAMPAIGN_ID,
        attempt_key="v3-deletion-late-outcome",
        reserved_microusd=0,
    )
    late_commitment = "6" * 64
    late_job_id = memory_extraction_job_id(
        TEST_CAMPAIGN_ID,
        attempt_key="v3-deletion-late-outcome",
        request_commitment=late_commitment,
    )
    late_job = {
        **job,
        "extraction_job_id": str(late_job_id),
        "reservation_id": str(late_reservation.reservation_id),
        "attempt_key": "v3-deletion-late-outcome",
        "request_commitment": late_commitment,
    }
    with raymond_sessions.begin() as session:
        session.execute(
            text("SELECT lucy.register_memory_import_job_v1(CAST(:job AS jsonb))"),
            {"job": json.dumps(late_job, separators=(",", ":"))},
        ).scalar_one()

    operation_id = _prepare_deletion_operation(scope_id, evidence_ids[0])
    with policy_sessions.begin() as session:
        raw_targets = session.execute(
            text("SELECT lucy.build_scoped_deletion_targets_v3(:operation)"),
            {"operation": operation_id},
        ).scalar_one()
        authority_snapshot = session.execute(
            text("SELECT lucy.read_claimed_deletion_authority_v2(:operation)"),
            {"operation": operation_id},
        ).scalar_one()
    targets = tuple(DeletionTargetReferenceV3.model_validate(item) for item in raw_targets)

    assert [target.artifact_class for target in targets] == [
        DeletionArtifactClassV3.ENCRYPTED_ARCHIVE,
        DeletionArtifactClassV3.MEMORY_CANDIDATE,
        DeletionArtifactClassV3.MEMORY_CANDIDATE,
        DeletionArtifactClassV3.MEMORY_CLAIM,
        DeletionArtifactClassV3.MEMORY_IMPORT_PROVIDER_OUTCOME,
    ]
    assert targets[1].artifact_id == candidate.candidate_id
    assert targets[2].artifact_id == candidate.candidate_id
    assert (targets[1].artifact_version, targets[2].artifact_version) == (1, 2)
    assert targets[-1].artifact_id == job_id
    assert targets[-1].representation_id == encryption_id
    assert targets[-1].wrapped_key_ref == encryption_id
    assert targets[-1].key_registry_id == registry_id
    assert authority_snapshot["targets"] == raw_targets
    assert authority_snapshot["closure_version"] == 3

    owner_sessions = create_session_factory(OWNER_URL)
    with owner_sessions.begin() as session:
        authority = session.execute(
            text(
                "SELECT p.id permit_id,p.permit_digest,p.serialized_permit,"
                "p.permit_claim_deadline,p.execution_completion_deadline,"
                "o.claimed_at,o.claim_idempotency_key "
                "FROM lucy.sensitive_operations_v2 o "
                "JOIN lucy.sensitive_action_permits_v3 p ON p.id=o.permit_id "
                "WHERE o.id=:operation"
            ),
            {"operation": operation_id},
        ).mappings().one()
    permit = authority["serialized_permit"]
    manifest = DeletionTargetManifestV3(
        signing_key_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        key_id="synthetic-policy-v3",
        issuer="synthetic-policy-v3",
        environment=DeploymentEnvironment.TEST,
        issued_at=authority["claimed_at"],
        signature="synthetic-signature",
        manifest_id=uuid4(),
        permit_id=authority["permit_id"],
        permit_digest=authority["permit_digest"],
        operation_id=operation_id,
        target_scope=OriginScopeV1.model_validate(permit["target_scope"]),
        workspace_id=UUID(permit["workspace_id"]),
        root_evidence_id=evidence_ids[0],
        root_representation_id=targets[0].representation_id,
        owner_assertion_id=UUID(permit["owner_assertion_id"]),
        owner_assertion_digest=permit["owner_assertion_digest"],
        idempotency_key=authority["claim_idempotency_key"],
        closure_version=3,
        targets=targets,
        target_count=len(targets),
        targets_digest=deletion_targets_digest_v3(targets),
        tombstone_policy_version=3,
        finality_policy_version=3,
        permit_claim_deadline=authority["permit_claim_deadline"],
        execution_completion_deadline=authority["execution_completion_deadline"],
        nonce="v3-manifest-nonce-000000000000000",
    )
    store = PostgresScopedDeletionManifestStoreV3(policy_sessions)
    first = store.store(manifest)
    replay = store.store(manifest)
    assert not first.replayed and replay.replayed
    assert first.manifest_digest == manifest.unsigned_digest_hex()
    with pytest.raises(ScopedDeletionUnavailable, match="unavailable"):
        store.store(manifest.model_copy(update={"nonce": "changed-nonce-0000000000000000000"}))

    with policy_sessions.begin() as session:
        execution_authority = session.execute(
            text("SELECT lucy.read_claimed_sensitive_authority_v2(:operation)"),
            {"operation": operation_id},
        ).scalar_one()
    issued_at = datetime.now(UTC)
    grant_id = uuid4()
    grant = {
        "canonicalization_version": "lucy-cjson-1",
        "signature_algorithm": "Ed25519",
        "signing_key_purpose": "policy_notary_v13",
        "key_id": "synthetic-policy-v3",
        "issuer": "synthetic-policy-v3",
        "environment": "test",
        "issued_at": issued_at.isoformat(),
        "signature": "synthetic-signature",
        "contract_version": "2",
        "object_type": "lucy.sensitive-execution-grant.v2",
        "grant_id": str(grant_id),
        "action": "evidence.delete",
        "permit_id": str(authority["permit_id"]),
        "permit_digest": authority["permit_digest"],
        "operation_id": str(operation_id),
        "caller_identity": execution_authority["caller_identity"],
        "target_scope": permit["target_scope"],
        "workspace_id": permit["workspace_id"],
        "resource_selector": permit["resource_selector"],
        "execution_binding": permit["execution_binding"],
        "restore_mapping_id": None,
        "deletion_manifest_id": str(manifest.manifest_id),
        "deletion_manifest_digest": manifest.unsigned_digest_hex(),
        "encrypted_package_digest": manifest.unsigned_digest_hex(),
        "package_size_bytes": execution_authority["package_size_bytes"],
        "idempotency_key": execution_authority["claim_idempotency_key"],
        "executor_identity": execution_authority["executor_identity"],
        "executor_alias_arn": execution_authority["executor_alias_arn"],
        "executor_version": execution_authority["executor_version"],
        "permit_claimed_at": authority["claimed_at"].isoformat(),
        "permit_claim_deadline": authority["permit_claim_deadline"].isoformat(),
        "execution_completion_deadline": authority[
            "execution_completion_deadline"
        ].isoformat(),
        "max_records": permit["max_records"],
        "max_bytes": permit["max_bytes"],
        "nonce": "synthetic-grant-nonce-000000000000000",
    }
    with policy_sessions.begin() as session:
        grant_digest = session.execute(
            text(
                "SELECT lucy.store_deletion_execution_grant_v3("
                ":operation,CAST(:grant AS jsonb))"
            ),
            {"operation": operation_id, "grant": json.dumps(grant)},
        ).scalar_one()
        assert session.execute(
            text(
                "SELECT lucy.store_deletion_execution_grant_v3("
                ":operation,CAST(:grant AS jsonb))"
            ),
            {"operation": operation_id, "grant": json.dumps(grant)},
        ).scalar_one() == grant_digest

    completed_at = datetime.now(UTC)
    receipt_id = uuid4()
    receipt = {
        "canonicalization_version": "lucy-cjson-1",
        "signature_algorithm": "ECDSA_SHA_256",
        "signing_key_purpose": "deletion_receipt_v13",
        "key_id": execution_authority["receipt_key_id"],
        "issuer": execution_authority["executor_identity"],
        "environment": "test",
        "issued_at": completed_at.isoformat(),
        "signature": "synthetic-signature",
        "contract_version": "2",
        "object_type": "lucy.executor-receipt.v2",
        "receipt_id": str(receipt_id),
        "action": "evidence.delete",
        "executor_identity": execution_authority["executor_identity"],
        "executor_alias_arn": execution_authority["executor_alias_arn"],
        "executor_version": execution_authority["executor_version"],
        "caller_identity": execution_authority["caller_identity"],
        "target_scope": permit["target_scope"],
        "execution_binding": permit["execution_binding"],
        "operation_id": str(operation_id),
        "permit_id": str(authority["permit_id"]),
        "permit_digest": authority["permit_digest"],
        "execution_grant_id": str(grant_id),
        "execution_grant_digest": grant_digest,
        "deletion_manifest_id": str(manifest.manifest_id),
        "deletion_manifest_digest": manifest.unsigned_digest_hex(),
        "package_digest": manifest.unsigned_digest_hex(),
        "result": "deletion_succeeded",
        "lambda_request_id": "synthetic-lambda-request",
        "kms_request_id": None,
        "transaction_client_token": "synthetic-deletion-transaction",
        "execution_completion_deadline": authority[
            "execution_completion_deadline"
        ].isoformat(),
        "completed_at": completed_at.isoformat(),
        "record_version": 1,
        "journal_ref": "synthetic-journal-ref",
        "finality_state": "operationally_deleted",
    }
    workflow_sessions = create_session_factory(WORKFLOW_URL)
    with policy_sessions.begin() as session:
        receipt_digest = session.execute(
            text(
                "SELECT lucy.attest_deletion_executor_receipt_v3("
                ":operation,CAST(:receipt AS jsonb))"
            ),
            {"operation": operation_id, "receipt": json.dumps(receipt)},
        ).scalar_one()
    with workflow_sessions.begin() as session:
        first_reconcile = session.execute(
            text("SELECT lucy.reconcile_scoped_deletion_v3(:operation)"),
            {"operation": operation_id},
        ).scalar_one()
        replay_reconcile = session.execute(
            text("SELECT lucy.reconcile_scoped_deletion_v3(:operation)"),
            {"operation": operation_id},
        ).scalar_one()
    assert first_reconcile["state"] == "FINALITY_PENDING"
    assert first_reconcile["receipt_digest"] == receipt_digest
    assert not first_reconcile["replayed"] and replay_reconcile["replayed"]

    with owner_sessions.begin() as session:
        candidate_versions = session.execute(
            text(
                "SELECT candidate_version FROM lucy.scoped_memory_candidate_tombstones_v3 "
                "WHERE candidate_id=:candidate ORDER BY candidate_version"
            ),
            {"candidate": candidate.candidate_id},
        ).scalars().all()
        outcome_tombstone = session.execute(
            text(
                "SELECT representation_id,wrapped_key_ref,key_registry_id "
                "FROM lucy.memory_import_outcome_tombstones_v3 "
                "WHERE extraction_job_id=:job"
            ),
            {"job": job_id},
        ).one()
    assert candidate_versions == [1, 2]
    assert tuple(outcome_tombstone) == (encryption_id, encryption_id, registry_id)
    late_envelope = envelope.model_copy(
        update={
            "binding": envelope.binding.model_copy(
                update={
                    "extraction_job_id": late_job_id,
                    "reservation_id": late_reservation.reservation_id,
                    "attempt_key": "v3-deletion-late-outcome",
                    "request_commitment": late_commitment,
                }
            ),
            "encryption_id": uuid4(),
            "registry_id": uuid4(),
        }
    )
    with pytest.raises(MemoryOutcomeUnavailable, match="outcome write unavailable"):
        PostgresMemoryOutcomeStore(raymond_sessions).put(late_envelope)
    with (
        pytest.raises(DBAPIError, match="append-only"),
        owner_sessions.begin() as session,
    ):
        session.execute(
            text(
                "DELETE FROM lucy.scoped_memory_candidate_tombstones_v3 "
                "WHERE candidate_id=:candidate"
            ),
            {"candidate": candidate.candidate_id},
        )

    # Simulate a database restore whose backup predates the durable deletion
    # fences, then replay only the independently preserved authority chain.
    with owner_sessions.begin() as session:
        session.execute(text("SET LOCAL session_replication_role='replica'"))
        session.execute(
            text("DELETE FROM lucy.scoped_evidence_deletion_fences_v2 WHERE operation_id=:id"),
            {"id": operation_id},
        )
        session.execute(
            text("DELETE FROM lucy.scoped_memory_candidate_tombstones_v3 WHERE operation_id=:id"),
            {"id": operation_id},
        )
        session.execute(
            text("DELETE FROM lucy.memory_import_outcome_tombstones_v3 WHERE operation_id=:id"),
            {"id": operation_id},
        )
        session.execute(
            text("DELETE FROM lucy.scoped_deletion_effects_v3 WHERE operation_id=:id"),
            {"id": operation_id},
        )
    scope_digest = canonical_sha256(
        OriginScopeV1.model_validate(permit["target_scope"]),
        prefix=b"lucy:authorized-deletion-recovery-scope:v2\0",
    )
    recovery_bindings = {
        "operation_id": str(operation_id),
        "permit_digest": authority["permit_digest"],
        "manifest_digest": manifest.unsigned_digest_hex(),
        "grant_digest": grant_digest,
        "receipt_digest": receipt_digest,
        "targets_digest": manifest.targets_digest,
        "scope_digest": scope_digest,
    }
    recovery = {
        "contract_version": "3",
        "object_type": "lucy.authorized-deletion-recovery.v3",
        "operation_id": str(operation_id),
        "permit_id": str(authority["permit_id"]),
        "manifest_id": str(manifest.manifest_id),
        "grant_id": str(grant_id),
        "receipt_id": str(receipt_id),
        "permit_digest": authority["permit_digest"],
        "manifest_digest": manifest.unsigned_digest_hex(),
        "grant_digest": grant_digest,
        "receipt_digest": receipt_digest,
        "targets_digest": manifest.targets_digest,
        "target_count": manifest.target_count,
        "scope_digest": scope_digest,
        "target_scope": permit["target_scope"],
        "workspace_id": permit["workspace_id"],
        "root_evidence_id": str(evidence_ids[0]),
        "root_representation_id": str(manifest.root_representation_id),
        "restore_mapping_id": None,
        "caller_identity": execution_authority["caller_identity"],
        "executor_identity": execution_authority["executor_identity"],
        "executor_alias_arn": execution_authority["executor_alias_arn"],
        "executor_version": execution_authority["executor_version"],
        "receipt_key_id": execution_authority["receipt_key_id"],
        "completed_at": completed_at.isoformat(),
        "reason_category": "owner_request",
        "recovery_digest": canonical_sha256(
            recovery_bindings,
            prefix=b"lucy:authorized-deletion-recovery:v3\0",
        ),
        "authority_evidence_digest": "d" * 64,
        "targets": [target.model_dump(mode="json") for target in manifest.targets],
    }
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        raymond_sessions.begin() as session,
    ):
        session.execute(
            text("SELECT lucy.apply_scoped_authorized_deletion_recovery_v3(CAST(:r AS jsonb))"),
            {"r": json.dumps(recovery, separators=(",", ":"))},
        )
    with (
        pytest.raises(DBAPIError, match="contract is malformed"),
        owner_sessions.begin() as session,
    ):
        session.execute(
            text("SELECT lucy.apply_scoped_authorized_deletion_recovery_v3(CAST(:r AS jsonb))"),
            {"r": json.dumps({**recovery, "unexpected": True}, separators=(",", ":"))},
        )
    with owner_sessions.begin() as session:
        recovered = session.execute(
            text("SELECT lucy.apply_scoped_authorized_deletion_recovery_v3(CAST(:r AS jsonb))"),
            {"r": json.dumps(recovery, separators=(",", ":"))},
        ).scalar_one()
        replayed = session.execute(
            text("SELECT lucy.apply_scoped_authorized_deletion_recovery_v3(CAST(:r AS jsonb))"),
            {"r": json.dumps(recovery, separators=(",", ":"))},
        ).scalar_one()
    assert recovered["state"] == "FINALITY_PENDING"
    assert recovered["replayed"] is False
    assert recovered["derived_summary"] == {
        "archive_keys_destroyed": 1,
        "candidates_suppressed": 2,
        "claims_suppressed": 1,
        "provider_outcome_keys_destroyed": 1,
        "target_count": 5,
    }
    assert replayed == {**recovered, "replayed": True}
    with raymond_sessions.begin() as session:
        assert session.execute(
            text("SELECT lucy.search_governed_scoped_memory_v1(:query,:limit)"),
            {"query": "synthetic", "limit": 10},
        ).scalar_one() == []
    with pytest.raises(MemoryOutcomeUnavailable, match="outcome lookup unavailable"):
        PostgresMemoryOutcomeStore(raymond_sessions).load(job_id)
    with (
        pytest.raises(DBAPIError, match="scoped evidence derivation unavailable"),
        owner_sessions.begin() as session,
    ):
        session.execute(
            text(
                "INSERT INTO lucy.scoped_memory_candidate_sources_v1("
                "candidate_id,candidate_version,evidence_id,record_version,byte_start,"
                "byte_end,content_scope_id) VALUES(:candidate,1,:evidence,1,0,1,:scope)"
            ),
            {
                "candidate": candidate.candidate_id,
                "evidence": evidence_ids[0],
                "scope": scope_id,
            },
        )

    # A backup may predate derived rows entirely. Historical deletion authority
    # still has to install exact future-resurrection tombstones.
    absent_operation_id = _prepare_deletion_operation(scope_id, evidence_ids[1])
    with owner_sessions.begin() as session:
        absent_root = session.execute(
            text(
                "SELECT representation_id,wrapped_key_ref FROM lucy.scoped_evidence_wrappers_v2 "
                "WHERE evidence_id=:evidence AND current"
            ),
            {"evidence": evidence_ids[1]},
        ).one()
    absent_candidate_id = uuid4()
    absent_job_id = uuid4()
    absent_representation_id = uuid4()
    absent_registry_id = uuid4()
    absent_targets = (
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.ENCRYPTED_ARCHIVE,
            artifact_id=evidence_ids[1],
            artifact_version=1,
            root_evidence_id=evidence_ids[1],
            disposition="destroy_wrapped_key",
            representation_id=absent_root.representation_id,
            wrapped_key_ref=absent_root.wrapped_key_ref,
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_CANDIDATE,
            artifact_id=absent_candidate_id,
            artifact_version=7,
            root_evidence_id=evidence_ids[1],
            disposition="invalidate",
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_IMPORT_PROVIDER_OUTCOME,
            artifact_id=absent_job_id,
            artifact_version=3,
            root_evidence_id=evidence_ids[1],
            disposition="destroy_wrapped_key",
            representation_id=absent_representation_id,
            wrapped_key_ref=absent_representation_id,
            key_registry_id=absent_registry_id,
        ),
    )
    absent_targets_digest = deletion_targets_digest_v3(absent_targets)
    absent_digests = {
        "permit_digest": "1" * 64,
        "manifest_digest": "2" * 64,
        "grant_digest": "3" * 64,
        "receipt_digest": "4" * 64,
    }
    absent_bindings = {
        "operation_id": str(absent_operation_id),
        **absent_digests,
        "targets_digest": absent_targets_digest,
        "scope_digest": scope_digest,
    }
    absent_recovery = {
        **recovery,
        "operation_id": str(absent_operation_id),
        "permit_id": str(uuid4()),
        "manifest_id": str(uuid4()),
        "grant_id": str(uuid4()),
        "receipt_id": str(uuid4()),
        **absent_digests,
        "targets_digest": absent_targets_digest,
        "target_count": len(absent_targets),
        "root_evidence_id": str(evidence_ids[1]),
        "root_representation_id": str(absent_root.representation_id),
        "recovery_digest": canonical_sha256(
            absent_bindings,
            prefix=b"lucy:authorized-deletion-recovery:v3\0",
        ),
        "authority_evidence_digest": "e" * 64,
        "targets": [target.model_dump(mode="json") for target in absent_targets],
    }
    with owner_sessions.begin() as session:
        absent_result = session.execute(
            text("SELECT lucy.apply_scoped_authorized_deletion_recovery_v3(CAST(:r AS jsonb))"),
            {"r": json.dumps(absent_recovery, separators=(",", ":"))},
        ).scalar_one()
        absent_rows = session.execute(
            text(
                "SELECT artifact_class,artifact_id,artifact_version "
                "FROM lucy.scoped_authorized_deletion_recovery_targets_v3 "
                "WHERE operation_id=:operation ORDER BY artifact_class"
            ),
            {"operation": absent_operation_id},
        ).all()
    assert absent_result["derived_summary"]["target_count"] == 3
    assert absent_rows == [
        ("encrypted_archive", evidence_ids[1], 1),
        ("memory_candidate", absent_candidate_id, 7),
        ("memory_import_provider_outcome", absent_job_id, 3),
    ]
    conflicting_recovery = {
        **absent_recovery,
        "receipt_digest": "5" * 64,
    }
    conflicting_bindings = {
        **absent_bindings,
        "receipt_digest": conflicting_recovery["receipt_digest"],
    }
    conflicting_recovery["recovery_digest"] = canonical_sha256(
        conflicting_bindings,
        prefix=b"lucy:authorized-deletion-recovery:v3\0",
    )
    with (
        pytest.raises(DBAPIError, match="replay state mismatch"),
        owner_sessions.begin() as session,
    ):
        session.execute(
            text("SELECT lucy.apply_scoped_authorized_deletion_recovery_v3(CAST(:r AS jsonb))"),
            {"r": json.dumps(conflicting_recovery, separators=(",", ":"))},
        )
    with owner_sessions.begin() as session:
        session.execute(
            text(
                "UPDATE lucy.runtime_admission SET state='ready',storage_epoch=:epoch,"
                "updated_at=clock_timestamp() WHERE singleton"
            ),
            {"epoch": uuid4()},
        )
    with (
        pytest.raises(DBAPIError, match="requires quarantined capture-off storage"),
        owner_sessions.begin() as session,
    ):
        session.execute(
            text("SELECT lucy.apply_scoped_authorized_deletion_recovery_v3(CAST(:r AS jsonb))"),
            {"r": json.dumps(recovery, separators=(",", ":"))},
        )
    with owner_sessions.begin() as session:
        session.execute(
            text(
                "UPDATE lucy.runtime_admission SET state='quarantined',storage_epoch=NULL,"
                "updated_at=clock_timestamp() WHERE singleton"
            )
        )


def test_success_completion_atomically_stages_batch_and_settles() -> None:
    assert all((OWNER_URL, RAYMOND_URL))
    scope_id, evidence_ids = _provision()
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    reservation = extractor.reserve_attempt(
        TEST_CAMPAIGN_ID, attempt_key="atomic-success", reserved_microusd=0
    )
    first = _candidate(
        scope_id,
        evidence_ids,
        protection=ProtectionClass.ORDINARY_PRIVATE,
        object_text="Use plan B",
    )
    second = _candidate(
        scope_id,
        evidence_ids[:1],
        protection=ProtectionClass.PROTECTED,
        object_text="The earlier plan was reversed",
    )

    completed = extractor.complete_success(
        reservation.reservation_id,
        candidates=(first, second),
        billed_microusd=0,
    )
    replayed = extractor.complete_success(
        reservation.reservation_id,
        candidates=(first, second),
        billed_microusd=0,
    )

    assert [candidate.replayed for candidate in completed.candidates] == [False, False]
    assert not completed.settlement_replayed
    assert [candidate.replayed for candidate in replayed.candidates] == [True, True]
    assert replayed.settlement_replayed


def test_success_completion_rolls_back_partial_batch_and_settlement() -> None:
    assert all((OWNER_URL, RAYMOND_URL))
    scope_id, evidence_ids = _provision()
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    reservation = extractor.reserve_attempt(
        TEST_CAMPAIGN_ID, attempt_key="atomic-rollback", reserved_microusd=0
    )
    first = _candidate(
        scope_id,
        evidence_ids,
        protection=ProtectionClass.ORDINARY_PRIVATE,
    )
    invalid_second = _candidate(
        scope_id,
        evidence_ids[:1],
        protection=ProtectionClass.PROTECTED,
    ).model_copy(
        update={
            "sources": (
                SourceSpanV1(
                    source_record_id="outside-approved-manifest",
                    evidence_id=evidence_ids[0],
                    record_version=1,
                    byte_start=0,
                    byte_end=10,
                ),
            )
        }
    )

    with pytest.raises(GovernedMemoryUnavailable, match="completion"):
        extractor.complete_success(
            reservation.reservation_id,
            candidates=(first, invalid_second),
            billed_microusd=0,
        )

    owner = create_session_factory(OWNER_URL)
    with owner() as session:
        staged = session.scalar(
            text(
                "SELECT count(*) FROM lucy.scoped_memory_candidate_versions_v1 "
                "WHERE candidate_id=:candidate"
            ),
            {"candidate": first.candidate_id},
        )
        settled = session.scalar(
            text(
                "SELECT count(*) FROM lucy.memory_import_attempt_settlements_v1 "
                "WHERE reservation_id=:reservation"
            ),
            {"reservation": reservation.reservation_id},
        )
    assert staged == 0
    assert settled == 0


def test_outcome_recovery_policy_requires_registered_exact_authorization() -> None:
    assert all((OWNER_URL, RAYMOND_URL, POLICY_URL))
    scope_id, _ = _provision()
    owner_sessions = create_session_factory(OWNER_URL)
    raymond_sessions = create_session_factory(RAYMOND_URL)
    policy_sessions = create_session_factory(POLICY_URL)
    now = datetime.now(UTC)
    campaign_id = uuid4()
    source_record_id = "policy-bridge-source"
    record = {
        "source_record_id": source_record_id,
        "content_commitment": "a" * 64,
        "byte_length": 16,
        "estimated_tokens": 6,
        "source_revision": 1,
        "role": "owner",
        "displayed": True,
        "included": True,
        "exclusion_reason": None,
        "native_role": None,
        "native_message_id": None,
        "native_node_id": None,
        "occurred_at": None,
        "parent_source_record_id": None,
    }
    manifest = ImportManifestV2(
        campaign_id=campaign_id,
        destination_content_scope_id=scope_id,
        source_namespace="synthetic/policy-bridge",
        source_conversation_id="policy-bridge-conversation",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="synthetic-private-zdr-v1",
        model_route="none",
        records=(record,),
        max_records=1,
        max_bytes=16,
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        max_source_estimated_tokens=6,
        max_request_input_tokens=50,
        max_request_output_tokens=50,
        max_request_total_tokens=100,
        max_model_spend_microusd=0,
        max_attempts=1,
        expires_at=now + timedelta(hours=1),
    )
    GovernedMemoryPolicy(policy_sessions).authorize_campaign(manifest)
    evidence_id = uuid4()
    with owner_sessions.begin() as session:
        archive_actor_id = session.execute(
            text(
                "SELECT id FROM lucy.realm_sensitive_actor_bindings_v1 "
                "WHERE content_scope_id=:scope AND actor_role='archive_writer'"
            ),
            {"scope": scope_id},
        ).scalar_one()
        session.add(
            ScopedEvidenceRecordV2Row(
                id=evidence_id,
                content_scope_id=scope_id,
                archive_actor_binding_id=archive_actor_id,
                content_classification="memory_import.protected",
                lineage_refs=[],
                idempotency_key=(
                    f"memory-import:{manifest.digest}:{source_record_id}:r1"
                ),
                status="active",
                created_at=now,
            )
        )
        session.flush()
        session.add(
            ScopedEvidencePayloadV2Row(
                evidence_id=evidence_id,
                record_version=1,
                payload_ciphertext_digest="b" * 64,
                serialized_payload={"ciphertext_b64": base64.b64encode(b"e" * 32).decode()},
                created_at=now,
            )
        )

    extractor = GovernedMemoryExtractor(raymond_sessions)
    reservation = extractor.reserve_attempt(
        campaign_id, attempt_key="policy-bridge-attempt", reserved_microusd=0
    )
    request_commitment = "c" * 64
    job_id = memory_extraction_job_id(
        campaign_id,
        attempt_key="policy-bridge-attempt",
        request_commitment=request_commitment,
    )
    job = {
        "contract_version": "1",
        "extraction_job_id": str(job_id),
        "reservation_id": str(reservation.reservation_id),
        "campaign_id": str(campaign_id),
        "manifest_digest": manifest.digest,
        "attempt_key": "policy-bridge-attempt",
        "source_record_ids": [source_record_id],
        "request_commitment": request_commitment,
        "request_bytes": 50,
        "input_token_upper_bound": 50,
        "maximum_output_tokens": 50,
        "token_accounting_version": manifest.token_accounting_version,
        "provider_policy_id": manifest.provider_policy_id,
        "model_route": manifest.model_route,
        "maximum_microusd": 0,
    }
    with raymond_sessions.begin() as session:
        session.execute(
            text("SELECT lucy.register_memory_import_job_v1(CAST(:job AS jsonb))"),
            {"job": json.dumps(job, separators=(",", ":"))},
        ).scalar_one()
    encryption_id = memory_outcome_encryption_id(job_id)
    envelope = MemoryOutcomeEnvelopeV1(
        binding=MemoryOutcomeBindingV1(
            extraction_job_id=job_id,
            reservation_id=reservation.reservation_id,
            campaign_id=campaign_id,
            destination_content_scope_id=scope_id,
            manifest_digest=manifest.digest,
            attempt_key="policy-bridge-attempt",
            source_record_ids=(source_record_id,),
            request_commitment=request_commitment,
            provider_policy_id=manifest.provider_policy_id,
            model_route=manifest.model_route,
            maximum_microusd=0,
        ),
        encryption_id=encryption_id,
        registry_id=uuid4(),
        algorithm="AES-256-GCM+AWS-KMS",
        encryption_context_version=3,
        record_version=1,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        ciphertext_b64=base64.b64encode(b"encrypted-outcome-with-tag").decode(),
        content_nonce_b64=base64.b64encode(b"n" * 12).decode(),
        keyed_commitment="d" * 64,
        billed_microusd=0,
        provider_reference_commitment="e" * 64,
    )
    PostgresMemoryOutcomeStore(raymond_sessions).put(envelope)
    with owner_sessions() as session:
        scope = session.execute(
            text(
                "SELECT tenant_account_id,node_id,node_tenure_id,tenure_epoch,"
                "security_realm_id,storage_epoch,deployment_id "
                "FROM lucy.realm_content_scopes_v1 WHERE id=:scope"
            ),
            {"scope": scope_id},
        ).mappings().one()
    origin_scope = OriginScopeV1.model_validate(
        {key: scope[key] for key in OriginScopeV1.model_fields}
    )
    package = MemoryOutcomeRecoveryPackageV1(
        target_scope=origin_scope,
        envelope=envelope,
    )
    bundle = PilotManifestBundleV1(
        selection_proposal_digest="1" * 64,
        archive_commitment="2" * 64,
        campaign_id=campaign_id,
        destination_content_scope_id=scope_id,
        manifest=manifest,
        included_record_count=1,
        excluded_record_count=0,
        included_source_bytes=16,
        estimated_source_tokens=6,
        excluded_attachment_reference_count=0,
    )
    authorization = AuthorizedPilotManifestV1(
        bundle=bundle,
        bundle_digest=bundle.digest,
        owner_approval_ref=uuid4(),
        owner_actor_id="raymond-owner",
        approved_at=now,
    )
    store = PostgresMemoryOutcomePolicyStore(policy_sessions)
    with pytest.raises(MemoryOutcomeUnavailable, match="admission unavailable"):
        store.admit(authorization, package)
    with owner_sessions.begin() as session:
        session.execute(text("SET LOCAL ROLE lucy_migration"))
        registered = session.execute(
            text(
                "SELECT lucy.register_memory_import_pilot_authorization_v1("
                "CAST(:authorization AS jsonb))"
            ),
            {
                "authorization": json.dumps(
                    authorization.model_dump(mode="json"), separators=(",", ":")
                )
            },
        ).scalar_one()
    assert registered["owner_approval_ref"] == str(authorization.owner_approval_ref)
    request = MemoryOutcomeGrantRequestV1(
        authorization=authorization,
        package=package,
    )
    with (
        pytest.raises(DBAPIError, match="memory outcome recovery unavailable"),
        policy_sessions.begin() as session,
    ):
        session.execute(
            text(
                "SELECT lucy.admit_memory_outcome_recovery_v1("
                "CAST(:authorization AS jsonb),CAST(:package AS jsonb),"
                ":package_digest,:request_digest)"
            ),
            {
                "authorization": json.dumps(
                    authorization.model_dump(mode="json"), separators=(",", ":")
                ),
                "package": json.dumps(
                    package.model_dump(mode="json"), separators=(",", ":")
                ),
                "package_digest": "f" * 64,
                "request_digest": request.digest_hex(),
            },
        ).scalar_one()
    signer = Ed25519V13Signer(
        ed25519.Ed25519PrivateKey.generate(),
        key_id="policy-bridge-test",
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
    )
    execution_binding = ExecutionBindingV1(
        deployment_id=scope["deployment_id"],
        active_realm_id=origin_scope.security_realm_id,
        active_storage_epoch=origin_scope.storage_epoch,
        realm_binding_generation=1,
        node_authz_epoch=1,
    )
    policy = MemoryOutcomeRecoveryPolicy(
        signer,
        store,
        environment=DeploymentEnvironment.TEST,
        issuer="lucy-policy-test",
        caller_identity="arn:aws:iam::123456789012:role/lucy-raymond-archive",
        target_scope=origin_scope,
        execution_binding=execution_binding,
        policy_version=1,
    )
    issuer = DurableMemoryOutcomeGrantIssuer(store, policy)
    first = issuer.issue(authorization=authorization, package=package, now=now)
    replay = issuer.issue(
        authorization=authorization,
        package=package,
        now=now + timedelta(seconds=1),
    )
    assert first == replay
    changed_grant = first.model_dump(mode="json")
    changed_grant["registry_id"] = str(uuid4())
    changed_grant_digest = canonical_sha256(
        {key: value for key, value in changed_grant.items() if key != "signature"},
        prefix=b"LUCY-SIGNED-CONTRACT\0",
    )
    with (
        pytest.raises(DBAPIError, match="memory outcome recovery grant is invalid"),
        policy_sessions.begin() as session,
    ):
        session.execute(
            text(
                "SELECT lucy.record_memory_outcome_recovery_grant_v1("
                ":request_digest,:grant_digest,CAST(:grant AS jsonb))"
            ),
            {
                "request_digest": request.digest_hex(),
                "grant_digest": changed_grant_digest,
                "grant": json.dumps(changed_grant, separators=(",", ":")),
            },
        ).scalar_one()
    with pytest.raises(DBAPIError, match="permission denied"), policy_sessions.begin() as session:
        session.execute(text("SELECT * FROM lucy.memory_import_provider_outcomes_v1"))
    _make_source_unavailable(evidence_id)
    with pytest.raises(MemoryOutcomeUnavailable, match="admission unavailable"):
        store.admit(authorization, package)


def test_memory_pilot_transport_is_capability_scoped_idempotent_and_revocable() -> None:
    assert all((OWNER_URL, RAYMOND_URL, POLICY_URL))
    scope_id, _ = _provision()
    now = datetime.now(UTC)
    campaign_id = uuid4()
    message = LocalChatGPTMessageV1(
        source_record_id="transport-conversation:node-1:message-1",
        conversation_id="transport-conversation",
        native_node_id="node-1",
        native_message_id="message-1",
        parent_source_record_id=None,
        native_role="user",
        role="owner",
        occurred_at=now,
        displayed=True,
        content="Synthetic transport evidence; no personal history.",
        inclusion_state="included",
    )
    record = manifest_record_for_local_message(message, b"f" * 32)
    manifest = ImportManifestV2(
        campaign_id=campaign_id,
        destination_content_scope_id=scope_id,
        source_namespace="synthetic/transport",
        source_conversation_id="transport-conversation",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="local-synthetic-only",
        model_route="none",
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        records=(record,),
        max_records=1,
        max_bytes=record.byte_length,
        max_source_estimated_tokens=record.estimated_tokens,
        max_request_input_tokens=10_000,
        max_request_output_tokens=100,
        max_request_total_tokens=10_100,
        max_model_spend_microusd=0,
        max_attempts=1,
        expires_at=now + timedelta(hours=1),
    )
    GovernedMemoryPolicy(create_session_factory(POLICY_URL)).authorize_campaign(manifest)
    bundle = PilotManifestBundleV1(
        selection_proposal_digest="a" * 64,
        archive_commitment="b" * 64,
        campaign_id=campaign_id,
        destination_content_scope_id=scope_id,
        manifest=manifest,
        included_record_count=1,
        excluded_record_count=0,
        included_source_bytes=record.byte_length,
        estimated_source_tokens=record.estimated_tokens,
        excluded_attachment_reference_count=0,
    )
    authorization = AuthorizedPilotManifestV1(
        bundle=bundle,
        bundle_digest=bundle.digest,
        owner_approval_ref=uuid4(),
        owner_actor_id="raymond-owner",
        approved_at=now,
    )
    prepared = prepare_memory_pilot_transport(
        LocalPilotBuildV1(
            bundle=bundle,
            conversations=(
                LocalChatGPTConversationV1(
                    conversation_id="transport-conversation", messages=(message,)
                ),
            ),
        ),
        authorization,
        expected_bundle_digest=bundle.digest,
        transfer_key=b"t" * 32,
        capability_token=b"c" * 32,
        maximum_microusd_per_attempt=0,
        timeout_seconds=30,
        expires_at=now + timedelta(minutes=30),
        now=now + timedelta(seconds=1),
    )
    owner_sessions = create_session_factory(OWNER_URL)
    with owner_sessions.begin() as session:
        session.execute(text("SET LOCAL ROLE lucy_migration"))
        session.execute(
            text(
                "SELECT lucy.register_memory_import_pilot_authorization_v1("
                "CAST(:authorization AS jsonb))"
            ),
            {"authorization": canonical_json_bytes(authorization).decode("utf-8")},
        ).scalar_one()
        registration = session.execute(
            text(
                "SELECT lucy.register_memory_pilot_transport_v1("
                "CAST(:registration AS jsonb))"
            ),
            {
                "registration": canonical_json_bytes(prepared.registration).decode(
                    "utf-8"
                )
            },
        ).scalar_one()
    assert registration["replayed"] is False
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        create_session_factory(RAYMOND_URL).begin() as session,
    ):
        session.execute(
            text("SELECT lucy.register_memory_pilot_transport_v1('{}'::jsonb)")
        )
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        create_session_factory(POLICY_URL).begin() as session,
    ):
        session.execute(
            text(
                "SELECT lucy.read_memory_pilot_transport_admission_v1("
                ":capability,:batch)"
            ),
            {
                "capability": prepared.registration.capability_token_digest,
                "batch": prepared.batches[0].batch_id,
            },
        )
    admission = PostgresMemoryPilotTransportAdmission(
        create_session_factory(RAYMOND_URL), transfer_key=b"t" * 32
    )
    with pytest.raises(MemoryPilotTransportUnavailable):
        admission.admit(
            prepared.batches[0], capability_token=b"w" * 32
        )
    first = admission.admit(
        prepared.batches[0], capability_token=b"c" * 32
    )
    replay = admission.admit(
        prepared.batches[0], capability_token=b"c" * 32
    )
    assert first.batch_id == replay.batch_id
    assert first.replayed is False and replay.replayed is True
    with owner_sessions() as session:
        scope = session.get(RealmContentScopeRow, scope_id)
        assert scope is not None
        origin_scope = OriginScopeV1(
            tenant_account_id=scope.tenant_account_id,
            node_id=scope.node_id,
            node_tenure_id=scope.node_tenure_id,
            tenure_epoch=scope.tenure_epoch,
            security_realm_id=scope.security_realm_id,
            storage_epoch=scope.storage_epoch,
        )
    backend = _ImportArchiveBackend()
    archive = GovernedMemoryArchive(
        create_session_factory(RAYMOND_URL),
        RealmArchiveEncryptor(
            backend,
            RealmArchiveIdentityV1(
                target_scope=origin_scope,
                evidence_key_arn=TEST_KMS_ARN,
                record_version=1,
            ),
            commitment_key=b"k" * 32,
        ),
        request_commitment_key=b"r" * 32,
    )
    extractor = GovernedMemoryExtractor(create_session_factory(RAYMOND_URL))
    provider = DeterministicFakeMemoryImportProvider(
        MemoryExtractionOutputV1(
            candidates=(
                ExtractedCandidateDraftV1(
                    subject="synthetic transport",
                    predicate="contains",
                    object="no personal history",
                    confidence_millionths=900_000,
                    memory_kind="assertion",
                    assertion_status="report",
                    epistemic_status="current",
                    domain_tags=("synthetic",),
                    sources=(
                        ExtractedSourceQuoteV1(
                            source_record_id=record.source_record_id,
                            exact_quote="no personal history",
                        ),
                    ),
                ),
            )
        )
    )
    outcomes = EncryptedMemoryOutcomeJournal(
        PostgresMemoryOutcomeStore(create_session_factory(RAYMOND_URL)),
        cipher=EnvelopeCipher(
            b"o" * 32, b"p" * 32, kek_version="synthetic-transport-outcome-v1"
        ),
        key_store=MemoryArchiveKeyStore(),
    )
    executor = VerifiedMemoryPilotBatchExecutor(
        admission=admission,
        archive=archive,
        accounting=extractor,
        eligibility=extractor,
        provider=provider,
        outcomes=outcomes,
        outcome_recovery=outcomes,
        candidate_store=extractor,
        now=lambda: datetime.now(UTC),
    )
    executed = executor.execute(prepared.batches[0], capability_token=b"c" * 32)
    executed_replay = executor.execute(
        prepared.batches[0], capability_token=b"c" * 32
    )
    assert executed.receipt.state == executed_replay.receipt.state == "succeeded"
    assert executed.receipt.candidate_count == 1
    assert executed.review_artifact == executed_replay.review_artifact
    assert provider.calls == 1
    assert backend.generate_calls == 1
    assert executed.review_artifact is not None
    candidate_id = executed.review_artifact.bundle.items[0].candidate.candidate_id
    with owner_sessions() as session:
        settled_job = session.scalar(
            text(
                "SELECT serialized_job FROM lucy.memory_import_extraction_jobs_v1 "
                "WHERE id=:job"
            ),
            {"job": prepared.batches[0].dispatch.extraction_job_id},
        )
    assert isinstance(settled_job, dict)
    conflicting_job = {**settled_job, "extraction_job_id": str(uuid4())}
    with (
        pytest.raises(DBAPIError, match="memory import job conflict"),
        create_session_factory(RAYMOND_URL).begin() as session,
    ):
        session.execute(
            text("SELECT lucy.register_memory_import_job_v1(CAST(:job AS jsonb))"),
            {"job": json.dumps(conflicting_job, separators=(",", ":"))},
        ).scalar_one()
    with owner_sessions() as session:
        assert session.scalar(
            text(
                "SELECT count(*) FROM lucy.scoped_memory_candidate_versions_v1 "
                "WHERE candidate_id=:candidate"
            ),
            {"candidate": candidate_id},
        ) == 1
        assert session.scalar(
            text(
                "SELECT count(*) FROM lucy.memory_import_attempt_settlements_v1 "
                "WHERE campaign_id=:campaign AND result='succeeded'"
            ),
            {"campaign": campaign_id},
        ) == 1
        outcome_count, serialized_outcome = session.execute(
            text(
                "SELECT count(*), min(serialized_envelope::text) "
                "FROM lucy.memory_import_provider_outcomes_v1 "
                "WHERE extraction_job_id=:job"
            ),
            {"job": prepared.batches[0].dispatch.extraction_job_id},
        ).one()
        assert outcome_count == 1
        assert "no personal history" not in serialized_outcome
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        create_session_factory(RAYMOND_URL).begin() as session,
    ):
        session.execute(text("SELECT * FROM lucy.memory_pilot_transport_batches_v1"))
    with ThreadPoolExecutor(max_workers=1) as executor:
        with owner_sessions.begin() as session:
            session.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtextextended("
                    "'memory-pilot-transport:'||CAST(:campaign AS text),0))"
                ),
                {"campaign": campaign_id},
            )
            waiting_admission = executor.submit(
                admission.admit,
                prepared.batches[0],
                capability_token=b"c" * 32,
            )
            deadline = time.monotonic() + 5
            waiting = False
            while time.monotonic() < deadline:
                with owner_sessions() as observer:
                    waiting = bool(
                        observer.scalar(
                            text(
                                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                                "WHERE usename='lucy_raymond_routine' "
                                "AND wait_event_type='Lock' AND wait_event='advisory')"
                            )
                        )
                    )
                if waiting:
                    break
                time.sleep(0.02)
            assert waiting, "admission did not reach the campaign-lock race"
            session.execute(text("SET LOCAL ROLE lucy_migration"))
            revoked = session.execute(
                text(
                    "SELECT lucy.revoke_memory_pilot_transport_v1("
                    ":campaign,:revocation,:reason)"
                ),
                {
                    "campaign": campaign_id,
                    "revocation": uuid4(),
                    "reason": hashlib.sha256(b"synthetic owner stop").hexdigest(),
                },
            ).scalar_one()
        with pytest.raises(MemoryPilotTransportUnavailable):
            waiting_admission.result(timeout=5)
    assert revoked["campaign_id"] == str(campaign_id)
    with pytest.raises(MemoryPilotTransportUnavailable):
        admission.admit(
            prepared.batches[0], capability_token=b"c" * 32
        )
