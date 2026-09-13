from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    DeletionArtifactClassV3,
    DeletionTargetManifestV3,
    DeletionTargetReferenceV3,
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
    MemoryOutcomeBindingV1,
    MemoryOutcomeEnvelopeV1,
    MemoryOutcomeUnavailable,
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
                        "memory.protected.read",
                        "sensitive.deletion_manifest.issue",
                    ],
                    binding_generation=1,
                    node_authz_epoch=1,
                    policy_version=1,
                    active=True,
                    created_at=now,
                ),
            )
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
                max_attempts=1,
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
                "TO lucy_raymond_policy"
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
                "security_realm_id,storage_epoch,workspace_id "
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
                "max_records": 90,
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
                "p.target_service_binding_id,p.actor_principal_id,c.id,'evidence.delete',"
                ":evidence,1,:digest,CAST(:serialized AS jsonb),:nonce,:issue_key,"
                ":now,:claim_deadline,"
                ":completion_deadline,'CLAIMED',:claim_key,:now,:now "
                "FROM lucy.realm_sensitive_actor_bindings_v1 p "
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
                "WHERE p.content_scope_id=:scope AND p.actor_role='policy_notary'"
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
    assert all((OWNER_URL, RAYMOND_URL, POLICY_URL))
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
