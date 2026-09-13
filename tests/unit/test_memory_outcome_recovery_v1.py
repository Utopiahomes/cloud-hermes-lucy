from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from lucy.archive_crypto import WrappedDataKey
from lucy.chatgpt_manifest import (
    AuthorizedPilotManifestV1,
    PilotManifestBundleV1,
)
from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.memory_outcome_recovery_v1 import (
    MemoryOutcomeBindingV1,
    MemoryOutcomeEnvelopeV1,
    MemoryOutcomeRecoveryGrantV1,
    MemoryOutcomeRecoveryPackageV1,
    MemoryOutcomeRecoveryResultV1,
)
from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    Ed25519V13Signer,
    ExecutionBindingV1,
    OriginScopeV1,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
)
from lucy.executors.outcome_recovery_v1 import (
    MemoryOutcomeRecoveryExecutor,
    MemoryOutcomeRecoveryRejected,
)
from lucy.memory_extraction import MemoryExtractionDispatchV1
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV2
from lucy.memory_outcome import memory_outcome_encryption_id
from lucy.memory_outcome_aws_v1 import (
    AwsKmsMemoryOutcomeEncryptor,
    DynamoMemoryOutcomeKeyWriter,
)
from lucy.memory_outcome_recovery import (
    AwsLambdaMemoryOutcomeRecoveryInvoker,
    DurableMemoryOutcomeGrantIssuer,
    HttpMemoryOutcomeGrantIssuer,
    MemoryOutcomeGrantAdmissionV1,
    MemoryOutcomeGrantRequestV1,
    MemoryOutcomeRecoveryPolicy,
    PermitBoundMemoryOutcomeRecovery,
    memory_outcome_recovery_from_environment,
)

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
KEY_ARN = "arn:aws:kms:us-east-1:429870640638:key/11111111-1111-1111-1111-111111111111"
SCOPE = OriginScopeV1(
    tenant_account_id=UUID(int=1),
    node_id=UUID(int=2),
    node_tenure_id=UUID(int=3),
    tenure_epoch=1,
    security_realm_id=UUID(int=4),
    storage_epoch=1,
)
BINDING = ExecutionBindingV1(
    deployment_id=UUID(int=5),
    active_realm_id=SCOPE.security_realm_id,
    active_storage_epoch=1,
    realm_binding_generation=1,
    node_authz_epoch=1,
)
OUTCOME_BINDING = MemoryOutcomeBindingV1(
    extraction_job_id=UUID(int=10),
    reservation_id=UUID(int=11),
    campaign_id=UUID(int=12),
    destination_content_scope_id=UUID(int=13),
    manifest_digest="a" * 64,
    attempt_key="attempt-1",
    source_record_ids=("source-1",),
    request_commitment="b" * 64,
    provider_policy_id="policy-1",
    model_route="openrouter/test",
    maximum_microusd=500,
)
ENCRYPTION_ID = memory_outcome_encryption_id(OUTCOME_BINDING.extraction_job_id)
REGISTRY_ID = UUID(int=15)


class FakeKms:
    def __init__(self) -> None:
        self.dek = b"d" * 32
        self.generated: list[dict[str, Any]] = []
        self.decrypted: list[dict[str, Any]] = []

    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]:
        self.generated.append(kwargs)
        return {"Plaintext": self.dek, "CiphertextBlob": b"wrapped", "KeyId": KEY_ARN}

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.decrypted.append(kwargs)
        return {"Plaintext": self.dek, "KeyId": KEY_ARN}


class FakeDynamo:
    def __init__(self) -> None:
        self.keys: dict[str, dict[str, Any]] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put_item", kwargs))
        item = kwargs["Item"]
        if "key_ref" in item:
            self.keys[item["key_ref"]["S"]] = item
        else:
            self.receipts[item["operation_id"]["S"]] = item
        return {}

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_item", kwargs))
        if "operation_id" in kwargs["Key"]:
            item = self.receipts.get(kwargs["Key"]["operation_id"]["S"])
        else:
            item = self.keys.get(kwargs["Key"]["key_ref"]["S"])
        return {} if item is None else {"Item": item}


def _trust() -> tuple[Ed25519V13Signer, V13ContractVerifier]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519V13Signer(
        private,
        key_id="policy-test",
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
    )
    key = V13VerificationKeyV1(
        key_id="policy-test",
        issuer="lucy-policy-test",
        environment=DeploymentEnvironment.TEST,
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        public_key_b64=signer.public_key_b64,
        status=V13VerificationKeyStatus.ACTIVE,
        valid_from=NOW - timedelta(days=1),
        issuance_not_after=NOW + timedelta(days=1),
        verify_not_after=NOW + timedelta(days=2),
    )
    return signer, V13ContractVerifier((key,))


def _package(kms: FakeKms, dynamo: FakeDynamo) -> MemoryOutcomeRecoveryPackageV1:
    cipher = AwsKmsMemoryOutcomeEncryptor(
        kms,
        key_arn=KEY_ARN,
        commitment_key=b"c" * 32,
        target_scope=SCOPE,
        registry_epoch=1,
        key_epoch=1,
    )
    outcome = {
        "output": "candidate output",
        "billed_microusd": 123,
        "provider_policy_id": "policy-1",
        "model_route": "openrouter/test",
        "provider_reference_commitment": "f" * 64,
    }
    encrypted = cipher.encrypt(
        ENCRYPTION_ID,
        canonical_json_bytes(outcome),
        canonical_json_bytes(OUTCOME_BINDING),
    )
    writer = DynamoMemoryOutcomeKeyWriter(
        dynamo,
        table_name="outcome-keys",
        registry_id=REGISTRY_ID,
    )
    writer.put_new(ENCRYPTION_ID, encrypted.wrapped_key)
    envelope = MemoryOutcomeEnvelopeV1(
        binding=OUTCOME_BINDING,
        encryption_id=ENCRYPTION_ID,
        registry_id=REGISTRY_ID,
        algorithm=cipher.algorithm,
        encryption_context_version=cipher.encryption_context_version,
        record_version=1,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        ciphertext_b64=base64.b64encode(encrypted.ciphertext).decode(),
        content_nonce_b64=base64.b64encode(encrypted.content_nonce).decode(),
        keyed_commitment=encrypted.keyed_commitment,
        billed_microusd=123,
        provider_reference_commitment="f" * 64,
    )
    return MemoryOutcomeRecoveryPackageV1(target_scope=SCOPE, envelope=envelope)


def _grant(
    package: MemoryOutcomeRecoveryPackageV1,
    signer: Ed25519V13Signer,
    **changes: object,
) -> MemoryOutcomeRecoveryGrantV1:
    values: dict[str, object] = {
        "key_id": "policy-test",
        "issuer": "lucy-policy-test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW,
        "operation_id": UUID(int=20),
        "caller_identity": "arn:aws:iam::429870640638:role/lucy-archive",
        "target_scope": SCOPE,
        "execution_binding": BINDING,
        "campaign_id": OUTCOME_BINDING.campaign_id,
        "manifest_digest": OUTCOME_BINDING.manifest_digest,
        "extraction_job_id": OUTCOME_BINDING.extraction_job_id,
        "reservation_id": OUTCOME_BINDING.reservation_id,
        "destination_content_scope_id": OUTCOME_BINDING.destination_content_scope_id,
        "encryption_id": ENCRYPTION_ID,
        "registry_id": REGISTRY_ID,
        "package_digest": package.digest_hex(),
        "pilot_authorization_id": UUID(int=21),
        "policy_version": 1,
        "permit_claim_deadline": NOW + timedelta(seconds=30),
        "execution_completion_deadline": NOW + timedelta(minutes=2),
        "max_plaintext_bytes": 4096,
        "nonce": "n" * 32,
    }
    values.update(changes)
    return signer.sign(MemoryOutcomeRecoveryGrantV1.model_validate(values))


def _executor(
    dynamo: FakeDynamo, kms: FakeKms, verifier: V13ContractVerifier
) -> MemoryOutcomeRecoveryExecutor:
    return MemoryOutcomeRecoveryExecutor(
        dynamo,
        kms,
        verifier,
        target_scope=SCOPE,
        execution_binding=BINDING,
        environment=DeploymentEnvironment.TEST,
        caller_identity="arn:aws:iam::429870640638:role/lucy-archive",
        key_arn=KEY_ARN,
        registry_id=str(REGISTRY_ID),
        key_table="outcome-keys",
        receipt_table="outcome-receipts",
    )


def test_writer_has_no_read_or_decrypt_surface_and_uses_outcome_context() -> None:
    kms = FakeKms()
    dynamo = FakeDynamo()
    _package(kms, dynamo)

    assert len(kms.generated) == 1
    assert kms.decrypted == []
    assert kms.generated[0]["EncryptionContext"]["purpose"] == "MEMORY_OUTCOME_DEK"
    assert kms.generated[0]["EncryptionContext"]["security_realm_id"] == str(
        SCOPE.security_realm_id
    )
    assert all(call[0] == "put_item" for call in dynamo.calls)
    assert not hasattr(DynamoMemoryOutcomeKeyWriter, "get")


def test_exact_grant_releases_once_and_replay_never_decrypts() -> None:
    kms = FakeKms()
    dynamo = FakeDynamo()
    package = _package(kms, dynamo)
    signer, verifier = _trust()
    grant = _grant(package, signer)
    executor = _executor(dynamo, kms, verifier)

    first = executor.execute(
        grant, package, now=NOW + timedelta(seconds=1), lambda_request_id="req-1"
    )
    assert first.released is True
    assert first.output == "candidate output"
    assert len(kms.decrypted) == 1

    second = executor.execute(
        grant, package, now=NOW + timedelta(seconds=2), lambda_request_id="req-2"
    )
    assert second.replayed is True
    assert second.output is None
    assert len(kms.decrypted) == 1


def test_substituted_package_is_rejected_before_key_read_or_decrypt() -> None:
    kms = FakeKms()
    dynamo = FakeDynamo()
    package = _package(kms, dynamo)
    signer, verifier = _trust()
    grant = _grant(package, signer)
    changed = package.model_copy(
        update={
            "envelope": package.envelope.model_copy(
                update={"ciphertext_b64": base64.b64encode(b"different-ciphertext").decode()}
            )
        }
    )
    before = len(dynamo.calls)

    with pytest.raises(MemoryOutcomeRecoveryRejected, match="package_binding_mismatch"):
        _executor(dynamo, kms, verifier).execute(
            grant, changed, now=NOW + timedelta(seconds=1), lambda_request_id="req-1"
        )

    assert len(dynamo.calls) == before
    assert kms.decrypted == []


def test_expired_grant_is_rejected_before_key_read_or_decrypt() -> None:
    kms = FakeKms()
    dynamo = FakeDynamo()
    package = _package(kms, dynamo)
    signer, verifier = _trust()
    grant = _grant(package, signer)
    before = len(dynamo.calls)

    with pytest.raises(MemoryOutcomeRecoveryRejected, match="grant_claim_expired"):
        _executor(dynamo, kms, verifier).execute(
            grant, package, now=NOW + timedelta(seconds=31), lambda_request_id="req-1"
        )

    assert len(dynamo.calls) == before
    assert kms.decrypted == []


def test_writer_rejects_non_kms_wrapped_key_ambiguity() -> None:
    dynamo = FakeDynamo()
    writer = DynamoMemoryOutcomeKeyWriter(
        dynamo, table_name="outcome-keys", registry_id=REGISTRY_ID
    )
    writer.put_new(
        ENCRYPTION_ID,
        WrappedDataKey(ciphertext=b"wrapped", nonce=b"kms", kek_version=KEY_ARN),
    )
    assert dynamo.keys[str(ENCRYPTION_ID)]["registry_id"]["S"] == str(REGISTRY_ID)


class Eligibility:
    def __init__(self) -> None:
        self.phases: list[str] = []

    def require_recoverable(self, **values: Any) -> None:
        self.phases.append(values["phase"])


class Store:
    def __init__(self, envelope: MemoryOutcomeEnvelopeV1) -> None:
        self.envelope = envelope

    def load(self, extraction_job_id: UUID) -> MemoryOutcomeEnvelopeV1 | None:
        assert extraction_job_id == OUTCOME_BINDING.extraction_job_id
        return self.envelope

    def put(self, envelope: MemoryOutcomeEnvelopeV1) -> MemoryOutcomeEnvelopeV1:
        raise AssertionError("recovery cannot write outcome envelopes")


class Invoker:
    def __init__(self) -> None:
        self.calls = 0

    def recover(
        self,
        grant: MemoryOutcomeRecoveryGrantV1,
        package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeRecoveryResultV1:
        self.calls += 1
        return MemoryOutcomeRecoveryResultV1(
            operation_id=grant.operation_id,
            extraction_job_id=grant.extraction_job_id,
            package_digest=package.digest_hex(),
            released=True,
            replayed=False,
            output="candidate output",
            billed_microusd=123,
            provider_policy_id="policy-1",
            model_route="openrouter/test",
            provider_reference_commitment="f" * 64,
        )


def _authorization() -> AuthorizedPilotManifestV1:
    record = ImportManifestRecordV1(
        source_record_id="source-1",
        content_commitment="e" * 64,
        byte_length=10,
        estimated_tokens=3,
        source_revision=1,
        role="owner",
        displayed=True,
    )
    manifest = ImportManifestV2(
        campaign_id=OUTCOME_BINDING.campaign_id,
        destination_content_scope_id=OUTCOME_BINDING.destination_content_scope_id,
        source_namespace="chatgpt-export",
        source_conversation_id="conversation-1",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="policy-1",
        model_route="openrouter/test",
        token_accounting_version="tokens-v1",
        records=(record,),
        max_records=1,
        max_bytes=10,
        max_source_estimated_tokens=3,
        max_request_input_tokens=100,
        max_request_output_tokens=100,
        max_request_total_tokens=200,
        max_model_spend_microusd=500,
        max_attempts=1,
        expires_at=NOW + timedelta(hours=1),
    )
    bundle = PilotManifestBundleV1(
        selection_proposal_digest="1" * 64,
        archive_commitment="2" * 64,
        campaign_id=manifest.campaign_id,
        destination_content_scope_id=manifest.destination_content_scope_id,
        manifest=manifest,
        included_record_count=1,
        excluded_record_count=0,
        included_source_bytes=10,
        estimated_source_tokens=3,
        excluded_attachment_reference_count=0,
    )
    return AuthorizedPilotManifestV1(
        bundle=bundle,
        bundle_digest=bundle.digest,
        owner_approval_ref=UUID(int=21),
        owner_actor_id="raymond-private-owner",
        approved_at=NOW - timedelta(minutes=1),
    )


def test_policy_path_rechecks_eligibility_around_exact_recovery() -> None:
    authorization = _authorization()
    manifest = authorization.bundle.manifest
    assert isinstance(manifest, ImportManifestV2)
    binding = OUTCOME_BINDING.model_copy(update={"manifest_digest": manifest.digest})
    encryption_id = memory_outcome_encryption_id(binding.extraction_job_id)
    envelope = MemoryOutcomeEnvelopeV1(
        binding=binding,
        encryption_id=encryption_id,
        registry_id=REGISTRY_ID,
        algorithm="AES-256-GCM+AWS-KMS",
        encryption_context_version=3,
        record_version=1,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        ciphertext_b64=base64.b64encode(b"ciphertext-with-tag").decode(),
        content_nonce_b64=base64.b64encode(b"n" * 12).decode(),
        keyed_commitment="c" * 64,
        billed_microusd=123,
        provider_reference_commitment="f" * 64,
    )
    eligibility = Eligibility()
    signer, _ = _trust()
    policy = MemoryOutcomeRecoveryPolicy(
        signer,
        eligibility,
        environment=DeploymentEnvironment.TEST,
        issuer="lucy-policy-test",
        caller_identity="arn:aws:iam::429870640638:role/lucy-archive",
        target_scope=SCOPE,
        execution_binding=BINDING,
        policy_version=1,
        operation_id_factory=lambda: UUID(int=20),
        nonce_factory=lambda: "n" * 32,
    )
    invoker = Invoker()
    recovery = PermitBoundMemoryOutcomeRecovery(
        Store(envelope),
        policy,
        eligibility,
        invoker,
        authorization=authorization,
        target_scope=SCOPE,
        clock=lambda: NOW,
    )
    dispatch = MemoryExtractionDispatchV1(
        extraction_job_id=binding.extraction_job_id,
        attempt_key=binding.attempt_key,
        source_record_ids=binding.source_record_ids,
        prompt="not sent during recovery",
        input_tokens=10,
        output_tokens=10,
        request_bytes=100,
        request_commitment=binding.request_commitment,
        maximum_microusd=binding.maximum_microusd,
        timeout_seconds=30,
    )

    outcome = recovery.load(
        manifest=manifest,
        dispatch=dispatch,
        reservation_id=binding.reservation_id,
    )

    assert outcome is not None and outcome.output == "candidate output"
    assert eligibility.phases == ["pre_grant", "pre_completion"]
    assert invoker.calls == 1


def test_policy_caps_recovery_deadlines_at_campaign_expiry() -> None:
    authorization = _authorization()
    manifest = authorization.bundle.manifest
    assert isinstance(manifest, ImportManifestV2)
    expiring = manifest.model_copy(update={"expires_at": NOW + timedelta(seconds=30)})
    bundle = authorization.bundle.model_copy(update={"manifest": expiring})
    authorization = authorization.model_copy(
        update={"bundle": bundle, "bundle_digest": bundle.digest}
    )
    binding = OUTCOME_BINDING.model_copy(update={"manifest_digest": expiring.digest})
    encryption_id = memory_outcome_encryption_id(binding.extraction_job_id)
    package = MemoryOutcomeRecoveryPackageV1(
        target_scope=SCOPE,
        envelope=MemoryOutcomeEnvelopeV1(
            binding=binding,
            encryption_id=encryption_id,
            registry_id=REGISTRY_ID,
            algorithm="AES-256-GCM+AWS-KMS",
            encryption_context_version=3,
            record_version=1,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            ciphertext_b64=base64.b64encode(b"ciphertext-with-tag").decode(),
            content_nonce_b64=base64.b64encode(b"n" * 12).decode(),
            keyed_commitment="c" * 64,
            billed_microusd=123,
            provider_reference_commitment="f" * 64,
        ),
    )
    eligibility = Eligibility()
    signer, _ = _trust()
    policy = MemoryOutcomeRecoveryPolicy(
        signer,
        eligibility,
        environment=DeploymentEnvironment.TEST,
        issuer="lucy-policy-test",
        caller_identity="arn:aws:iam::429870640638:role/lucy-archive",
        target_scope=SCOPE,
        execution_binding=BINDING,
        policy_version=1,
    )

    grant = policy.issue(authorization=authorization, package=package, now=NOW)

    assert grant.execution_completion_deadline == expiring.expires_at
    assert grant.permit_claim_deadline < expiring.expires_at


class DurablePolicyStore(Eligibility):
    def __init__(self) -> None:
        super().__init__()
        self.grant: MemoryOutcomeRecoveryGrantV1 | None = None
        self.admissions = 0

    def admit(
        self,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeGrantAdmissionV1:
        assert authorization.owner_approval_ref == UUID(int=21)
        self.admissions += 1
        return MemoryOutcomeGrantAdmissionV1(
            request_digest=MemoryOutcomeGrantRequestV1(
                authorization=authorization, package=package
            ).digest_hex(),
            admitted_at=NOW,
            authorization_expires_at=authorization.bundle.manifest.expires_at,
            replayed=self.admissions > 1,
        )

    def load_grant(
        self,
        _authorization: AuthorizedPilotManifestV1,
        _package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeRecoveryGrantV1 | None:
        return self.grant

    def record_grant(
        self,
        _authorization: AuthorizedPilotManifestV1,
        _package: MemoryOutcomeRecoveryPackageV1,
        grant: MemoryOutcomeRecoveryGrantV1,
    ) -> MemoryOutcomeRecoveryGrantV1:
        if self.grant is None:
            self.grant = grant
        return self.grant


def test_durable_policy_issuer_replays_one_winning_exact_grant() -> None:
    authorization = _authorization()
    manifest = authorization.bundle.manifest
    assert isinstance(manifest, ImportManifestV2)
    package = _package(FakeKms(), FakeDynamo())
    package = package.model_copy(
        update={
            "envelope": package.envelope.model_copy(
                update={
                    "binding": package.envelope.binding.model_copy(
                        update={"manifest_digest": manifest.digest}
                    )
                }
            )
        }
    )
    store = DurablePolicyStore()
    signer, _ = _trust()
    policy = MemoryOutcomeRecoveryPolicy(
        signer,
        store,
        environment=DeploymentEnvironment.TEST,
        issuer="lucy-policy-test",
        caller_identity="arn:aws:iam::429870640638:role/lucy-archive",
        target_scope=SCOPE,
        execution_binding=BINDING,
        policy_version=1,
        operation_id_factory=lambda: UUID(int=30),
        nonce_factory=lambda: "d" * 32,
    )
    issuer = DurableMemoryOutcomeGrantIssuer(store, policy)  # type: ignore[arg-type]

    first = issuer.issue(authorization=authorization, package=package, now=NOW)
    second = issuer.issue(
        authorization=authorization, package=package, now=NOW + timedelta(seconds=1)
    )

    assert first == second
    assert first.issued_at == NOW
    assert store.grant == first
    assert store.admissions == 2


def test_grant_request_digest_binds_authorization_and_ciphertext_package() -> None:
    authorization = _authorization()
    package = _package(FakeKms(), FakeDynamo())
    request = MemoryOutcomeGrantRequestV1(
        authorization=authorization,
        package=package,
    )
    changed = request.model_copy(
        update={
            "package": package.model_copy(
                update={
                    "envelope": package.envelope.model_copy(
                        update={"keyed_commitment": "9" * 64}
                    )
                }
            )
        }
    )

    assert request.digest_hex() != changed.digest_hex()


def test_routine_environment_assembles_private_policy_and_qualified_lambda_only() -> None:
    values = {
        "LUCY_SERVICE_MODE": "routine",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_V13_TARGET_SCOPE_JSON": canonical_json_bytes(SCOPE).decode("utf-8"),
        "LUCY_POLICY_HOSTPORT": "lucy-policy:10000",
        "LUCY_POLICY_GATEWAY_TOKEN": "synthetic-policy-token",
        "LUCY_AWS_OUTCOME_RECOVERY_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:429870640638:"
            "function:lucy-outcome-recovery:live"
        ),
    }
    recovery = memory_outcome_recovery_from_environment(
        object(),  # type: ignore[arg-type]
        _authorization(),
        values=values,
        lambda_client=object(),
        clock=lambda: NOW,
    )

    assert isinstance(recovery, PermitBoundMemoryOutcomeRecovery)
    assert isinstance(recovery._policy, HttpMemoryOutcomeGrantIssuer)
    assert isinstance(recovery._invoker, AwsLambdaMemoryOutcomeRecoveryInvoker)
    assert not any("SIGNING_PRIVATE" in key for key in values)

    with pytest.raises(ValueError, match="restricted to routine mode"):
        memory_outcome_recovery_from_environment(
            object(),  # type: ignore[arg-type]
            _authorization(),
            values={**values, "LUCY_SERVICE_MODE": "policy"},
            lambda_client=object(),
        )
