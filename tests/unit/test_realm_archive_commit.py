from __future__ import annotations

import base64
from typing import Any
from uuid import UUID

import pytest

from lucy.contracts.security_v1_3 import OriginScopeV1
from lucy.realm_archive import (
    GeneratedDataKeyV1,
    RealmArchiveEncryptor,
    RealmArchiveEnvelopeV1,
    RealmArchiveIdentityV1,
)
from lucy.realm_archive_commit import (
    RealmArchiveClaimV1,
    RealmArchiveCommitInputV1,
    RealmArchiveCommitResultV1,
    RealmArchiveCommitService,
    RealmArchiveOutcomeV1,
    realm_archive_commit_from_environment,
)

KEY_ARN = (
    "arn:aws:kms:us-east-1:123456789012:"
    "key/11111111-1111-4111-8111-111111111111"
)
SCOPE = OriginScopeV1(
    tenant_account_id=UUID(int=1),
    node_id=UUID(int=2),
    node_tenure_id=UUID(int=3),
    tenure_epoch=1,
    security_realm_id=UUID(int=4),
    storage_epoch=1,
)


class FakeBackend:
    def __init__(self) -> None:
        self.envelopes: dict[UUID, RealmArchiveEnvelopeV1] = {}
        self.generate_calls = 0

    def generate_data_key(
        self, *, key_arn: str, encryption_context: dict[str, str]
    ) -> GeneratedDataKeyV1:
        assert key_arn == KEY_ARN
        assert encryption_context["security_realm_id"] == str(SCOPE.security_realm_id)
        self.generate_calls += 1
        return GeneratedDataKeyV1(b"d" * 32, b"wrapped", KEY_ARN, "kms-request")

    def load_archive_envelope(self, key_ref: UUID) -> RealmArchiveEnvelopeV1 | None:
        return self.envelopes.get(key_ref)

    def put_archive_envelope(
        self,
        *,
        envelope: RealmArchiveEnvelopeV1,
        wrapped_key: bytes,
        key_arn: str,
    ) -> None:
        assert wrapped_key == b"wrapped"
        assert key_arn == KEY_ARN
        key_ref = envelope.wrapper_binding.wrapped_key_ref
        if key_ref in self.envelopes:
            raise ValueError("duplicate key ref")
        self.envelopes[key_ref] = envelope


class FakeStore:
    def __init__(self, *, fail_first_outcome: bool = False) -> None:
        self.operation_id = UUID(int=10)
        self.evidence_id = UUID(int=11)
        self.representation_id = UUID(int=12)
        self.key_ref = UUID(int=13)
        self.commitment: str | None = None
        self.outcome: RealmArchiveEnvelopeV1 | None = None
        self.reconciliations = 0
        self.fail_first_outcome = fail_first_outcome

    def claim(
        self, request: RealmArchiveCommitInputV1, *, request_commitment: str
    ) -> RealmArchiveClaimV1:
        del request
        replayed = self.commitment is not None
        if self.commitment is not None and self.commitment != request_commitment:
            raise PermissionError("idempotency conflict")
        self.commitment = request_commitment
        stage = (
            "RECONCILED"
            if self.reconciliations
            else "AWS_COMMITTED"
            if self.outcome is not None
            else "INTENT_RECORDED"
        )
        return RealmArchiveClaimV1(
            operation_id=self.operation_id,
            evidence_id=self.evidence_id,
            representation_id=self.representation_id,
            wrapped_key_ref=self.key_ref,
            stage=stage,
            replayed=replayed,
        )

    def record_outcome(
        self, operation_id: UUID, envelope: RealmArchiveEnvelopeV1
    ) -> RealmArchiveOutcomeV1:
        assert operation_id == self.operation_id
        if self.fail_first_outcome:
            self.fail_first_outcome = False
            raise ConnectionError("synthetic crash after DynamoDB commit")
        replayed = self.outcome is not None
        self.outcome = envelope
        return RealmArchiveOutcomeV1(
            operation_id=operation_id,
            envelope_digest="a" * 64,
            replayed=replayed,
        )

    def reconcile(self, operation_id: UUID) -> RealmArchiveCommitResultV1:
        assert operation_id == self.operation_id
        assert self.outcome is not None
        replayed = self.reconciliations > 0
        self.reconciliations += 1
        return RealmArchiveCommitResultV1(
            operation_id=operation_id,
            evidence_id=self.evidence_id,
            representation_id=self.representation_id,
            replayed=replayed,
        )


def _service(
    store: FakeStore, backend: FakeBackend
) -> RealmArchiveCommitService:
    encryptor = RealmArchiveEncryptor(
        backend,
        RealmArchiveIdentityV1(
            target_scope=SCOPE,
            evidence_key_arn=KEY_ARN,
            record_version=1,
        ),
        commitment_key=b"c" * 32,
    )
    return RealmArchiveCommitService(
        store, encryptor, request_commitment_key=b"r" * 32
    )


def _request(**changes: Any) -> RealmArchiveCommitInputV1:
    values: dict[str, Any] = {
        "source_conversation_id": "conversation-1",
        "source_turn_id": "turn-1",
        "idempotency_key": "archive-1",
        "plaintext": b"synthetic owner message",
        "authenticated_header": b'{"classification":"private"}',
        "content_classification": "owner_conversation",
        "lineage_refs": (),
    }
    values.update(changes)
    return RealmArchiveCommitInputV1(**values)


def test_commit_service_preserves_once_and_replays_without_aws() -> None:
    store, backend = FakeStore(), FakeBackend()
    service = _service(store, backend)

    first = service.preserve(_request())
    replay = service.preserve(_request())

    assert first.replayed is False
    assert replay.replayed is True
    assert first.evidence_id == replay.evidence_id == store.evidence_id
    assert backend.generate_calls == 1
    assert len(backend.envelopes) == 1


def test_commit_service_recovers_crash_after_dynamodb_without_new_key() -> None:
    store, backend = FakeStore(fail_first_outcome=True), FakeBackend()
    service = _service(store, backend)

    with pytest.raises(ConnectionError, match="after DynamoDB"):
        service.preserve(_request())
    assert backend.generate_calls == 1
    assert len(backend.envelopes) == 1

    recovered = service.preserve(_request())
    assert recovered.evidence_id == store.evidence_id
    assert backend.generate_calls == 1
    assert store.outcome is backend.envelopes[store.key_ref]


def test_commit_service_binds_idempotency_to_plaintext_without_plain_hash() -> None:
    store, backend = FakeStore(), FakeBackend()
    service = _service(store, backend)
    service.preserve(_request())

    with pytest.raises(PermissionError, match="idempotency conflict"):
        service.preserve(_request(plaintext=b"changed owner message"))


def test_recovery_rejects_an_envelope_from_a_different_intent() -> None:
    store, backend = FakeStore(fail_first_outcome=True), FakeBackend()
    service = _service(store, backend)
    with pytest.raises(ConnectionError):
        service.preserve(_request())
    original = backend.envelopes[store.key_ref]
    backend.envelopes[store.key_ref] = original.model_copy(
        update={"request_commitment": "f" * 64}
    )

    with pytest.raises(RuntimeError, match="differs from its intent"):
        service.preserve(_request())


def test_factory_requires_a_separate_request_commitment_key() -> None:
    encryptor = RealmArchiveEncryptor(
        FakeBackend(),
        RealmArchiveIdentityV1(
            target_scope=SCOPE,
            evidence_key_arn=KEY_ARN,
            record_version=1,
        ),
        commitment_key=b"c" * 32,
    )
    values = {
        "LUCY_DATABASE_URL": "postgresql+psycopg://synthetic.invalid/lucy",
        "LUCY_ARCHIVE_REQUEST_COMMITMENT_KEY_B64": base64.b64encode(b"r" * 32).decode(),
    }
    assert realm_archive_commit_from_environment(values, encryptor=encryptor)
    with pytest.raises(ValueError, match="configuration is incomplete"):
        realm_archive_commit_from_environment(
            {"LUCY_DATABASE_URL": values["LUCY_DATABASE_URL"]}, encryptor=encryptor
        )
    with pytest.raises(ValueError, match="must contain 32 bytes"):
        realm_archive_commit_from_environment(
            {
                **values,
                "LUCY_ARCHIVE_REQUEST_COMMITMENT_KEY_B64": base64.b64encode(b"short").decode(),
            },
            encryptor=encryptor,
        )
