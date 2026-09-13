"""Encrypted, exact-job provider outcomes for private-memory recovery."""

from __future__ import annotations

import base64
from typing import Protocol
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field

from lucy.archive_crypto import ArchiveCipher, ArchiveKeyStore, EncryptedPayload
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_extraction import (
    MemoryExtractionDispatchV1,
    MemoryExtractionProviderOutcomeV1,
)
from lucy.memory_import import ImportManifestV2


class MemoryOutcomeUnavailable(RuntimeError):
    """The exact provider outcome cannot be durably recorded or recovered."""


class MemoryOutcomeBindingV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: str = Field(default="1", pattern=r"^1$")
    extraction_job_id: UUID
    reservation_id: UUID
    campaign_id: UUID
    destination_content_scope_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    attempt_key: str = Field(min_length=1, max_length=512)
    source_record_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    request_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_policy_id: str = Field(min_length=1, max_length=200)
    model_route: str = Field(min_length=1, max_length=200)
    maximum_microusd: int = Field(ge=0)


class MemoryOutcomeEnvelopeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: str = Field(default="1", pattern=r"^1$")
    binding: MemoryOutcomeBindingV1
    encryption_id: UUID
    registry_id: UUID
    algorithm: str = Field(min_length=1, max_length=100)
    encryption_context_version: int = Field(ge=1)
    record_version: int = Field(ge=1)
    storage_epoch: int = Field(ge=1)
    registry_epoch: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    ciphertext_b64: str = Field(min_length=1)
    content_nonce_b64: str = Field(min_length=1)
    keyed_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    billed_microusd: int = Field(ge=0)
    provider_reference_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")


class MemoryOutcomeStore(Protocol):
    def load(self, extraction_job_id: UUID) -> MemoryOutcomeEnvelopeV1 | None: ...

    def put(self, envelope: MemoryOutcomeEnvelopeV1) -> MemoryOutcomeEnvelopeV1: ...


class EncryptedMemoryOutcomeJournal:
    """Persist model output encrypted before it may enter completion processing."""

    def __init__(
        self,
        store: MemoryOutcomeStore,
        *,
        cipher: ArchiveCipher,
        key_store: ArchiveKeyStore,
    ) -> None:
        self._store = store
        self._cipher = cipher
        self._keys = key_store

    def record(
        self,
        *,
        manifest: ImportManifestV2,
        dispatch: MemoryExtractionDispatchV1,
        reservation_id: UUID,
        outcome: MemoryExtractionProviderOutcomeV1,
    ) -> MemoryExtractionProviderOutcomeV1:
        binding = _binding(manifest, dispatch, reservation_id)
        self._validate_outcome(binding, outcome)
        existing = self._store.load(dispatch.extraction_job_id)
        if existing is not None:
            recovered = self._decrypt_exact(existing, binding)
            if recovered != outcome:
                raise MemoryOutcomeUnavailable("provider outcome replay conflicts")
            return recovered
        encryption_id = memory_outcome_encryption_id(dispatch.extraction_job_id)
        if self._keys.get(encryption_id) is not None:
            raise MemoryOutcomeUnavailable(
                "provider outcome key exists without a recoverable envelope"
            )
        plaintext = canonical_json_bytes(outcome)
        aad = canonical_json_bytes(binding)
        try:
            encrypted = self._cipher.encrypt(encryption_id, plaintext, aad)
            self._keys.put(encryption_id, encrypted.wrapped_key)
            envelope = MemoryOutcomeEnvelopeV1(
                binding=binding,
                encryption_id=encryption_id,
                registry_id=self._keys.registry_identity,
                algorithm=self._cipher.algorithm,
                encryption_context_version=self._cipher.encryption_context_version,
                record_version=self._cipher.record_version,
                storage_epoch=self._cipher.storage_epoch,
                registry_epoch=self._cipher.registry_epoch,
                key_epoch=self._cipher.key_epoch,
                ciphertext_b64=base64.b64encode(encrypted.ciphertext).decode("ascii"),
                content_nonce_b64=base64.b64encode(encrypted.content_nonce).decode("ascii"),
                keyed_commitment=encrypted.keyed_commitment,
                billed_microusd=outcome.billed_microusd,
                provider_reference_commitment=outcome.provider_reference_commitment,
            )
            stored = self._store.put(envelope)
        except Exception as exc:
            raise MemoryOutcomeUnavailable(
                "provider outcome persistence requires reconciliation"
            ) from exc
        return self._decrypt_exact(stored, binding)

    def load(
        self,
        *,
        manifest: ImportManifestV2,
        dispatch: MemoryExtractionDispatchV1,
        reservation_id: UUID,
    ) -> MemoryExtractionProviderOutcomeV1 | None:
        binding = _binding(manifest, dispatch, reservation_id)
        envelope = self._store.load(dispatch.extraction_job_id)
        return None if envelope is None else self._decrypt_exact(envelope, binding)

    def _decrypt_exact(
        self, envelope: MemoryOutcomeEnvelopeV1, binding: MemoryOutcomeBindingV1
    ) -> MemoryExtractionProviderOutcomeV1:
        if envelope.binding != binding or envelope.registry_id != self._keys.registry_identity:
            raise MemoryOutcomeUnavailable("provider outcome binding is unavailable")
        wrapped = self._keys.get(envelope.encryption_id)
        if wrapped is None:
            raise MemoryOutcomeUnavailable("provider outcome key is unavailable")
        try:
            encrypted = EncryptedPayload(
                ciphertext=base64.b64decode(envelope.ciphertext_b64, validate=True),
                content_nonce=base64.b64decode(
                    envelope.content_nonce_b64, validate=True
                ),
                wrapped_key=wrapped,
                keyed_commitment=envelope.keyed_commitment,
            )
            raw = self._cipher.decrypt(
                envelope.encryption_id,
                encrypted,
                canonical_json_bytes(binding),
            )
            outcome = MemoryExtractionProviderOutcomeV1.model_validate_json(raw)
        except Exception as exc:
            raise MemoryOutcomeUnavailable("provider outcome decryption failed") from exc
        self._validate_outcome(binding, outcome)
        if (
            envelope.billed_microusd != outcome.billed_microusd
            or envelope.provider_reference_commitment
            != outcome.provider_reference_commitment
        ):
            raise MemoryOutcomeUnavailable("provider outcome metadata is invalid")
        return outcome

    @staticmethod
    def _validate_outcome(
        binding: MemoryOutcomeBindingV1, outcome: MemoryExtractionProviderOutcomeV1
    ) -> None:
        if (
            outcome.provider_policy_id != binding.provider_policy_id
            or outcome.model_route != binding.model_route
            or outcome.billed_microusd > binding.maximum_microusd
        ):
            raise MemoryOutcomeUnavailable("provider outcome exceeds its exact job binding")


def memory_outcome_encryption_id(extraction_job_id: UUID) -> UUID:
    return uuid5(extraction_job_id, "memory-provider-outcome:v1")


def _binding(
    manifest: ImportManifestV2,
    dispatch: MemoryExtractionDispatchV1,
    reservation_id: UUID,
) -> MemoryOutcomeBindingV1:
    return MemoryOutcomeBindingV1(
        extraction_job_id=dispatch.extraction_job_id,
        reservation_id=reservation_id,
        campaign_id=manifest.campaign_id,
        destination_content_scope_id=manifest.destination_content_scope_id,
        manifest_digest=manifest.digest,
        attempt_key=dispatch.attempt_key,
        source_record_ids=dispatch.source_record_ids,
        request_commitment=dispatch.request_commitment,
        provider_policy_id=manifest.provider_policy_id,
        model_route=manifest.model_route,
        maximum_microusd=dispatch.maximum_microusd,
    )
