"""Verified-batch execution for the private-memory transport pilot."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.chatgpt_manifest import AuthorizedPilotManifestV1
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_candidate_extraction import (
    MemoryExtractionOutputV1,
    build_candidate_review_artifact,
    materialize_verified_pending_candidates,
    parse_memory_extraction_output,
)
from lucy.memory_candidate_review import CandidateReviewBundleArtifactV1
from lucy.memory_extraction import (
    MemoryExtractionCompletionRejected,
    MemoryExtractionCoordinator,
    MemoryExtractionDispatchV1,
    MemoryExtractionOutcomeRecovery,
    MemoryExtractionOutcomeWriter,
    MemoryExtractionProviderOutcomeV1,
    MemoryImportCampaignAccounting,
    MemoryImportProvider,
    MemoryImportSourceEligibility,
)
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV2
from lucy.memory_pilot import MemoryCandidateBatchStore
from lucy.memory_pilot_runner import MemoryPilotArchive
from lucy.memory_pilot_transport import (
    AdmittedMemoryPilotTransportBatch,
    MemoryPilotTransportAdmissionReceiptV1,
    MemoryPilotTransportBatchV1,
    MemoryPilotTransportRecordV1,
)
from lucy.realm_archive_commit import RealmArchiveCommitInputV1


class MemoryPilotExecutionAdmission(Protocol):
    def admit_for_execution(
        self, batch: MemoryPilotTransportBatchV1, *, capability_token: bytes
    ) -> AdmittedMemoryPilotTransportBatch: ...


class MemoryPilotTransportExecutionReceiptV1(BaseModel):
    """Content-free durable execution status."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: UUID
    batch_id: UUID
    extraction_job_id: UUID
    reservation_id: UUID
    state: str = Field(pattern=r"^(succeeded|discarded|reconciliation_required)$")
    archived_source_count: int = Field(ge=1)
    billed_microusd: int = Field(ge=0)
    candidate_count: int = Field(ge=0)


@dataclass(frozen=True)
class MemoryPilotTransportExecutionResult:
    """In-process result; the review artifact contains sensitive source excerpts."""

    receipt: MemoryPilotTransportExecutionReceiptV1
    review_artifact: CandidateReviewBundleArtifactV1 | None


class _TransportCompletion:
    def __init__(
        self,
        store: MemoryCandidateBatchStore,
        *,
        manifest: ImportManifestV2,
        batch: MemoryPilotTransportBatchV1,
        evidence_by_source_record_id: dict[str, UUID],
    ) -> None:
        self._store = store
        self._manifest = manifest
        self._batch = batch
        self._evidence = evidence_by_source_record_id
        self.artifact: CandidateReviewBundleArtifactV1 | None = None
        self.candidate_count = 0

    def complete_success(
        self, *, reservation_id: UUID, outcome: MemoryExtractionProviderOutcomeV1
    ) -> None:
        try:
            output = parse_memory_extraction_output(outcome.output)
            plaintext = {item.source_record_id: item.content for item in self._batch.records}
            candidates = materialize_verified_pending_candidates(
                output,
                manifest=self._manifest,
                plaintext_by_source_record_id=plaintext,
                permitted_source_record_ids=frozenset(self._batch.dispatch.source_record_ids),
                evidence_by_source_record_id=self._evidence,
                extraction_job_id=self._batch.dispatch.extraction_job_id,
            )
            artifact = (
                build_candidate_review_artifact(output, candidates) if candidates else None
            )
        except Exception as exc:
            raise MemoryExtractionCompletionRejected(
                "provider output failed deterministic transport validation"
            ) from exc
        self._store.complete_success(
            reservation_id,
            candidates=candidates,
            billed_microusd=outcome.billed_microusd,
        )
        self.artifact = artifact
        self.candidate_count = len(candidates)


class VerifiedMemoryPilotBatchExecutor:
    """Recheck admission around archive effects, then use the durable job coordinator."""

    def __init__(
        self,
        *,
        admission: MemoryPilotExecutionAdmission,
        archive: MemoryPilotArchive,
        accounting: MemoryImportCampaignAccounting,
        eligibility: MemoryImportSourceEligibility,
        provider: MemoryImportProvider,
        outcomes: MemoryExtractionOutcomeWriter,
        candidate_store: MemoryCandidateBatchStore,
        now: Callable[[], datetime],
        outcome_recovery: MemoryExtractionOutcomeRecovery | None = None,
        outcome_recovery_factory: (
            Callable[[AuthorizedPilotManifestV1], MemoryExtractionOutcomeRecovery] | None
        ) = None,
    ) -> None:
        if outcome_recovery is not None and outcome_recovery_factory is not None:
            raise ValueError("configure one memory outcome recovery boundary")
        self._admission = admission
        self._archive = archive
        self._accounting = accounting
        self._eligibility = eligibility
        self._provider = provider
        self._outcomes = outcomes
        self._candidate_store = candidate_store
        self._now = now
        self._outcome_recovery = outcome_recovery
        self._outcome_recovery_factory = outcome_recovery_factory

    def execute(
        self, batch: MemoryPilotTransportBatchV1, *, capability_token: bytes
    ) -> MemoryPilotTransportExecutionResult:
        context = self._admission.admit_for_execution(
            batch, capability_token=capability_token
        )
        outcome_recovery = self._outcome_recovery
        if self._outcome_recovery_factory is not None:
            outcome_recovery = self._outcome_recovery_factory(context.authorization)
        manifest = context.manifest
        records = {item.source_record_id: item for item in manifest.records}
        evidence: dict[str, UUID] = {}
        for supplied in batch.records:
            # Admission is continuing authority: recheck immediately before each
            # independently durable archive effect.
            self._recheck(batch, capability_token, manifest)
            record = records.get(supplied.source_record_id)
            if record is None or not record.included:
                raise ValueError("transport archive source is outside the manifest")
            archived = self._archive.preserve(
                manifest,
                record,
                build_transport_archive_request(manifest, record, supplied),
            )
            evidence[record.source_record_id] = archived.evidence_id
        self._recheck(batch, capability_token, manifest)
        completion = _TransportCompletion(
            self._candidate_store,
            manifest=manifest,
            batch=batch,
            evidence_by_source_record_id=evidence,
        )
        result = MemoryExtractionCoordinator(
            self._accounting,
            self._eligibility,
            self._provider,
            self._outcomes,
            completion,
            outcome_recovery=outcome_recovery,
            now=self._now,
        ).execute(manifest=manifest, dispatch=batch.dispatch)
        return MemoryPilotTransportExecutionResult(
            MemoryPilotTransportExecutionReceiptV1(
                campaign_id=manifest.campaign_id,
                batch_id=batch.batch_id,
                extraction_job_id=batch.dispatch.extraction_job_id,
                reservation_id=result.reservation_id,
                state=result.state,
                archived_source_count=len(evidence),
                billed_microusd=result.billed_microusd,
                candidate_count=completion.candidate_count,
            ),
            completion.artifact,
        )

    def _recheck(
        self,
        batch: MemoryPilotTransportBatchV1,
        capability_token: bytes,
        manifest: ImportManifestV2,
    ) -> MemoryPilotTransportAdmissionReceiptV1:
        current = self._admission.admit_for_execution(
            batch, capability_token=capability_token
        )
        if current.manifest != manifest:
            raise PermissionError("memory pilot transport manifest changed")
        return current.receipt


class DeterministicFakeMemoryImportProvider:
    """Synthetic-only provider with no credential, network, or production fallback."""

    def __init__(self, output: MemoryExtractionOutputV1) -> None:
        self._output = output
        self.calls = 0

    def infer(
        self, *, manifest: ImportManifestV2, dispatch: MemoryExtractionDispatchV1
    ) -> MemoryExtractionProviderOutcomeV1:
        if (
            manifest.provider_policy_id != "local-synthetic-only"
            or manifest.model_route != "none"
            or manifest.max_model_spend_microusd != 0
        ):
            raise PermissionError("fake provider requires a zero-cost synthetic manifest")
        self.calls += 1
        raw = self._output.model_dump_json()
        return MemoryExtractionProviderOutcomeV1(
            output=raw,
            billed_microusd=0,
            provider_policy_id=manifest.provider_policy_id,
            model_route=manifest.model_route,
            provider_reference_commitment=hashlib.sha256(
                b"LUCY-SYNTHETIC-PROVIDER-V1\x00" + raw.encode("utf-8")
            ).hexdigest(),
        )


def build_transport_archive_request(
    manifest: ImportManifestV2,
    record: ImportManifestRecordV1,
    supplied: MemoryPilotTransportRecordV1,
) -> RealmArchiveCommitInputV1:
    header = canonical_json_bytes(
        {
            "contract_version": "1",
            "manifest_digest": manifest.digest,
            "source_namespace": manifest.source_namespace,
            "source_record_id": record.source_record_id,
            "content_commitment": record.content_commitment,
            "byte_length": record.byte_length,
            "source_revision": record.source_revision,
            "role": record.role,
            "parent_source_record_id": record.parent_source_record_id,
            "displayed": record.displayed,
            "destination_content_scope_id": manifest.destination_content_scope_id,
            "protection_class": manifest.default_protection,
        }
    )
    return RealmArchiveCommitInputV1(
        source_conversation_id=supplied.source_conversation_id,
        source_turn_id=supplied.source_record_id,
        idempotency_key=(
            f"memory-import:{manifest.digest}:{record.source_record_id}:"
            f"r{record.source_revision}"
        ),
        plaintext=supplied.content.encode("utf-8"),
        authenticated_header=header,
        content_classification="memory_import.protected",
        lineage_refs=(record.parent_source_record_id,)
        if record.parent_source_record_id
        else (),
    )
