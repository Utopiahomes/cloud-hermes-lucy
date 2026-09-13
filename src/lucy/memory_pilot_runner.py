"""Pilot-only assembly for the authorized private-memory vertical slice."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.chatgpt_manifest import LocalPilotBuildV1, build_exact_archive_requests
from lucy.governed_memory import ImportArchiveResultV1
from lucy.memory_candidate_review import CandidateReviewBundleArtifactV1
from lucy.memory_extraction import (
    MemoryExtractionCoordinator,
    MemoryExtractionOutcomeJournal,
    MemoryImportCampaignAccounting,
    MemoryImportProvider,
    MemoryImportSourceEligibility,
)
from lucy.memory_import import ImportManifest, ImportManifestRecordV1, ImportManifestV2
from lucy.memory_pilot import MemoryCandidateBatchStore, MemoryPilotSuccessCompletion
from lucy.memory_pilot_compiler import compile_memory_pilot_batches
from lucy.realm_archive_commit import RealmArchiveCommitInputV1


class MemoryPilotArchive(Protocol):
    def preserve(
        self,
        manifest: ImportManifest,
        record: ImportManifestRecordV1,
        request: RealmArchiveCommitInputV1,
    ) -> ImportArchiveResultV1: ...


class MemoryPilotBatchResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    extraction_job_id: UUID
    reservation_id: UUID
    state: str = Field(pattern=r"^(succeeded|discarded|reconciliation_required)$")
    billed_microusd: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    review_artifact: CandidateReviewBundleArtifactV1 | None


class MemoryPilotRunResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    archived_source_count: int = Field(ge=1)
    batches: tuple[MemoryPilotBatchResultV1, ...] = Field(min_length=1)


class MemoryPilotRunner:
    """Archive every selected source, then execute exact protected extraction batches."""

    def __init__(
        self,
        *,
        archive: MemoryPilotArchive,
        accounting: MemoryImportCampaignAccounting,
        eligibility: MemoryImportSourceEligibility,
        provider: MemoryImportProvider,
        outcomes: MemoryExtractionOutcomeJournal,
        candidate_store: MemoryCandidateBatchStore,
        now: Callable[[], datetime],
    ) -> None:
        self._archive = archive
        self._accounting = accounting
        self._eligibility = eligibility
        self._provider = provider
        self._outcomes = outcomes
        self._candidate_store = candidate_store
        self._now = now

    def run(
        self,
        build: LocalPilotBuildV1,
        *,
        fingerprint_key: bytes,
        maximum_microusd_per_attempt: int,
        timeout_seconds: int,
    ) -> MemoryPilotRunResultV1:
        manifest = build.bundle.manifest
        if not isinstance(manifest, ImportManifestV2):
            raise ValueError("real pilot execution requires an executable v2 manifest")
        requests = build_exact_archive_requests(build, fingerprint_key=fingerprint_key)
        records = tuple(record for record in manifest.records if record.included)
        if len(records) != len(requests):
            raise RuntimeError("pilot archive inputs lost exact manifest alignment")
        evidence: dict[str, UUID] = {}
        for record, request in zip(records, requests, strict=True):
            archive_result = self._archive.preserve(manifest, record, request)
            evidence[record.source_record_id] = archive_result.evidence_id
        compilation = compile_memory_pilot_batches(
            build,
            maximum_microusd_per_attempt=maximum_microusd_per_attempt,
            timeout_seconds=timeout_seconds,
        )
        completed: list[MemoryPilotBatchResultV1] = []
        for dispatch in compilation.batches:
            completion = MemoryPilotSuccessCompletion(
                self._candidate_store,
                build=build,
                fingerprint_key=fingerprint_key,
                evidence_by_source_record_id=evidence,
                extraction_job_id=dispatch.extraction_job_id,
            )
            extraction_result = MemoryExtractionCoordinator(
                self._accounting,
                self._eligibility,
                self._provider,
                self._outcomes,
                completion,
                now=self._now,
            ).execute(manifest=manifest, dispatch=dispatch)
            artifact: CandidateReviewBundleArtifactV1 | None = None
            candidate_count = 0
            if extraction_result.state == "succeeded":
                pilot_completion = completion.result
                artifact = pilot_completion.review_artifact
                candidate_count = len(pilot_completion.candidates)
            completed.append(
                MemoryPilotBatchResultV1(
                    extraction_job_id=dispatch.extraction_job_id,
                    reservation_id=extraction_result.reservation_id,
                    state=extraction_result.state,
                    billed_microusd=extraction_result.billed_microusd,
                    candidate_count=candidate_count,
                    review_artifact=artifact,
                )
            )
            if extraction_result.state == "reconciliation_required":
                break
        return MemoryPilotRunResultV1(
            campaign_id=manifest.campaign_id,
            manifest_digest=manifest.digest,
            archived_source_count=len(evidence),
            batches=tuple(completed),
        )
