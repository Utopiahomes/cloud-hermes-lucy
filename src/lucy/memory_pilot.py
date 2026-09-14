"""Pilot-only assembly for deterministic private-memory extraction completion."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from lucy.chatgpt_manifest import LocalPilotBuildV1
from lucy.governed_memory import ImportCompletionResultV1
from lucy.memory_candidate_extraction import (
    build_candidate_review_artifact,
    materialize_pending_candidates,
    parse_memory_extraction_output,
)
from lucy.memory_candidate_review import CandidateReviewBundleArtifactV1
from lucy.memory_extraction import (
    MemoryExtractionCompletionRejected,
    MemoryExtractionProviderOutcomeV1,
)
from lucy.memory_import import MemoryCandidatePayloadV1


class MemoryCandidateBatchStore(Protocol):
    def complete_success(
        self,
        reservation_id: UUID,
        *,
        candidates: tuple[MemoryCandidatePayloadV1, ...],
        billed_microusd: int,
    ) -> ImportCompletionResultV1: ...


class MemoryPilotCompletionResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reservation_id: UUID
    candidates: tuple[MemoryCandidatePayloadV1, ...]
    review_artifact: CandidateReviewBundleArtifactV1 | None


class MemoryPilotSuccessCompletion:
    """Validate provider JSON, bind provenance, then atomically stage and settle."""

    def __init__(
        self,
        store: MemoryCandidateBatchStore,
        *,
        build: LocalPilotBuildV1,
        fingerprint_key: bytes,
        evidence_by_source_record_id: dict[str, UUID],
        extraction_job_id: UUID,
    ) -> None:
        if len(fingerprint_key) != 32:
            raise ValueError("manifest fingerprint key must contain 32 bytes")
        self._store = store
        self._build = build
        self._fingerprint_key = fingerprint_key
        self._evidence = dict(evidence_by_source_record_id)
        self._extraction_job_id = extraction_job_id
        self._result: MemoryPilotCompletionResultV1 | None = None

    def complete_success(
        self,
        *,
        reservation_id: UUID,
        outcome: MemoryExtractionProviderOutcomeV1,
    ) -> None:
        try:
            output = parse_memory_extraction_output(outcome.output)
            candidates = materialize_pending_candidates(
                output,
                build=self._build,
                fingerprint_key=self._fingerprint_key,
                evidence_by_source_record_id=self._evidence,
                extraction_job_id=self._extraction_job_id,
            )
            review_artifact = (
                build_candidate_review_artifact(output, candidates)
                if candidates
                else None
            )
        except Exception as exc:
            raise MemoryExtractionCompletionRejected(
                "provider output failed deterministic pilot validation"
            ) from exc
        self._store.complete_success(
            reservation_id,
            candidates=candidates,
            billed_microusd=outcome.billed_microusd,
        )
        self._result = MemoryPilotCompletionResultV1(
            reservation_id=reservation_id,
            candidates=candidates,
            review_artifact=review_artifact,
        )

    @property
    def result(self) -> MemoryPilotCompletionResultV1:
        if self._result is None:
            raise RuntimeError("pilot completion has no acknowledged result")
        return self._result
