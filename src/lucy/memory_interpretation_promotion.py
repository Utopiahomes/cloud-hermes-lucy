"""Project a reviewed interpretation into the existing governed candidate contract.

The claim object is a bounded, structured JSON projection. Exact excerpts remain
in protected source evidence; the candidate links every source used by the review.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from uuid import uuid5

from lucy.memory_import import (
    AssertionStatus,
    EpistemicStatus,
    ImportManifestRecordV1,
    MemoryCandidatePayloadV1,
    SourceSpanV1,
)
from lucy.memory_interpretation import InterpretationRecordV1, Speaker


def build_interpreted_candidate(
    original: MemoryCandidatePayloadV1,
    interpretation: InterpretationRecordV1,
    manifest_records: Mapping[str, ImportManifestRecordV1],
) -> MemoryCandidatePayloadV1:
    """Create a new immutable protected version, never relabel the extracted one."""
    if (
        interpretation.candidate_id != original.candidate_id
        or interpretation.candidate_version != original.candidate_version
        or len(interpretation.versions) != 1
    ):
        raise ValueError("interpretation does not match one original candidate")
    current = interpretation.current
    linked = []
    original_sources = {source.source_record_id: source for source in original.sources}
    for source in current.evidence:
        record = manifest_records.get(source.source_record_id)
        if record is None or not record.included or record.role != source.role.value:
            raise ValueError("interpretation source is outside the authorized manifest")
        if source.role not in {Speaker.OWNER, Speaker.ASSISTANT}:
            raise ValueError("interpretation source speaker is not exact")
        source_span = original_sources.get(source.source_record_id)
        if source_span is None:
            source_span = SourceSpanV1(
                source_record_id=source.source_record_id,
                evidence_id=uuid5(
                    original.campaign_id,
                    f"evidence:{source.source_record_id}:r{record.source_revision}",
                ),
                record_version=record.source_revision,
                byte_start=0,
                byte_end=record.byte_length,
            )
        linked.append(source_span)
    if not set(original_sources).issubset({source.source_record_id for source in linked}):
        raise ValueError("interpretation dropped an original candidate source")

    body = {
        "kind": "lucy_versioned_interpretation_v1",
        "source_candidate_version": original.candidate_version,
        "source_candidate_digest": original.digest,
        "interpretation": current.model_dump(mode="json", exclude={"evidence"}),
        "evidence_refs": [
            {"source_record_id": source.source_record_id,
             "role": source.role.value, "relation": source.relation.value}
            for source in current.evidence
        ],
    }
    object_text = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(object_text) > 4_000:
        raise ValueError("reviewed interpretation does not fit the candidate contract")
    return MemoryCandidatePayloadV1.model_validate({
        **original.model_dump(mode="json"),
        "candidate_version": original.candidate_version + 1,
        "predicate": "historical_interpretation",
        "object": object_text,
        "assertion_status": AssertionStatus.ATTRIBUTED_INTERPRETATION,
        "epistemic_status": EpistemicStatus.HISTORICAL,
        "valid_from": None,
        "valid_to": None,
        "sources": tuple(linked),
    })
