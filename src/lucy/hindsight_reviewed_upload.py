"""Transfer Ray's exact approved 32 reviewed interpretations to private Hindsight."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from deploy.postgres.promote_raymond_interpretations_v1 import (
    CAMPAIGN_ID,
    PROPOSAL_SHA256,
)
from deploy.render.import_raymond_hindsight import SELECTED, _content
from lucy.contracts.canonical import canonical_json_bytes
from lucy.hindsight_backfill_intake import ReviewedBatch
from lucy.hindsight_backfill_upload import _inside, _upload
from lucy.interpreted_recall import StoredInterpretationEnvelopeV1
from lucy.memory_import import MemoryCandidatePayloadV1

_ALREADY_RETAINED = frozenset(candidate_id for candidate_id, *_ in SELECTED)


def upload_reviewed(
    *, intake_root: Path, proposal_path: Path, token_path: Path,
    receipt_dir: Path, endpoint: str,
) -> tuple[int, int]:
    if not endpoint.startswith("https://") or not endpoint.endswith(
        ".onrender.com/v1/raymond/hindsight/reviewed"
    ):
        raise ValueError("reviewed HTTPS destination differs")
    root = intake_root.resolve()
    raw = _inside(proposal_path, root).read_bytes()
    if sha256(raw).hexdigest() != PROPOSAL_SHA256:
        raise ValueError("reviewed proposal commitment differs")
    proposal = json.loads(raw)
    if (proposal.get("candidate_count") != 32
            or proposal.get("campaign_id") != str(CAMPAIGN_ID)
            or proposal.get("review_sha256")
            != "7b0d35ad1de8b9c38912fca8015c1d218c464d9a4ec24fa4faf6d035a26cc50b"):
        raise ValueError("reviewed proposal identity differs")
    token = _inside(token_path, root).read_text(encoding="ascii").strip()
    if len(token) < 32:
        raise ValueError("reviewed capability unavailable")
    receipts = _inside(receipt_dir, root)
    receipts.mkdir(parents=True, exist_ok=True)
    failures = receipts.parent / "reviewed_failures"
    failures.mkdir(parents=True, exist_ok=True)
    uploaded = 0
    reconciled = 0
    consecutive_failures = 0
    for entry in proposal["items"]:
        candidate = MemoryCandidatePayloadV1.model_validate(entry["candidate"])
        if (candidate.digest != entry["candidate_digest"]
                or candidate.campaign_id != CAMPAIGN_ID
                or candidate.candidate_version != 2
                or candidate.protection_class != "protected"
                or candidate.assertion_status != "attributed_interpretation"
                or candidate.epistemic_status != "historical"):
            raise ValueError("reviewed candidate differs")
        envelope = StoredInterpretationEnvelopeV1.model_validate_json(candidate.object)
        candidate_id = str(candidate.candidate_id)
        item: dict[str, object] = {
            "content": _content(envelope),
            "document_id": f"lucy-reviewed:{candidate_id}:v2",
            "update_mode": "replace",
            "context": "Ray's reviewed Personal Lucy historical interpretation pilot",
            "metadata": {
                "source": "lucy_governed_reviewed_interpretation",
                "candidate_id": candidate_id,
                "candidate_version": "2",
                "object_sha256": sha256(candidate.object.encode()).hexdigest(),
                "source_record_ids": json.dumps(
                    [ref.source_record_id for ref in envelope.evidence_refs],
                    separators=(",", ":"),
                ),
                "source_evidence_ids": json.dumps(
                    [str(source.evidence_id) for source in candidate.sources],
                    separators=(",", ":"),
                ),
                "campaign_id": str(CAMPAIGN_ID),
                "proposal_sha256": PROPOSAL_SHA256,
            },
        }
        if envelope.interpretation.source_utterance_at:
            item["timestamp"] = envelope.interpretation.source_utterance_at.isoformat()
        batch = ReviewedBatch.model_validate({
            "proposal_sha256": PROPOSAL_SHA256, "items": [item],
        })
        body = canonical_json_bytes(batch)
        digest = sha256(body).hexdigest()
        receipt = receipts / f"{candidate_id}.json"
        expected = {"candidate_id": candidate_id, "digest": digest, "processed_count": 1}
        if receipt.exists():
            if json.loads(receipt.read_text(encoding="utf-8")) != expected:
                raise ValueError("reviewed receipt differs")
            continue
        failure = failures / f"{candidate_id}.json"
        if failure.exists():
            if json.loads(failure.read_text(encoding="utf-8")) != {
                "candidate_id": candidate_id, "digest": digest,
                "reason": "intake_unavailable",
            }:
                raise ValueError("reviewed failure differs")
            continue
        already_retained = candidate_id in _ALREADY_RETAINED
        try:
            processed = 1 if already_retained else _upload(endpoint, token, body)
        except RuntimeError:
            failure.write_text(json.dumps({
                "candidate_id": candidate_id, "digest": digest,
                "reason": "intake_unavailable",
            }, sort_keys=True) + "\n", encoding="utf-8")
            consecutive_failures += 1
            print(f"REVIEWED:{candidate_id}:failed", flush=True)
            if consecutive_failures >= 3:
                raise RuntimeError("three consecutive reviewed imports failed") from None
            continue
        if processed != 1:
            raise RuntimeError("reviewed intake count differs")
        consecutive_failures = 0
        receipt.write_text(json.dumps(expected, sort_keys=True) + "\n", encoding="utf-8")
        if already_retained:
            reconciled += 1
        else:
            uploaded += 1
        print(f"REVIEWED:{candidate_id}:"
              f"{'reconciled' if already_retained else 'uploaded'}", flush=True)
    return uploaded, reconciled
