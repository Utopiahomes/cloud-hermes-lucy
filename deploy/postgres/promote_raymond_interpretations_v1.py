"""One-time, all-or-nothing promotion of Ray's reviewed private interpretations."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import sys
from uuid import UUID, uuid5

from sqlalchemy import text
from sqlalchemy.engine import make_url

from lucy.contracts.canonical import canonical_json_bytes
from lucy.db import create_session_factory
from lucy.memory_import import MemoryCandidatePayloadV1

AUTHORIZATION = "raymond-promote-32-reviewed-interpretations-v1"
PROPOSAL_SHA256 = "fc2085b497de87d8da997159c2416cb1411e1f33b91007c0d4ea7558901fc36c"
REVIEW_SHA256 = "7b0d35ad1de8b9c38912fca8015c1d218c464d9a4ec24fa4faf6d035a26cc50b"
CAMPAIGN_ID = UUID("c1800ec3-1158-42f0-bb0b-46a04df7a65c")
SCOPE_ID = UUID("5ee9fc67-4c46-4416-876e-5e028bf8ae4e")
APPROVAL_NAMESPACE = UUID("774e29b4-e529-4393-a4ce-25520b42cdee")


def load_proposal() -> tuple[MemoryCandidatePayloadV1, ...]:
    count = int(os.environ["LUCY_PROMOTION_PART_COUNT"])
    if not 1 <= count <= 4:
        raise RuntimeError("promotion transfer part count is invalid")
    encoded = "".join(os.environ[f"LUCY_PROMOTION_PART_{index}"] for index in range(count))
    raw = gzip.decompress(base64.b64decode(encoded, validate=True))
    if len(raw) > 500_000 or hashlib.sha256(raw).hexdigest() != PROPOSAL_SHA256:
        raise RuntimeError("promotion proposal bytes changed")
    proposal = json.loads(raw)
    if (proposal.get("kind") != "raymond_interpreted_candidate_promotion_proposal_v1_not_executed"
            or proposal.get("review_sha256") != REVIEW_SHA256
            or proposal.get("candidate_count") != 32
            or proposal.get("campaign_id") != str(CAMPAIGN_ID)):
        raise RuntimeError("promotion proposal identity changed")
    candidates = []
    for item in proposal["items"]:
        candidate = MemoryCandidatePayloadV1.model_validate(item["candidate"])
        if (candidate.digest != item["candidate_digest"]
                or candidate.campaign_id != CAMPAIGN_ID
                or candidate.destination_content_scope_id != SCOPE_ID
                or candidate.candidate_version != 2
                or candidate.protection_class != "protected"
                or candidate.assertion_status != "attributed_interpretation"
                or candidate.epistemic_status != "historical"
                or candidate.predicate != "historical_interpretation"):
            raise RuntimeError("candidate differs from reviewed projection")
        body = json.loads(candidate.object)
        if (body.get("kind") != "lucy_versioned_interpretation_v1"
                or body.get("source_candidate_version") != 1
                or body.get("interpretation", {}).get("version") != 1
                or body.get("interpretation", {}).get("current_applicability") != "not_checked"
                or len(body.get("evidence_refs", [])) != len(candidate.sources)):
            raise RuntimeError("candidate interpretation envelope is invalid")
        candidates.append(candidate)
    if len(candidates) != 32 or len({candidate.candidate_id for candidate in candidates}) != 32:
        raise RuntimeError("promotion candidate set differs")
    return tuple(candidates)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"stage", "promote"}:
        raise RuntimeError("expected stage or promote phase")
    phase = sys.argv[1]
    if (os.getenv("RENDER") != "true"
            or os.getenv("LUCY_ENVIRONMENT") != "production"
            or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
            or os.getenv("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
            or os.getenv("LUCY_INTERPRETED_PROMOTION_AUTHORIZATION") != AUTHORIZATION):
        raise RuntimeError("promotion environment is invalid")
    url = make_url(os.environ["LUCY_DATABASE_URL"])
    expected_user = "lucy_raymond_routine" if phase == "stage" else "lucy_raymond_policy"
    if (url.host != "dpg-dak5bqad0e5s73b2e3d0-a" or url.database != "lucy_raymond"
            or url.username != expected_user or not url.password
            or url.query.get("sslmode") != "require"):
        raise RuntimeError("promotion database boundary changed")
    candidates = load_proposal()
    sessions = create_session_factory(url.render_as_string(hide_password=False))
    with sessions.begin() as session:
        database, login = session.execute(
            text("SELECT current_database(),session_user")
        ).one()
        if database != "lucy_raymond" or login != expected_user:
            raise RuntimeError("connected promotion identity changed")
        if phase == "stage":
            replayed = 0
            for candidate in candidates:
                result = session.execute(
                    text("SELECT lucy.stage_memory_import_candidate_v1(CAST(:value AS jsonb))"),
                    {"value": canonical_json_bytes(candidate).decode("utf-8")},
                ).scalar_one()
                if (result["candidate_id"] != str(candidate.candidate_id)
                        or result["candidate_version"] != 2
                        or result["candidate_digest"] != candidate.digest):
                    raise RuntimeError("candidate staging acknowledgement changed")
                replayed += int(result["replayed"])
            status = {"phase": phase, "staged": 32, "replayed": replayed}
        else:
            approval_ids = []
            for candidate in candidates:
                owner_ref = uuid5(
                    APPROVAL_NAMESPACE,
                    f"{PROPOSAL_SHA256}:{candidate.candidate_id}:{candidate.digest}",
                )
                approved = session.execute(
                    text("SELECT lucy.approve_scoped_memory_candidate_v1("
                         ":id,2,:digest,:owner_ref,:owner_actor)"),
                    {"id": candidate.candidate_id, "digest": candidate.digest,
                     "owner_ref": owner_ref,
                     "owner_actor": "raymond-reviewed-32-2026-09-23"},
                ).scalar_one()
                approval_ids.append((candidate, approved["approval_id"]))
            claim_ids = set()
            for candidate, approval_id in approval_ids:
                promoted = session.execute(
                    text("SELECT lucy.promote_scoped_memory_candidate_v1(:approval,:digest)"),
                    {"approval": approval_id, "digest": candidate.digest},
                ).scalar_one()
                claim_ids.add(promoted["claim_id"])
            if len(claim_ids) != 32:
                raise RuntimeError("promotion claims are not distinct")
            for candidate in candidates:
                recalled = session.execute(
                    text("SELECT lucy.search_protected_scoped_memory_v1("
                         ":query,20,:interaction,:reason)"),
                    {"query": json.loads(candidate.object)["source_candidate_digest"],
                     "interaction": uuid5(APPROVAL_NAMESPACE, f"recall:{candidate.candidate_id}"),
                     "reason": "owner_reviewed_pilot_verification"},
                ).scalar_one()
                matches = [item for item in recalled
                           if item["candidate_id"] == str(candidate.candidate_id)
                           and item["candidate_version"] == 2]
                if len(matches) != 1 or matches[0]["object"] != candidate.object:
                    raise RuntimeError("protected recall differs from reviewed interpretation")
                if set(matches[0]["source_evidence_ids"]) != {
                    str(source.evidence_id) for source in candidate.sources
                }:
                    raise RuntimeError("protected recall source links differ")
            status = {"phase": phase, "promoted": 32,
                      "protected_recall_verified": 32}
    print(json.dumps({"status": "passed", "proposal_sha256": PROPOSAL_SHA256,
                      **status, "provider_calls": 0, "telegram_messages": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
