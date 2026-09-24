"""Copy a small reviewed interpretation slice into Ray's Hindsight bank.

The protected proposal and live governed recall remain the authority. Hindsight
receives source-linked, revisable documents only after both checks agree.
"""

from __future__ import annotations

import json
import os
from hashlib import sha256
from urllib.request import Request, urlopen
from uuid import uuid5

from sqlalchemy import text
from sqlalchemy.engine import make_url

from deploy.postgres.promote_raymond_interpretations_v1 import (
    APPROVAL_NAMESPACE,
    CAMPAIGN_ID,
    PROPOSAL_SHA256,
)
from lucy.db import create_session_factory
from lucy.interpreted_recall import StoredInterpretationEnvelopeV1

BANK = "ray-personal"
SELECTED = (
    ("9263c5f6-1cfe-581c-b038-96abcea82384",
     "2357068cdead03bdcf50e86a31e563a540bd5d1ae6bd38cc332deefc58c02c4d",
     "4d932e465b7f6466076511ab43048a06a72e8a66a1d2fc218ac2fec790c3c710", 2),
    ("a2f5788d-a662-5186-a65e-18e19c58d0c1",
     "1a3c4ccd741157fe40a5c59a0075f371a2bb0383779baba032ad9025da14994f",
     "00d11cb52f3eda9fa6c507cebb3485c1c288702d32598616445e1a1b05fc0fd3", 3),
    ("c8618f70-7d75-5afd-becb-67e7c400f5e3",
     "e3837a999c7b543dd3a91caa982be21dd07c2b249ca7c7285372e7ae73a40350",
     "02c881c1523bd31996c804c845eac36982d7bd711b4c16b83a2995460e237ba4", 3),
)
HINDSIGHT_URL = "http://raymond-hindsight-api:8888"


def _content(envelope: StoredInterpretationEnvelopeV1) -> str:
    meaning = envelope.interpretation
    lines = [
        "Reviewed historical interpretation. This records what was discussed then; "
        "it is not a present-day confirmation.",
        f"Statement: {meaning.statement}",
        f"Speech act: {meaning.speech_act.value}.",
        f"Proposer: {meaning.proposer.value}.",
        f"Ray confirmation scope: {meaning.confirmation_scope.value}.",
        f"Current applicability: {meaning.current_applicability.value}.",
    ]
    if meaning.confirmed_proposition:
        lines.append(f"Confirmed portion only: {meaning.confirmed_proposition}")
    if meaning.material_qualifiers:
        lines.append("Qualifiers: " + " | ".join(meaning.material_qualifiers))
    if meaning.applicable_period:
        lines.append(f"Historical period: {meaning.applicable_period}")
    lines.append("Source record IDs: " + ", ".join(
        ref.source_record_id for ref in envelope.evidence_refs
    ))
    return "\n".join(lines)


def _retain(item: dict[str, object], key: str) -> dict[str, object]:
    wire = json.dumps({"items": [item], "async": False}, separators=(",", ":")).encode()
    request = Request(
        f"{HINDSIGHT_URL}/v1/default/banks/{BANK}/memories",
        data=wire, method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=180) as response:  # noqa: S310 - exact private URL
        if response.status != 200:
            raise RuntimeError("Hindsight retain did not complete")
        result = json.load(response)
    if not isinstance(result, dict) or result.get("success") is not True:
        raise RuntimeError("Hindsight retain result differs")
    return result


def main() -> None:
    if (os.environ.get("RENDER") != "true"
            or os.environ.get("LUCY_ENVIRONMENT") != "production"
            or os.environ.get("LUCY_HINDSIGHT_IMPORT_AUTHORIZATION")
            != "raymond-reviewed-three-hindsight-import-v1"):
        raise RuntimeError("Hindsight import authorization unavailable")
    url = make_url(os.environ["LUCY_DATABASE_URL"])
    if (url.host != "dpg-dak5bqad0e5s73b2e3d0-a"
            or url.database != "lucy_raymond"
            or url.username != "lucy_raymond_policy"
            or url.query.get("sslmode") != "require"):
        raise RuntimeError("Raymond governed-source boundary differs")
    sessions = create_session_factory(url.render_as_string(hide_password=False))
    chosen = []
    with sessions.begin() as session:
        for candidate_id, source_digest, object_hash, source_count in SELECTED:
            rows = session.execute(
                text("SELECT lucy.search_protected_scoped_memory_v1("
                     ":query,20,:interaction,:reason)"),
                {"query": source_digest,
                 "interaction": uuid5(APPROVAL_NAMESPACE, f"recall:{candidate_id}"),
                 "reason": "hindsight_reviewed_pilot_import"},
            ).scalar_one()
            matches = [row for row in rows if row["candidate_id"] == candidate_id
                       and row["candidate_version"] == 2]
            if len(matches) != 1:
                raise RuntimeError("reviewed source claim is unavailable")
            row = matches[0]
            if (sha256(row["object"].encode()).hexdigest() != object_hash
                    or row["protection_class"] != "protected"
                    or row["assertion_status"] != "attributed_interpretation"
                    or row["epistemic_status"] != "historical"
                    or len(row["source_evidence_ids"]) != source_count):
                raise RuntimeError("reviewed source claim differs")
            chosen.append(row)
    key = os.environ["HINDSIGHT_API_KEY"]
    imported = []
    for candidate in chosen:
        envelope = StoredInterpretationEnvelopeV1.model_validate_json(candidate["object"])
        source_ids = [ref.source_record_id for ref in envelope.evidence_refs]
        item: dict[str, object] = {
            "content": _content(envelope),
            "document_id": f"lucy-reviewed:{candidate['candidate_id']}:v2",
            "update_mode": "replace",
            "context": "Ray's reviewed Personal Lucy historical interpretation pilot",
            "metadata": {
                "source": "lucy_governed_reviewed_interpretation",
                "candidate_id": candidate["candidate_id"],
                "candidate_version": "2",
                "object_sha256": sha256(candidate["object"].encode()).hexdigest(),
                "source_record_ids": json.dumps(source_ids, separators=(",", ":")),
                "source_evidence_ids": json.dumps(
                    candidate["source_evidence_ids"],
                    separators=(",", ":"),
                ),
                "campaign_id": str(CAMPAIGN_ID),
                "proposal_sha256": PROPOSAL_SHA256,
            },
        }
        if envelope.interpretation.source_utterance_at:
            item["timestamp"] = envelope.interpretation.source_utterance_at.isoformat()
        _retain(item, key)
        imported.append(candidate["candidate_id"])
    print("HINDSIGHT_IMPORT:" + json.dumps({
        "bank": BANK, "imported_count": len(imported),
        "candidate_ids": imported, "source_archive_unchanged": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
