"""Copy a small reviewed interpretation slice into Ray's Hindsight bank.

The protected proposal and live governed recall remain the authority. Hindsight
receives source-linked, revisable documents only after both checks agree.
"""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen

from sqlalchemy.engine import make_url

from deploy.postgres.promote_raymond_interpretations_v1 import (
    CAMPAIGN_ID,
    PROPOSAL_SHA256,
    load_proposal,
    verify_protected_recall,
)
from lucy.db import create_session_factory
from lucy.interpreted_recall import StoredInterpretationEnvelopeV1

BANK = "ray-personal"
SELECTED = (5, 7, 9)
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
    candidates = load_proposal()
    chosen = tuple(candidates[number - 1] for number in SELECTED)
    sessions = create_session_factory(url.render_as_string(hide_password=False))
    with sessions() as session:
        verify_protected_recall(session, chosen)
    key = os.environ["HINDSIGHT_API_KEY"]
    imported = []
    for candidate in chosen:
        envelope = StoredInterpretationEnvelopeV1.model_validate_json(candidate.object)
        source_ids = [ref.source_record_id for ref in envelope.evidence_refs]
        item: dict[str, object] = {
            "content": _content(envelope),
            "document_id": f"lucy-reviewed:{candidate.candidate_id}:v2",
            "update_mode": "replace",
            "context": "Ray's reviewed Personal Lucy historical interpretation pilot",
            "timestamp": envelope.interpretation.source_utterance_at.isoformat()
                if envelope.interpretation.source_utterance_at else "unset",
            "metadata": {
                "source": "lucy_governed_reviewed_interpretation",
                "candidate_id": str(candidate.candidate_id),
                "candidate_version": "2",
                "candidate_digest": candidate.digest,
                "source_record_ids": json.dumps(source_ids, separators=(",", ":")),
                "source_evidence_ids": json.dumps(
                    [str(source.evidence_id) for source in candidate.sources],
                    separators=(",", ":"),
                ),
                "campaign_id": str(CAMPAIGN_ID),
                "proposal_sha256": PROPOSAL_SHA256,
            },
        }
        _retain(item, key)
        imported.append(str(candidate.candidate_id))
    print("HINDSIGHT_IMPORT:" + json.dumps({
        "bank": BANK, "imported_count": len(imported),
        "candidate_ids": imported, "source_archive_unchanged": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
