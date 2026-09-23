"""One-shot Raymond policy-login check of cited interpretation answer contexts."""

from __future__ import annotations

import json
import os
from uuid import uuid5

from sqlalchemy.engine import make_url

from deploy.postgres.promote_raymond_interpretations_v1 import (
    APPROVAL_NAMESPACE,
    CAMPAIGN_ID,
    load_proposal,
)
from lucy.db import create_session_factory
from lucy.governed_memory import GovernedMemoryPolicy
from lucy.interpreted_recall import recall_interpreted_answer_context

AUTHORIZATION = "raymond-read-32-interpreted-contexts-v1"


def main() -> int:
    if (
        os.getenv("RENDER") != "true"
        or os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or os.getenv("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
        or os.getenv("LUCY_INTERPRETED_CONTEXT_AUTHORIZATION") != AUTHORIZATION
    ):
        raise RuntimeError("Raymond context-check environment is invalid")
    url = make_url(os.environ["LUCY_DATABASE_URL"])
    if (
        url.host != "dpg-dak5bqad0e5s73b2e3d0-a"
        or url.database != "lucy_raymond"
        or url.username != "lucy_raymond_policy"
        or not url.password
        or url.query.get("sslmode") != "require"
    ):
        raise RuntimeError("Raymond policy database boundary changed")
    candidates = load_proposal()
    sessions = create_session_factory(url.render_as_string(hide_password=False))
    policy = GovernedMemoryPolicy(sessions)
    citations = 0
    for candidate in candidates:
        digest = json.loads(candidate.object)["source_candidate_digest"]
        owner_ref = uuid5(APPROVAL_NAMESPACE, f"context:{candidate.candidate_id}")
        contexts = recall_interpreted_answer_context(
            policy,
            digest,
            owner_interaction_ref=owner_ref,
            reason_code="owner_reviewed_pilot_answer_context_check",
            campaign_id=CAMPAIGN_ID,
            question_is_current=True,
            limit=20,
        )
        matches = [
            context for context in contexts
            if context.candidate_id == candidate.candidate_id
        ]
        if len(matches) != 1:
            raise RuntimeError("reviewed interpretation context is absent or duplicated")
        context = matches[0]
        if (
            context.current_applicability != "not_checked"
            or not context.temporal_boundary
            or {citation.evidence_id for citation in context.citations}
            != {source.evidence_id for source in candidate.sources}
        ):
            raise RuntimeError("reviewed interpretation answer boundary changed")
        citations += len(context.citations)
    print(json.dumps({
        "status": "passed",
        "campaign_id": str(CAMPAIGN_ID),
        "contexts": len(candidates),
        "citations": citations,
        "provider_calls": 0,
        "telegram_messages": 0,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
