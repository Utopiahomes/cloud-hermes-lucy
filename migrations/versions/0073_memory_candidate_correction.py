"""Retire corrected scoped memories from recall while preserving immutable history."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0073_memory_candidate_correction"
down_revision: str | None = "0072_memory_pilot_auth_context"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _replace_function(signature: str, replacements: tuple[tuple[str, str], ...]) -> None:
    definition = op.get_bind().execute(
        sa.text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))"),
        {"signature": signature},
    ).scalar_one()
    for before, after in replacements:
        if definition.count(before) != 1:
            raise RuntimeError(f"Unexpected correction migration boundary: {signature}")
        definition = definition.replace(before, after)
    op.execute(sa.text(definition))


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE lucy.scoped_memory_supersessions_v1 (
          prior_claim_id uuid PRIMARY KEY REFERENCES lucy.scoped_memory_claims_v1(id),
          successor_claim_id uuid NOT NULL UNIQUE REFERENCES lucy.scoped_memory_claims_v1(id),
          content_scope_id uuid NOT NULL REFERENCES lucy.realm_content_scopes_v1(id),
          approval_id uuid NOT NULL UNIQUE
            REFERENCES lucy.scoped_memory_candidate_approvals_v1(id),
          superseded_at timestamptz NOT NULL,
          CHECK (prior_claim_id<>successor_claim_id)
        );
        CREATE TRIGGER scoped_memory_supersessions_v1_immutable BEFORE UPDATE OR DELETE
          ON lucy.scoped_memory_supersessions_v1 FOR EACH ROW
          EXECUTE FUNCTION lucy.reject_mutation();
        REVOKE ALL ON lucy.scoped_memory_supersessions_v1 FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_memory_supersessions_v1
          TO lucy_security_function_owner;
        """
    )
    actor_check = (
        "IF NOT FOUND THEN RAISE EXCEPTION 'memory candidate promotion unavailable'; END IF;"
    )
    source_loop = (
        "FOR v_source IN SELECT * FROM lucy.scoped_memory_candidate_sources_v1"
    )
    event_insert = "INSERT INTO lucy.scoped_memory_events_v1("
    _replace_function(
        "lucy.promote_scoped_memory_candidate_v1(uuid,text)",
        (
            (
                "v_source lucy.scoped_memory_candidate_sources_v1%ROWTYPE;",
                "v_source lucy.scoped_memory_candidate_sources_v1%ROWTYPE;\n"
                "v_prior lucy.scoped_memory_claims_v1%ROWTYPE; v_target uuid;",
            ),
            (
                actor_check,
                actor_check + """
          -- Serialize promotions in this scope, including competing corrections.
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-promotion-scope:'||v_actor.content_scope_id::text,0));
                """,
            ),
            (
                source_loop,
                """
          v_target:=(v_candidate.serialized_candidate->>'supersedes_candidate_id')::uuid;
          IF v_target IS NOT NULL THEN
            -- Exact replay was handled above. A fresh correction needs exactly one
            -- current target in this realm, never a missing or already retired claim.
            BEGIN
              SELECT c.* INTO STRICT v_prior FROM lucy.scoped_memory_claims_v1 c
              WHERE c.content_scope_id=v_actor.content_scope_id
                AND c.candidate_id=v_target AND c.status='accepted'
                AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_supersessions_v1 s
                                WHERE s.prior_claim_id=c.id);
            EXCEPTION WHEN no_data_found OR too_many_rows THEN
              RAISE EXCEPTION 'memory correction target unavailable';
            END;
            IF v_prior.subject<>v_candidate.serialized_candidate->>'subject'
              OR v_prior.predicate<>v_candidate.serialized_candidate->>'predicate'
              OR v_prior.object=v_candidate.serialized_candidate->>'object'
              OR v_candidate.epistemic_status<>'current'
              OR v_prior.candidate_id=v_candidate.candidate_id
                 AND v_prior.candidate_version>=v_candidate.candidate_version
            THEN RAISE EXCEPTION 'memory correction target mismatch'; END IF;
          END IF;
                """ + source_loop,
            ),
            (
                event_insert,
                """
          IF v_target IS NOT NULL THEN
            INSERT INTO lucy.scoped_memory_supersessions_v1(
              prior_claim_id,successor_claim_id,content_scope_id,approval_id,superseded_at)
            VALUES(v_prior.id,v_claim_id,v_actor.content_scope_id,p_approval_id,v_now);
          END IF;
                """ + event_insert,
            ),
        ),
    )
    current_filter = "AND c.status='accepted'"
    for signature in (
        "lucy.search_scoped_memory_v1(text,integer)",
        "lucy.search_governed_scoped_memory_v1(text,integer)",
        "lucy.search_protected_scoped_memory_v1(text,integer,uuid,text)",
    ):
        _replace_function(
            signature,
            ((current_filter, current_filter + """
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_supersessions_v1 s
                              WHERE s.prior_claim_id=c.id)
            """),),
        )


def downgrade() -> None:
    raise RuntimeError("Correction history is durable; roll back application code only")
