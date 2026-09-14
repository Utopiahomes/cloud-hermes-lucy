"""Gate the realm-bound public answer path on admission and storage epoch."""

from __future__ import annotations

from alembic import op

revision: str = "0052_r1_public_answer_gate"
down_revision: str | None = "0051_stage1_private_telegram"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        r"""
        GRANT SELECT ON lucy.channel_bindings,lucy.nodes,
          lucy.public_projection_routes,lucy.public_projection_versions,
          lucy.runtime_admission,lucy.lifecycle
          TO lucy_security_function_owner;

        CREATE FUNCTION lucy.public_projection_answer_v2(
          p_hostname text,p_question text,p_storage_epoch uuid
        ) RETURNS jsonb
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT jsonb_build_object(
            'answer',faq.item->>'answer',
            'source',faq.item->>'source',
            'version',v.version,
            'snapshot_digest',v.snapshot_digest
          )
          FROM lucy.channel_bindings c
          JOIN lucy.nodes n ON n.id=c.node_id
          JOIN lucy.public_projection_routes r ON r.channel_binding_id=c.id
          JOIN lucy.public_projection_versions v ON v.id=r.active_version_id
            AND v.channel_binding_id=c.id
          CROSS JOIN lucy.runtime_admission a
          CROSS JOIN lucy.lifecycle l
          CROSS JOIN LATERAL jsonb_array_elements(v.snapshot->'faqs') AS faq(item)
          WHERE c.hostname=lower(trim(trailing '.' from btrim(p_hostname)))
            AND c.active
            AND c.channel_kind='website_public'
            AND session_user='lucy_' || replace(n.slug,'-','_') || '_public'
            AND a.singleton
            AND a.state='ready'
            AND a.storage_epoch=p_storage_epoch
            AND l.singleton
            AND l.state='ready'
            AND faq.item->>'question'=
              lower(regexp_replace(btrim(p_question), E'\\s+', ' ', 'g'))
          LIMIT 1
        $function$;
        ALTER FUNCTION lucy.public_projection_answer_v2(text,text,uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.public_projection_answer_v2(text,text,uuid)
          FROM PUBLIC,lucy_app,lucy_public_runtime;
        """
    )


def downgrade() -> None:
    raise RuntimeError("the admitted public answer boundary requires a reviewed forward migration")
