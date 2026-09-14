"""Return the exact pilot authorization through bounded transport admission."""

from collections.abc import Sequence

from alembic import op

revision: str = "0072_memory_pilot_auth_context"
down_revision: str | None = "0071_memory_import_job_replay"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION lucy.read_memory_pilot_transport_admission_v1(
          p_capability_digest text,p_batch_id uuid
        ) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE; v_result jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND service_role='realm_evidence' AND active
            AND allowed_actions @> '["evidence.archive","memory.propose"]'::jsonb;
          SELECT jsonb_build_object(
            'campaign_id',r.campaign_id,'owner_approval_ref',r.owner_approval_ref,
            'destination_content_scope_id',r.content_scope_id,
            'bundle_digest',r.bundle_digest,'manifest_digest',r.manifest_digest,
            'transfer_key_commitment',r.transfer_key_commitment,'expires_at',r.expires_at,
            'authorization',a.serialized_authorization,
            'manifest',c.serialized_manifest,
            'batch',jsonb_build_object('batch_id',b.batch_id,'batch_index',b.batch_index,
              'extraction_job_id',b.extraction_job_id,'attempt_key',b.attempt_key,
              'source_record_ids',b.source_record_ids,
              'request_commitment',b.request_commitment,
              'transport_commitment',b.transport_commitment,
              'transport_bytes',b.transport_bytes)) INTO v_result
          FROM lucy.memory_pilot_transport_registrations_v1 r
          JOIN lucy.memory_pilot_transport_batches_v1 b ON b.campaign_id=r.campaign_id
          JOIN lucy.memory_import_campaigns_v1 c ON c.id=r.campaign_id
          JOIN lucy.memory_import_pilot_authorizations_v1 a
            ON a.owner_approval_ref=r.owner_approval_ref
           AND a.campaign_id=r.campaign_id
           AND a.content_scope_id=r.content_scope_id
           AND a.bundle_digest=r.bundle_digest
           AND a.manifest_digest=r.manifest_digest
           AND a.expires_at>=r.expires_at
          WHERE r.capability_token_digest=p_capability_digest AND b.batch_id=p_batch_id
            AND r.content_scope_id=v_binding.content_scope_id AND r.expires_at>clock_timestamp()
            AND a.expires_at>clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM lucy.memory_pilot_transport_revocations_v1 x
                           WHERE x.campaign_id=r.campaign_id);
          IF v_binding.id IS NULL OR v_result IS NULL
          THEN RAISE EXCEPTION 'memory pilot transport admission unavailable'; END IF;
          RETURN v_result;
        END $function$;
        ALTER FUNCTION lucy.read_memory_pilot_transport_admission_v1(text,uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.read_memory_pilot_transport_admission_v1(text,uuid)
          FROM PUBLIC,lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("pilot authorization context requires a reviewed forward migration")
