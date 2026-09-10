"""Stage durable membership revocation and public withdrawal recovery events."""

from collections.abc import Sequence

from alembic import op

revision: str = "0045_r1_authority_recovery_staging"
down_revision: str | None = "0044_r1_cost_outcome_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        ALTER TABLE lucy.public_projection_routes
          ADD COLUMN authority_generation bigint NOT NULL DEFAULT 1
          CHECK (authority_generation>0);

        CREATE FUNCTION lucy.guard_authority_restriction_writes_v1()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
          IF current_user NOT IN ('lucy_authority_function_owner','lucy_owner') THEN
            IF TG_TABLE_NAME='node_memberships'
               AND OLD.status='active' AND NEW.status='revoked'
            THEN RAISE EXCEPTION 'membership revocation requires authority transition'; END IF;
            IF TG_TABLE_NAME='public_projection_routes'
               AND OLD.active_version_id IS NOT NULL AND NEW.active_version_id IS NULL
            THEN RAISE EXCEPTION 'publication withdrawal requires authority transition'; END IF;
          END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER node_membership_authority_restriction_guard_v1
          BEFORE UPDATE ON lucy.node_memberships FOR EACH ROW
          EXECUTE FUNCTION lucy.guard_authority_restriction_writes_v1();
        CREATE TRIGGER public_route_authority_restriction_guard_v1
          BEFORE UPDATE ON lucy.public_projection_routes FOR EACH ROW
          EXECUTE FUNCTION lucy.guard_authority_restriction_writes_v1();

        CREATE TABLE lucy.authority_transition_events_v1 (
          id uuid PRIMARY KEY,
          idempotency_key text NOT NULL UNIQUE CHECK (
            length(idempotency_key) BETWEEN 1 AND 300 AND
            idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
          ),
          stream_id uuid NOT NULL,
          authority_epoch bigint NOT NULL CHECK (authority_epoch>0),
          event_type text NOT NULL CHECK (
            event_type IN ('membership_revoked','publication_withdrawn')
          ),
          security_realm_id uuid NOT NULL REFERENCES lucy.security_realms(id),
          workspace_id uuid NOT NULL REFERENCES lucy.workspaces(id),
          subject_id uuid NOT NULL,
          actor_id uuid NOT NULL REFERENCES lucy.principals(id),
          previous_generation bigint NOT NULL CHECK (previous_generation>=0),
          new_generation bigint NOT NULL CHECK (new_generation=previous_generation+1),
          source_authority_ref text NOT NULL CHECK (
            length(source_authority_ref) BETWEEN 1 AND 512 AND
            source_authority_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
          ),
          source_authority_digest text NOT NULL CHECK (
            source_authority_digest ~ '^[0-9a-f]{64}$'
          ),
          transition_digest text NOT NULL CHECK (transition_digest ~ '^[0-9a-f]{64}$'),
          occurred_at timestamptz NOT NULL
        );
        CREATE TABLE lucy.authority_recovery_outbox_v1 (
          event_id uuid PRIMARY KEY REFERENCES lucy.authority_transition_events_v1(id),
          journal_sequence bigint CHECK (journal_sequence>0),
          journal_previous_digest text CHECK (
            journal_previous_digest IS NULL OR journal_previous_digest ~ '^[0-9a-f]{64}$'
          ),
          journal_event_digest text CHECK (
            journal_event_digest IS NULL OR journal_event_digest ~ '^[0-9a-f]{64}$'
          ),
          journal_head_digest text CHECK (
            journal_head_digest IS NULL OR journal_head_digest ~ '^[0-9a-f]{64}$'
          ),
          acknowledged_at timestamptz,
          CHECK ((journal_sequence IS NULL)=(journal_previous_digest IS NULL)),
          CHECK ((journal_sequence IS NULL)=(journal_event_digest IS NULL)),
          CHECK ((journal_head_digest IS NULL)=(acknowledged_at IS NULL)),
          CHECK (journal_head_digest IS NULL OR journal_head_digest=journal_event_digest)
        );
        CREATE TRIGGER authority_transition_events_immutable_v1
          BEFORE UPDATE OR DELETE ON lucy.authority_transition_events_v1
          FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        REVOKE ALL ON lucy.authority_transition_events_v1,
          lucy.authority_recovery_outbox_v1
          FROM PUBLIC,lucy_app,lucy_public_runtime;
        GRANT USAGE ON SCHEMA lucy TO lucy_authority_function_owner;
        GRANT SELECT ON lucy.principals,lucy.node_memberships,lucy.workspaces,
          lucy.channel_bindings,lucy.realm_bindings,lucy.public_projection_routes,
          lucy.authority_transition_events_v1,lucy.authority_recovery_outbox_v1
          TO lucy_authority_function_owner;
        GRANT INSERT ON lucy.authority_transition_events_v1,
          lucy.authority_recovery_outbox_v1,lucy.public_projection_events
          TO lucy_authority_function_owner;
        GRANT UPDATE ON lucy.node_memberships,lucy.public_projection_routes,
          lucy.authority_recovery_outbox_v1 TO lucy_authority_function_owner;
        REVOKE ALL ON FUNCTION lucy.guard_authority_restriction_writes_v1()
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_transition,
            lucy_authority_recovery_writer;
        ALTER FUNCTION lucy.guard_authority_restriction_writes_v1()
          OWNER TO lucy_authority_function_owner;

        CREATE FUNCTION lucy.authority_transition_result_v1(
          p_event_id uuid,p_replayed boolean
        ) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object(
            'event_id',e.id,'state',CASE WHEN o.acknowledged_at IS NULL
              THEN 'PERSISTENCE_PENDING' ELSE 'DURABLY_RECORDED' END,
            'stream_id',e.stream_id,'authority_epoch',e.authority_epoch,
            'event_type',e.event_type,'security_realm_id',e.security_realm_id,
            'workspace_id',e.workspace_id,'subject_id',e.subject_id,
            'previous_generation',e.previous_generation,
            'new_generation',e.new_generation,
            'transition_digest',e.transition_digest,
            'journal_sequence',o.journal_sequence,
            'journal_previous_digest',o.journal_previous_digest,
            'journal_event_digest',o.journal_event_digest,
            'journal_head_digest',o.journal_head_digest,'replayed',p_replayed
          ) FROM lucy.authority_transition_events_v1 e
          JOIN lucy.authority_recovery_outbox_v1 o ON o.event_id=e.id
          WHERE e.id=p_event_id
        $function$;

        CREATE FUNCTION lucy.stage_membership_revocation_v1(
          p_membership_id uuid,p_actor_id uuid,p_stream_id uuid,p_authority_epoch bigint,
          p_idempotency_key text,p_source_authority_ref text,
          p_source_authority_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_existing lucy.authority_transition_events_v1%ROWTYPE;
          v_target lucy.node_memberships%ROWTYPE; v_realm uuid; v_event uuid:=gen_random_uuid();
          v_now timestamptz:=clock_timestamp(); v_digest text;
        BEGIN
          IF p_authority_epoch<1 OR length(p_idempotency_key) NOT BETWEEN 1 AND 300
             OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR length(p_source_authority_ref) NOT BETWEEN 1 AND 512
             OR p_source_authority_ref !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR p_source_authority_digest !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'membership revocation unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.authority_transition_events_v1
            WHERE idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.event_type<>'membership_revoked'
               OR v_existing.subject_id<>p_membership_id
               OR v_existing.actor_id<>p_actor_id OR v_existing.stream_id<>p_stream_id
               OR v_existing.authority_epoch<>p_authority_epoch
               OR v_existing.source_authority_ref<>p_source_authority_ref
               OR v_existing.source_authority_digest<>p_source_authority_digest
            THEN RAISE EXCEPTION 'authority transition idempotency conflict'; END IF;
            RETURN lucy.authority_transition_result_v1(v_existing.id,true); END IF;
          SELECT * INTO v_target FROM lucy.node_memberships
            WHERE id=p_membership_id FOR UPDATE;
          IF NOT FOUND OR v_target.status<>'active' THEN
            RAISE EXCEPTION 'membership revocation unavailable'; END IF;
          IF NOT EXISTS(SELECT 1 FROM lucy.node_memberships a
            WHERE a.principal_id=p_actor_id AND a.workspace_id=v_target.workspace_id
              AND a.status='active' AND a.role='owner')
          THEN RAISE EXCEPTION 'membership revocation unavailable'; END IF;
          IF v_target.role='owner' AND NOT EXISTS(SELECT 1 FROM lucy.node_memberships o
            WHERE o.workspace_id=v_target.workspace_id AND o.status='active'
              AND o.role='owner' AND o.id<>v_target.id)
          THEN RAISE EXCEPTION 'last owner revocation unavailable'; END IF;
          SELECT rb.realm_id INTO STRICT v_realm FROM lucy.workspaces w
            JOIN lucy.realm_bindings rb ON rb.tenure_id=w.tenure_id AND rb.valid_to IS NULL
            WHERE w.id=v_target.workspace_id;
          v_digest:=encode(public.digest(
            'membership_revoked:'||p_stream_id::text||':'||p_authority_epoch::text||':'||
            v_realm::text||':'||v_target.workspace_id::text||':'||v_target.id::text||':'||
            v_target.generation::text||':'||(v_target.generation+1)::text||':'||
            p_source_authority_digest,'sha256'),'hex');
          UPDATE lucy.node_memberships SET status='revoked',generation=generation+1
            WHERE id=v_target.id;
          INSERT INTO lucy.authority_transition_events_v1 VALUES(
            v_event,p_idempotency_key,p_stream_id,p_authority_epoch,'membership_revoked',
            v_realm,v_target.workspace_id,v_target.id,p_actor_id,v_target.generation,
            v_target.generation+1,p_source_authority_ref,p_source_authority_digest,
            v_digest,v_now
          );
          INSERT INTO lucy.authority_recovery_outbox_v1(event_id) VALUES(v_event);
          RETURN lucy.authority_transition_result_v1(v_event,false);
        END
        $function$;

        CREATE FUNCTION lucy.stage_publication_withdrawal_v1(
          p_channel_binding_id uuid,p_actor_id uuid,p_stream_id uuid,
          p_authority_epoch bigint,p_idempotency_key text,p_source_authority_ref text,
          p_source_authority_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_existing lucy.authority_transition_events_v1%ROWTYPE;
          v_workspace uuid; v_realm uuid; v_generation bigint; v_active uuid;
          v_event uuid:=gen_random_uuid(); v_now timestamptz:=clock_timestamp();
          v_digest text;
        BEGIN
          IF p_authority_epoch<1 OR length(p_idempotency_key) NOT BETWEEN 1 AND 300
             OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR length(p_source_authority_ref) NOT BETWEEN 1 AND 512
             OR p_source_authority_ref !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR p_source_authority_digest !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'publication withdrawal unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.authority_transition_events_v1
            WHERE idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.event_type<>'publication_withdrawn'
               OR v_existing.subject_id<>p_channel_binding_id
               OR v_existing.actor_id<>p_actor_id OR v_existing.stream_id<>p_stream_id
               OR v_existing.authority_epoch<>p_authority_epoch
               OR v_existing.source_authority_ref<>p_source_authority_ref
               OR v_existing.source_authority_digest<>p_source_authority_digest
            THEN RAISE EXCEPTION 'authority transition idempotency conflict'; END IF;
            RETURN lucy.authority_transition_result_v1(v_existing.id,true); END IF;
          SELECT c.workspace_id,rb.realm_id,r.authority_generation,r.active_version_id
          INTO v_workspace,v_realm,v_generation,v_active
          FROM lucy.channel_bindings c JOIN lucy.workspaces w ON w.id=c.workspace_id
          JOIN lucy.realm_bindings rb ON rb.tenure_id=w.tenure_id AND rb.valid_to IS NULL
          JOIN lucy.public_projection_routes r ON r.channel_binding_id=c.id
          WHERE c.id=p_channel_binding_id AND c.active FOR UPDATE OF r;
          IF NOT FOUND OR v_active IS NULL THEN
            RAISE EXCEPTION 'publication withdrawal unavailable'; END IF;
          IF NOT EXISTS(SELECT 1 FROM lucy.node_memberships a
            WHERE a.principal_id=p_actor_id AND a.workspace_id=v_workspace
              AND a.status='active' AND a.role IN ('owner','approver'))
          THEN RAISE EXCEPTION 'publication withdrawal unavailable'; END IF;
          v_digest:=encode(public.digest(
            'publication_withdrawn:'||p_stream_id::text||':'||p_authority_epoch::text||':'||
            v_realm::text||':'||v_workspace::text||':'||p_channel_binding_id::text||':'||
            v_generation::text||':'||(v_generation+1)::text||':'||
            p_source_authority_digest,'sha256'),'hex');
          UPDATE lucy.public_projection_routes SET active_version_id=NULL,
            authority_generation=authority_generation+1,updated_at=v_now
            WHERE channel_binding_id=p_channel_binding_id;
          INSERT INTO lucy.public_projection_events(
            id,channel_binding_id,event_type,candidate_id,version_id,actor_id,occurred_at
          ) VALUES(v_event,p_channel_binding_id,'withdrawal_blocked',NULL,NULL,p_actor_id,v_now);
          INSERT INTO lucy.authority_transition_events_v1 VALUES(
            v_event,p_idempotency_key,p_stream_id,p_authority_epoch,'publication_withdrawn',
            v_realm,v_workspace,p_channel_binding_id,p_actor_id,v_generation,v_generation+1,
            p_source_authority_ref,p_source_authority_digest,v_digest,v_now
          );
          INSERT INTO lucy.authority_recovery_outbox_v1(event_id) VALUES(v_event);
          RETURN lucy.authority_transition_result_v1(v_event,false);
        END
        $function$;

        CREATE FUNCTION lucy.get_pending_authority_event_v1(p_event_id uuid)
        RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object(
            'event_id',e.id,'idempotency_key',e.idempotency_key,
            'stream_id',e.stream_id,'authority_epoch',e.authority_epoch,
            'event_type',e.event_type,'security_realm_id',e.security_realm_id,
            'workspace_id',e.workspace_id,'subject_id',e.subject_id,
            'previous_generation',e.previous_generation,'new_generation',e.new_generation,
            'source_authority_ref',e.source_authority_ref,
            'source_authority_digest',e.source_authority_digest,
            'transition_digest',e.transition_digest,'occurred_at',e.occurred_at,
            'journal_sequence',o.journal_sequence,
            'journal_previous_digest',o.journal_previous_digest,
            'journal_event_digest',o.journal_event_digest
          ) FROM lucy.authority_transition_events_v1 e
          JOIN lucy.authority_recovery_outbox_v1 o ON o.event_id=e.id
          WHERE e.id=p_event_id AND o.acknowledged_at IS NULL
        $function$;

        CREATE FUNCTION lucy.prepare_authority_event_v1(
          p_event_id uuid,p_journal_sequence bigint,p_journal_previous_digest text,
          p_journal_event_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_sequence bigint; v_previous text; v_event_digest text; v_ack timestamptz;
        BEGIN
          IF p_journal_sequence<1
             OR p_journal_previous_digest !~ '^[0-9a-f]{64}$'
             OR p_journal_event_digest !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'authority event preparation unavailable'; END IF;
          SELECT journal_sequence,journal_previous_digest,journal_event_digest,acknowledged_at
          INTO v_sequence,v_previous,v_event_digest,v_ack
          FROM lucy.authority_recovery_outbox_v1 WHERE event_id=p_event_id FOR UPDATE;
          IF NOT FOUND OR v_ack IS NOT NULL THEN
            RAISE EXCEPTION 'authority event preparation unavailable'; END IF;
          IF v_sequence IS NOT NULL THEN
            IF (v_sequence,v_previous,v_event_digest) IS DISTINCT FROM
              (p_journal_sequence,p_journal_previous_digest,p_journal_event_digest)
            THEN RAISE EXCEPTION 'authority event preparation conflicts'; END IF;
          ELSE
            UPDATE lucy.authority_recovery_outbox_v1 SET
              journal_sequence=p_journal_sequence,
              journal_previous_digest=p_journal_previous_digest,
              journal_event_digest=p_journal_event_digest
              WHERE event_id=p_event_id;
          END IF;
          RETURN lucy.get_pending_authority_event_v1(p_event_id);
        END
        $function$;

        CREATE FUNCTION lucy.acknowledge_authority_event_v1(
          p_event_id uuid,p_journal_sequence bigint,p_journal_event_digest text,
          p_journal_head_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_sequence bigint; v_event_digest text; v_head_digest text;
          v_ack timestamptz; v_now timestamptz:=clock_timestamp();
        BEGIN
          IF p_journal_sequence<1 OR p_journal_event_digest !~ '^[0-9a-f]{64}$'
             OR p_journal_head_digest !~ '^[0-9a-f]{64}$'
             OR p_journal_event_digest<>p_journal_head_digest
          THEN RAISE EXCEPTION 'authority acknowledgement unavailable'; END IF;
          SELECT journal_sequence,journal_event_digest,journal_head_digest,acknowledged_at
          INTO v_sequence,v_event_digest,v_head_digest,v_ack
          FROM lucy.authority_recovery_outbox_v1 WHERE event_id=p_event_id FOR UPDATE;
          IF NOT FOUND THEN RAISE EXCEPTION 'authority acknowledgement unavailable'; END IF;
          IF v_ack IS NOT NULL THEN
            IF (v_sequence,v_event_digest,v_head_digest) IS DISTINCT FROM
              (p_journal_sequence,p_journal_event_digest,p_journal_head_digest)
            THEN RAISE EXCEPTION 'authority acknowledgement conflicts'; END IF;
            RETURN lucy.authority_transition_result_v1(p_event_id,true); END IF;
          IF v_sequence IS NULL OR v_event_digest IS NULL
             OR v_sequence<>p_journal_sequence OR v_event_digest<>p_journal_event_digest
          THEN RAISE EXCEPTION 'authority acknowledgement unavailable'; END IF;
          UPDATE lucy.authority_recovery_outbox_v1 SET
            journal_head_digest=p_journal_head_digest,acknowledged_at=v_now
            WHERE event_id=p_event_id;
          RETURN lucy.authority_transition_result_v1(p_event_id,false);
        END
        $function$;
        """
    )
    signatures = {
        "lucy.authority_transition_result_v1(uuid,boolean)": (),
        "lucy.stage_membership_revocation_v1(uuid,uuid,uuid,bigint,text,text,text)": (
            "lucy_authority_transition",
        ),
        "lucy.stage_publication_withdrawal_v1(uuid,uuid,uuid,bigint,text,text,text)": (
            "lucy_authority_transition",
        ),
        "lucy.get_pending_authority_event_v1(uuid)": ("lucy_authority_transition",),
        "lucy.prepare_authority_event_v1(uuid,bigint,text,text)": (
            "lucy_authority_transition",
        ),
        "lucy.acknowledge_authority_event_v1(uuid,bigint,text,text)": (
            "lucy_authority_recovery_writer",
        ),
    }
    for signature, grantees in signatures.items():
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_authority_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC,lucy_app,lucy_public_runtime,"
            "lucy_authority_transition,lucy_authority_recovery_writer"
        )
        for grantee in grantees:
            op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {grantee}")


def downgrade() -> None:
    raise RuntimeError("R1 authority recovery history requires a reviewed forward migration")
