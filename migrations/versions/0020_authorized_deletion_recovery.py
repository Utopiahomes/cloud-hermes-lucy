"""Add fail-closed replay for authorized deletions after PostgreSQL restore."""

from collections.abc import Sequence

from alembic import op

revision: str = "0020_authorized_delete_recovery"
down_revision: str | None = "0019_security_v1_2_reconcile"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Migration 0019 closes schema CREATE after installing the v1.2 functions.
    # Re-open it only for the dedicated function-owner role while this reviewed
    # forward migration installs the recovery entry point, then close it again.
    op.execute("GRANT USAGE, CREATE ON SCHEMA lucy TO lucy_security_function_owner")
    op.execute(
        r"""
        CREATE TABLE lucy.authorized_deletion_recoveries_v1 (
          operation_id uuid PRIMARY KEY REFERENCES lucy.operations(id),
          permit_id uuid NOT NULL,
          manifest_id uuid NOT NULL UNIQUE,
          receipt_id uuid NOT NULL UNIQUE,
          permit_digest char(64) NOT NULL UNIQUE,
          manifest_digest char(64) NOT NULL UNIQUE,
          grant_digest char(64) NOT NULL UNIQUE,
          receipt_digest char(64) NOT NULL UNIQUE,
          targets_digest char(64) NOT NULL,
          target_count integer NOT NULL CHECK (target_count BETWEEN 1 AND 90),
          original_storage_epoch bigint NOT NULL CHECK (original_storage_epoch >= 1),
          original_registry_epoch bigint NOT NULL CHECK (original_registry_epoch >= 1),
          original_key_epoch bigint NOT NULL CHECK (original_key_epoch >= 1),
          recovered_storage_epoch bigint NOT NULL CHECK (recovered_storage_epoch >= 1),
          executor_identity text NOT NULL,
          executor_alias_arn text NOT NULL,
          executor_version bigint NOT NULL CHECK (executor_version >= 1),
          receipt_key_id text NOT NULL,
          deletion_effective_at timestamptz NOT NULL,
          finality_not_before timestamptz NOT NULL,
          finality_status text NOT NULL
            CHECK (finality_status IN ('PENDING','EXTENDED','VERIFIED')),
          finality_verified_at timestamptz,
          metadata_observed_at timestamptz,
          earliest_restorable_at timestamptz,
          latest_restorable_at timestamptz,
          recoverable_copy_count integer,
          metadata_inventory_digest char(64),
          recovery_digest char(64) NOT NULL UNIQUE,
          authority_evidence_digest char(64) NOT NULL,
          recovered_at timestamptz NOT NULL,
          derived_summary jsonb NOT NULL,
          CHECK (finality_not_before >= deletion_effective_at)
        );

        CREATE TABLE lucy.authorized_deletion_recovery_targets_v1 (
          operation_id uuid NOT NULL
            REFERENCES lucy.authorized_deletion_recoveries_v1(operation_id),
          evidence_id uuid NOT NULL REFERENCES lucy.evidence(id),
          key_ref uuid NOT NULL,
          record_version bigint NOT NULL CHECK (record_version >= 1),
          key_epoch bigint NOT NULL CHECK (key_epoch >= 1),
          PRIMARY KEY (operation_id,evidence_id),
          UNIQUE (operation_id,key_ref)
        );

        REVOKE ALL ON lucy.authorized_deletion_recoveries_v1,
          lucy.authorized_deletion_recovery_targets_v1 FROM PUBLIC, lucy_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON lucy.authorized_deletion_recoveries_v1,
          lucy.authorized_deletion_recovery_targets_v1 TO lucy_security_function_owner;
        CREATE TRIGGER authorized_deletion_recovery_targets_v1_immutable
          BEFORE UPDATE OR DELETE ON lucy.authorized_deletion_recovery_targets_v1
          FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.apply_authorized_deletion_recovery_v1(p_recovery jsonb)
        RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation_id uuid;
          v_manifest_id uuid;
          v_permit_id uuid;
          v_receipt_id uuid;
          v_target_count integer;
          v_original_key_epoch bigint;
          v_recovered_storage_epoch bigint;
          v_now timestamptz := clock_timestamp();
          v_completed_at timestamptz;
          v_reason text;
          v_existing lucy.authorized_deletion_recoveries_v1%ROWTYPE;
          v_claims integer := 0;
          v_relationships integer := 0;
          v_proposals integer := 0;
          v_corrections integer := 0;
          v_entities integer := 0;
          v_contexts integer := 0;
          v_turns integer := 0;
          v_payloads integer := 0;
          v_summary jsonb;
        BEGIN
          IF jsonb_typeof(p_recovery) <> 'object'
             OR p_recovery - ARRAY[
               'contract_version','object_type','operation_id','permit_id','manifest_id',
               'receipt_id','permit_digest','manifest_digest','grant_digest','receipt_digest',
               'targets_digest','target_count','storage_epoch','registry_epoch','key_epoch',
               'executor_identity','executor_alias_arn','executor_version','receipt_key_id',
               'completed_at','reason_category','recovery_digest','authority_evidence_digest',
               'recovered_storage_epoch','targets'
             ] <> '{}'::jsonb
             OR NOT (p_recovery ?& ARRAY[
               'contract_version','object_type','operation_id','permit_id','manifest_id',
               'receipt_id','permit_digest','manifest_digest','grant_digest','receipt_digest',
               'targets_digest','target_count','storage_epoch','registry_epoch','key_epoch',
               'executor_identity','executor_alias_arn','executor_version','receipt_key_id',
               'completed_at','reason_category','recovery_digest','authority_evidence_digest',
               'recovered_storage_epoch','targets'
             ]) THEN
            RAISE EXCEPTION 'authorized deletion recovery contract is malformed';
          END IF;
          IF p_recovery->>'contract_version' <> '1'
             OR p_recovery->>'object_type' <> 'lucy.authorized-deletion-recovery.v1'
             OR jsonb_typeof(p_recovery->'targets') <> 'array'
             OR p_recovery->>'reason_category' NOT IN
                ('owner_request','sensitive_data','retention_expired') THEN
            RAISE EXCEPTION 'authorized deletion recovery contract is unsupported';
          END IF;
          v_operation_id := (p_recovery->>'operation_id')::uuid;
          v_manifest_id := (p_recovery->>'manifest_id')::uuid;
          v_permit_id := (p_recovery->>'permit_id')::uuid;
          v_receipt_id := (p_recovery->>'receipt_id')::uuid;
          v_target_count := (p_recovery->>'target_count')::integer;
          v_original_key_epoch := (p_recovery->>'key_epoch')::bigint;
          v_recovered_storage_epoch := (p_recovery->>'recovered_storage_epoch')::bigint;
          v_completed_at := (p_recovery->>'completed_at')::timestamptz;
          v_reason := p_recovery->>'reason_category';
          IF v_target_count NOT BETWEEN 1 AND 90
             OR jsonb_array_length(p_recovery->'targets') <> v_target_count
             OR EXISTS (
               SELECT 1 FROM (VALUES
                 (p_recovery->>'permit_digest'),(p_recovery->>'manifest_digest'),
                 (p_recovery->>'grant_digest'),(p_recovery->>'receipt_digest'),
                 (p_recovery->>'targets_digest'),(p_recovery->>'recovery_digest'),
                 (p_recovery->>'authority_evidence_digest')
               ) AS d(value) WHERE value !~ '^[0-9a-f]{64}$'
             ) THEN
            RAISE EXCEPTION 'authorized deletion recovery digest or target count is invalid';
          END IF;
          IF NOT EXISTS (
               SELECT 1 FROM lucy.runtime_admission WHERE singleton AND state='quarantined'
             ) OR EXISTS (
               SELECT 1 FROM lucy.conversation_capture_states WHERE capture_enabled
             ) OR EXISTS (
               SELECT 1 FROM lucy.capture_receipts WHERE capture_enabled
             ) THEN
            RAISE EXCEPTION 'authorized deletion recovery requires quarantined capture-off storage';
          END IF;
          IF (SELECT storage_epoch FROM lucy.security_contract_epochs WHERE singleton)
               <> v_recovered_storage_epoch THEN
            RAISE EXCEPTION 'authorized deletion recovery storage epoch mismatch';
          END IF;

          SELECT * INTO v_existing FROM lucy.authorized_deletion_recoveries_v1
            WHERE operation_id=v_operation_id;
          IF FOUND THEN
            IF v_existing.recovery_digest <> p_recovery->>'recovery_digest'
               OR v_existing.authority_evidence_digest <>
                    p_recovery->>'authority_evidence_digest'
               OR v_existing.target_count <> v_target_count
               OR (SELECT count(*) FROM lucy.authorized_deletion_recovery_targets_v1
                   WHERE operation_id=v_operation_id) <> v_target_count
               OR (SELECT count(*) FROM lucy.evidence_tombstones
                   WHERE deletion_operation_id=v_operation_id) <> v_target_count
               OR EXISTS (
                 SELECT 1 FROM lucy.authorized_deletion_recovery_targets_v1 t
                 JOIN lucy.evidence_payloads p ON p.evidence_id=t.evidence_id
                 WHERE t.operation_id=v_operation_id
               ) THEN
              RAISE EXCEPTION 'authorized deletion recovery replay state mismatch';
            END IF;
            RETURN jsonb_build_object('state','FINALITY_PENDING','replayed',true,
                                      'derived_summary',v_existing.derived_summary);
          END IF;
          IF EXISTS (SELECT 1 FROM lucy.operations WHERE id=v_operation_id) THEN
            RAISE EXCEPTION 'authorized deletion recovery operation ID already exists';
          END IF;

          IF (SELECT count(*) FROM (
                SELECT DISTINCT x.evidence_id,x.key_ref,x.record_version,x.key_epoch
                FROM jsonb_to_recordset(p_recovery->'targets')
                  AS x(evidence_id uuid,key_ref uuid,record_version bigint,key_epoch bigint)
              ) q) <> v_target_count
             OR (SELECT count(*) FROM lucy.evidence_payloads p
                 JOIN jsonb_to_recordset(p_recovery->'targets')
                   AS x(evidence_id uuid,key_ref uuid,record_version bigint,key_epoch bigint)
                   ON p.evidence_id=x.evidence_id AND p.key_ref=x.key_ref
                  AND p.record_version=x.record_version AND p.key_epoch=x.key_epoch)
                <> v_target_count
             OR EXISTS (
               SELECT 1 FROM jsonb_to_recordset(p_recovery->'targets')
                 AS x(evidence_id uuid,key_ref uuid,record_version bigint,key_epoch bigint)
               WHERE x.key_epoch <> v_original_key_epoch
             ) THEN
            RAISE EXCEPTION 'restored PostgreSQL targets do not match the authorized manifest';
          END IF;

          INSERT INTO lucy.operations(id,idempotency_key,outcome,result,created_at,completed_at)
          VALUES (
            v_operation_id,'recovery:authorized-deletion:' || v_operation_id::text,
            'succeeded',jsonb_build_object('state','FINALITY_PENDING','recovery',true),
            v_completed_at,v_now
          );
          INSERT INTO lucy.authorized_deletion_recoveries_v1(
            operation_id,permit_id,manifest_id,receipt_id,permit_digest,manifest_digest,
            grant_digest,receipt_digest,targets_digest,target_count,original_storage_epoch,
            original_registry_epoch,original_key_epoch,recovered_storage_epoch,
            executor_identity,executor_alias_arn,executor_version,receipt_key_id,
            deletion_effective_at,finality_not_before,finality_status,recovery_digest,
            authority_evidence_digest,recovered_at,derived_summary
          ) VALUES (
            v_operation_id,v_permit_id,v_manifest_id,v_receipt_id,
            p_recovery->>'permit_digest',p_recovery->>'manifest_digest',
            p_recovery->>'grant_digest',p_recovery->>'receipt_digest',
            p_recovery->>'targets_digest',v_target_count,
            (p_recovery->>'storage_epoch')::bigint,
            (p_recovery->>'registry_epoch')::bigint,v_original_key_epoch,
            v_recovered_storage_epoch,p_recovery->>'executor_identity',
            p_recovery->>'executor_alias_arn',(p_recovery->>'executor_version')::bigint,
            p_recovery->>'receipt_key_id',v_completed_at,
            v_completed_at+interval '30 days','PENDING',p_recovery->>'recovery_digest',
            p_recovery->>'authority_evidence_digest',v_now,'{}'::jsonb
          );
          INSERT INTO lucy.authorized_deletion_recovery_targets_v1(
            operation_id,evidence_id,key_ref,record_version,key_epoch
          ) SELECT v_operation_id,x.evidence_id,x.key_ref,x.record_version,x.key_epoch
            FROM jsonb_to_recordset(p_recovery->'targets')
              AS x(evidence_id uuid,key_ref uuid,record_version bigint,key_epoch bigint);

          WITH RECURSIVE affected_claims(id) AS (
            SELECT c.id FROM lucy.memory_claims c
              WHERE c.evidence_id IN (
                SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                WHERE operation_id=v_operation_id
              ) OR c.id IN (
                SELECT claim_id FROM lucy.claim_sources WHERE evidence_id IN (
                  SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                  WHERE operation_id=v_operation_id
                )
              )
            UNION
            SELECT c.id FROM lucy.memory_claims c JOIN affected_claims a
              ON c.supersedes_claim_id=a.id
          )
          UPDATE lucy.memory_claims c
            SET subject='[redacted]',predicate='[redacted]',object='[redacted]',status='invalidated'
            WHERE c.id IN (SELECT id FROM affected_claims);
          GET DIAGNOSTICS v_claims = ROW_COUNT;

          WITH RECURSIVE affected_claims(id) AS (
            SELECT c.id FROM lucy.memory_claims c
              WHERE c.evidence_id IN (
                SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                WHERE operation_id=v_operation_id
              ) OR c.id IN (
                SELECT claim_id FROM lucy.claim_sources WHERE evidence_id IN (
                  SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                  WHERE operation_id=v_operation_id
                )
              )
            UNION
            SELECT c.id FROM lucy.memory_claims c JOIN affected_claims a
              ON c.supersedes_claim_id=a.id
          )
          UPDATE lucy.memory_relationships r SET predicate='[redacted]',
            valid_to=coalesce(r.valid_to,v_now)
            WHERE r.evidence_id IN (
              SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
              WHERE operation_id=v_operation_id
            ) OR r.claim_id IN (SELECT id FROM affected_claims);
          GET DIAGNOSTICS v_relationships = ROW_COUNT;

          WITH affected_entities(id) AS (
            SELECT subject_entity_id FROM lucy.memory_relationships r
              WHERE r.predicate='[redacted]' AND (
                r.evidence_id IN (
                  SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                  WHERE operation_id=v_operation_id
                ) OR EXISTS (
                  SELECT 1 FROM lucy.memory_claims c
                  WHERE c.id=r.claim_id AND c.status='invalidated'
                )
              )
            UNION
            SELECT object_entity_id FROM lucy.memory_relationships r
              WHERE r.predicate='[redacted]' AND (
                r.evidence_id IN (
                  SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                  WHERE operation_id=v_operation_id
                ) OR EXISTS (
                  SELECT 1 FROM lucy.memory_claims c
                  WHERE c.id=r.claim_id AND c.status='invalidated'
                )
              )
          )
          UPDATE lucy.memory_entities e SET canonical_name='[redacted]:' || e.id::text,
            version=e.version+1 WHERE e.id IN (SELECT id FROM affected_entities)
            AND NOT EXISTS (
              SELECT 1 FROM lucy.memory_relationships r JOIN lucy.memory_claims c ON c.id=r.claim_id
              WHERE (r.subject_entity_id=e.id OR r.object_entity_id=e.id)
                AND c.status <> 'invalidated'
            );
          GET DIAGNOSTICS v_entities = ROW_COUNT;

          WITH RECURSIVE affected_claims(id) AS (
            SELECT c.id FROM lucy.memory_claims c
              WHERE c.evidence_id IN (
                SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                WHERE operation_id=v_operation_id
              ) OR c.id IN (
                SELECT claim_id FROM lucy.claim_sources WHERE evidence_id IN (
                  SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                  WHERE operation_id=v_operation_id
                )
              )
            UNION
            SELECT c.id FROM lucy.memory_claims c JOIN affected_claims a
              ON c.supersedes_claim_id=a.id
          )
          UPDATE lucy.memory_write_proposals p
            SET subject='[redacted]',predicate='[redacted]',object='[redacted]',status='rejected'
            WHERE p.evidence_id IN (
              SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
              WHERE operation_id=v_operation_id
            ) OR p.claim_id IN (SELECT id FROM affected_claims) OR p.id IN (
              SELECT proposal_id FROM lucy.proposal_sources WHERE evidence_id IN (
                SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                WHERE operation_id=v_operation_id
              )
            );
          GET DIAGNOSTICS v_proposals = ROW_COUNT;

          WITH RECURSIVE affected_claims(id) AS (
            SELECT c.id FROM lucy.memory_claims c
              WHERE c.evidence_id IN (
                SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                WHERE operation_id=v_operation_id
              ) OR c.id IN (
                SELECT claim_id FROM lucy.claim_sources WHERE evidence_id IN (
                  SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                  WHERE operation_id=v_operation_id
                )
              )
            UNION
            SELECT c.id FROM lucy.memory_claims c JOIN affected_claims a
              ON c.supersedes_claim_id=a.id
          )
          UPDATE lucy.memory_corrections c SET replacement_object='[redacted]',status='rejected'
            WHERE c.new_evidence_id IN (
              SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
              WHERE operation_id=v_operation_id
            ) OR c.old_claim_id IN (SELECT id FROM affected_claims)
              OR c.new_claim_id IN (SELECT id FROM affected_claims) OR c.id IN (
              SELECT correction_id FROM lucy.correction_sources WHERE evidence_id IN (
                SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
                WHERE operation_id=v_operation_id
              )
            );
          GET DIAGNOSTICS v_corrections = ROW_COUNT;

          UPDATE lucy.approval_requests a SET action_payload=jsonb_build_object('redacted',true),
            status=CASE WHEN a.status='pending' THEN 'denied' ELSE a.status END,
            decided_at=CASE WHEN a.status='pending' THEN v_now ELSE a.decided_at END,
            decided_by=CASE WHEN a.status='pending' THEN 'authorized-deletion-recovery'
                            ELSE a.decided_by END,
            actor_type=CASE WHEN a.status='pending' THEN 'human_owner' ELSE a.actor_type END,
            decision_reason='source_evidence_deleted',
            version=CASE WHEN a.status='pending' THEN a.version+1 ELSE a.version END
            WHERE a.id IN (
              SELECT approval_id FROM lucy.memory_write_proposals
                WHERE status='rejected' AND subject='[redacted]'
              UNION
              SELECT approval_id FROM lucy.memory_corrections
                WHERE status='rejected' AND replacement_object='[redacted]'
            );

          DELETE FROM lucy.working_contexts;
          GET DIAGNOSTICS v_contexts = ROW_COUNT;
          UPDATE lucy.conversation_turns t SET status='redacted',updated_at=v_now
            WHERE t.user_evidence_id IN (
              SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
              WHERE operation_id=v_operation_id
            ) OR t.assistant_evidence_id IN (
              SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
              WHERE operation_id=v_operation_id
            );
          GET DIAGNOSTICS v_turns = ROW_COUNT;
          DELETE FROM lucy.evidence_payloads p WHERE p.evidence_id IN (
            SELECT evidence_id FROM lucy.authorized_deletion_recovery_targets_v1
            WHERE operation_id=v_operation_id
          );
          GET DIAGNOSTICS v_payloads = ROW_COUNT;
          IF v_payloads <> v_target_count THEN
            RAISE EXCEPTION 'authorized deletion recovery payload cardinality changed';
          END IF;

          v_summary := jsonb_build_object(
            'claims_invalidated',v_claims,'relationships_invalidated',v_relationships,
            'proposals_rejected',v_proposals,'corrections_rejected',v_corrections,
            'entities_redacted',v_entities,'working_contexts_purged',v_contexts,
            'turns_redacted',v_turns,'evidence_records_deleted',v_payloads
          );
          INSERT INTO lucy.evidence_tombstones(
            evidence_id,deletion_operation_id,reason_category,deleted_at,derived_summary
          ) SELECT evidence_id,v_operation_id,v_reason,v_now,v_summary
              FROM lucy.authorized_deletion_recovery_targets_v1
              WHERE operation_id=v_operation_id;
          UPDATE lucy.authorized_deletion_recoveries_v1
            SET derived_summary=v_summary WHERE operation_id=v_operation_id;
          PERFORM lucy.append_sensitive_event_v1(
            v_operation_id,'sensitive.authorized_deletion_recovered',
            jsonb_build_object('manifest_id',v_manifest_id,
                               'receipt_digest',p_recovery->>'receipt_digest',
                               'recovery_digest',p_recovery->>'recovery_digest',
                               'target_count',v_target_count,
                               'finality_not_before',v_completed_at+interval '30 days')
          );
          RETURN jsonb_build_object('state','FINALITY_PENDING','replayed',false,
                                    'derived_summary',v_summary);
        END
        $function$;
        ALTER FUNCTION lucy.apply_authorized_deletion_recovery_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.apply_authorized_deletion_recovery_v1(jsonb)
          FROM PUBLIC, lucy_app;
        GRANT EXECUTE ON FUNCTION lucy.apply_authorized_deletion_recovery_v1(jsonb)
          TO lucy_migration;
        """
    )
    op.execute("REVOKE CREATE ON SCHEMA lucy FROM lucy_security_function_owner")


def downgrade() -> None:
    raise RuntimeError(
        "Authorized deletion recovery is durable security authority; "
        "use a reviewed forward migration"
    )
