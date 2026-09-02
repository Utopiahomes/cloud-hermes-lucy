"""Install receipt-only reconciliation, deletion cascade, delivery, and finality gates."""

from collections.abc import Sequence

from alembic import op

revision: str = "0019_security_v1_2_reconcile"
down_revision: str | None = "0018_security_v1_2_gates"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _secure(signature: str) -> None:
    op.execute(
        f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
        f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
    )


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.reconcile_evidence_retrieval_v1(p_operation_id uuid) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation lucy.sensitive_operations_v1%ROWTYPE;
          v_attestation lucy.executor_receipt_attestations_v1%ROWTYPE;
          v_now timestamptz := clock_timestamp();
        BEGIN
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v1
            WHERE id=p_operation_id FOR UPDATE;
          IF v_operation.action <> 'evidence.retrieve'
             OR v_operation.caller_session_user <> session_user THEN
            RAISE EXCEPTION 'retrieval reconciliation identity mismatch';
          END IF;
          IF v_operation.state IN (
            'EXECUTOR_RECEIPTED','DELIVERY_CONFIRMED','DELIVERY_UNKNOWN'
          ) THEN
            RETURN v_operation.state;
          END IF;
          IF v_operation.state <> 'EXECUTING' THEN
            RAISE EXCEPTION 'retrieval operation is not reconcilable';
          END IF;
          SELECT * INTO STRICT v_attestation FROM lucy.executor_receipt_attestations_v1
            WHERE operation_id=p_operation_id;
          IF v_attestation.receipt_digest <> v_operation.executor_receipt_digest THEN
            RAISE EXCEPTION 'policy receipt attestation digest mismatch';
          END IF;
          IF v_attestation.result = 'rejected' THEN
            UPDATE lucy.sensitive_operations_v1
              SET state='FAILED_FINAL',updated_at=v_now WHERE id=p_operation_id;
            UPDATE lucy.operations SET outcome='failed',completed_at=v_now,
              result=jsonb_build_object('state','FAILED_FINAL') WHERE id=p_operation_id;
            PERFORM lucy.append_sensitive_event_v1(
              p_operation_id,'sensitive.retrieval_failed_final',
              jsonb_build_object('receipt_digest',v_attestation.receipt_digest)
            );
            RETURN 'FAILED_FINAL';
          END IF;
          IF v_attestation.result NOT IN ('retrieval_succeeded','idempotent_replay') THEN
            RAISE EXCEPTION 'receipt result cannot reconcile retrieval';
          END IF;
          UPDATE lucy.sensitive_operations_v1
            SET state='EXECUTOR_RECEIPTED',updated_at=v_now WHERE id=p_operation_id;
          PERFORM lucy.append_sensitive_event_v1(
            p_operation_id,'sensitive.retrieval_executor_receipted',
            jsonb_build_object('receipt_digest',v_attestation.receipt_digest)
          );
          RETURN 'EXECUTOR_RECEIPTED';
        END
        $function$
        """
    )
    _secure("lucy.reconcile_evidence_retrieval_v1(uuid)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.record_evidence_delivery_v1(
          p_operation_id uuid, p_transport_outcome text
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation lucy.sensitive_operations_v1%ROWTYPE;
          v_target text;
        BEGIN
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v1
            WHERE id=p_operation_id FOR UPDATE;
          IF v_operation.action <> 'evidence.retrieve'
             OR v_operation.caller_session_user <> session_user THEN
            RAISE EXCEPTION 'retrieval delivery identity mismatch';
          END IF;
          v_target := CASE p_transport_outcome
            WHEN 'accepted' THEN 'DELIVERY_CONFIRMED'
            WHEN 'unknown' THEN 'DELIVERY_UNKNOWN'
            ELSE NULL
          END;
          IF v_target IS NULL THEN RAISE EXCEPTION 'unsupported delivery outcome'; END IF;
          IF v_operation.state = v_target THEN RETURN v_target; END IF;
          IF v_operation.state <> 'EXECUTOR_RECEIPTED' THEN
            RAISE EXCEPTION 'retrieval delivery is not recordable';
          END IF;
          UPDATE lucy.sensitive_operations_v1
            SET state=v_target,updated_at=clock_timestamp() WHERE id=p_operation_id;
          UPDATE lucy.operations SET outcome='succeeded',completed_at=clock_timestamp(),
            result=jsonb_build_object('state',v_target) WHERE id=p_operation_id;
          PERFORM lucy.append_sensitive_event_v1(
            p_operation_id,'sensitive.retrieval_delivery_recorded',
            jsonb_build_object('transport_outcome',p_transport_outcome,'state',v_target)
          );
          RETURN v_target;
        END
        $function$
        """
    )
    _secure("lucy.record_evidence_delivery_v1(uuid,text)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.reconcile_evidence_deletion_v1(p_operation_id uuid) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation lucy.sensitive_operations_v1%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v2%ROWTYPE;
          v_attestation lucy.executor_receipt_attestations_v1%ROWTYPE;
          v_now timestamptz := clock_timestamp();
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
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v1
            WHERE id=p_operation_id FOR UPDATE;
          IF v_operation.action <> 'evidence.delete'
             OR v_operation.caller_session_user <> session_user THEN
            RAISE EXCEPTION 'deletion reconciliation identity mismatch';
          END IF;
          IF v_operation.state IN ('EFFECTIVE','FINALITY_PENDING','FINALITY_EXTENDED',
                                   'FINALITY_VERIFIED') THEN
            SELECT derived_summary INTO v_summary FROM lucy.evidence_tombstones
              WHERE deletion_operation_id=p_operation_id LIMIT 1;
            RETURN jsonb_build_object('state',v_operation.state,'derived_summary',v_summary,
                                      'replayed',true);
          END IF;
          IF v_operation.state <> 'EXECUTING' THEN
            RAISE EXCEPTION 'deletion operation is not reconcilable';
          END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v2
            WHERE id=v_operation.permit_id;
          SELECT * INTO STRICT v_attestation FROM lucy.executor_receipt_attestations_v1
            WHERE operation_id=p_operation_id;
          IF v_attestation.receipt_digest <> v_operation.executor_receipt_digest THEN
            RAISE EXCEPTION 'policy receipt attestation digest mismatch';
          END IF;
          IF v_attestation.result = 'rejected' THEN
            UPDATE lucy.sensitive_operations_v1
              SET state='FAILED_FINAL',updated_at=v_now WHERE id=p_operation_id;
            UPDATE lucy.operations SET outcome='failed',completed_at=v_now,
              result=jsonb_build_object('state','FAILED_FINAL') WHERE id=p_operation_id;
            PERFORM lucy.append_sensitive_event_v1(
              p_operation_id,'sensitive.deletion_failed_final',
              jsonb_build_object('receipt_digest',v_attestation.receipt_digest)
            );
            RETURN jsonb_build_object('state','FAILED_FINAL','replayed',false);
          END IF;
          IF v_attestation.result NOT IN ('deletion_succeeded','idempotent_replay') THEN
            RAISE EXCEPTION 'receipt result cannot reconcile deletion';
          END IF;
          UPDATE lucy.sensitive_operations_v1
            SET state='EXECUTOR_RECEIPTED',updated_at=v_now WHERE id=p_operation_id;

          WITH RECURSIVE affected_claims(id) AS (
            SELECT c.id FROM lucy.memory_claims c
              WHERE c.evidence_id IN (
                SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                WHERE manifest_id=v_operation.manifest_id
              )
                 OR c.id IN (
                   SELECT s.claim_id FROM lucy.claim_sources s
                   WHERE s.evidence_id IN (
                     SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                     WHERE manifest_id=v_operation.manifest_id
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
                SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                WHERE manifest_id=v_operation.manifest_id
              ) OR c.id IN (
                SELECT claim_id FROM lucy.claim_sources WHERE evidence_id IN (
                  SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                  WHERE manifest_id=v_operation.manifest_id
                )
              )
            UNION
            SELECT c.id FROM lucy.memory_claims c JOIN affected_claims a
              ON c.supersedes_claim_id=a.id
          )
          UPDATE lucy.memory_relationships r
            SET predicate='[redacted]',valid_to=coalesce(r.valid_to,v_now)
            WHERE r.evidence_id IN (
              SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
              WHERE manifest_id=v_operation.manifest_id
            ) OR r.claim_id IN (SELECT id FROM affected_claims);
          GET DIAGNOSTICS v_relationships = ROW_COUNT;

          WITH affected_entities(id) AS (
            SELECT subject_entity_id FROM lucy.memory_relationships r
              WHERE r.predicate='[redacted]' AND (
                r.evidence_id IN (SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                                  WHERE manifest_id=v_operation.manifest_id)
                OR EXISTS (SELECT 1 FROM lucy.memory_claims c
                           WHERE c.id=r.claim_id AND c.status='invalidated')
              )
            UNION
            SELECT object_entity_id FROM lucy.memory_relationships r
              WHERE r.predicate='[redacted]' AND (
                r.evidence_id IN (SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                                  WHERE manifest_id=v_operation.manifest_id)
                OR EXISTS (SELECT 1 FROM lucy.memory_claims c
                           WHERE c.id=r.claim_id AND c.status='invalidated')
              )
          )
          UPDATE lucy.memory_entities e
            SET canonical_name='[redacted]:' || e.id::text,version=e.version+1
            WHERE e.id IN (SELECT id FROM affected_entities)
              AND NOT EXISTS (
                SELECT 1 FROM lucy.memory_relationships r
                JOIN lucy.memory_claims c ON c.id=r.claim_id
                WHERE (r.subject_entity_id=e.id OR r.object_entity_id=e.id)
                  AND c.status <> 'invalidated'
              );
          GET DIAGNOSTICS v_entities = ROW_COUNT;

          WITH RECURSIVE affected_claims(id) AS (
            SELECT id FROM lucy.memory_claims WHERE status='invalidated'
            UNION
            SELECT c.id FROM lucy.memory_claims c JOIN affected_claims a
              ON c.supersedes_claim_id=a.id
          )
          UPDATE lucy.memory_write_proposals p
            SET subject='[redacted]',predicate='[redacted]',object='[redacted]',status='rejected'
            WHERE p.evidence_id IN (
              SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
              WHERE manifest_id=v_operation.manifest_id
            ) OR p.claim_id IN (SELECT id FROM affected_claims)
              OR p.id IN (
                SELECT proposal_id FROM lucy.proposal_sources WHERE evidence_id IN (
                  SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                  WHERE manifest_id=v_operation.manifest_id
                )
              );
          GET DIAGNOSTICS v_proposals = ROW_COUNT;

          UPDATE lucy.memory_corrections c
            SET replacement_object='[redacted]',status='rejected'
            WHERE c.new_evidence_id IN (
              SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
              WHERE manifest_id=v_operation.manifest_id
            ) OR EXISTS (SELECT 1 FROM lucy.memory_claims x
                         WHERE x.id IN (c.old_claim_id,c.new_claim_id) AND x.status='invalidated')
              OR c.id IN (
                SELECT correction_id FROM lucy.correction_sources WHERE evidence_id IN (
                  SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
                  WHERE manifest_id=v_operation.manifest_id
                )
              );
          GET DIAGNOSTICS v_corrections = ROW_COUNT;

          UPDATE lucy.approval_requests a
            SET action_payload=jsonb_build_object('redacted',true),
                status=CASE WHEN a.status='pending' THEN 'denied' ELSE a.status END,
                decided_at=CASE WHEN a.status='pending' THEN v_now ELSE a.decided_at END,
                decided_by=CASE WHEN a.status='pending' THEN 'owner-evidence-deletion'
                                ELSE a.decided_by END,
                actor_type=CASE WHEN a.status='pending' THEN 'human_owner' ELSE a.actor_type END,
                decision_reason='source_evidence_deleted',
                version=CASE WHEN a.status='pending' THEN a.version+1 ELSE a.version END
            WHERE a.id IN (
              SELECT approval_id FROM lucy.memory_write_proposals p
              WHERE p.status='rejected' AND p.subject='[redacted]'
              UNION
              SELECT approval_id FROM lucy.memory_corrections c
              WHERE c.status='rejected' AND c.replacement_object='[redacted]'
            );

          DELETE FROM lucy.working_contexts;
          GET DIAGNOSTICS v_contexts = ROW_COUNT;
          UPDATE lucy.conversation_turns t SET status='redacted',updated_at=v_now
            WHERE t.user_evidence_id IN (
              SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
              WHERE manifest_id=v_operation.manifest_id
            ) OR t.assistant_evidence_id IN (
              SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
              WHERE manifest_id=v_operation.manifest_id
            );
          GET DIAGNOSTICS v_turns = ROW_COUNT;
          DELETE FROM lucy.evidence_payloads p WHERE p.evidence_id IN (
            SELECT evidence_id FROM lucy.deletion_manifest_targets_v1
            WHERE manifest_id=v_operation.manifest_id
          );
          GET DIAGNOSTICS v_payloads = ROW_COUNT;

          v_summary := jsonb_build_object(
            'claims_invalidated',v_claims,'relationships_invalidated',v_relationships,
            'proposals_rejected',v_proposals,'corrections_rejected',v_corrections,
            'entities_redacted',v_entities,'working_contexts_purged',v_contexts,
            'turns_redacted',v_turns,'evidence_records_deleted',v_payloads
          );
          INSERT INTO lucy.evidence_tombstones(
            evidence_id,deletion_operation_id,reason_category,deleted_at,derived_summary
          ) SELECT evidence_id,p_operation_id,v_permit.reason,v_now,v_summary
              FROM lucy.deletion_manifest_targets_v1 WHERE manifest_id=v_operation.manifest_id
            ON CONFLICT (evidence_id) DO NOTHING;
          UPDATE lucy.evidence_deletion_fences_v1
            SET state='EFFECTIVE',effective_at=v_now WHERE operation_id=p_operation_id;
          INSERT INTO lucy.deletion_finality_v1(
            operation_id,deletion_effective_at,finality_not_before,finality_status
          ) VALUES (p_operation_id,v_now,v_now+interval '30 days','PENDING');
          UPDATE lucy.sensitive_operations_v1
            SET state='FINALITY_PENDING',updated_at=v_now WHERE id=p_operation_id;
          UPDATE lucy.operations SET outcome='succeeded',completed_at=v_now,
            result=jsonb_build_object('state','FINALITY_PENDING','derived_summary',v_summary)
            WHERE id=p_operation_id;
          PERFORM lucy.append_sensitive_event_v1(
            p_operation_id,'sensitive.deletion_effective',
            jsonb_build_object('receipt_digest',v_attestation.receipt_digest,
                               'manifest_id',v_operation.manifest_id,
                               'derived_summary',v_summary,
                               'finality_not_before',v_now+interval '30 days')
          );
          RETURN jsonb_build_object('state','FINALITY_PENDING','derived_summary',v_summary,
                                    'replayed',false);
        END
        $function$
        """
    )
    _secure("lucy.reconcile_evidence_deletion_v1(uuid)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.record_finality_verification_v1(
          p_operation_id uuid, p_metadata jsonb
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation lucy.sensitive_operations_v1%ROWTYPE;
          v_finality lucy.deletion_finality_v1%ROWTYPE;
          v_status text;
          v_observed_at timestamptz;
          v_verified_at timestamptz;
          v_pitr_status text;
          v_pitr_days integer;
          v_pitr_earliest timestamptz;
          v_pitr_latest timestamptz;
          v_exceptional_earliest timestamptz;
          v_exceptional_latest timestamptz;
          v_exceptional_count integer;
          v_stream_enabled boolean;
          v_earliest timestamptz;
          v_latest timestamptz;
          v_count integer;
          v_digest text;
        BEGIN
          IF jsonb_typeof(p_metadata) <> 'object'
             OR p_metadata - ARRAY[
               'contract_version','object_type','operation_id','metadata_observed_at',
               'pitr_status','pitr_recovery_period_days',
               'pitr_earliest_restorable_at','pitr_latest_restorable_at',
               'on_demand_backup_count','aws_backup_recovery_point_count',
               'export_count','import_count','global_replica_count',
               'quarantine_table_count','stream_enabled',
               'exceptional_earliest_restorable_at',
               'exceptional_latest_restorable_at','metadata_inventory_digest'
             ] <> '{}'::jsonb
             OR NOT (p_metadata ?& ARRAY[
               'contract_version','object_type','operation_id','metadata_observed_at',
               'pitr_status','pitr_recovery_period_days',
               'pitr_earliest_restorable_at','pitr_latest_restorable_at',
               'on_demand_backup_count','aws_backup_recovery_point_count',
               'export_count','import_count','global_replica_count',
               'quarantine_table_count','stream_enabled',
               'exceptional_earliest_restorable_at',
               'exceptional_latest_restorable_at','metadata_inventory_digest'
             ]) THEN
            RAISE EXCEPTION 'finality metadata contract contains unknown fields';
          END IF;
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v1
            WHERE id=p_operation_id FOR UPDATE;
          SELECT * INTO STRICT v_finality FROM lucy.deletion_finality_v1
            WHERE operation_id=p_operation_id FOR UPDATE;
          IF v_operation.action <> 'evidence.delete'
             OR v_operation.state NOT IN ('FINALITY_PENDING','FINALITY_EXTENDED')
             OR p_metadata->>'contract_version' <> '1'
             OR p_metadata->>'object_type' <> 'lucy.deletion-recovery-inventory.v1'
             OR p_metadata->>'operation_id' <> p_operation_id::text THEN
            RAISE EXCEPTION 'finality operation is not verifiable';
          END IF;
          v_observed_at := (p_metadata->>'metadata_observed_at')::timestamptz;
          v_pitr_status := p_metadata->>'pitr_status';
          v_pitr_days := nullif(p_metadata->>'pitr_recovery_period_days','')::int;
          v_pitr_earliest := nullif(
            p_metadata->>'pitr_earliest_restorable_at',''
          )::timestamptz;
          v_pitr_latest := nullif(
            p_metadata->>'pitr_latest_restorable_at',''
          )::timestamptz;
          v_exceptional_earliest := nullif(
            p_metadata->>'exceptional_earliest_restorable_at',''
          )::timestamptz;
          v_exceptional_latest := nullif(
            p_metadata->>'exceptional_latest_restorable_at',''
          )::timestamptz;
          v_exceptional_count :=
              (p_metadata->>'on_demand_backup_count')::int
            + (p_metadata->>'aws_backup_recovery_point_count')::int
            + (p_metadata->>'export_count')::int
            + (p_metadata->>'import_count')::int
            + (p_metadata->>'global_replica_count')::int
            + (p_metadata->>'quarantine_table_count')::int;
          v_stream_enabled := (p_metadata->>'stream_enabled')::boolean;
          v_digest := p_metadata->>'metadata_inventory_digest';
          IF v_observed_at IS NULL OR v_observed_at < v_finality.deletion_effective_at
             OR v_observed_at > clock_timestamp() + interval '5 minutes'
             OR (v_finality.metadata_observed_at IS NOT NULL
                 AND v_observed_at < v_finality.metadata_observed_at)
             OR v_exceptional_count IS NULL OR v_exceptional_count < 0
             OR v_stream_enabled IS NULL
             OR v_digest IS NULL OR v_digest !~ '^[0-9a-f]{64}$'
             OR v_pitr_status IS NULL OR v_pitr_status NOT IN ('ENABLED','DISABLED')
             OR (v_pitr_status = 'ENABLED' AND
                 (v_pitr_days IS NULL OR v_pitr_earliest IS NULL OR v_pitr_latest IS NULL))
             OR (v_pitr_status = 'DISABLED' AND
                 (v_pitr_days IS NOT NULL OR v_pitr_earliest IS NOT NULL
                  OR v_pitr_latest IS NOT NULL))
             OR (v_pitr_earliest IS NOT NULL AND v_pitr_latest IS NOT NULL
                 AND v_pitr_earliest > v_pitr_latest)
             OR (v_exceptional_earliest IS NOT NULL AND v_exceptional_latest IS NOT NULL
                 AND v_exceptional_earliest > v_exceptional_latest)
             OR (v_exceptional_count = 0 AND
                 (v_exceptional_earliest IS NOT NULL OR v_exceptional_latest IS NOT NULL)) THEN
            RAISE EXCEPTION 'finality metadata is not monotonic';
          END IF;
          v_count := v_exceptional_count + CASE WHEN v_stream_enabled THEN 1 ELSE 0 END;
          IF v_pitr_status <> 'ENABLED' OR v_pitr_days <> 30 THEN
            v_count := v_count + 1;
          ELSIF v_pitr_earliest <= v_finality.deletion_effective_at THEN
            v_count := v_count + 1;
            v_earliest := v_pitr_earliest;
            v_latest := v_pitr_latest;
          END IF;
          IF v_exceptional_count > 0 THEN
            v_earliest := CASE
              WHEN v_earliest IS NULL THEN v_exceptional_earliest
              WHEN v_exceptional_earliest IS NULL THEN v_earliest
              ELSE least(v_earliest,v_exceptional_earliest)
            END;
            v_latest := CASE
              WHEN v_latest IS NULL THEN v_exceptional_latest
              WHEN v_exceptional_latest IS NULL THEN v_latest
              ELSE greatest(v_latest,v_exceptional_latest)
            END;
          END IF;
          IF v_observed_at >= v_finality.finality_not_before AND v_count = 0 THEN
            v_status := 'VERIFIED';
            v_verified_at := v_observed_at;
            v_earliest := NULL;
            v_latest := NULL;
          ELSE
            v_status := 'EXTENDED';
            v_verified_at := NULL;
          END IF;
          UPDATE lucy.deletion_finality_v1
            SET finality_verified_at=v_verified_at,finality_status=v_status,
                metadata_observed_at=v_observed_at,earliest_restorable_at=v_earliest,
                latest_restorable_at=v_latest,recoverable_copy_count=v_count,
                metadata_inventory_digest=v_digest,
                finality_not_before=CASE
                  WHEN v_exceptional_latest IS NOT NULL
                  THEN greatest(finality_not_before,v_exceptional_latest)
                  ELSE finality_not_before
                END
            WHERE operation_id=p_operation_id;
          UPDATE lucy.sensitive_operations_v1
            SET state=CASE v_status WHEN 'VERIFIED' THEN 'FINALITY_VERIFIED'
                                    ELSE 'FINALITY_EXTENDED' END,
                updated_at=clock_timestamp()
            WHERE id=p_operation_id;
          PERFORM lucy.append_sensitive_event_v1(
            p_operation_id,'sensitive.deletion_finality_recorded',
            jsonb_build_object('finality_status',v_status,'metadata_observed_at',v_observed_at,
                               'metadata_inventory_digest',v_digest,
                               'recoverable_copy_count',v_count)
          );
          RETURN v_status;
        END
        $function$
        """
    )
    _secure("lucy.record_finality_verification_v1(uuid,jsonb)")

    op.execute("REVOKE CREATE ON SCHEMA lucy FROM lucy_security_function_owner")
    op.execute("UPDATE lucy.runtime_admission SET state='quarantined', updated_at=now()")


def downgrade() -> None:
    raise RuntimeError("v1.2 reconciliation and finality require a reviewed forward migration")
