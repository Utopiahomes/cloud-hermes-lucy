"""Install hardened v1.2 issue, scope, claim, notary, and attestation gates."""

from collections.abc import Sequence

from alembic import op

revision: str = "0018_security_v1_2_gates"
down_revision: str | None = "0017_security_v1_2_state"
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
        CREATE FUNCTION lucy.canonical_jsonb_v1(p_value jsonb) RETURNS text
        LANGUAGE plpgsql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_kind text;
          v_result text;
        BEGIN
          v_kind := jsonb_typeof(p_value);
          IF v_kind = 'object' THEN
            SELECT '{' || coalesce(
              string_agg(to_jsonb(e.key)::text || ':' || lucy.canonical_jsonb_v1(e.value),
                         ',' ORDER BY e.key COLLATE "C"), '') || '}'
              INTO v_result
              FROM jsonb_each(p_value) AS e(key, value);
            RETURN v_result;
          ELSIF v_kind = 'array' THEN
            SELECT '[' || coalesce(
              string_agg(lucy.canonical_jsonb_v1(a.value), ',' ORDER BY a.ordinality), '') || ']'
              INTO v_result
              FROM jsonb_array_elements(p_value) WITH ORDINALITY AS a(value, ordinality);
            RETURN v_result;
          ELSIF v_kind IN ('string','number','boolean','null') THEN
            RETURN p_value::text;
          END IF;
          RAISE EXCEPTION 'unsupported canonical JSON type';
        END
        $function$
        """
    )
    _secure("lucy.canonical_jsonb_v1(jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.normalize_security_contract_v1(p_contract jsonb) RETURNS jsonb
        LANGUAGE plpgsql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_result jsonb := p_contract;
          v_name text;
          v_timestamp timestamptz;
        BEGIN
          FOREACH v_name IN ARRAY ARRAY[
            'issued_at','interaction_created_at','expires_at','permit_claim_deadline',
            'execution_deadline','completed_at'
          ] LOOP
            IF v_result ? v_name THEN
              IF jsonb_typeof(v_result->v_name) <> 'string' THEN
                RAISE EXCEPTION 'canonical contract timestamp must be a string';
              END IF;
              v_timestamp := (v_result->>v_name)::timestamptz;
              v_result := jsonb_set(
                v_result,
                ARRAY[v_name],
                to_jsonb(to_char(v_timestamp AT TIME ZONE 'UTC',
                                 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
              );
            END IF;
          END LOOP;
          RETURN v_result;
        END
        $function$
        """
    )
    _secure("lucy.normalize_security_contract_v1(jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.security_contract_digest_v1(p_contract jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT encode(
            public.digest(
              convert_to('LUCY-SIGNED-CONTRACT','UTF8') || decode('00','hex') ||
              convert_to(lucy.canonical_jsonb_v1(
                lucy.normalize_security_contract_v1(p_contract) - 'signature'
              ),'UTF8'),
              'sha256'
            ),
            'hex'
          )
        $function$
        """
    )
    _secure("lucy.security_contract_digest_v1(jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.package_digest_v1(p_package jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT encode(
            public.digest(
              convert_to('LUCY-ENCRYPTED-EVIDENCE-PACKAGE-V1','UTF8') || decode('00','hex') ||
              convert_to(lucy.canonical_jsonb_v1(p_package),'UTF8'),
              'sha256'
            ),
            'hex'
          )
        $function$
        """
    )
    _secure("lucy.package_digest_v1(jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.deletion_targets_digest_v1(p_targets jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT encode(
            public.digest(
              convert_to('LUCY-DELETION-TARGETS-V1','UTF8') || decode('00','hex') ||
              convert_to(lucy.canonical_jsonb_v1(p_targets),'UTF8'),
              'sha256'
            ),
            'hex'
          )
        $function$
        """
    )
    _secure("lucy.deletion_targets_digest_v1(jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.append_sensitive_event_v1(
          p_operation_id uuid, p_event_type text, p_details jsonb
        ) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF p_event_type !~ '^[a-z0-9_.]{3,100}$' OR jsonb_typeof(p_details) <> 'object' THEN
            RAISE EXCEPTION 'invalid sensitive-operation event';
          END IF;
          INSERT INTO lucy.sensitive_operation_events_v1(
            event_id, operation_id, event_type, occurred_at, details
          ) VALUES (gen_random_uuid(), p_operation_id, p_event_type, clock_timestamp(), p_details);
        END
        $function$
        """
    )
    _secure("lucy.append_sensitive_event_v1(uuid,text,jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.issue_sensitive_action_permit_v2(
          p_assertion jsonb,
          p_permit jsonb,
          p_issuance_idempotency_key text
        ) RETURNS uuid
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_now timestamptz := clock_timestamp();
          v_assertion_id uuid;
          v_permit_id uuid;
          v_evidence_id uuid;
          v_assertion_digest text;
          v_permit_digest text;
          v_action text;
          v_reason text;
          v_issued_at timestamptz;
          v_assertion_expires timestamptz;
          v_claim_deadline timestamptz;
          v_operation_id uuid;
          v_epochs lucy.security_contract_epochs%ROWTYPE;
          v_existing lucy.sensitive_action_permits_v2%ROWTYPE;
        BEGIN
          IF p_issuance_idempotency_key IS NULL
             OR length(p_issuance_idempotency_key) NOT BETWEEN 1 AND 512 THEN
            RAISE EXCEPTION 'invalid permit issuance idempotency key';
          END IF;
          IF jsonb_typeof(p_assertion) <> 'object' OR jsonb_typeof(p_permit) <> 'object' THEN
            RAISE EXCEPTION 'signed authorization contracts must be JSON objects';
          END IF;
          IF p_assertion - ARRAY[
            'canonicalization_version','signature_algorithm','key_id','issuer','environment',
            'issued_at','storage_epoch','registry_epoch','key_epoch','signature',
            'contract_version','object_type','assertion_id','broker_identity','channel',
            'owner_subject','source_interaction_id','source_message_id','requested_action',
            'evidence_id','authentication_method','interaction_created_at','max_age_seconds',
            'expires_at','nonce','anti_replay_id'
          ] <> '{}'::jsonb THEN
            RAISE EXCEPTION 'owner assertion contains unknown fields';
          END IF;
          IF p_permit - ARRAY[
            'canonicalization_version','signature_algorithm','key_id','issuer','environment',
            'issued_at','storage_epoch','registry_epoch','key_epoch','signature',
            'contract_version','object_type','permit_id','action','owner_subject',
            'owner_assertion_id','owner_assertion_digest','evidence_id','reason','max_records',
            'max_bytes','record_version','permit_claim_deadline','nonce'
          ] <> '{}'::jsonb THEN
            RAISE EXCEPTION 'V2 permit contains unknown fields';
          END IF;
          IF p_assertion->>'contract_version' <> '1'
             OR p_assertion->>'object_type' <> 'lucy.owner-interaction-assertion.v1'
             OR p_assertion->>'canonicalization_version' <> 'lucy-cjson-1'
             OR p_assertion->>'signature_algorithm' <> 'Ed25519'
             OR coalesce(p_assertion->>'signature','') = '' THEN
            RAISE EXCEPTION 'invalid owner assertion contract domain';
          END IF;
          IF p_permit->>'contract_version' <> '2'
             OR p_permit->>'object_type' <> 'lucy.sensitive-action-permit.v2'
             OR p_permit->>'canonicalization_version' <> 'lucy-cjson-1'
             OR p_permit->>'signature_algorithm' <> 'Ed25519'
             OR coalesce(p_permit->>'signature','') = '' THEN
            RAISE EXCEPTION 'invalid V2 permit contract domain';
          END IF;

          v_assertion_id := (p_assertion->>'assertion_id')::uuid;
          v_permit_id := (p_permit->>'permit_id')::uuid;
          v_evidence_id := (p_permit->>'evidence_id')::uuid;
          v_action := p_permit->>'action';
          v_reason := p_permit->>'reason';
          v_issued_at := (p_permit->>'issued_at')::timestamptz;
          v_assertion_expires := (p_assertion->>'expires_at')::timestamptz;
          v_claim_deadline := (p_permit->>'permit_claim_deadline')::timestamptz;
          v_assertion_digest := lucy.security_contract_digest_v1(p_assertion);
          v_permit_digest := lucy.security_contract_digest_v1(p_permit);
          SELECT * INTO STRICT v_epochs FROM lucy.security_contract_epochs WHERE singleton;

          IF p_permit->>'owner_assertion_id' <> v_assertion_id::text
             OR p_permit->>'owner_assertion_digest' <> v_assertion_digest
             OR p_permit->>'owner_subject' <> p_assertion->>'owner_subject'
             OR p_permit->>'action' <> p_assertion->>'requested_action'
             OR (p_assertion->>'evidence_id' IS NOT NULL
                 AND p_assertion->>'evidence_id' <> v_evidence_id::text) THEN
            RAISE EXCEPTION 'owner assertion and permit bindings differ';
          END IF;
          IF p_assertion->>'environment' <> p_permit->>'environment'
             OR (p_assertion->>'storage_epoch')::bigint <> v_epochs.storage_epoch
             OR (p_assertion->>'registry_epoch')::bigint <> v_epochs.registry_epoch
             OR (p_assertion->>'key_epoch')::bigint <> v_epochs.key_epoch
             OR (p_permit->>'storage_epoch')::bigint <> v_epochs.storage_epoch
             OR (p_permit->>'registry_epoch')::bigint <> v_epochs.registry_epoch
             OR (p_permit->>'key_epoch')::bigint <> v_epochs.key_epoch THEN
            RAISE EXCEPTION 'authorization environment or epoch mismatch';
          END IF;
          IF (p_assertion->>'issued_at')::timestamptz > v_now + interval '30 seconds'
             OR v_assertion_expires <= v_now
             OR v_assertion_expires
                > (p_assertion->>'interaction_created_at')::timestamptz
                  + make_interval(secs => (p_assertion->>'max_age_seconds')::int)
             OR (p_assertion->>'max_age_seconds')::int NOT BETWEEN 1 AND 300 THEN
            RAISE EXCEPTION 'owner assertion is outside its freshness window';
          END IF;
          IF v_issued_at > v_now + interval '30 seconds'
             OR v_claim_deadline <= v_now
             OR v_claim_deadline > v_issued_at + interval '5 minutes' THEN
            RAISE EXCEPTION 'permit is outside its claim window';
          END IF;
          IF length(p_permit->>'nonce') NOT BETWEEN 32 AND 128
             OR length(p_assertion->>'nonce') NOT BETWEEN 32 AND 128 THEN
            RAISE EXCEPTION 'authorization nonce length is invalid';
          END IF;
          IF v_action = 'evidence.retrieve' THEN
            IF v_reason NOT IN (
              'verify_exact_wording','resolve_ambiguity','recover_missing_context','owner_review'
            ) OR (p_permit->>'max_records')::int <> 1
              OR (p_permit->>'max_bytes')::int NOT BETWEEN 1 AND 65536 THEN
              RAISE EXCEPTION 'retrieval permit scope is invalid';
            END IF;
          ELSIF v_action = 'evidence.delete' THEN
            IF v_reason NOT IN ('owner_request','sensitive_data','retention_expired')
               OR (p_permit->>'max_records')::int NOT BETWEEN 1 AND 90
               OR (p_permit->>'max_bytes')::int NOT BETWEEN 1 AND 131072 THEN
              RAISE EXCEPTION 'deletion permit scope is invalid';
            END IF;
          ELSE
            RAISE EXCEPTION 'unsupported sensitive action';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM lucy.evidence WHERE id = v_evidence_id)
             OR EXISTS (SELECT 1 FROM lucy.evidence_tombstones WHERE evidence_id = v_evidence_id)
             OR EXISTS (
               SELECT 1 FROM lucy.evidence_deletion_fences_v1
               WHERE evidence_id = v_evidence_id
             ) THEN
            RAISE EXCEPTION 'evidence is unavailable for new authorization';
          END IF;

          SELECT * INTO v_existing
            FROM lucy.sensitive_action_permits_v2
            WHERE issuance_idempotency_key = p_issuance_idempotency_key
            FOR UPDATE;
          IF FOUND THEN
            IF v_existing.id <> v_permit_id OR v_existing.serialized_permit <> p_permit THEN
              RAISE EXCEPTION 'permit issuance idempotency conflict';
            END IF;
            RETURN v_existing.id;
          END IF;

          v_operation_id := gen_random_uuid();
          INSERT INTO lucy.operations(id,idempotency_key,outcome,result,created_at,completed_at)
          VALUES (
            v_operation_id, p_issuance_idempotency_key, 'succeeded',
            jsonb_build_object('contract','SensitiveActionPermitV2','permit_id',v_permit_id),
            v_now, v_now
          );
          INSERT INTO lucy.owner_interaction_assertions_v1(
            id,nonce,anti_replay_id,action,evidence_id,owner_subject,issuer,environment,
            assertion_digest,serialized_assertion,issued_at,expires_at,storage_epoch,
            registry_epoch,key_epoch,accepted_at
          ) VALUES (
            v_assertion_id,p_assertion->>'nonce',p_assertion->>'anti_replay_id',
            p_assertion->>'requested_action',nullif(p_assertion->>'evidence_id','')::uuid,
            p_assertion->>'owner_subject',p_assertion->>'issuer',p_assertion->>'environment',
            v_assertion_digest,p_assertion,(p_assertion->>'issued_at')::timestamptz,
            v_assertion_expires,v_epochs.storage_epoch,v_epochs.registry_epoch,v_epochs.key_epoch,
            v_now
          );
          INSERT INTO lucy.sensitive_action_permits_v2(
            id,nonce,action,owner_subject,owner_assertion_id,evidence_id,reason,max_records,
            max_bytes,record_version,permit_digest,serialized_permit,issued_at,
            permit_claim_deadline,storage_epoch,registry_epoch,key_epoch,
            issuance_idempotency_key,issued_operation_id,state
          ) VALUES (
            v_permit_id,p_permit->>'nonce',v_action,p_permit->>'owner_subject',v_assertion_id,
            v_evidence_id,v_reason,(p_permit->>'max_records')::int,
            (p_permit->>'max_bytes')::int,(p_permit->>'record_version')::bigint,
            v_permit_digest,p_permit,v_issued_at,v_claim_deadline,v_epochs.storage_epoch,
            v_epochs.registry_epoch,v_epochs.key_epoch,p_issuance_idempotency_key,
            v_operation_id,'ISSUED'
          );
          PERFORM lucy.append_sensitive_event_v1(
            v_operation_id,'sensitive.permit_issued',
            jsonb_build_object('permit_id',v_permit_id,'action',v_action,'evidence_id',v_evidence_id)
          );
          RETURN v_permit_id;
        EXCEPTION
          WHEN invalid_text_representation OR not_null_violation OR check_violation THEN
            RAISE EXCEPTION 'malformed v1.2 authorization contract';
        END
        $function$
        """
    )
    _secure("lucy.issue_sensitive_action_permit_v2(jsonb,jsonb,text)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.deletion_scope_v1(p_manifest_id uuid) RETURNS jsonb
        LANGUAGE sql STABLE STRICT SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT jsonb_build_object(
            'manifest_id',m.id,
            'permit_id',m.permit_id,
            'root_evidence_id',m.root_evidence_id,
            'idempotency_key',m.idempotency_key,
            'scope_version',m.scope_version,
            'root_record_version',p.record_version,
            'target_count',m.target_count,
            'targets',(
              SELECT jsonb_agg(jsonb_build_object(
                'evidence_id',t.evidence_id,
                'key_ref',t.key_ref,
                'record_version',t.record_version,
                'key_epoch',t.key_epoch
              ) ORDER BY t.evidence_id::text,t.key_ref::text)
              FROM lucy.deletion_manifest_targets_v1 t WHERE t.manifest_id=m.id
            ),
            'permit_claim_deadline',m.permit_claim_deadline,
            'execution_deadline',m.execution_deadline,
            'state',m.state,
            'storage_epoch',p.storage_epoch,
            'registry_epoch',p.registry_epoch,
            'key_epoch',p.key_epoch,
            'owner_assertion_id',p.owner_assertion_id,
            'owner_assertion_digest',p.serialized_permit->>'owner_assertion_digest',
            'permit_nonce',p.nonce
          )
          FROM lucy.deletion_target_manifests_v1 m
          JOIN lucy.sensitive_action_permits_v2 p ON p.id=m.permit_id
          WHERE m.id=p_manifest_id
        $function$
        """
    )
    _secure("lucy.deletion_scope_v1(uuid)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.prepare_deletion_scope_v1(
          p_manifest_id uuid, p_permit_id uuid, p_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_permit lucy.sensitive_action_permits_v2%ROWTYPE;
          v_existing lucy.deletion_target_manifests_v1%ROWTYPE;
          v_count integer;
          v_now timestamptz := clock_timestamp();
          v_execution_deadline timestamptz := v_now + interval '10 minutes';
        BEGIN
          IF p_idempotency_key IS NULL OR length(p_idempotency_key) NOT BETWEEN 1 AND 512 THEN
            RAISE EXCEPTION 'invalid deletion idempotency key';
          END IF;
          SELECT * INTO v_existing FROM lucy.deletion_target_manifests_v1
            WHERE id=p_manifest_id OR idempotency_key=p_idempotency_key FOR UPDATE;
          IF FOUND THEN
            IF v_existing.id <> p_manifest_id OR v_existing.permit_id <> p_permit_id
               OR v_existing.idempotency_key <> p_idempotency_key THEN
              RAISE EXCEPTION 'deletion scope idempotency conflict';
            END IF;
            RETURN lucy.deletion_scope_v1(v_existing.id);
          END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v2
            WHERE id=p_permit_id FOR UPDATE;
          IF v_permit.action <> 'evidence.delete' OR v_permit.state <> 'ISSUED'
             OR v_permit.permit_claim_deadline <= v_now THEN
            RAISE EXCEPTION 'deletion permit cannot prepare a new scope';
          END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(c.id::text,0))
            FROM (
              WITH RECURSIVE closure(id) AS (
                SELECT v_permit.evidence_id
                UNION
                SELECT d.child_id FROM lucy.evidence_derivations d
                JOIN closure c ON d.parent_id=c.id
              ) SELECT id FROM closure
            ) c ORDER BY c.id;
          WITH RECURSIVE closure(id) AS (
            SELECT v_permit.evidence_id
            UNION
            SELECT d.child_id FROM lucy.evidence_derivations d JOIN closure c ON d.parent_id=c.id
          )
          SELECT count(*) INTO v_count FROM closure;
          IF v_count < 1 OR EXISTS (
            WITH RECURSIVE closure(id) AS (
              SELECT v_permit.evidence_id
              UNION
              SELECT d.child_id FROM lucy.evidence_derivations d JOIN closure c ON d.parent_id=c.id
            )
            SELECT 1 FROM closure c
            LEFT JOIN lucy.evidence_payloads p ON p.evidence_id=c.id
            WHERE p.evidence_id IS NULL OR p.algorithm <> 'AES-256-GCM+AWS-KMS'
               OR p.encryption_context_version <> 2
               OR EXISTS (
                 SELECT 1 FROM lucy.evidence_tombstones x WHERE x.evidence_id=c.id
               )
          ) THEN
            RAISE EXCEPTION 'deletion closure is incomplete or not v1.2 encrypted';
          END IF;
          INSERT INTO lucy.deletion_target_manifests_v1(
            id,permit_id,root_evidence_id,idempotency_key,scope_version,target_count,
            permit_claim_deadline,execution_deadline,state,prepared_at
          ) VALUES (
            p_manifest_id,p_permit_id,v_permit.evidence_id,p_idempotency_key,1,v_count,
            v_permit.permit_claim_deadline,v_execution_deadline,
            CASE WHEN v_count > 90 THEN 'BULK_REQUIRED' ELSE 'PREPARED' END,v_now
          );
          WITH RECURSIVE closure(id) AS (
            SELECT v_permit.evidence_id
            UNION
            SELECT d.child_id FROM lucy.evidence_derivations d JOIN closure c ON d.parent_id=c.id
          )
          INSERT INTO lucy.deletion_manifest_targets_v1(
            manifest_id,evidence_id,key_ref,record_version,key_epoch
          )
          SELECT p_manifest_id,p.evidence_id,p.key_ref,p.record_version,p.key_epoch
            FROM closure c JOIN lucy.evidence_payloads p ON p.evidence_id=c.id
            ORDER BY p.evidence_id,p.key_ref;
          IF v_count > 90 THEN
            INSERT INTO lucy.evidence_deletion_fences_v1(
              evidence_id,permit_id,operation_id,state,fenced_at,effective_at
            )
            SELECT evidence_id,p_permit_id,NULL,'BULK_REQUIRED',v_now,NULL
              FROM lucy.deletion_manifest_targets_v1 WHERE manifest_id=p_manifest_id
            ON CONFLICT (evidence_id) DO NOTHING;
            UPDATE lucy.sensitive_action_permits_v2 SET state='BULK_REQUIRED'
              WHERE id=p_permit_id;
            PERFORM lucy.append_sensitive_event_v1(
              v_permit.issued_operation_id,'sensitive.deletion_bulk_required',
              jsonb_build_object('permit_id',p_permit_id,'manifest_id',p_manifest_id,
                                 'target_count',v_count)
            );
          ELSE
            PERFORM lucy.append_sensitive_event_v1(
              v_permit.issued_operation_id,'sensitive.deletion_scope_prepared',
              jsonb_build_object('permit_id',p_permit_id,'manifest_id',p_manifest_id,
                                 'target_count',v_count)
            );
          END IF;
          RETURN lucy.deletion_scope_v1(p_manifest_id);
        END
        $function$
        """
    )
    _secure("lucy.prepare_deletion_scope_v1(uuid,uuid,text)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.finalize_deletion_scope_v1(
          p_manifest_id uuid, p_unsigned_manifest jsonb, p_signed_manifest jsonb
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_manifest lucy.deletion_target_manifests_v1%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v2%ROWTYPE;
          v_targets jsonb;
          v_targets_digest text;
          v_manifest_digest text;
          v_unsigned_digest text;
        BEGIN
          SELECT * INTO STRICT v_manifest FROM lucy.deletion_target_manifests_v1
            WHERE id=p_manifest_id FOR UPDATE;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v2
            WHERE id=v_manifest.permit_id FOR UPDATE;
          IF v_manifest.state = 'SIGNED' THEN
            IF v_manifest.signed_manifest = p_signed_manifest THEN
              RETURN v_manifest.signed_manifest_digest;
            END IF;
            RAISE EXCEPTION 'signed manifest replay differs';
          END IF;
          IF v_manifest.state <> 'PREPARED' OR v_manifest.target_count > 90 THEN
            RAISE EXCEPTION 'deletion scope is not eligible for ordinary finalization';
          END IF;
          SELECT jsonb_agg(jsonb_build_object(
              'evidence_id',t.evidence_id,'key_ref',t.key_ref,
              'record_version',t.record_version,'key_epoch',t.key_epoch
            ) ORDER BY t.evidence_id::text,t.key_ref::text)
            INTO v_targets
            FROM lucy.deletion_manifest_targets_v1 t WHERE t.manifest_id=p_manifest_id;
          v_targets_digest := lucy.deletion_targets_digest_v1(v_targets);
          IF p_signed_manifest - 'signature' <> p_unsigned_manifest - 'signature'
             OR coalesce(p_unsigned_manifest->>'signature','') <> ''
             OR coalesce(p_signed_manifest->>'signature','') = ''
             OR p_signed_manifest->>'contract_version' <> '1'
             OR p_signed_manifest->>'object_type' <> 'lucy.deletion-target-manifest.v1'
             OR p_signed_manifest->>'canonicalization_version' <> 'lucy-cjson-1'
             OR p_signed_manifest->>'signature_algorithm' <> 'Ed25519'
             OR p_signed_manifest->>'manifest_id' <> p_manifest_id::text
             OR p_signed_manifest->>'permit_id' <> v_manifest.permit_id::text
             OR p_signed_manifest->>'permit_nonce' <> v_permit.nonce
             OR p_signed_manifest->>'action' <> 'evidence.delete'
             OR p_signed_manifest->>'root_evidence_id' <> v_manifest.root_evidence_id::text
             OR p_signed_manifest->>'owner_assertion_id' <> v_permit.owner_assertion_id::text
             OR p_signed_manifest->>'owner_assertion_digest'
                <> v_permit.serialized_permit->>'owner_assertion_digest'
             OR p_signed_manifest->>'idempotency_key' <> v_manifest.idempotency_key
             OR (p_signed_manifest->>'scope_version')::bigint <> v_manifest.scope_version
             OR (p_signed_manifest->>'root_record_version')::bigint <> v_permit.record_version
             OR (p_signed_manifest->>'target_count')::int <> v_manifest.target_count
             OR p_signed_manifest->'targets' <> v_targets
             OR p_signed_manifest->>'targets_digest' <> v_targets_digest
             OR (p_signed_manifest->>'permit_claim_deadline')::timestamptz
                <> v_manifest.permit_claim_deadline
             OR (p_signed_manifest->>'execution_deadline')::timestamptz
                <> v_manifest.execution_deadline
             OR (p_signed_manifest->>'storage_epoch')::bigint <> v_permit.storage_epoch
             OR (p_signed_manifest->>'registry_epoch')::bigint <> v_permit.registry_epoch
             OR (p_signed_manifest->>'key_epoch')::bigint <> v_permit.key_epoch THEN
            RAISE EXCEPTION 'signed deletion manifest differs from the prepared scope';
          END IF;
          IF octet_length(convert_to(
               lucy.canonical_jsonb_v1(p_signed_manifest - 'signature'),'UTF8'
             ))
             + length('LUCY-SIGNED-CONTRACT') + 1 > 65536 THEN
            RAISE EXCEPTION 'canonical deletion manifest exceeds Phase 1';
          END IF;
          v_unsigned_digest := lucy.security_contract_digest_v1(p_unsigned_manifest);
          v_manifest_digest := lucy.security_contract_digest_v1(p_signed_manifest);
          IF v_unsigned_digest <> v_manifest_digest THEN
            RAISE EXCEPTION 'signed and unsigned deletion manifest digests differ';
          END IF;
          UPDATE lucy.deletion_target_manifests_v1
            SET targets_digest=v_targets_digest,unsigned_manifest_digest=v_unsigned_digest,
                unsigned_manifest=p_unsigned_manifest,signed_manifest_digest=v_manifest_digest,
                signed_manifest=p_signed_manifest,state='SIGNED',finalized_at=clock_timestamp()
            WHERE id=p_manifest_id;
          PERFORM lucy.append_sensitive_event_v1(
            v_permit.issued_operation_id,'sensitive.deletion_scope_signed',
            jsonb_build_object('permit_id',v_permit.id,'manifest_id',p_manifest_id,
                               'manifest_digest',v_manifest_digest)
          );
          RETURN v_manifest_digest;
        END
        $function$
        """
    )
    _secure("lucy.finalize_deletion_scope_v1(uuid,jsonb,jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.claim_evidence_retrieval_v1(
          p_serialized_permit jsonb, p_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_permit lucy.sensitive_action_permits_v2%ROWTYPE;
          v_payload lucy.evidence_payloads%ROWTYPE;
          v_evidence lucy.evidence%ROWTYPE;
          v_existing lucy.sensitive_operations_v1%ROWTYPE;
          v_operation_id uuid;
          v_package jsonb;
          v_digest text;
          v_size integer;
          v_now timestamptz := clock_timestamp();
          v_execution_deadline timestamptz := v_now + interval '10 minutes';
        BEGIN
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v2
            WHERE id=(p_serialized_permit->>'permit_id')::uuid FOR UPDATE;
          IF v_permit.serialized_permit <> p_serialized_permit
             OR v_permit.action <> 'evidence.retrieve' THEN
            RAISE EXCEPTION 'retrieval permit does not match policy storage';
          END IF;
          IF v_permit.state = 'CLAIMED' THEN
            IF v_permit.claimed_idempotency_key <> p_idempotency_key
               OR v_permit.claimed_session_user <> session_user THEN
              RAISE EXCEPTION 'retrieval permit was already consumed';
            END IF;
            SELECT * INTO STRICT v_existing FROM lucy.sensitive_operations_v1
              WHERE id=v_permit.claimed_operation_id;
            RETURN jsonb_build_object(
              'operation_id',v_existing.id,'package',v_existing.encrypted_package,
              'package_digest',v_existing.package_digest,
              'execution_deadline',v_existing.execution_deadline,'state',v_existing.state,
              'receipt_digest',v_existing.executor_receipt_digest,'replayed',true
            );
          END IF;
          IF v_permit.state <> 'ISSUED' OR v_permit.permit_claim_deadline <= v_now THEN
            RAISE EXCEPTION 'retrieval permit is not claimable';
          END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(v_permit.evidence_id::text,0));
          IF EXISTS (
            SELECT 1 FROM lucy.evidence_tombstones WHERE evidence_id=v_permit.evidence_id
          ) OR EXISTS (
            SELECT 1 FROM lucy.evidence_deletion_fences_v1 WHERE evidence_id=v_permit.evidence_id
          ) THEN
            RAISE EXCEPTION 'evidence is fenced or deleted';
          END IF;
          SELECT * INTO STRICT v_evidence FROM lucy.evidence WHERE id=v_permit.evidence_id;
          SELECT * INTO STRICT v_payload FROM lucy.evidence_payloads
            WHERE evidence_id=v_permit.evidence_id;
          IF v_payload.algorithm <> 'AES-256-GCM+AWS-KMS'
             OR v_payload.encryption_context_version <> 2
             OR v_payload.record_version <> v_permit.record_version
             OR v_payload.storage_epoch <> v_permit.storage_epoch
             OR v_payload.registry_epoch <> v_permit.registry_epoch
             OR v_payload.key_epoch <> v_permit.key_epoch
             OR octet_length(v_payload.ciphertext) > v_permit.max_bytes + 16 THEN
            RAISE EXCEPTION 'encrypted evidence is outside the V2 permit boundary';
          END IF;
          v_operation_id := gen_random_uuid();
          v_package := jsonb_build_object(
            'contract_version','1','canonicalization_version','lucy-cjson-1',
            'object_type','lucy.encrypted-evidence-package.v1',
            'operation_id',v_operation_id,'permit_id',v_permit.id,
            'action','evidence.retrieve','evidence_id',v_permit.evidence_id,
            'key_ref',v_payload.key_ref,'algorithm',v_payload.algorithm,
            'ciphertext_b64',replace(encode(v_payload.ciphertext,'base64'),E'\n',''),
            'content_nonce_b64',replace(encode(v_payload.content_nonce,'base64'),E'\n',''),
            'aad_b64',replace(encode(convert_to(lucy.canonical_jsonb_v1(v_evidence.content),'UTF8'),
                                      'base64'),E'\n',''),
            'encryption_context',jsonb_build_object(
              'application','cloud-hermes-lucy',
              'environment',v_permit.serialized_permit->>'environment',
              'evidence_id',v_permit.evidence_id,
              'storage_epoch',v_payload.storage_epoch,
              'registry_epoch',v_payload.registry_epoch,
              'key_epoch',v_payload.key_epoch,
              'record_version',v_payload.record_version
            ),
            'record_version',v_payload.record_version,
            'storage_epoch',v_payload.storage_epoch,
            'registry_epoch',v_payload.registry_epoch,
            'key_epoch',v_payload.key_epoch
          );
          v_size := octet_length(convert_to(lucy.canonical_jsonb_v1(v_package),'UTF8'));
          IF v_size > 131072 THEN
            RAISE EXCEPTION 'encrypted retrieval package exceeds Phase 1';
          END IF;
          v_digest := lucy.package_digest_v1(v_package);
          INSERT INTO lucy.operations(id,idempotency_key,outcome,result,created_at,completed_at)
          VALUES (v_operation_id,p_idempotency_key,'pending',NULL,v_now,NULL);
          INSERT INTO lucy.sensitive_operations_v1(
            id,permit_id,action,evidence_id,manifest_id,idempotency_key,caller_session_user,
            state,encrypted_package,package_digest,package_size_bytes,record_version,
            storage_epoch,registry_epoch,key_epoch,permit_claim_deadline,execution_deadline,
            created_at,updated_at
          ) VALUES (
            v_operation_id,v_permit.id,v_permit.action,v_permit.evidence_id,NULL,
            p_idempotency_key,session_user,'CLAIMED',v_package,v_digest,v_size,
            v_payload.record_version,v_payload.storage_epoch,v_payload.registry_epoch,
            v_payload.key_epoch,v_permit.permit_claim_deadline,v_execution_deadline,v_now,v_now
          );
          UPDATE lucy.sensitive_action_permits_v2
            SET state='CLAIMED',claimed_at=v_now,claimed_operation_id=v_operation_id,
                claimed_idempotency_key=p_idempotency_key,claimed_session_user=session_user
            WHERE id=v_permit.id;
          PERFORM lucy.append_sensitive_event_v1(
            v_operation_id,'sensitive.retrieval_claimed',
            jsonb_build_object('permit_id',v_permit.id,'evidence_id',v_permit.evidence_id,
                               'caller',session_user,'package_digest',v_digest)
          );
          RETURN jsonb_build_object(
            'operation_id',v_operation_id,'package',v_package,'package_digest',v_digest,
            'execution_deadline',v_execution_deadline,'state','CLAIMED',
            'receipt_digest',NULL,'replayed',false
          );
        END
        $function$
        """
    )
    _secure("lucy.claim_evidence_retrieval_v1(jsonb,text)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.claim_evidence_deletion_v1(
          p_serialized_permit jsonb, p_signed_manifest jsonb, p_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_permit lucy.sensitive_action_permits_v2%ROWTYPE;
          v_manifest lucy.deletion_target_manifests_v1%ROWTYPE;
          v_existing lucy.sensitive_operations_v1%ROWTYPE;
          v_operation_id uuid;
          v_size integer;
          v_now timestamptz := clock_timestamp();
        BEGIN
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v2
            WHERE id=(p_serialized_permit->>'permit_id')::uuid FOR UPDATE;
          SELECT * INTO STRICT v_manifest FROM lucy.deletion_target_manifests_v1
            WHERE id=(p_signed_manifest->>'manifest_id')::uuid FOR UPDATE;
          IF v_permit.serialized_permit <> p_serialized_permit
             OR v_permit.action <> 'evidence.delete'
             OR v_manifest.permit_id <> v_permit.id
             OR v_manifest.signed_manifest <> p_signed_manifest
             OR v_manifest.state NOT IN ('SIGNED','CLAIMED')
             OR v_manifest.signed_manifest_digest
                <> lucy.security_contract_digest_v1(p_signed_manifest)
             OR v_manifest.target_count > 90 THEN
            RAISE EXCEPTION 'deletion permit or manifest does not match policy storage';
          END IF;
          IF v_permit.state = 'CLAIMED' THEN
            IF v_permit.claimed_idempotency_key <> p_idempotency_key
               OR v_permit.claimed_session_user <> session_user THEN
              RAISE EXCEPTION 'deletion permit was already consumed';
            END IF;
            SELECT * INTO STRICT v_existing FROM lucy.sensitive_operations_v1
              WHERE id=v_permit.claimed_operation_id;
            RETURN jsonb_build_object(
              'operation_id',v_existing.id,'manifest',v_existing.encrypted_package,
              'package_digest',v_existing.package_digest,
              'execution_deadline',v_existing.execution_deadline,'state',v_existing.state,
              'receipt_digest',v_existing.executor_receipt_digest,'replayed',true
            );
          END IF;
          IF v_permit.state <> 'ISSUED' OR v_permit.permit_claim_deadline <= v_now
             OR v_manifest.execution_deadline <= v_now THEN
            RAISE EXCEPTION 'deletion permit is not claimable';
          END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(t.evidence_id::text,0))
            FROM lucy.deletion_manifest_targets_v1 t
            WHERE t.manifest_id=v_manifest.id ORDER BY t.evidence_id;
          IF EXISTS (
            SELECT 1 FROM lucy.deletion_manifest_targets_v1 t
            LEFT JOIN lucy.evidence_payloads p ON p.evidence_id=t.evidence_id
            WHERE t.manifest_id=v_manifest.id
              AND (p.evidence_id IS NULL OR p.key_ref <> t.key_ref
                   OR p.record_version <> t.record_version OR p.key_epoch <> t.key_epoch
                   OR p.encryption_context_version <> 2)
          ) OR EXISTS (
            SELECT 1 FROM lucy.deletion_manifest_targets_v1 t
            JOIN lucy.evidence_deletion_fences_v1 f ON f.evidence_id=t.evidence_id
            WHERE t.manifest_id=v_manifest.id AND f.permit_id <> v_permit.id
          ) THEN
            RAISE EXCEPTION 'deletion scope changed or conflicts with another fence';
          END IF;
          v_operation_id := gen_random_uuid();
          v_size := octet_length(convert_to(lucy.canonical_jsonb_v1(p_signed_manifest),'UTF8'));
          IF v_size > 131072 THEN
            RAISE EXCEPTION 'deletion invocation package exceeds Phase 1';
          END IF;
          INSERT INTO lucy.operations(id,idempotency_key,outcome,result,created_at,completed_at)
          VALUES (v_operation_id,p_idempotency_key,'pending',NULL,v_now,NULL);
          INSERT INTO lucy.sensitive_operations_v1(
            id,permit_id,action,evidence_id,manifest_id,idempotency_key,caller_session_user,
            state,encrypted_package,package_digest,package_size_bytes,record_version,
            storage_epoch,registry_epoch,key_epoch,permit_claim_deadline,execution_deadline,
            created_at,updated_at
          ) VALUES (
            v_operation_id,v_permit.id,v_permit.action,v_permit.evidence_id,v_manifest.id,
            p_idempotency_key,session_user,'CLAIMED',p_signed_manifest,
            v_manifest.signed_manifest_digest,v_size,v_permit.record_version,
            v_permit.storage_epoch,v_permit.registry_epoch,v_permit.key_epoch,
            v_permit.permit_claim_deadline,v_manifest.execution_deadline,v_now,v_now
          );
          INSERT INTO lucy.evidence_deletion_fences_v1(
            evidence_id,permit_id,operation_id,state,fenced_at,effective_at
          ) SELECT evidence_id,v_permit.id,v_operation_id,'CLAIMED',v_now,NULL
              FROM lucy.deletion_manifest_targets_v1 WHERE manifest_id=v_manifest.id
            ON CONFLICT (evidence_id) DO UPDATE
              SET operation_id=excluded.operation_id,state='CLAIMED'
              WHERE lucy.evidence_deletion_fences_v1.permit_id=excluded.permit_id;
          UPDATE lucy.sensitive_action_permits_v2
            SET state='CLAIMED',claimed_at=v_now,claimed_operation_id=v_operation_id,
                claimed_idempotency_key=p_idempotency_key,claimed_session_user=session_user
            WHERE id=v_permit.id;
          UPDATE lucy.deletion_target_manifests_v1 SET state='CLAIMED'
            WHERE id=v_manifest.id;
          PERFORM lucy.append_sensitive_event_v1(
            v_operation_id,'sensitive.deletion_claimed',
            jsonb_build_object('permit_id',v_permit.id,'manifest_id',v_manifest.id,
                               'caller',session_user,'target_count',v_manifest.target_count)
          );
          RETURN jsonb_build_object(
            'operation_id',v_operation_id,'manifest',p_signed_manifest,
            'package_digest',v_manifest.signed_manifest_digest,
            'execution_deadline',v_manifest.execution_deadline,'state','CLAIMED',
            'receipt_digest',NULL,'replayed',false
          );
        END
        $function$
        """
    )
    _secure("lucy.claim_evidence_deletion_v1(jsonb,jsonb,text)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.read_claim_digest_for_notary_v1(p_operation_id uuid) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation lucy.sensitive_operations_v1%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v2%ROWTYPE;
        BEGIN
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v1
            WHERE id=p_operation_id;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v2
            WHERE id=v_operation.permit_id;
          IF v_operation.state NOT IN ('CLAIMED','EXECUTING','EXECUTOR_RECEIPTED')
             OR v_operation.execution_deadline <= clock_timestamp() THEN
            RAISE EXCEPTION 'operation is not eligible for policy notarization';
          END IF;
          RETURN jsonb_build_object(
            'operation_id',v_operation.id,'action',v_operation.action,
            'permit_id',v_operation.permit_id,'permit_nonce',v_permit.nonce,
            'evidence_id',v_operation.evidence_id,'manifest_id',v_operation.manifest_id,
            'manifest_digest',CASE WHEN v_operation.action='evidence.delete'
                                   THEN v_operation.package_digest ELSE NULL END,
            'package_digest',v_operation.package_digest,
            'package_size_bytes',v_operation.package_size_bytes,
            'database_session_user',v_operation.caller_session_user,
            'idempotency_key',v_operation.idempotency_key,
            'record_version',v_operation.record_version,
            'storage_epoch',v_operation.storage_epoch,
            'registry_epoch',v_operation.registry_epoch,'key_epoch',v_operation.key_epoch,
            'environment',v_permit.serialized_permit->>'environment',
            'permit_claim_deadline',v_operation.permit_claim_deadline,
            'execution_deadline',v_operation.execution_deadline
          );
        END
        $function$
        """
    )
    _secure("lucy.read_claim_digest_for_notary_v1(uuid)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.store_sensitive_execution_grant_v1(
          p_operation_id uuid, p_signed_grant jsonb
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation lucy.sensitive_operations_v1%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v2%ROWTYPE;
          v_binding lucy.executor_bindings_v1%ROWTYPE;
          v_existing lucy.sensitive_execution_grants_v1%ROWTYPE;
          v_digest text;
          v_grant_id uuid;
          v_now timestamptz := clock_timestamp();
        BEGIN
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v1
            WHERE id=p_operation_id FOR UPDATE;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v2
            WHERE id=v_operation.permit_id;
          SELECT * INTO STRICT v_binding FROM lucy.executor_bindings_v1
            WHERE action=v_operation.action
              AND environment=v_permit.serialized_permit->>'environment' AND active;
          v_grant_id := (p_signed_grant->>'grant_id')::uuid;
          v_digest := lucy.security_contract_digest_v1(p_signed_grant);
          SELECT * INTO v_existing FROM lucy.sensitive_execution_grants_v1
            WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_grant=p_signed_grant THEN
              RETURN v_existing.grant_digest;
            END IF;
            RAISE EXCEPTION 'execution grant replay differs';
          END IF;
          IF v_operation.state <> 'CLAIMED' OR v_operation.execution_deadline <= v_now
             OR p_signed_grant->>'contract_version' <> '1'
             OR p_signed_grant->>'object_type' <> 'lucy.sensitive-execution-grant.v1'
             OR p_signed_grant->>'canonicalization_version' <> 'lucy-cjson-1'
             OR p_signed_grant->>'signature_algorithm' <> 'Ed25519'
             OR coalesce(p_signed_grant->>'signature','') = ''
             OR p_signed_grant->>'operation_id' <> v_operation.id::text
             OR p_signed_grant->>'action' <> v_operation.action
             OR p_signed_grant->>'permit_id' <> v_operation.permit_id::text
             OR p_signed_grant->>'permit_nonce' <> v_permit.nonce
             OR p_signed_grant->>'database_session_user' <> v_operation.caller_session_user
             OR p_signed_grant->>'evidence_id' <> v_operation.evidence_id::text
             OR p_signed_grant->>'encrypted_package_digest' <> v_operation.package_digest
             OR (p_signed_grant->>'package_size_bytes')::int <> v_operation.package_size_bytes
             OR p_signed_grant->>'idempotency_key' <> v_operation.idempotency_key
             OR (p_signed_grant->>'record_version')::bigint <> v_operation.record_version
             OR (p_signed_grant->>'storage_epoch')::bigint <> v_operation.storage_epoch
             OR (p_signed_grant->>'registry_epoch')::bigint <> v_operation.registry_epoch
             OR (p_signed_grant->>'key_epoch')::bigint <> v_operation.key_epoch
             OR p_signed_grant->>'executor_identity' <> v_binding.executor_identity
             OR p_signed_grant->>'executor_alias_arn' <> v_binding.executor_alias_arn
             OR (p_signed_grant->>'executor_version')::bigint <> v_binding.executor_version
             OR (p_signed_grant->>'permit_claim_deadline')::timestamptz
                <> v_operation.permit_claim_deadline
             OR (p_signed_grant->>'execution_deadline')::timestamptz
                <> v_operation.execution_deadline
             OR (p_signed_grant->>'issued_at')::timestamptz > v_now + interval '30 seconds'
             OR (v_operation.action='evidence.retrieve' AND (
                   p_signed_grant->>'deletion_manifest_id' IS NOT NULL
                   OR p_signed_grant->>'deletion_manifest_digest' IS NOT NULL))
             OR (v_operation.action='evidence.delete' AND (
                   p_signed_grant->>'deletion_manifest_id' <> v_operation.manifest_id::text
                   OR p_signed_grant->>'deletion_manifest_digest'
                      <> v_operation.package_digest)) THEN
            RAISE EXCEPTION 'execution grant differs from the database claim';
          END IF;
          INSERT INTO lucy.sensitive_execution_grants_v1(
            id,operation_id,grant_digest,serialized_grant,executor_identity,
            executor_alias_arn,executor_version,issued_at,execution_deadline,stored_at
          ) VALUES (
            v_grant_id,p_operation_id,v_digest,p_signed_grant,v_binding.executor_identity,
            v_binding.executor_alias_arn,v_binding.executor_version,
            (p_signed_grant->>'issued_at')::timestamptz,v_operation.execution_deadline,v_now
          );
          UPDATE lucy.sensitive_operations_v1 SET state='EXECUTING',updated_at=v_now
            WHERE id=p_operation_id;
          PERFORM lucy.append_sensitive_event_v1(
            p_operation_id,'sensitive.execution_granted',
            jsonb_build_object('grant_id',v_grant_id,'grant_digest',v_digest,
                               'executor_alias_arn',v_binding.executor_alias_arn,
                               'executor_version',v_binding.executor_version)
          );
          RETURN v_digest;
        END
        $function$
        """
    )
    _secure("lucy.store_sensitive_execution_grant_v1(uuid,jsonb)")

    op.execute(
        r"""
        CREATE FUNCTION lucy.attest_executor_receipt_v1(
          p_operation_id uuid, p_verified_receipt jsonb
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_operation lucy.sensitive_operations_v1%ROWTYPE;
          v_grant lucy.sensitive_execution_grants_v1%ROWTYPE;
          v_binding lucy.executor_bindings_v1%ROWTYPE;
          v_existing lucy.executor_receipt_attestations_v1%ROWTYPE;
          v_digest text;
          v_receipt_id uuid;
          v_result text;
          v_completed_at timestamptz;
          v_now timestamptz := clock_timestamp();
        BEGIN
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v1
            WHERE id=p_operation_id FOR UPDATE;
          SELECT * INTO STRICT v_grant FROM lucy.sensitive_execution_grants_v1
            WHERE operation_id=p_operation_id;
          SELECT * INTO STRICT v_binding FROM lucy.executor_bindings_v1
            WHERE action=v_operation.action
              AND executor_alias_arn=v_grant.executor_alias_arn AND active;
          v_receipt_id := (p_verified_receipt->>'receipt_id')::uuid;
          v_result := p_verified_receipt->>'result';
          v_completed_at := (p_verified_receipt->>'completed_at')::timestamptz;
          v_digest := lucy.security_contract_digest_v1(p_verified_receipt);
          SELECT * INTO v_existing FROM lucy.executor_receipt_attestations_v1
            WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.receipt_digest=v_digest THEN RETURN v_existing.receipt_digest; END IF;
            RAISE EXCEPTION 'executor receipt attestation replay differs';
          END IF;
          IF v_operation.state <> 'EXECUTING'
             OR p_verified_receipt->>'contract_version' <> '1'
             OR p_verified_receipt->>'object_type' <> 'lucy.executor-receipt.v1'
             OR p_verified_receipt->>'canonicalization_version' <> 'lucy-cjson-1'
             OR p_verified_receipt->>'signature_algorithm' <> 'ECDSA_SHA_256'
             OR coalesce(p_verified_receipt->>'signature','') = ''
             OR p_verified_receipt->>'operation_id' <> v_operation.id::text
             OR p_verified_receipt->>'action' <> v_operation.action
             OR p_verified_receipt->>'permit_id' <> v_operation.permit_id::text
             OR p_verified_receipt->>'execution_grant_id' <> v_grant.id::text
             OR p_verified_receipt->>'package_digest' <> v_operation.package_digest
             OR p_verified_receipt->>'executor_identity' <> v_binding.executor_identity
             OR p_verified_receipt->>'executor_alias_arn' <> v_binding.executor_alias_arn
             OR (p_verified_receipt->>'executor_version')::bigint <> v_binding.executor_version
             OR p_verified_receipt->>'key_id' <> v_binding.receipt_key_id
             OR (p_verified_receipt->>'execution_deadline')::timestamptz
                <> v_operation.execution_deadline
             OR v_completed_at > v_operation.execution_deadline + interval '30 seconds'
             OR (p_verified_receipt->>'record_version')::bigint <> v_operation.record_version
             OR (p_verified_receipt->>'storage_epoch')::bigint <> v_operation.storage_epoch
             OR (p_verified_receipt->>'registry_epoch')::bigint <> v_operation.registry_epoch
             OR (p_verified_receipt->>'key_epoch')::bigint <> v_operation.key_epoch
             OR (v_operation.action='evidence.retrieve' AND (
                   v_result NOT IN ('retrieval_succeeded','idempotent_replay','rejected')
                   OR p_verified_receipt->>'deletion_manifest_id' IS NOT NULL
                   OR p_verified_receipt->>'kms_request_id' IS NULL
                   OR p_verified_receipt->>'transaction_client_token' IS NOT NULL))
             OR (v_operation.action='evidence.delete' AND (
                   v_result NOT IN ('deletion_succeeded','idempotent_replay','rejected')
                   OR p_verified_receipt->>'deletion_manifest_id' <> v_operation.manifest_id::text
                   OR p_verified_receipt->>'transaction_client_token' IS NULL
                   OR p_verified_receipt->>'kms_request_id' IS NOT NULL)) THEN
            RAISE EXCEPTION 'verified executor receipt differs from the stored grant';
          END IF;
          INSERT INTO lucy.executor_receipt_attestations_v1(
            receipt_id,operation_id,execution_grant_id,receipt_digest,result,receipt_key_id,
            executor_identity,completed_at,verified_at,policy_session_user
          ) VALUES (
            v_receipt_id,p_operation_id,v_grant.id,v_digest,v_result,v_binding.receipt_key_id,
            v_binding.executor_identity,v_completed_at,v_now,session_user
          );
          UPDATE lucy.sensitive_operations_v1 SET executor_receipt_digest=v_digest,updated_at=v_now
            WHERE id=p_operation_id;
          PERFORM lucy.append_sensitive_event_v1(
            p_operation_id,'sensitive.executor_receipt_attested',
            jsonb_build_object('receipt_id',v_receipt_id,'receipt_digest',v_digest,'result',v_result)
          );
          RETURN v_digest;
        END
        $function$
        """
    )
    _secure("lucy.attest_executor_receipt_v1(uuid,jsonb)")


def downgrade() -> None:
    raise RuntimeError("v1.2 authorization gates require a reviewed forward migration")
