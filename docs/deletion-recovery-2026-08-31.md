# Independent deletion journal: local recovery checkpoint

Date: 2026-08-31

Status: local implementation and synthetic acceptance, **not production
acceptance or permission to enable capture**. This supersedes the interrupted
deletion behavior in the previous provenance checkpoint. No live image, profile,
database, credentials, AWS/Render configuration, or capture setting was changed.

## What changed

An accepted owner deletion is durably recorded outside PostgreSQL **before**
destroying any wrapped data key. Every HTTP service transaction compares that
journal's current head with PostgreSQL's completion receipt. An unmatched head
blocks ordinary storage access, even if PostgreSQL still contains an old `ready`
flag, the matching storage epoch, and plaintext structured memory.

The journal contains a versioned intent: opaque evidence/key/operation IDs,
the signed owner permit, its acceptance time, a reason code, and the exact
algorithmically derived deletion targets. It contains no transcript body,
ciphertext, wrapped DEK, decryption key, or plaintext commitment. Owner/interaction
identifiers in the signed permit are still sensitive metadata; this is not a
public log. These identifiers must not carry free-text conversation content.

The PostgreSQL receipt stores the journal sequence, intent ID, integrity digest,
and operation ID. It is committed in the **same transaction** as ciphertext
removal, projection redaction, tombstones, permit consumption and audit events.
There is no second external "mark completed" write whose failure could reopen
access prematurely.

## Transaction and interruption protocol

1. Drain normal admitted transactions using the exclusive admission lock, before
   the retention/operation locks. New normal transactions wait on the shared lock.
2. Verify journal/registry identity, current owner permit, sealed provenance and
   target/key coverage. A first attempt requires all remaining keys to exist.
3. Atomically append the accepted intent to the independent journal. Failure or
   an ambiguous append response never permits key destruction to proceed.
4. Delete each recorded wrapped DEK, confirming absence with a read-back. Perform
   the existing full derived-data cascade without decrypting anything.
5. Commit the database receipt and deletion result together. After the lock is
   released, queued transactions recheck the external head, not an old readiness
   result. A rollback/process kill leaves the head unmatched and access fenced.

| Interruption | Result |
| --- | --- |
| Before durable intent | No keys destroyed; normal access can continue |
| Append committed but response lost | No keys destroyed; unmatched intent blocks access |
| After one/all key deletions, before database commit | Intent survives rollback; projections are inaccessible through admitted services |
| Database committed but response lost | Receipt matches; replay returns the durable result without repeating key operations |
| Pre-deletion PostgreSQL backup restored | Old ready flag/epoch cannot bypass the journal mismatch |

This is exactly-once **logical completion**, not exactly-once external IO. Key
deletion after an ambiguous result can be retried idempotently. Previously
acknowledged intents are not re-applied during ordinary maintenance.

This boundary covers new admitted database work, not revocation of bytes already
read/delivered to a caller, an in-flight model prompt, or Hermes history. Direct
SQL clients (including a compromised routine database credential) bypass the
application admission hook; plaintext structured memory remains the documented
Phase 1 residual confidentiality boundary, not an encrypted semantic store.
The pending clean-history/reset work is still essential.

## Explicit offline recovery, not startup repair

HTTP startup remains read-only. It never accepts new deletion authority, scans
old work, replays a model call, destroys keys or starts recovery. `/health` remains
liveness only; journal/admission failure yields a content-free HTTP 503.

Operator `prepare` first persists quarantine and requires all executors and
service connection pools to be stopped. It verifies the complete journal chain,
permit signatures and acknowledged receipt prefix before any recovery write.
Unacknowledged intents require the explicit `--recover-deletions` option, the
identity-bound key registry and policy public verification key. It then applies
only that suffix and verifies archive/control-plane state before reopening with
a new independent storage epoch. No signing private key or KMS capability is
needed by the deletion/recovery primitive.

A permit accepted while valid can complete after it expires: recovery is
finishing that existing accepted operation, not granting a fresh capability.
The independent intent also survives a database restore that predates permit
issuance. A conflicting database permit, changed key mapping, changed deletion
closure, missing payload coverage, invalid signature or chain, wrong registry,
or rolled-back journal blocks recovery. Missing keys alone never authorize it.

A backup older than the operator journal binding is deliberately not auto-adopted.
It needs a separate reviewed identity repair. A corrupted/inconsistent backup
is not silently repaired into an apparently valid state.

## Identity and permission boundaries

Revision `0016_deletion_journal` adds an operator-owned immutable journal/registry
binding and append-only completion receipts. It closes admission and does not
backfill authority from existing tombstones or missing keys. Services can read
the binding and receipts; only the deletion capability can insert receipts.
No service can alter the binding, update/delete receipts, or open admission.
The separate-role PostgreSQL acceptance tests exercise these denied privileges.

The local SQLite key registry now has a persistent UUID. Its journal has a
different UUID plus the bound registry UUID. Replacing a missing registry with
an empty newly initialized one does not prove deletion; its identity differs.
The test-only memory registry also has an explicit identity.

## Important local-provider and deployment limits

The implemented provider is `SqliteDeletionJournal`, outside PostgreSQL. Creation
is explicit (`initialize` on a new absolute file path); routine opening uses an
existing file and never recreates a missing journal. Append is atomic, serialized
and uses SQLite `synchronous=FULL`. A hash chain and mutation-rejecting triggers
detect ordinary corruption/mutation, **not a malicious filesystem administrator**.
Accepted timestamps/manifests depend on the trusted approved journal writer;
the owner signature authenticates the permit, not the writer's acceptance time.

This is a same-host acceptance provider, not a four-identity cloud authorization
boundary, independent disaster recovery store, or proof of power-loss safety.
Local filesystem/host administrators remain trusted. Rolling back PostgreSQL
and its independent journal together to matching old state is not detected by
this prototype. Keys/journal must not be restored from ordinary database backups.

The local runtime requires `LUCY_DELETION_JOURNAL_PATH`,
`LUCY_DELETION_JOURNAL_ID`, and `LUCY_ARCHIVE_REGISTRY_ID`, followed by explicit
operator binding/preparation. Tests initialize/bind only disposable synthetic
stores. Normal Compose/Render mounts and cloud IAM have **not** been provisioned
for this boundary. Do not rebuild live services or run live migrations from this
worktree. The subsequent [production-journal checkpoint](production-journal-2026-08-31.md)
implements a fail-closed DynamoDB provider and reviewed IAM templates, but it is
only locally mocked: real-cloud acceptance remains required and there is no local
fallback in production, even with capture disabled.

The cloud adapter must preserve least privilege: routine services need only
fresh journal-head metadata, never wrapped-key reads or intent-write authority.
The policy service's **no-AWS-role** baseline must remain intact, for example
through an appropriately authenticated metadata-only admission boundary; this
batch grants it no AWS access. The deleter still must have **zero KMS master-key
administration or decrypt authority**. Independent writer authorization,
anti-rollback/freshness, backup retention, journal size/paging, identity checks
historical permit verification-key rotation, and outages need real AWS/Render
acceptance. No new cloud permissions are implied
by a passing local test.

## Synthetic verification

Tests include append ambiguity, rollback before commit, read-back confirmation,
expired accepted permits, wrong identities, missing/corrupt journals, journal
rollback, multi-intent suffix recovery, and ordinary-reader/deleter concurrency.
The process test kills an actual child process after an external SQLite key
deletion commits and recovers using fresh provider instances. It is not a host
power-loss or distributed network-partition test.

The backup test uses real `pg_dump`/`pg_restore` against only the disposable
`lucy_test` database in `cloud-lucy-retention-tests-postgres-1`. Its backup predates
the owner permit and deletion. The restored plaintext claim is verified present
by the test administrator while service access is refused, then redacted by
accepted-intent recovery. The independent journal/key files are not restored.
No real transcript or live database is involved.

Start the two isolated clusters with `docker compose -f compose.test.yaml up -d
--wait --wait-timeout 45`, then use the previous checkpoint's synthetic migration
and database environment values. Include this additional variable to run the
real backup test instead of skipping it:

```powershell
$env:LUCY_TEST_DOCKER_BIN='C:\Program Files\Docker\Docker\resources\bin\docker.exe'
.\.venv\Scripts\python.exe -m pytest -q --tb=short
```

Docker access is required for that test. On Windows, switching sandbox/security
tokens can make an existing pytest cache inaccessible; use a fresh **nonexisting**
unique synthetic-only `--basetemp` directory and `-p no:cacheprovider` rather than
changing permissions on existing user directories. Never point `--basetemp` at
an existing data directory: pytest may delete its contents.

Final verification:

- **295 tests passed**, zero skips: 125 unit and 170 PostgreSQL integration tests.
  The latter include 13 new recovery cases and 100 separate-role/admission cases.
- The complete run included the OS-process kill, expired accepted authority,
  actual database backup/restore and journal rollback tests.
- Both isolated clusters migrated through `0016_deletion_journal`; separate-role
  migrations ran as the non-superuser schema owner. There is one Alembic head.
- Ruff, strict MyPy (32 source files), compilation and Git whitespace checks passed.
- All 13 recovery cases passed again after adding an explicit test-container
  project/service identity check before backup restoration.
- Two non-failing dependency warnings remain: Starlette's HTTPX test-client
  deprecation and Alembic's legacy path-separator warning.
- Both test containers' project labels were verified before removing them and
  their network. Only synthetic tmpfs database contents were discarded. Live
  Lucy's API/PostgreSQL remained healthy and its gateway remained running,
  without restart. No real-data deletion or key destruction was performed.

## Remaining capture blockers

1. Real-cloud acceptance of the implemented production journal/registry identity,
   least-privilege admission metadata access, audit trail and compound restore/failure path.
2. Verified clean Hermes history/reset/resumption, including restart/compaction
   and visible off-record state; old model context must not recreate deleted data.
3. Independent owner-event verification, scope revocation and disclosure limits.
4. Legacy residues, complete budgets, OIDC/KMS/backup testing and final owner
   acceptance before enabling transcript capture.
