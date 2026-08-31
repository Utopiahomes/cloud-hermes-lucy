# Deletion provenance: local hardening checkpoint

Date: 2026-08-31. **Local implementation and synthetic tests only; not deployed.**

This follows [service admission and quarantine](service-boundaries-2026-08-31.md).
It advances F02/F03 for the artifact types that exist today. The independent
deletion ledger, complete runtime-history boundary, owner-event broker, and
real-cloud recovery acceptance remain blockers for live transcript capture.

## What changed

Previously, deleting an input could leave an independently encrypted assistant
reply, or a memory whose primary citation was another record. The service now
tracks every declared/observed source, not only the primary citation.

- `evidence_derivations` records immutable parent-to-child evidence edges.
- `claim_sources`, `proposal_sources`, and `correction_sources` record immutable
  multi-source support with real foreign keys and reverse-lookup indexes.
- New encrypted metadata is version 3. Its canonical source-ID list is bound
  into authenticated encryption metadata and must agree with the edge table.
- `DerivationSourcesV1` accepts only a canonical, duplicate-free UUID tuple,
  at most 512 entries. It contains no text or approval authority. Ingestion also
  enforces the bound after expanding all ancestors; it never silently truncates.
- The primary citation remains available for display but is no longer the
  deletion boundary. Approvals bind the complete stored source set, and apply
  revalidates it. Corrections inherit all support from the old claim as well as
  their new evidence. Graph relationships inherit their claim's support.
- Recall filters secondary-source tombstones, not just the primary source and
  claim status. Materialization and replay also reject deleted support.

The migration backfills known primary/supersession support only. It does not
invent missing historical sources, alter encrypted legacy metadata, or silently
approve old proposal payloads without a matching source manifest.

## Supported conversation provenance

Inbound user records are independent sources; callers cannot attach derived
parents to them. The server automatically attaches the current retained input
to a reply or gateway proposal. It also conservatively includes **all retained
prior conversation history**, expanding the evidence ancestry of that history.
A model cannot hide the current input merely by citing an older fact.

The plugin collects source UUIDs from successful structured-memory lookups and
bounded raw-evidence retrieval before exposing their text to the model. These
observed sources are included in subsequent proposal/reply requests. Tool
middleware supplies the session/turn identity; model-authored identity/source
arguments are ignored. The database independently validates source existence,
ancestry and deletion state. Source-ID collection is scoped to the active turn,
and a cold gateway refuses to resume a retained turn whose uncommitted tool
exposure state it no longer has.

This is intentionally conservative provenance based on possible exposure, not a
claim that the model actually used every supplied fact. Forgetting an earlier
source may invalidate later replies that were exposed to it, even if the replies
appear unrelated. Independent user inputs and independently supported memories
are retained. A user can deliberately state a fact again as new independent
evidence; deletion is not a global ban on those words.

## Clean-history limitation and user-visible consequence

Prior excluded, unfinished, or redacted turns block new retained derivatives
in the same conversation until a **verified clean runtime-history boundary**
exists. A missing current input blocks a late reply before encryption or key
creation. Source sets over the ingestion limit also fail closed.

Consequently, toggling "back on the record" alone is not yet a complete safe
resumption workflow: Hermes may still carry off-record text in its prompt or
summary. Similarly, forgetting a source must not let old runtime history write
that source back into a new answer. This batch does not clear `/opt/data`,
implement a history-reset certificate, or prove Hermes compaction/hidden-summary
coverage. A caller-supplied new conversation ID is not proof of a clean prompt.
The final adapter/history-reset and visible resumption UX must pass acceptance
before this capture path is deployed. No live user-facing behavior was changed.

## Governed deletion closure

Under the existing exclusive retention fence, deletion computes the full
forward evidence closure. It validates payload/tombstone coverage before key
destruction and checks every retained member's edges against its sealed metadata.
A late forged edge therefore cannot expand deletion into an unrelated record
whose immutable manifest does not name that parent. It then removes each
affected wrapped DEK and ciphertext, and cascades
through every supported claim/proposal/correction and its graph/approval data.
Disposable working contexts are purged conservatively. One exact-root owner
permit authorizes the algorithmically determined descendant cascade; it does
not authorize deleting parents, siblings or arbitrary unrelated evidence.

All newly deleted evidence receives a tombstone linked to the same operation.
The migration replaces the old one-tombstone-per-operation uniqueness rule with
a nonunique operation index. Source edges remain as content-free provenance;
they are not erased to conceal a deletion. Replays return the durable result
without repeating the external operation. The service never decrypts while
deleting and still has no KMS master-key administration authority.

The four-role PostgreSQL test now performs a real routine ingest of an input and
derived reply, policy permit issuance, evidence-reader retrieval, and deletion
of both records plus a reply-based proposal. The policy, reader, and deleter
cannot add provenance edges. No service can update/delete/truncate them. A
routine writer can insert valid links but cannot rewrite them. These are local
PostgreSQL grants, not evidence of deployed Render/AWS permissions.

## Interrupted deletion is still a separate P1 blocker

Historical checkpoint: the subsequent [local recovery batch](deletion-recovery-2026-08-31.md)
adds independent intent and access fencing. Production cloud acceptance is still
required; the failure behavior below describes this earlier batch.

PostgreSQL and an external key store do **not** share a transaction. A failure
after destroying one key can roll back the database transaction while leaving
that key absent. The new injected-failure test confirms that the service returns
no success, operator maintenance detects the mismatch and stays quarantined,
and a controlled retry with the original still-valid owner permit can complete
the exact cascade without decrypting or restoring any key.

That is **not automatic crash recovery or continuous confidentiality**. Until
the operator closes admission, rolled-back plaintext projections can still
exist. Absence from a wrongly selected registry is not proof that the correct
key was destroyed. A database backup can also restore old projections. The
independent, identity-bound deletion-intent ledger and a protocol fencing
ordinary access across interruption/restore must address these gaps before
capture. Do not treat this passing failure test as permission to deploy.

The test injects an exception between key operations; it is not an OS-process
kill, DynamoDB outage simulation, or real-cloud backup restoration rehearsal.

## Migration and admission

Revision `0015_derivation_sources` follows `0014_service_admission` and closes
admission. The current runtime requires exactly revision 0015. Operator
maintenance rejects retained legacy encrypted evidence lacking v3 provenance,
missing payload coverage, mismatched sealed source lists, invalid manifests,
cycles, and deleted support. It neither infers consent nor authorizes deletion.
Readiness remains read-only and does not scan the archive or key registry.

Use the fresh-cluster role/bootstrap and separate maintenance procedure in the
[previous checkpoint](service-boundaries-2026-08-31.md). The SQL grant template
now includes the four new provenance tables. Existing deployments require a
coordinated, reviewed migration/API/plugin rollout with executors stopped; do
not migrate beneath old binaries or reseed the live profile from this worktree.
Legacy grant cleanup and legacy content/residue review remain separate work.

## Verification

Use the isolated PowerShell verification commands in the previous checkpoint;
they run all migrations through the current head. Tests truncate only the
validated temporary databases on loopback ports 54329 and 54330.

Coverage added in this batch includes:

- transitive, multi-conversation reply dependencies and secondary-source memory;
- complete support inherited by corrections and bound into approvals;
- primary-citation substitution that cannot conceal the current turn;
- preserved independent inputs/memories, redacted descendants and exact replay;
- stale projections, deleted sources, late replies and incomplete history;
- append-only source links, sealed metadata consistency and legacy quarantine;
- both archive/deletion concurrency orderings and partial key-store failure;
- canonical source contracts and plugin tracking before text disclosure;
- separate PostgreSQL identities, including denied edge creation by the deleter.

The actual pinned Hermes registry/middleware/output hooks were exercised with
two interleaved sessions in a disposable, network-disabled container. Lookup and
raw-retrieval source tracking passed; no Hermes core changes or model/cloud calls
were needed. This probe does not certify hidden prompt/compaction history.

Final verification:

- **256 tests passed**, zero skips: 110 unit and 146 PostgreSQL integration
  tests, including 18 derivation tests and 89 separate-role/admission tests.
- Both fresh test clusters migrated through `0015_derivation_sources`; the
  separate-role cluster ran migrations as a non-superuser owner. One Alembic head.
- Ruff, strict MyPy (31 source files), Python compilation and Git whitespace
  checks passed.
- Both reply/deletion orderings, both proposal-promotion/deletion orderings and
  the quarantine/admitted-transaction race passed five additional repetitions
  each (25 successful test cases).
- The pinned, network-disabled Hermes provenance probe passed, including
  observed sources, turn binding, registry dispatch and output hooks.
- Two non-failing dependency warnings remain: Starlette's HTTPX test-client
  deprecation and Alembic's legacy path-separator warning.
- Test-container project labels were checked before cleanup. Both disposable
  PostgreSQL containers and their network were removed, discarding only
  synthetic tmpfs data. The live API/PostgreSQL remained healthy and the live
  gateway remained running without restart.

## Next required security work

1. Independent deletion-intent ledger, registry identity and failure/restore
   fencing; then process-crash and real compound restore acceptance.
2. Verified runtime-history reset/resumption with visible off-record state,
   including restart, compaction and hidden-summary source coverage.
3. Independently verified owner events, scope revocation and disclosure limits.
4. Legacy residues, complete budget accounting, cloud IAM/OIDC/KMS/backup tests,
   and owner acceptance before enabling capture.

Future summary, embedding, export or artifact writers must implement the same
source contract and deletion behavior before being added. They do not exist in
the current monolith, and this batch does not claim to delete imaginary stores.

No live deployment, real-data migration, secret access/change, cloud provisioning,
gateway restart, profile reseed, `/opt/data` purge, or transcript activation was
performed. All prior uncommitted work was preserved.
