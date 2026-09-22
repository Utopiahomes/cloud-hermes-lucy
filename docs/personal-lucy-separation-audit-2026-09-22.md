# Personal Lucy separation audit

Date: 2026-09-22. Repository inspected: `a04eef6`.

## Updated scope: basic check accepted for development

Ray subsequently identified `utopia-homes-web` as the likely Tiamat location and explicitly
requested basic separation validation, prioritizing speed. This supersedes the extensive
audit below as a prerequisite for continuing Personal Lucy development. Deep cross-identity
SQL/IAM/restore tests are deferred, not claimed as passed. Existing explicit production
activation and exact personal-import authorization requirements remain in place.

The follow-up read-only inspection found:

- `utopia-homes-web` is the Homes website with a Public Lucy HTTP integration. No Tiamat
  or Dragon implementation/reference was found in the searched application code, scripts
  and Markdown documentation; its identity as Tiamat is unconfirmed.
- Homes' local configuration uses a Supabase endpoint, distinct from both Render databases.
  Its local environment contains no Raymond database connection or Public Lucy configuration.
  The Public Lucy server code requires an explicit enable flag and dedicated endpoint/token.
  This is local configuration evidence, not a fresh Vercel production configuration check.
- The earlier fresh Render checks establish a separate Raymond database resource and a
  different administrator password. No obvious Homes-to-Raymond connection was found in
  this basic inspection. Runtime access denial has not been exhaustively tested.
- The practical unresolved item is Telegram: the active gateway is still configured against
  Utopia's companion service/database. That routing fact is not changed by reducing audit depth.

**Development decision:** the basic check is sufficient to proceed with isolated Personal Lucy
development and synthetic memory work using the existing Raymond resources. Do not rebuild
the database or block that work on locating Tiamat or completing a comprehensive security audit.
Before using Raymond memory through the live Telegram bot, prepare the exact routing/service
activation change and any necessary existing-history treatment for the normal production gate.

Next action under this reduced scope: resume the existing synthetic-memory implementation and
commissioning checkpoint, reusing its passing evidence; resolve Telegram routing as part of the
concrete personal-service activation. The broader checklist below is retained as deferred reference.

## Decision and scope

Personal Lucy remains with Lyra. Ray requests a separate logical database and independent
credentials from Homes and Tiamat, followed by separation proof, a synthetic memory
demonstration, a bounded approved real-history pilot, and only then expanded import.
Separate paid servers are not a requirement. No migration or rebuild is justified by names alone.

This audit performed read-only local inspection and Render API GET requests. It made no
deployment, credential, database, Telegram, import, or provider changes. Saved conversation
content was treated as reference, not execution authority. The supplied HTML contains the
conversation and a link label for `personal-lucy-separation-and-next-steps-v0.1.md`, but not
the specification body; that Markdown file was not found at the top level of Downloads.
This checkpoint is an audit against Ray's explicit request, not a copy of the missing specification.

## Fresh observations

| Boundary | Observed result | Limit |
|---|---|---|
| Raymond database | Render `raymond-lucy-postgres`, resource `dpg-dak5bqad0e5s73b2e3d0-a`, database `lucy_raymond`, available | SQL privileges and contents were not queried |
| Utopia database | Render `lucy-postgres`, resource `dpg-daca8gafngtc73clvafg-a`, database `lucy_6tns`, available | Does not establish which personal records already reside there |
| Database credentials | Administrator connection passwords compared in memory and differ; both administrator login names are `lucy_migration` on different database resources | Runtime credential independence and cross-login denials still need verification |
| Network exposure | Both database public IP allowlists are empty | Not a complete internal network or IAM proof |
| Raymond services | Eight services in `evm-dak5bboae00c73fnvu4g`, all suspended and auto-deploy disabled; environment key inventories contain commissioning flags only | Environment-group inheritance and effective cloud permissions were not audited |
| Telegram gateway | `srv-dai4k467bikc73bhs6r0` is not suspended in Utopia environment `evm-daca8g2fngtc73clv91g`; Stage 2, capture setting true, companion `lucy-routine:10000` | Configuration inspection, not a new message or capture-success test |
| Telegram companion | Active `lucy-routine` points to Utopia database `lucy_6tns` as `lucy_utopia_routine` | No conversation content was accessed |
| Tiamat | No Tiamat mapping found in searched `docs`, `deploy`, or `src` | Tiamat identities, deployment and effective access remain unknown |

**Finding:** separate Raymond database resources already exist. The active Telegram path is
configured against Utopia, not Raymond. Therefore full Personal Lucy separation is not accepted.
This does not establish a content leak or prove that Homes application identities can read the
existing private Telegram content; those are separate permission and data-location questions.

## Historical evidence inspected, not freshly re-executed

- [Cloud head receipt](evidence/raymond-private-memory-head-2026-09-15.json): passed six
  predicates at `ee52a20`; accompanying checkpoint identifies migration 0072, quarantined
  admission, offline lifecycle, capture fence, exact scope and service binding.
- [Outcome recovery receipt](evidence/raymond-memory-outcome-recovery-aws-2026-09-15.json):
  separate Raymond KMS key, registry, receipt ledger and qualified recovery Lambda; rotation,
  table deletion protection/PITR and fail-closed canary recorded. Cross-realm IAM simulation
  remains part of deployed synthetic acceptance. Fresh AWS drift inspection was not run.
- [Import checkpoint](private-memory-import-synthetic-slice-2026-09-12.md): substantial
  synthetic import, candidate, recall, deletion and replay evidence already exists. It records
  a specific 11-conversation, 13-batch pilot authorization under a $2 ceiling and no personal
  upload. Existing authorization must be checked for exact scope, expiry and drift before use.
  Its final commissioning state awaits destination-specific secret installation authorization.
- The older [realm preparation](raymond-private-realm-preparation-2026-09-14.md) is a
  historical planning snapshot, superseded in part by the later commissioning evidence.

## Ordered remaining acceptance

1. Complete the map: identify Tiamat's current deployment and principals; inspect effective
   Raymond/Homes/Tiamat database grants, credential destinations, network boundaries, storage,
   archive and outcome keys, recovery roles, backup retention and restore destinations. Inventory
   current Telegram content location using counts and identifiers rather than private text.
2. Prove denied access using synthetic markers and each actual application/retrieval/recovery
   identity. Test cross-database login, SQL access, memory retrieval, key unwrap, archive access
   and restore/recovery paths. Positive owner access must also pass. Metadata and distinct names
   alone are insufficient. Record exact revision, identities, environment and invalidation rules.
3. Decide the Telegram transition from that evidence. Reuse the existing Raymond database.
   If personal content exists in Utopia, prepare an exact migration and rollback plan preserving
   provenance, deletion fences, keys and recovery journals. Do not copy data or switch the bot
   before the concrete production transition is authorized. Retain a single Telegram consumer.
4. Complete the owner-visible synthetic demonstration in the accepted personal realm: import,
   review, remember, cite the exact source, distinguish user facts from assistant suggestions,
   correct a fact, and forget it across recall and recovery. Reuse passing local evidence where
   code/configuration has not changed; add the missing deployed and Telegram checks.
5. Revalidate the recorded exact pilot authorization, destination, expiry and budget. Complete
   required commissioning and synthetic acceptance before uploading or invoking a provider.
   Demonstrate useful approved memory in Telegram with provenance and recorded spend.
6. Expand only after pilot acceptance and the separate exact bulk authorization.

Shared repository/migration changes require coordination with the Tiamat work. This audit does
not change ownership or send a handoff to another agent. Tiamat is not assumed to receive live
guest queries.

## Verification ledger and next action

Fresh on September 22: Render database identities/status/allowlists, administrator-password
inequality, eight Raymond service states/configuration-key inventories, Telegram routing/capture
settings and companion database binding. All succeeded as read-only checks. No passwords or
conversation content were emitted or saved in this document. These observations become stale
when the associated Render resources/configuration or credentials change.

Not executed: live SQL cross-access tests, current AWS policy/backup review, Tiamat access tests,
new Telegram behavior test, synthetic cloud demonstration, real pilot and migration.

Exact next action: resolve the current Tiamat deployment and principal inventory, then perform
the read-only effective-permission comparison against the existing Raymond and Utopia resources.
The complete separation gate remains open; no rebuild is needed based on the evidence so far.
