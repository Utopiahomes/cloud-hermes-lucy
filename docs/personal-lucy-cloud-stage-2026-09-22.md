# Raymond cloud stage: scoped credentials installed

The correction release has been packaged and checked locally. Ray approved credential
installation on the two named suspended Raymond services and the quarantined schema
migration. Both completed on 2026-09-22. No service activation, personal import or Telegram
change was performed.

## Applied stage and fresh verification

The exact `stage-raymond-synthetic-suspended-v1` command completed with status
`staged_suspended`. Independent Render GET requests then confirmed, for both `policy` and
`routine`: exact service ID, byte-for-byte environment equality with the saved stage
artifact, saved rollback snapshot, `suspended`, auto-deploy `no`, and false capture,
product ingress, executor and intake flags. OpenRouter and Telegram credentials are absent.
Secret values were compared in memory and were not printed. The gitignored state and
rollback files are `secrets/generated/raymond-synthetic-stage-v1.json` and
`secrets/generated/raymond-synthetic-stage-rollback-v1.json`.

## Staging boundary

Run the prepared operator tool to install Raymond's own scoped credentials on these existing
Render private services, keeping both suspended and auto-deploy disabled:

| Destination | Resource | Credentials staged |
|---|---|---|
| `raymond-lucy-policy` | `srv-dak5bd5g1s2s7389ml7g` | Raymond policy database login, Raymond policy signing key/trust, new private gateway token |
| `raymond-lucy-routine` | `srv-dak5bc2d0e5s73b2c8vg` | Raymond routine database login and the same private gateway token; no signing key |

Both services belong to `evm-dak5bboae00c73fnvu4g`. Their database is
`dpg-dak5bqad0e5s73b2e3d0-a` / `lucy_raymond`. Fresh GET-only inspection confirmed both
services are suspended with auto-deploy off. The tool rechecks those predicates before writing.

Local preparation succeeded and printed only configuration key names. It reads neither the
personal export nor its pilot authorization. It installs no OpenRouter or Telegram credential.
Capture, product ingress, pilot executor and pilot intake flags are all false. It does not
change service commands, branches, schema or deployment state, or create cloud resources.
This is inert credential staging; it is not a ready-to-serve runtime or completed cloud demo.

The authorized command that was executed:

```powershell
.\.venv\Scripts\python.exe -m deploy.render.stage_raymond_synthetic --apply --authorization stage-raymond-synthetic-suspended-v1
```

The operator saves the exact previous environments to the gitignored
`secrets/generated/raymond-synthetic-stage-rollback-v1.json` before mutation, saves the new
values separately, reads back each write, and verifies that services remain suspended.
On a failed or uncertain write it attempts restoration for every attempted service, including
the failing one. Saved state prevents an automatic second attempt after an ambiguous failure;
inspect remote state and the rollback snapshot before any retry. No credentials enter logs or Git.

## Release and verification

- Local image: `lucy-personal-memory:0073-20260922`.
- Image ID: `sha256:27a97777d68d895de6811055015cf71cfac4b44f8fd8807bdb79c0da2061e782`.
- Network-disabled image smoke test passed: migrations, bootstrap, head verifier and synthetic
  commissioning agree on `0073_memory_candidate_correction`; executor/proxy modules import;
  `/app/secrets` and `/app/.env` are absent.
- Fixed two stale `0072` pins in the head verifier and commissioning tool. Their 34 focused
  unit tests, Ruff and strict mypy pass. The earlier 99 passing checks remain applicable to
  unchanged portions of this increment.
- Three new staging tests pass: local preparation without network/provider/pilot dependencies,
  authorization before cloud access, and restoration of both environments after an uncertain
  second write. Ruff and strict mypy pass for the staging operator.
- Schema/runtime sources in this image are based on `a04eef6` plus the current local increment;
  source is locally committed as `92c75b6fac5dabe795dafc15716637e8440d35a8` on
  `codex/personal-lucy-memory-20260922`. The image is locally built, not deployed. The
  staging tool is a local operator utility, not copied into the service image.

Ray explicitly approved publishing the branch after the initial automatic approval rejection.
`codex/personal-lucy-memory-20260922` is published at verified remote commit
`d126f7064c58acdb644fbf14f4def78353f49996`. The credential stage and rollback files
remain ignored by Git.

## Completed quarantined migration

The local, gitignored operator `secrets/generated/_migrate_raymond_memory_0073.py` pins that
commit and the Raymond database ID. Its read-only preflight passed on 2026-09-22: the two
existing services are still suspended, their environments match the saved stage, no temporary
migration service existed, and the private migration URL targeted `lucy_raymond` as
`lucy_migration`. Ruff, strict mypy and compilation passed.

The first authorized attempt created a temporary Render service, but Windows Application
Control blocked the local Render CLI before deployment. The operator deleted that service;
an independent GET found none and the saved state had no job ID. The retry used the Render
API to deploy the pinned commit. Its migration job and separate read-only six-check head
verifier job both reported `succeeded`. The migration command verifies revision `0073`,
quarantined admission, a safe capture boundary and no residual schema CREATE authority before
exiting successfully. The head verifier runs all six predicates in a read-only transaction.
The saved job state is gitignored at `secrets/generated/raymond-memory-migration-0073-state.json`.
Render's logs API returned 403 for this token, so the evidence is the two terminal job
statuses and the independent post-run GET, not the job's printed JSON receipts. That GET
confirmed no temporary service remains and both policy/routine services are suspended.
The executed invocation was:

```powershell
.\.venv\Scripts\python.exe secrets/generated/_migrate_raymond_memory_0073.py --apply --authorization migrate-raymond-quarantined-memory-0073-v1
```

Next prepare the bounded synthetic cloud execution. Preserve
the additive correction ledger on rollback; suspend services and quarantine admission rather
than downgrading it. Public intake, actual history and Telegram cutover remain later steps.

## Disabled pilot configuration and renewed proposal

On 2026-09-22, a fresh **non-authorizing** pilot proposal was built locally from the same
11 selected conversations. The local ZIP commitment and every selected manifest record match
the prior approved bundle; destination, route and limits are unchanged. It has a new campaign
ID and exact bundle digest `15b2d1f70e50920d4605862d5c6772a8e28b24003681b5101671648813312b24`,
expires 2026-09-29 23:25 UTC, and retains the $2 cumulative spend ceiling and 20-attempt
limit. Files are in Ray's protected `chatgpt/2026-09-22-renewal` intake directory. The
proposal grants **no authority** to upload or process real history. The model route is still
listed by [OpenRouter](https://openrouter.ai/google/gemini-3.1-flash-lite); endpoint policy and
price must be rechecked immediately before any real provider request.

Ray approved use of the existing shared OpenRouter billing key for **synthetic demonstration
only**. A local operator prepared the two exact Raymond service environments from that
proposal, the prior scoped-credential stage and Raymond AWS bindings. The executor startup
configuration parsed successfully with activation simulated locally. Three focused staging
tests, Ruff and strict mypy passed. The disabled config was then applied to the two existing
suspended services using `stage-raymond-disabled-pilot-suspended-v1`. Independent Render GETs
confirmed exact environment equality and that both services remain suspended, with capture,
product ingress, pilot executor and pilot intake all false. A gitignored rollback snapshot and
stage receipt are saved under `secrets/generated/raymond-disabled-pilot-*20260922.json`.
No service command, branch, deployment, provider request, personal-data import or Telegram
route changed.

Next prepare the bounded synthetic cloud runner and its exact rollback, then commission only
the synthetic boundary. Real-history execution requires a fresh exact owner authorization
for the new digest and a separate decision on the provider credential; this shared-key
approval does not cover real history.

## Deployment boundary found during preparation

The two existing Raymond services are still on `codex/r1-tenant-foundation`; a read-only GET
found their latest deploys canceled. Ray approved an exact attempt to deploy commit
`39d285924dd5caa91d85ebea05479cee446ad3b8` while both remained suspended. The
operator saved the prior branch and commands and tried the policy deploy first. Render
returned HTTP 400, `cannot deploy suspended service`, before any new build started. The
operator restored both prior configurations, and an independent GET confirmed both services
remain suspended on their original branch and commands, with no new deployment. The
gitignored receipt is `secrets/generated/raymond-synthetic-deploy-state-v1.json`.

Ray subsequently authorized a bounded synthetic activation. On 2026-09-22, the temporary
Raymond-only Render job verified the quarantined `0073` head, ran the audited empty-realm
recovery, and opened admission with capture disabled. An initial recovery job failed because
the new command was absent from the Docker image's explicit copy list; commit `188f9d1`
added it, and the corrected job succeeded. The existing policy and routine services then
deployed exact commit `188f9d1a00a81f297d991e3ad447c5f8aada3350` and reached Render
`live`. A same-network one-off check of both private `/ready` endpoints succeeded. The two
services were suspended again, the quarantine job succeeded, and the temporary utility was
deleted. Independent Render GETs confirmed both services suspended, capture, product ingress,
pilot executor and pilot intake all `false`, and no temporary utility remaining. The
gitignored job and deploy receipts are `secrets/generated/raymond-synthetic-activation-state-v1.json`
and `secrets/generated/raymond-live-deploy-state-v1.json`.

This is deployed startup/admission evidence, not a cloud import/remember/correct/forget
acceptance. The local synthetic memory flow passed separately; the cloud synthetic import
still needs its purpose-built runner. No Telegram route, real-history import or provider call
was part of this activation. The lifecycle is now `ready` after audited recovery, while
runtime admission is quarantined; the former offline-head verifier's lifecycle predicate is
therefore intentionally stale. A future opening must recheck admission and service state.

## Authorization and blockers

Automatic approval review rejected execution of the historical mixed-purpose commissioning
helper, even in its requested preflight mode, because it can persist secrets and Render service
configuration without explicit destination authorization. It was not executed. Ray then
explicitly approved the two destination services and a narrower operator staged them. The
subsequent independent read-only verification passed.

The saved real-history pilot authorization expired at `2026-09-21T16:09:00Z`. It cannot be reused
for real import. It was inspected only for authorization metadata; no conversation data was read.
Synthetic preparation is independent of that authorization. A real pilot needs a fresh exact
authorization after the cloud demonstration, with the existing $2 budget proposal revalidated.

## Raymond early-file pilot completed (2026-09-23 UTC)

Ray explicitly approved the prepared 11-conversation, 474-included-record ChatGPT pilot and
its $2 campaign cap in this task. The exact bundle digest was
`15b2d1f70e50920d4605862d5c6772a8e28b24003681b5101671648813312b24`, campaign
`c1800ec3-1158-42f0-bb0b-46a04df7a65c`, scoped only to Raymond's `lucy_raymond`
database. This supersedes the older expired-authorization note above for this exact pilot.

The registered 13 batches ran through a temporary Raymond-only HTTPS intake. A deployed
read-only count at commit `a6d02d7` found **474 active archived source records**, **32 pending
candidate versions**, and settlements of 10 succeeded batches ($0.090930) plus 3 discarded
batches ($0.027214): **$0.118144 total**, under the $2 cap. The discarded batches archived
113 of the sources but produced no pending candidates; their exact jobs are final and must
not be replayed for another provider call. Invalid model drafts were excluded from later
batches only when their claimed quote or source failed the existing exact checks; all 32
saved candidates retain verified source spans. The local protected review directory contains
9 review artifacts with 32 items. No candidate has been approved or promoted to remembered
memory, and Telegram was not enabled. Source archive is complete; memory review remains.

Verification ledger: `tests/unit/test_memory_pilot_transport_runner.py` (5 passed at
`7fdd510`), deployed Raymond diagnostic job `job-dapj46jbc2fs73atef60` (passed at
`a6d02d7`), and protected local `pilot-tail-receipt.v1.json` plus the review artifacts
under `C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-22-renewal`.
The deployed count remains valid unless the Raymond database or campaign rows change;
the local test result remains valid unless transport completion code or dependencies change.

After verification, both private Raymond services were suspended, pilot executor and intake
flags set false, and the temporary HTTPS intake plus three temporary Render cron utilities
deleted. Capture and product ingress stayed false. The next step is human review of the
32 pending candidates, followed by the already-designed remember/correct/forget acceptance
checks. Any re-extraction of the three discarded batches needs a new exact campaign and
freshly bounded authorization; their archived source records need no re-import.

## Pending-memory interpretation review (2026-09-22 local)

Ray accepted the evolving-interpretation architecture as a working baseline and chose to
test the 32 pending pilot candidates before applying it to other ingested material. The
protected pilot directory now contains `candidate-recall-prototype-v0.1.md`, derived from
the v0.2 contextual review, and `candidate-recall-dry-run-v0.1.md`. The compact prototype
has 32 dated entries and primary evidence links; exact neighboring-turn references were
added for the decisions and endorsements that depend on them. A read-only local digest and
structure check passed against the authorized export, and eight nuanced question/answer
examples were reviewed as expected behavior. This was a **human dry run**, not a test of
deployed Lucy's retrieval or revision behavior. No candidate was approved or promoted,
the Raymond services were not changed, and no provider call was made.

Next, run the same cases through a local retrieval prototype with controlled corrections,
then assess all 32 before broader interpretation backfill. Keep the three views derived
from one versioned record, and retain source and neighboring-turn links. Do not treat the
compact review artifact as live memory or the dry run as runtime acceptance.

## Offline recall probe completed (2026-09-22 local)

The protected pilot directory now also contains `candidate-recall-local-probe-v0.4.json`
and `candidate-recall-local-test-v0.1.md`. A deterministic local prototype indexed the
32 compact pending interpretations with their primary evidence IDs. One independently
phrased query for each candidate found the intended item in the top three 32/32 times
and first 28/32 times. All eight nuanced review queries retrieved their expected
item or pair within the specified window. Three **hypothetical** correction scenarios
created new in-memory versions while preserving prior wording, source links and all
five independent assessment dimensions; unchanged dimensions stayed unchanged.

This is smoke-test evidence for retrieval and revision data handling, **not** an
end-to-end Lucy answer, citation, current-status or forgetting test. The four first-rank
misses involved related concepts (Gate/Magician tags, Lucy/Lyra origin dates,
SC Consulting site/Wix advice, and LLC manager/equity proposals). The next required
behavioral check should resolve such related hits by question context and produce
cited answers under explicit historical/current and correction scenarios. The 32
candidates remain pending; no Render service, provider, Telegram route or live memory
was changed. Broader interpretation backfill remains deferred until that behavioral
check and candidate review.

## Local answer/citation preparation (2026-09-23 local)

The protected pilot directory now contains `candidate-answer-and-revision-check-v0.2.md`.
Thirteen question-sensitive answer targets were written against the pending compact
interpretations. The local top-three retrieval set included every selected item, and
all 27 primary/neighbor citations (20 distinct turns) in the examples were verified
against the authorized source manifest; none was outside the 474 imported records.
The examples include the four earlier first-rank ambiguities. Three isolated,
**hypothetical** corrections passed an explicit current-versus-historical version
selection check: current questions selected version 2, dated historical questions
selected version 1, and original source IDs were preserved. The hypothetical claims
are not Ray statements.

This is a local target/evidence check, not Lucy-generated output or deployed behavior.
The 32 candidates remain pending and both Raymond services remain unchanged. The
shared OpenRouter billing key was authorized for synthetic demonstration only; this
check sent no personal history to it. A true model answer test on these 32 requires
an explicitly authorized personal-history model route and a local shadow path that
does not promote candidates or enable Telegram.

The exact local shadow packet is prepared at
`candidate-shadow-answer-packet-v0.1.json` (SHA-256
`5b472e45298baa7f25c842bf4dcf6812edf7d2fe81fcf077372ec8cda712eea2`):
13 questions, selected exact excerpts, maximum 350 output tokens per call and
$0.25 total spend. Its runner dry-run passed with no credential read or network call.
The model route is the pilot's `google/gemini-3.1-flash-lite`, with ZDR,
data-collection denial and no fallback requested. At preparation time, the live
call awaited Ray's decision to extend shared-key use beyond synthetic data; that
exact approval and execution are recorded below.

## First shadow answer test completed (2026-09-23 local)

Ray approved the **exact** 13-question v0.1 shadow test using the shared OpenRouter
key for this real-history evaluation. It ran all 13 calls; the protected receipt is
`candidate-shadow-answer-receipt-v0.1.json`, with estimated spend **$0.005459**
against the $0.25 ceiling. No candidates were approved/promoted, no Telegram or
Render services changed, and no hypothetical correction was sent as a Ray fact.
The strict human review is in `candidate-shadow-answer-evaluation-v0.1.md`:
3 clean answers, 3 partial and 7 failed. The failures include treating a past tag
as current, promoting an assistant LLC recommendation to a fact, overstating draft
data rights, and losing revenue details or Ray's uncertainty because the first
packet supplied excerpts that were too narrow. Several long citation IDs were
truncated or shortened in model output.

A corrected packet was then prepared at
`candidate-shadow-answer-packet-v0.3.json` (SHA-256
`36918d1c8ae3c97f063feee608068bf699094f28f9f2bd4bf34f5dffc325cac9`).
It supplies the compact interpretation as a reviewer summary, broader exact turns
for the missing evidence, and short `[E1]` citations mapped locally to full source
IDs. Its 13-call, 500-output-token, $0.25 runner dry-run passed without reading a
credential or making a network call. The v0.1 approval was consumed by the first
test; Ray's separate approval and the v0.3 execution are recorded below. Keep
the 32 candidates pending until answer quality and human candidate review pass.

## Corrected shadow answer test completed (2026-09-23 local)

Ray explicitly approved the corrected v0.3 real-history packet using the shared
OpenRouter key under a new $0.25 cap. All 13 calls completed. The protected receipt
is `candidate-shadow-answer-receipt-v0.2.json`; estimated spend was **$0.004087**
for this run and **$0.009546** across both runs. The mechanical short-citation
check found valid mapped labels in 13/13 answers; its corrected report is
`candidate-shadow-answer-citation-check-v0.3.json`. Human semantic review is in
`candidate-shadow-answer-evaluation-v0.2.md`: **8 pass, 2 partial, 3 fail**
against the same strict targets.

The corrected evidence package resolved the omitted 80/3/12/5 figures and Ray's
Philodelphio uncertainty. Remaining failures concern the scope of a short tag
confirmation, the assistant origin of an 85% equity proposal, and whether Ray
or Lucy stated Lucy's exact origin date. The next local implementation should
encode confirmation scope, proposer identity and exact-date attribution as
structured fields in the one versioned interpretation, then test answer behavior.
No candidates were promoted and no service, database or Telegram route changed.
Do not backfill the other ingested material from these results alone.

## Structured interpretation baseline prepared (2026-09-23 local)

The 32 pending candidates now have a protected, local structured baseline in
`candidate-structured-interpretations-v0.1.json` and a human-readable review at
`candidate-structured-interpretations-review-v0.3.md`. The baseline has one
version per candidate, linked exact excerpts from 37 source turns in the 474-record
authorized import, and independent support, counterevidence, owner-endorsement,
present-applicability, and remembering-value assessments. All 32 are explicitly
`not_checked` for current applicability. The model distinguishes source speech act,
proposer, owner confirmation scope, and exact-date speaker/source. The Gate dual-tag
item is marked ambiguous, the May 21 Lucy date assistant-stated, and the 85% equity
structure an unconfirmed assistant recommendation. Ray's owner-authored revised
economics turn remains separate from the equity recommendation.

`src/lucy/memory_interpretation.py` defines a validated versioned record and an
answer-context view; `tests/unit/test_memory_interpretation.py` checks history/current
recall, confirmation, attribution, revision history, and evidence integrity. Six
focused unit tests passed; Ruff and strict mypy passed for the new module. The local
protected baseline checker validated 32 distinct candidate IDs, 37 included source
IDs, one ambiguous and three partial confirmations, and the three earlier failure
cases. This is local preparation only; no candidate was promoted and no deployed
service or Telegram route changed.

A third 13-question shadow packet is prepared at
`candidate-shadow-answer-packet-v0.4.json` (SHA-256
`61ef3b56f875f742f24651026beffded1d2c1d07df70bc456b4bfab70ec0513b`).
It feeds the new structured fields and 28 exact evidence references into the same
historical questions, with at most 13 calls, 500 output tokens per call, a $0.25
total ceiling, the prior `google/gemini-3.1-flash-lite` route and ZDR/data-collection
denial/no-fallback policy. Packet and one-shot runner dry-runs passed: zero network
calls and no credential read. The earlier one-time authorizations were consumed;
Ray's separate v0.4 approval and execution are recorded below. Keep all candidates
pending until human review. Do not backfill other ingested material from these
local checks alone.

## Structured shadow answer test completed (2026-09-23 local)

Ray approved the exact v0.4 real-history packet above for a one-time provider test.
All 13 calls completed; `candidate-shadow-answer-receipt-v0.3.json` records estimated
spend **$0.00468250** against the $0.25 cap. Estimated total across all three runs
is **$0.01422850**. The mechanical short-citation report is
`candidate-shadow-answer-citation-check-v0.4.json`: valid mapped source labels in
13/13 answers. Human semantic review in `candidate-shadow-answer-evaluation-v0.3.md`
finds **12 pass, 1 partial, 0 fail** against the established targets. The structured
fields fixed all three prior strict failures: Gate confirmation scope, assistant
origin of the 85% recommendation, and assistant attribution for Lucy's exact May 21
date. The remaining partial is temporal wording: a historical Philodelphio answer
said Ray “has not settled,” implying today's state from a past exchange.

The one-time v0.4 provider authorization is consumed. At this checkpoint, the 32
candidate versions were still pending, and the other ingested records had not been
reinterpreted. That shadow run made no promotion, production database, Render
service, or Telegram change. Ray's later batch-promotion decision and execution
are recorded below.

## Reviewed batch promotion in progress (2026-09-23 local)

Ray authorized moving the reviewed 32-item batch into Personal Lucy's private memory.
The existing extracted candidates cannot be promoted as-is: all 32 are marked
`current`, and every original claim object differs from the reviewed historical
interpretation. The local, protected proposal
`candidate-interpreted-promotion-proposal-v0.1.json` instead contains 32 immutable
candidate version-2 projections. Each keeps the original candidate identity and
source provenance, adds reviewed neighboring source links, stores the five separate
assessment dimensions and attribution/confirmation fields as bounded structured
JSON, and is marked `historical` / `attributed_interpretation`. It has 52 source
links, maximum object length 2,002 characters, and proposal SHA-256
`fc2085b497de87d8da997159c2416cb1411e1f33b91007c0d4ea7558901fc36c`.
At preparation time this was a local proposal; its cloud execution is recorded below.

The Philodelphio temporal boundary is explicit in the answer-context contract.
Seven focused interpretation/projection unit tests, Ruff, and strict mypy pass.
The one-time cloud operator `promote_raymond_interpretations_v1.py` has a staged
routine-login phase and a single-transaction policy-login approval/promotion and
protected-recall verification phase. Its exact proposal decoder passed locally
with no database or provider call. Fresh Render GET checks found both Raymond
services still suspended, auto-deploy off, capture/product/pilot flags false, and
the expected distinct `lucy_raymond` policy/routine logins. The operator has not
run at this checkpoint. No Telegram or service activation was planned for this batch.

## Reviewed 32-item batch promoted and verified (2026-09-23 cloud)

Ray's “go for it” authorized promotion of the reviewed batch. The exact protected
proposal above was staged as candidate version 2 under the Raymond routine login
using temporary Render job `job-daprtlegekts73f058m0` at commit `0bb2470`.
All 32 stage calls succeeded in one transaction. The policy identity then approved
and promoted all 32 in one transaction with built-in protected recall checks using
job `job-daprv1u7bikc738jqm00` at commit `ddb30ce`. Before that transaction, a
local check found that two broad subject queries could exceed the recall limit;
the operator was changed to use each source candidate's unique digest and verified
locally to find exactly one item per query.

A separate post-commit policy job `job-daps0gm7bikc738juif0` at commit `bbc5fea`
recalled all 32 through `lucy.search_protected_scoped_memory_v1` and confirmed the
exact reviewed structured object, `protected` class, `historical` epistemic status,
`attributed_interpretation` assertion status, and all 52 expected source-evidence
links. The protected recall function wrote its normal access audit rows. No model
provider or Telegram call was made by these jobs. Independent Render GET checks
afterward confirmed both Raymond services still `suspended`, auto-deploy `no`,
capture and product ingress false, and all three temporary utilities deleted.
The original 32 version-1 extraction candidates were not promoted.

This is database promotion and source-linked recall evidence, not evidence that a
live Telegram answer path consumes the new structured JSON yet: both services are
still suspended and their long-running builds were not changed by temporary jobs.
The local synthetic correction tests at schema `0073` remain valid, but no new
correction to Ray's real memories was invented merely to test that path. A later
real correction should create a new version from new evidence while retaining the
historical source and the earlier interpretation. Broader interpretation backfill
remains separate from this 32-item pilot.

## Cited interpretation context verified (2026-09-23 cloud)

`src/lucy/interpreted_recall.py` now converts a reviewed protected claim into a
bounded answer context with explicit speech act, proposer, confirmation scope,
five independent assessments, current-applicability boundary, exact-date speaker,
and citations tied to the claim's evidence UUIDs. It rejects a missing or extra
source link, a mismatched exact-date speaker, an unprotected claim, and a claim
outside the reviewed version-2 historical interpretation shape. This is an
internal policy-side function; it does not itself authenticate a Telegram user.

The exact protected 32-item proposal passed a local aggregate check: 32 contexts
and 52 mapped citations. Eleven focused interpretation/recall tests, Ruff and
strict mypy passed at commit `4d9b92d`. The first temporary cloud check built but
failed; inspection found that `Dockerfile` did not copy its operator module.
The utility was deleted. After that packaging fix at `7eac357`, the new one-time policy-login job
`job-dapuhjnlk1mc73cv70a0` succeeded. Its program checked all 32 recalled
interpretations, temporal boundaries and 52 citation links against the exact
promoted proposal. It made zero provider or Telegram calls; normal protected
recall access audits were written. The temporary utility was deleted. Fresh
Render GET checks confirmed both Raymond policy and routine services remain
suspended with disabled ingress/capture and neither temporary utility exists.
The gitignored receipts are
`secrets/generated/raymond-interpreted-context-check-state-v1.json` (failed
packaging attempt) and `...-state-v2.json` (succeeded).

This validates the policy-side database-to-answer-context path, not a live
Telegram answer. The active Telegram gateway remains on Utopia, and the Raymond
services have no Telegram bot credential or owner-event route for protected
recall. The existing generic `/v1/memory/lookup` reads the older ordinary
projection and must not be used to expose Raymond's protected content. Next,
resolve whether Ray wants a separate Personal Lucy bot or an exact cutover of
the active bot, then bind authenticated owner events to this policy-side recall,
perform a synthetic deny/allow check, and activate only that reviewed route.
This evidence is invalidated by changes to the 32 promoted claims, campaign
source revisions, protected recall contract, interpreter, or policy database
identity. The citation mapper assumes source revision 1 for this pilot; future
mixed-revision imports need an explicit source-ID map.

## Current-bot Raymond cutover preparation (2026-09-23)

Ray chose to move the current Telegram bot from Utopia to Raymond. The fresh
Render route inventory found gateway `srv-dai4k467bikc73bhs6r0` active in the
Utopia environment with Stage 2 capture enabled, using `lucy-routine:10000` as
its companion. That companion is active on Utopia's database. Raymond policy and
routine remain suspended, capture/ingress disabled, and have no Telegram bot,
allowlist, or adapter token staged. Both identities are on the Personal Lucy
branch. Utopia's adapter credential differs from Raymond's policy credential.

A temporary Utopia administrator-login job at `63bc413` completed a count-only
inventory without reading message content. It found eight Telegram turn rows
across eight conversation identifiers, three marked committed, eight capture
receipts marked retained, 16 Telegram-labeled evidence rows, and six evidence
payload rows. These are metadata counts, not a statement that all 16 rows are
complete or portable. The first two count jobs failed before reading counts;
the second exposed the bundled psycopg-driver mismatch, which was fixed. All
three temporary utilities were deleted. The succeeded job's gitignored receipt
is `secrets/generated/utopia-telegram-history-count-state-v3.json`. Ray chose
not to move this earlier archive to Raymond. On 2026-09-23 he explicitly
authorized deleting the old Utopia Telegram archive. This does not include
Raymond's imported ChatGPT evidence or 32 protected interpretations. Deletion
has not yet been performed.

A follow-up read-only exact-target inventory at `cfac540` succeeded in a
temporary Render job (full job ID and exact UUIDs in the gitignored receipt
`secrets/generated/utopia-telegram-deletion-inventory-state-v2.json`); its
utility was deleted. It found 16 Telegram evidence records: 10 already
tombstoned without payloads and six with encrypted payloads, all linked to
recorded Telegram turns. There were no payload/tombstone coverage anomalies.
No message content was read. The first utility attempt stopped at a
short-vs-full commit check before running any database job; it was deleted.

Utopia's policy and deletion services are suspended. The legacy `/owner/v1`
single-evidence deletion endpoint is deliberately unavailable in production
(`_require_legacy_sensitive_api_allowed`); the V1.3 `/owner/v3` endpoint is
for scoped evidence, whereas these six records are in the older
`lucy.evidence`/`lucy.evidence_payloads` archive. Direct SQL deletion would
leave wrapped encryption keys and recovery copies and is not a valid completion.
Subsequent read-only jobs at `c03a6a7`, `13aab59`, `08a452c`, and `d39f322`
expanded the inventory; their exact receipts are gitignored under
`secrets/generated/utopia-telegram-*-state-v*.json`, and each temporary
utility was deleted. They establish that **all 16 legacy records are labeled
cloud-acceptance probes**, including the six encrypted payloads. A direct
comparison with the numeric Telegram home-chat ID found no legacy or scoped
matches, but that comparison is not a reliable owner selector: the Hermes
plugin archives its session ID, not the numeric chat ID. The scoped
`owner_conversation` archive has six records, two each dated September 10,
12, and 14. The September 10 pair matches the V1.3 synthetic acceptance
receipt. One of that pair has an existing deletion fence and operation state
`FINALITY_PENDING`, so its remaining PostgreSQL payload/wrapper metadata does
not prove its wrapped key still exists. The September 12 pair aligns with the
documented live owner retained round trip; the September 14 pair still needs
source/session classification. No message content was read.

Do not treat the earlier total of six legacy encrypted payloads as six private
owner messages. The immediate deletion target is the actual owner conversation
inside the scoped archive, identified by the immutable scoped archive intent
and Telegram event/session metadata; preserve the synthetic acceptance
fence/recovery history. The production V1.3 deletion route requires a fresh
broker-signed owner assertion, which the Telegram gateway does not yet issue.
An exact manual owner-broker path must be commissioned before invoking the
existing manifest-bound, key-destroying V1.3 deletion workflow. Stop Utopia
capture at the bot handoff before the final inventory/sweep so new records do
not replenish the archive. The legacy synthetic probes can be cleaned up
separately only through a key-destroying legacy operator; they are not evidence
of Ray's private Telegram messages.

The new, default-disabled `/v1/memory/interpreted-lookup` route in Raymond's
routine identity calls a separate policy-only protected-recall endpoint over
the private Render network. It requires the Raymond adapter token at the routine
boundary and the separate Raymond policy gateway token at the policy boundary;
the feature flag and exact expected database login prevent the route from
appearing on Utopia. The Hermes memory tool uses this route only for an active
private turn when the flag is enabled. It returns dated interpretation contexts
and mapped evidence labels, with a prompt instruction to avoid asserting
unverified present truth. No raw evidence retrieval or automatic memory write
is added. Seventy-six focused API, plugin and interpretation tests, Ruff and
strict mypy passed locally. Neither long-running service has been deployed or
resumed with this route, and the Utopia bot continues its existing behavior.

Cutover still requires a Raymond Telegram channel binding and durable authority
activation, owner allowlist and separate gateway adapter credential, and a
one-bot handoff. Ray's authorization to delete the old archive does not require
migrating it to Raymond.
The existing Utopia Stage 1 commissioning operator hardcodes Utopia identities,
so it cannot safely commission Raymond as-is. Raymond authority writer and
recovery coordinator are still suspended configuration shells. Do not redirect
the active bot to the current Raymond routine service: it would fail the
Telegram lease/retention boundary and could interrupt replies. Retain the old
archive only until the authorized, key-destroying deletion completes.
