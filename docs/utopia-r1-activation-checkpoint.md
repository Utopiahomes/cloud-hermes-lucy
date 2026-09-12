# Utopia R1 activation checkpoint

Status: Private Telegram Stage 2 production acceptance passed on 2026-09-12 at exact
application release `e6f66d3c2aa1b2b17bedcae1b67a4cd613346067` and PostgreSQL revision
`0054_stage2_scoped_turn_commit`. Encrypted private-Telegram evidence capture is active;
automatic memory writes and raw-evidence retrieval remain disabled. Public Lucy remains
disabled and unprovisioned. Its local implementation is ready for a separately authorized,
fail-closed public activation. The complete private record is
`docs/private-telegram-stage2-implementation-2026-09-11.md`.

## Completed preparation

- R1-0 through R1-5 technical acceptance passed at commit
  `d43f7e67cb5cd9e26a4ce1eafa5009d20671260d`.
- A fail-closed activation manifest, validator, template, and seven focused tests were
  added at commit `9724b220dfdd0f5ccf1dcc78a6c8f95bfc724d6f`.
- The validator requires exact source/rollback/image/schema/AWS pins, exact HTTPS
  origins and hostnames, bounded rates, an approved public snapshot, and complete
  provider-cost limits if paid inference is enabled. A `public_only` activation now
  requires no customer IdP, no private hostname, and paid inference off; it still
  cannot authorize transcript capture.
- A quarantined rollout attempt confirmed the operational fence: Render built the exact
  candidate, but the ordinary runtime correctly refused admission while PostgreSQL was
  quarantined. Cleanup re-suspended all four ordinary services. The PostgreSQL public
  allow-list remained empty and no capture, provider call, public route, or data change
  occurred.
- Read-only inspection of `C:\Users\Forti\Projects\utopia-homes-web` found a public
  Vercel/Next.js site with no implemented Clerk, Auth0, Cognito, Entra, Auth.js, or other
  customer login. Its local `NEXT_PUBLIC_SITE_URL` remains `http://localhost:3000`;
  production DNS is intentionally outside that repository's committed configuration.
- The website now contains a disabled, same-origin `/api/lucy` proxy and accessible
  widget. Ray approved its exact eight-answer V0 snapshot with SHA-256
  `6232b5fa0b382346fba692f29e74d2b3fdbcd9a19ee960d2e609fd0b2ce2b99e`.
- Cloud Lucy now has a separate `lucy.public_runtime` ASGI process, a dedicated
  `lucy_utopia_public` execute-only PostgreSQL identity, and migration
  `0052_r1_public_answer_gate`. The answer path rechecks lifecycle, admission, storage
  epoch, login-derived realm, hostname, origin, bearer, body, and rate boundaries.
  The reviewed Render change remains an example and has not provisioned anything.

## Owner decisions recorded

1. First customer-facing website scope: Public Lucy only. The already commissioned private
   Telegram surface remains operationally and cryptographically separate; it is not a
   customer identity provider or a browser fallback.
2. Browser boundary: `https://www.utopiahomes.com/api/lucy`, using a same-origin website
   proxy and a separate authenticated Cloud Lucy upstream.
3. Public knowledge: only the exact approved V0 website snapshot and lineage above.
   Its canonical Cloud projection payload is
   `deploy/render/utopia-public-projection.v0.json`.
4. OpenRouter/paid inference: disabled for this first launch.
5. Transcript capture: disabled.

## Exact next action

Prepare the digest-pinned Public Lucy provisioning and activation artifact against schema
`0054_stage2_scoped_turn_commit`, then review it before any production mutation. Production
migration, Render provisioning, projection publication, website enablement, DNS changes, and
live endpoint checks still require explicit authorization.

## Current Public Lucy reconciliation ledger

- Repository drift review: passed at
  `a3a624211c389804ad707e87df866161f3afb6ad`; Private Stage 2 changes do not merge the
  public runtime with the private archive or gateway processes.
- Public activation manifest: advanced from superseded schema `0053` to exact current head
  `0054`; a regression check rejects the former revision.
- Cloud static/unit checks: Ruff passed; strict mypy passed across 79 source files; the
  complete 748-test unit suite passed before the manifest correction, followed by 61 focused
  public/manifest/Render tests after it.
- Website checks: TypeScript, repository-wide ESLint, all 84 Vitest tests, and the 27-route
  Next.js production build passed.
- PostgreSQL integration rerun: passed after recoverably moving two corrupt Docker AF_UNIX
  runtime directories aside. A fresh `0001`-to-`0054` migration and six focused public and
  realm-role checks passed on the loopback-only tmpfs PostgreSQL stack. Any migration, role,
  or readiness change invalidates this evidence.

## Stage 1 verification ledger

- Fresh PostgreSQL migration `0001` through `0053`: passed locally on 2026-09-11.
- Channel activation/withdrawal acknowledgement, execute-only role denial, and exact
  quarantined replay: 14 focused checks passed locally on 2026-09-11.
- Complete unit suite: 677 passed; Ruff and mypy passed on 2026-09-11.
- Realm/recovery role stamps and Telegram lease/dedup/budget boundary: 4 focused
  PostgreSQL checks passed on 2026-09-11.
- Production migration to `0053_r1_telegram_authority`: passed on Render at commit
  `805ee5f3a478ec46674d7ff2322812cc610c8a85`; admission remained quarantined,
  capture-safe was true, and residual function-owner schema CREATE was false.
- Compatible recovery services: authority writer, cost writer, and acknowledgement
  coordinator deployed and private readiness probe completed on 2026-09-11.
- Production Telegram binding: provisioned and independently journal-acknowledged on
  2026-09-11; replay verification passed at commit
  `01773c9200afe737b50e32ae5c02faf8bc4f74f8` with channel generation 2, admission
  quarantined, and capture disabled.
- Render gateway resource: created suspended and credential-free with auto-deploy off.
- The ignored, identifier-bearing Stage 1 activation manifest was built and validated
  at source commit `01773c9200afe737b50e32ae5c02faf8bc4f74f8`; it pins the reviewed
  Hermes release/image/platform/source, rollback commit, schema, realm, gateway, budget,
  one-consumer rule, capture-off rule, and memory-write/evidence-retrieval prohibitions.
- Render configuration inspection after the interrupted secret installation confirmed
  that both services remained suspended and capture-safe. After explicit authorization,
  the existing local adapter token was installed on both services and the bot/OpenRouter
  credentials were installed on the gateway. Exact key-shape and token-match inspection
  passed without emitting values.
- The first admission attempt built exact commit
  `01773c9200afe737b50e32ae5c02faf8bc4f74f8` and failed closed because the database
  reported a capture blocker. Admission stayed quarantined and temporary database
  credentials were cleared. The commissioning command now emits specific content-free
  blocker codes; its 15 focused tests, Ruff, and strict mypy pass locally.
- Exact receipt reconciliation named only the preserved R1-2 synthetic cloud-acceptance
  receipt; after adding that exact conversation/turn pair to the ignored commissioning
  exception list, all capture blocker codes cleared. No receipt was mutated or erased.
- Read-only status then reported two unresolved items and one expected 30-day deletion
  finality item. The unresolved query was counting expired, never-claimed permits as live
  indefinitely. It now blocks only still-claimable issued permits while continuing to
  block every claimed/ambiguous operation; expired unclaimed permits remain separately
  counted for audit. Sixteen focused tests, Ruff, and strict mypy pass locally.
- Owner transport and inference passed through the active cloud gateway. The owner event
  produced one model operation and one successful settlement, with no new capture receipt,
  evidence, scoped memory, or legacy memory row.
- Restart recovery and post-restart duplicate replay passed: the new lease fence advanced,
  the old delivery remained sent, the replay was not admitted, and no second operation was
  created.
- The deployed numeric allowlist and focused pre-inference unauthorized-owner test passed;
  a second live Telegram account was not used.
- The final cloud-boundary check passed all 12 assertions and found neither conversation
  content nor deployed secrets in 600 sampled Render log messages.

## Current blocker

None for Stage 1 private Telegram use. Stage 2 transcript capture remains intentionally
unauthorized and disabled.

## Follow-on, not an activation prerequisite

Automatic Hermes upgrade analysis remains future work. Lucy should inspect upstream
release changes, prepare a digest-pinned candidate, and exercise compatibility and
security tests in isolation. Promotion must remain a separately controlled release; no
moving tag or automatic production upgrade is permitted.
