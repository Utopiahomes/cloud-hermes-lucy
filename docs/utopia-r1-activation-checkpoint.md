# Utopia R1 activation checkpoint

Status: Ray authorized Stage 1 private Telegram activation using the existing Lucy bot.
The private gateway, execute-only Telegram ledger and budget path, and protected channel
activation/recovery boundary are implemented locally through migration
`0053_r1_telegram_authority`. Production commissioning and the one-gateway handoff remain.
Transcript capture remains disabled.

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

1. First live scope: Public Lucy only. Private Lucy remains closed until a customer
   identity provider and strong-auth contract are separately selected and approved.
2. Browser boundary: `https://www.utopiahomes.com/api/lucy`, using a same-origin website
   proxy and a separate authenticated Cloud Lucy upstream.
3. Public knowledge: only the exact approved V0 website snapshot and lineage above.
   Its canonical Cloud projection payload is
   `deploy/render/utopia-public-projection.v0.json`.
4. OpenRouter/paid inference: disabled for this first launch.
5. Transcript capture: disabled.

## Exact next action

Commit and push the verified Stage 1 candidate, deploy compatible authority writer and
recovery acknowledgement readers, migrate the quarantined production database through
`0053`, and commission the exact inactive Telegram binding. Append and acknowledge the
activation through the independent authority journal before starting the Render gateway.
Only after the cloud worker is ready may the local gateway relinquish the bot lease.
Commissioning must verify owner-only access, restart/deduplication, one model settlement,
content-free logs, and rollback without reverting authority or deletion history.

## Stage 1 verification ledger

- Fresh PostgreSQL migration `0001` through `0053`: passed locally on 2026-09-11.
- Channel activation/withdrawal acknowledgement, execute-only role denial, and exact
  quarantined replay: 14 focused checks passed locally on 2026-09-11.
- Complete unit suite: 677 passed; Ruff and mypy passed on 2026-09-11.
- Realm/recovery role stamps and Telegram lease/dedup/budget boundary: 4 focused
  PostgreSQL checks passed on 2026-09-11.
- Deployed owner, unauthorized-caller, restart, duplicate-delivery, budget settlement,
  log-content, and rollback checks: not yet executed. These require the exact production
  candidate and invalidate only if its source/configuration/environment changes.

## Follow-on, not an activation prerequisite

Automatic Hermes upgrade analysis remains future work. Lucy should inspect upstream
release changes, prepare a digest-pinned candidate, and exercise compatibility and
security tests in isolation. Promotion must remain a separately controlled release; no
moving tag or automatic production upgrade is permitted.
