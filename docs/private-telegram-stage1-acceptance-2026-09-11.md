# Private Telegram Stage 1 acceptance

## Decision

Stage 1 private Telegram activation passed on 2026-09-11 with the documented
limitations below. Private Lucy is live through the existing Telegram bot for the
numeric owner allowlist and the commissioned Utopia private realm. The local gateway
is stopped, the replaced Render gateway is suspended, and exactly one cloud gateway
holds production update-consumer authority.

This acceptance does **not** authorize Stage 2. Encrypted transcript capture,
automatic memory creation from new conversations, and raw evidence retrieval remain
disabled.

## Deployed identity and version

- Application commit: `3563a9b2a1d847e043594a78948675130c760017`.
- PostgreSQL revision: `0053_r1_telegram_authority`.
- Routine service: `srv-daca8gafngtc73clva90`.
- Active Telegram gateway: `srv-dai4k467bikc73bhs6r0`.
- Replaced gateway: `srv-dai3hmu743jc73do9ebg`, suspended.
- Hermes release/version: `v2026.8.19` / `0.20.5`.
- Hermes upstream commit: `fcbd1076a93841fa88855acce810e342a5b78101`.
- Linux AMD64 image manifest: `sha256:3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09`.
- Linux AMD64 platform digest: `sha256:f3cba556e7b35dbe20a67d32b715090d9babd5907798c79721380757d9a12bb6`.
- Auto-deploy is off; the deployment is reproducibly pinned.

## Commissioning evidence

| Boundary | Result |
| --- | --- |
| Owner access | Passed. Ray sent a private message and Lucy answered through the cloud gateway. |
| Unauthorized users | The deployed numeric user/chat/DM allowlist and focused test reject a wrong owner before claim or inference. A second live Telegram account was not used. |
| Realm selection | Passed through the exact node, realm, content-scope, channel, bot, database-login, and `stage1_telegram_scope_v1` binding. |
| One consumer | Passed. Cloud gateway live; local gateway stopped; replaced cloud gateway suspended. |
| Restart recovery | Passed. A replacement process failed closed until the old lease expired, then acquired a higher lease fence and started. |
| Duplicate handling | Passed. Replaying the prior update after restart was not admitted, was classified as replayed, and preserved the prior event identity. |
| Budget | Passed. The owner event has exactly one model operation and one successful settlement. |
| Persistence | Passed. The owner event produced no scoped capture receipt, evidence, scoped memory, or legacy memory write. The gateway has no persistent disk and stages its managed home in RAM. |
| Logs | Passed. 600 current Render messages contained neither sampled conversation content nor deployed secret values. |
| Rollback | Passed earlier in commissioning: failed cloud handoffs re-suspended cloud authority and restored the local consumer. Authority, deletion, and journal history were not rolled back. |

The machine-readable record is
`docs/evidence/utopia-private-telegram-stage1-acceptance-2026-09-11.json`.

## Known limitations

- Hermes first-run onboarding answered the live canary with a profile offer instead of
  echoing the requested phrase. This does not invalidate transport, inference, budget,
  or persistence evidence. Do not accept a profile-memory setup during Stage 1.
- The unauthorized-user failure path was not exercised with a second live Telegram
  account. Its deployed configuration and focused pre-inference regression test passed.
- Render had not indexed final output from two private verification jobs. Both jobs
  reached terminal `succeeded`; each command was constructed to exit nonzero if any
  embedded assertion failed.
- Restart can remain fail-closed for up to the 30-second lease period. This avoids two
  simultaneous consumers at the cost of a short recovery delay.

## How to use private Lucy

Open a private direct-message conversation with `@UtopiaLucy_bot` and message normally.
Only the configured numeric owner account is admitted. Lucy may read already-approved,
realm-scoped memory, but Stage 1 does not automatically retain the new conversation or
promote it into durable memory.

## Rollback route

Suspend the active Render gateway before starting the pinned local gateway. Never run
both consumers together. Roll back only to the manifest's compatible application commit;
do not downgrade PostgreSQL and do not reverse authority, revocation, deletion, budget,
or recovery-journal history.

Automatic Hermes upgrade analysis remains follow-on work. Candidate upgrades must be
reviewed, digest-pinned, and tested in isolation before a separately controlled release.
