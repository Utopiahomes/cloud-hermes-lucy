# Rejoining acceptance

Rejoining is Lucy's deterministic startup gate. It is implemented in domain
code, not in a prompt, and serializes concurrent startup attempts with a
PostgreSQL advisory lock.

## Healthy path

Before permitting normal work, Lucy verifies:

- the observed Hermes source commit exactly matches the reviewed full commit;
- lifecycle and audit singleton records exist;
- every audit sequence, previous hash, event hash, and audit head is consistent;
- each budget is nonnegative and its spent plus reserved amount is within its
  limit; and
- no previously committed operation remains pending.

A healthy run durably and audibly transitions through `OFFLINE -> REJOINING ->
RECONCILING -> READY`. Restarting from `READY` first returns to `OFFLINE` and
repeats the complete protocol.

## Degraded paths

A pin mismatch, invalid budget, missing invariant, or invalid starting state
forces `DEGRADED`. A pending operation is marked `AMBIGUOUS` with `retried:
false`; Lucy never repeats its possible external effect.

Audit corruption is handled specially. Lucy persists the startup diagnostic and
sets the lifecycle to `DEGRADED`, but does not append to the broken audit chain.
This avoids making a corrupt history appear valid. Human repair and a governed
audit recovery procedure will be required before leaving degraded mode.

Each attempt is preserved in `lucy.startup_runs`, including its individual check
results and final state. The test suite covers healthy repeated restart, pin
mismatch, budget failure, ambiguous operation quarantine, and audit-head
corruption using synthetic data only.
