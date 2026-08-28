# Action budget and recovery acceptance

Lucy now connects deterministic action classification to durable approval,
budget, execution, and recovery state.

Submission is idempotent. Denied and unknown actions stop without approval or
reservation. Gated actions remain `awaiting_approval` until a human owner or
delegate approves them. Allowed actions and approved gated actions reserve from
their policy-selected account before execution can begin; insufficient budget
rolls back the entire authorization transaction.

Beginning execution creates a pending operation only after reservation. The
caller may then perform the external effect and settle actual cost exactly once.
Settlement releases the complete reservation, charges actual cost up to the
reserved ceiling, records success or failure, and audits the result. Lost begin
or settlement responses are safely replayed.

If Lucy restarts while an action is executing, Rejoining marks both its pending
operation and action journal row `ambiguous`, records `retried: false`, and never
repeats the effect. Lucy conservatively charges the full reservation because the
actual external cost is unknowable, then enters `DEGRADED`.

The synthetic acceptance suite proves human gating, reserve-before-execute,
exact settlement, replay behavior, unknown-action denial, and ambiguous crash
recovery with conservative accounting.
