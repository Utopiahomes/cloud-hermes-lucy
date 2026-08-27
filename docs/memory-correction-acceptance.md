# Memory correction acceptance

Lucy changes her mind through a governed correction workflow, never by rewriting
archive evidence or silently replacing a graph value.

A correction proposal must reference an existing current claim and different
immutable evidence, supply a genuinely contradictory replacement, and pass
basic confidence validation. Proposal retries are idempotent. Each proposal
creates a `memory.correct` approval request and cannot be applied until a human
owner or delegate approves it.

Application is one PostgreSQL transaction. It:

- marks the old claim `superseded` without deleting it;
- creates an accepted successor linked by `supersedes_claim_id`;
- retains the successor's distinct evidence provenance;
- closes the old graph relationship's `valid_to` timestamp;
- creates the versioned replacement relationship;
- marks the proposal applied; and
- records the mutation in the tamper-evident audit chain.

Restart retries replay the applied result. Default working-context retrieval
filters superseded claims, while direct historical queries retain both claims,
both evidence links, and both graph relationship versions.

The acceptance test uses two synthetic conversations and proves refusal before
approval, human approval, atomic application, restart replay, current-only
retrieval, closed temporal validity, and complete provenance history.
