# Hermes memory-proposal acceptance

Hermes may now submit a candidate memory derived from an existing immutable
evidence record. Submission is not a memory write.

The authenticated endpoint requires Lucy to be `READY`, a caller-supplied
idempotency key, a valid evidence UUID, bounded text fields, and confidence in
the range zero through one. In one transaction it creates a pending proposal,
a `memory.write` human approval request, an audit record, and a completed
submission operation. Retries return the same proposal.

The public adapter exposes exactly two versioned routes: read-only lookup and
proposal submission. It exposes no route for decisions, proposal application,
archive access, database operations, shell execution, or administration.

Only the internal control service can apply a proposal. It refuses application
until the linked approval was decided by a human owner or delegate, then creates
an accepted provenance-linked claim in an audited, idempotent transaction.

The pinned Hermes container submitted a synthetic candidate and received
`pending`, a proposal ID, and a human approval ID with `claim_id: null`. The
PostgreSQL suite proves refusal before approval, human approval, application,
provenance, submission replay, and restart-safe application replay.
