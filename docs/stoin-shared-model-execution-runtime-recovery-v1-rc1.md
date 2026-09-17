# Stoin Shared Model Execution Runtime-Recovery Companion RC1

**Document revision:** RC1\
**Capability version:** `inference.execute@1.0`\
**Companion to:** Stoin Shared Model Execution Contract RC1\
**Status:** jointly pinned freeze-package component; no implementation, credential, spending, deployment, or production authority\
**Date:** 2026-09-17

## 1. Purpose and authority

This companion isolates the initial normative runtime-recovery profile required to make the caller-visible guarantees in the Shared Model Execution Contract RC1 true. It does not add a public endpoint, widen caller authority, or replace the wire contract.

The normative extract below is mechanically copied from §§11–13.1 of the companion contract. The RC1 freeze manifest pins both complete files and the exact UTF-8 bytes of this extract. A package with any mismatch is invalid; neither copy silently overrides the other.

The main contract remains normative for transport and ordered admission (§6.3), authentication and replay-state scope (§7), privacy (§§14–15), wire errors (§16), compatibility (§17), and acceptance criteria (§20). Cross-references inside the extract continue to refer to the main contract unless this companion says otherwise.

## 2. Initial topology and change rule

The initial profile uses exactly one active admission/replay coordinator per environment and durable authoritative state that survives loss of any single node. Provider transport workers may scale behind it. Future topology may change only through a later companion revision that preserves the jointly pinned wire behavior, privacy boundary, single-dispatch guarantee, cost semantics, and failure invariants.

Implementation-specific table layouts, process classes, provider SDKs, and hosting products are not frozen. The state transitions, fencing, admission order, receipt truthfulness, exposure bounds, reconciliation behavior, and fail-closed outcomes are frozen.

## 3. Normative recovery extract

<!-- BEGIN NORMATIVE EXTRACT: contract RC1 §§11-13.1 -->
## 11. Canonical request identity and idempotency

The provider scopes `Idempotency-Key` to the authenticated service identity, mapped realm,
environment, operation, and exact contract major version.

Before hashing, the provider:

1. strictly decodes UTF-8 JSON;
2. rejects duplicate object names and non-integer numeric values where integers are required;
3. validates the complete request and restricted schema;
4. serializes the validated request using RFC 8785 JSON Canonicalization Scheme; and
5. computes a keyed digest using an environment-specific secret.

After steps 10–14 pass, the provider performs step 15 and atomically creates the scoped key digest,
canonical request digest, admitted profile release, `admitted` state, lease
owner/deadline/fencing epoch, complete cost reservation, cost reference, and timestamps. No request
or response content enters durable idempotency state.

States are `admitted`, `dispatched`, `completed`, `failed`, and `outcome_unknown`.

- Same key and different canonical request returns `409 idempotency_conflict`.
- A duplicate while active waits for a state change for at most the smaller of its own
  `X-Execution-Timeout-Ms` and the time remaining through the original execution deadline plus the
  30-second settlement margin. It then returns the applicable replay, terminal failure,
  outcome-unknown, invalidated, or recovery-unavailable result. It returns
  `409 request_in_progress` with `Retry-After` only when the record remains `admitted` or `dispatched`
  when that wait ends. Waiting never renews the owner's lease or dispatches a second provider call.
- Every `admitted` or `dispatched` owner holds a renewable lease with a fencing epoch represented as
  the ordered pair `(coordinator_generation, record_generation)`. Failover atomically increases the
  coordinator generation before a successor may acquire leases. Every acquisition, renewal, reaper
  expiry, failover adoption, reconciliation mutation, invalidation, and other owner or non-owner
  state transition increases the record generation. Owner writes compare-and-set both the expected
  state and the complete held epoch.
- An `admitted` lease expires no later than five seconds after admission. Because no provider request
  may have started in that state, expiry atomically changes it to `failed`, releases the entire cost
  reservation, and retains the content-free deduplication record through its normal ten-minute
  window. It records `execution_aborted`, with `settlement_status: settled` and
  `settled_microusd: 0`.
- The active coordinator/owner atomically changes `admitted` to `dispatched` and durably confirms that
  commit before the first provider-request byte is sent. If the commit outcome is unclear, it sends
  nothing and the coordinator—not the caller or the caller's retry—performs a fenced authoritative
  lookup that blocks the partition until resolved. If lookup proves `dispatched` under the same live
  owner epoch, the owner—being the only possible sender—atomically commits `failed`, releases the reservation, and
  records `execution_aborted` at zero settled cost. If ownership or the lease is lost first, the
  authoritative reaper transition governs and may conservatively produce `outcome_unknown`. If the
  owner cannot read or write authoritative state, it returns `state_store_unavailable` without an
  execution-state or cost receipt; it never infers release of the reservation. Once `dispatched` is
  confirmed, failure to prove whether provider bytes were sent is treated as potentially billable.
- Every `dispatched` operation holds a renewable content-free lease whose deadline is no later than
  the admitted execution deadline plus 30 seconds. If the lease expires without a live owner or an
  authoritative provider outcome, the store atomically changes the state to `outcome_unknown`.
- A late or partitioned owner whose fencing epoch is stale cannot write `completed`, `failed`, replay
  content, or a new operational state over the authoritative record. Its content-free provider cost
  reference may still enter the separate reconciliation path; any candidate output it holds is not
  replayed. An owner may return `200` only after one atomic operation rechecks the current local
  security/privacy eligibility generation and durably commits `completed` using the expected state,
  epoch, and eligibility generation. A revocation activated before that commit makes the comparison
  fail and follows the revocation mapping in §16. If that commit fails or proves the owner stale while its original HTTP connection
  remains open, it discards the candidate. It returns `execution_outcome_unknown` with the current
  execution/cost receipt only after authoritative lookup establishes that state; otherwise it returns
  `state_store_unavailable` without fabricating current state or settlement.
- A completed duplicate may replay the candidate only while it remains in volatile memory, for at
  most ten minutes, and the admitted profile release remains eligible. Eligible means that exact
  release remains active, its route is not quarantined, and no settlement overrun invalidated the
  execution. Activating a successor profile release therefore invalidates replay from the predecessor,
  even when both releases resolve to the same provider route. This is intentionally conservative: a
  connected original request may finish under its pinned routine release, but a response lost during
  that rollout becomes unrecoverable and is never regenerated. Replay preserves `execution_id`,
  candidate output, usage, profile ID/release, and finish reason. It echoes the retry's new
  `X-Request-ID`/`request_id`, marks `replayed: true`, and returns the latest authoritative cost state.
  The original response has `replayed: false`.
- If durable state proves completion but volatile output is absent, the provider returns
  `409 idempotency_recovery_unavailable`; it never silently executes again under that key.
- If dispatch may have reached the provider but the outcome is unknown, the provider returns
  `409 execution_outcome_unknown` and never automatically repeats the billable generation.
- If the admitted profile or route is withdrawn, a cached result is not replayed and the provider
  returns `409 execution_invalidated`.
- A `failed` record is terminal for that idempotency key. During its required retention, a duplicate
  always returns the durable recorded generic error code with the current authoritative receipt; if
  authoritative state is unavailable, it returns `state_store_unavailable`, not another terminal
  result. It never re-admits or dispatches the execution. A caller may begin a new logical execution only
  under the calling synth's ordinary policy and a new idempotency key, never as an implicit transport
  retry. An unclear step-15 commit can therefore consume the one transport retry: if its record was
  created and the reaper aborts it, that retry receives terminal `execution_aborted`. Starting a new
  logical execution and key is a separate caller decision subject to normal policy and budget.
- Settled completed and settled definitively failed deduplication records may expire ten minutes after admission.
  An unresolved, dispatched, outcome-unknown, or unsettled record MUST NOT expire into a state that
  permits another dispatch. Its content-free tombstone remains until the provider outcome and cost
  are authoritatively reconciled and for at least ten minutes afterward. If cost reaches
  `reservation_forfeited` without later authoritative reconciliation, the idempotency tombstone is
  retained for 30 days after forfeiture and then may expire; the separate content-free financial
  accounting reference follows its approved longer retention policy.

Lease expiry is applied only by the authoritative store's fenced reaper, not by a step-10 reader.
When lookup observes an elapsed timestamp whose reaper transition is not yet committed, it waits
within the current attempt budget for the authoritative transition and otherwise returns
`state_store_unavailable`; it neither reports the stale lease as active nor mutates it locally.

For a transport or dispatch failure after step 15 with no authoritative terminal provider outcome,
proof that zero provider-request bytes were sent atomically produces `failed`, releases the
reservation, and records `execution_aborted` with zero settled cost. An unconfirmed `admitted` to
`dispatched` write follows the fenced-lookup procedure above; uncertainty is never described as a
definite commit failure. When dispatch or the provider's terminal execution outcome remains ambiguous,
the executor uses `outcome_unknown` and retains the reservation. An authoritative terminal provider
failure instead becomes `failed` under §16 even when provider bytes were sent. Cost uncertainty alone
changes settlement status; it never changes a definitive execution outcome to `outcome_unknown`.

The initial v1.0 deployment uses exactly one active admission/replay coordinator per environment.
Provider transport workers may scale behind it. A later multi-coordinator profile must provide
deterministic request affinity or a shared non-persistent replay cache. Without that mechanism, a
retry that reaches a coordinator without the volatile candidate returns
`idempotency_recovery_unavailable`; it never dispatches again.

Coordinator failover is fail-closed for replay: the successor obtains a higher fencing epoch before
admitting work and returns `idempotency_recovery_unavailable` for a completed execution whose
candidate existed only in the predecessor's memory. At most one coordinator can hold a current lease
epoch at a time. Cost settlement and reconciliation also compare-and-set state and epoch so a stale
owner and a reaper cannot settle the same provider charge twice.

The authoritative idempotency, lease, and accounting store survives loss of any single node. If the
authoritative state is lost entirely or quorum cannot establish the latest fencing epoch, the
spending partition blocks every new dispatch until an operator reconciles provider charges and
restores an authoritative state. The system does not claim that a lost store preserved a tombstone.

Keyed-digest records carry a digest-key version. During rotation, the service retains and checks every
key version needed by live ten-minute records and unresolved tombstones. A previous digest key is not
retired until no record depending on it can authorize, block, replay, or reconcile an execution.

One execution permits exactly one billable provider dispatch. A calling synth may intentionally perform a
separate generation, support review, or repair call only as a new operation with a new idempotency
key and a separately admitted cost ceiling. Caller-pipeline retries and repairs remain caller-owned.

## 12. Deadlines and retry

The caller communicates its remaining attempt budget through `X-Execution-Timeout-Ms`. The provider
stores an absolute execution deadline at first admission. The response deadline is exactly the
earliest of the stored execution deadline, the current attempt ceiling measured from receipt of that
attempt, and the admitted profile deadline. It uses a shorter provider timeout that leaves
time to settle or mark the charge uncertain and return a normalized response. A duplicate's smaller
attempt ceiling is a long-poll ceiling under §11; it does not extend or restart the original
execution.

The caller may make at most one automatic retry after a transport failure or an explicitly retryable
response. It uses:

- the same exact body bytes, canonical identity, and `Idempotency-Key`;
- a fresh JWT, `jti`, and `X-Request-ID`;
- the server's `Retry-After` when present, otherwise randomized 250–750 ms backoff; and
- the original enclosing calling-interaction deadline.

The calling synth skips the retry when `Retry-After`, randomized backoff, minimum request transit
allowance, and the retry's complete profile ceiling cannot all fit inside the remaining calling-
interaction budget. For Utopia Homes, that enclosing interaction is the `guest.answer` Business
Contract deadline. It
never begins a retry merely because the first response was marked retryable.

The retry observes the original operation; it does not authorize another dispatch. Validation,
`401 authentication_failed`, authorization, profile, privacy, cost, and idempotency-conflict errors
are not retried automatically. The distinct `authentication_state_unavailable` error remains
retryable under its exact table entry and the one-retry rule.

HTTP clients, provider SDKs, proxies, and transport libraries have automatic retries disabled. Only
the explicit caller retry above is permitted. In particular, no generic retry behavior may react to
`429`, `502`, `503`, or `504` independently of this contract.

Cancellation or client disconnect does not prove provider cancellation and does not release a cost
reservation until settlement or uncertain-charge recovery completes.

After `dispatched`, a response deadline that expires without an authoritative provider outcome first
durably commits `outcome_unknown` under the current fencing epoch and then returns
`504 deadline_exceeded` with the authoritative current cost receipt. If the executor authoritatively
proves a completed non-usable/cancelled outcome and cost, it first durably commits `failed` and the
settlement, then returns the same error with the settled receipt. If either transition cannot be
established authoritatively, the service returns `state_store_unavailable` without claiming a current
state or receipt. A complete valid candidate and exact cost that arrive after the deadline but before
the fenced deadline transition commit produce a durable `failed` state with authoritative settlement
and `504 deadline_exceeded`; the candidate is not delivered. A candidate arriving after `failed` or
`outcome_unknown` has been committed is discarded from content memory and never becomes replayable or
caller-visible; only its content-free provider/cost evidence enters fenced reconciliation. Late
reconciliation may change `outcome_unknown` to `failed` and settle cost, but it cannot make that
candidate eligible for replay.

## 13. Cost admission and settlement

Shared Model Execution owns a locally authoritative, atomic reservation and accounting store. Every
serving replica either uses that shared store or receives a disjoint spending partition. Replicas
MUST NOT independently spend the same grant.

Before dispatch, the executor:

1. resolves the exact authorized profile and pinned rate release;
2. computes a conservative input-token upper bound using either the exact pinned route tokenizer plus
   profile framing overhead or the fallback bound
   `message_utf8_bytes + schema_canonical_utf8_bytes + (16 * message_count) + 256`, where schema bytes
   are zero for text mode and otherwise include the complete RFC 8785-canonical output schema;
3. admits the fallback only when route conformance evidence proves it cannot understate that route's
   tokenizer or framing cost; otherwise the route is ineligible;
4. computes the worst-case charge from that input bound, the requested combined visible/reasoning
   token bound, pinned rates, provider rounding, and every permitted charge category;
5. rejects with `cost_ceiling_insufficient` if the worst-case charge exceeds the request, profile,
   route, or environment per-call ceiling;
6. rejects with `spending_authority_exhausted` if locally authoritative unreserved spending authority
   cannot cover the complete worst-case charge; and
7. supplies that complete worst-case charge to the §6.3 step-15 atomic create-and-reserve operation.

The executor never truncates a reservation to a smaller ceiling and dispatches anyway.

Routes with unbounded, unpublished, or unmodeled charge categories are ineligible for v1.0.
Automatic top-up is prohibited.

After provider completion, an authenticated final provider response that identifies the exact
admitted route and supplies exact usage under §9.5 is authoritative for synchronous settlement when
that usage multiplied by the pinned rate release covers every charge category. The service atomically
settles that calculated cost and releases the remainder. Later provider billing evidence confirms the
settlement or triggers the overrun/reconciliation rules below; it is not required before ordinary
calls can settle. When the final response or required usage is absent, ambiguous, or not sufficient
under the pinned rate model, the reservation remains held and the cost settlement status becomes
`pending_reconciliation`; asynchronous recovery may settle it later using content-free
provider/accounting references. A reservation is never released merely because the caller timed out.

Each spending partition also holds a bounded, non-dispatchable settlement-contingency reserve. If an
authoritative provider charge exceeds the admitted reservation because of rate drift, provider
rounding, or incorrect provider metadata, the service atomically debits the full actual charge,
using the contingency reserve only for the excess; marks `settlement_overrun`; quarantines that
route/rate release; starts no further call through it; and returns `cost_settlement_violation` rather
than a candidate. If the contingency reserve cannot cover the excess, the partition records the full
external liability, blocks all new dispatch, and requires operator reconciliation. It never hides or
clips the charge to preserve an apparent ceiling.

The same quarantine, accounting, and blocking rules apply when asynchronous reconciliation discovers
an overrun after a candidate was already returned with `pending_reconciliation`. The earlier customer
response cannot be withdrawn, but the service records a content-free overrun event, marks the
execution ineligible for replay, and every later duplicate returns `execution_invalidated` with the
updated `settlement_overrun` receipt instead of replaying the candidate.

The contingency reserve is at least `2 × partition maximum concurrency × partition largest per-call
ceiling`. Active executions are capped at the partition maximum concurrency `N`; saturating that
request-time concurrency gate returns step-13 `429 rate_limited`. Admission also atomically requires
`active + pending_reconciliation < 2N` before adding a new active exposure; saturating that financial-
exposure gate returns step-14 `503 spending_authority_exhausted`. An active execution may always move
to `pending_reconciliation` without losing or rejecting its liability, so pending exposure alone may
reach `2N`. Completion and admission update the combined exposure count atomically. Thus combined
active-plus-pending exposure never exceeds `2N`, matching the reserve formula even across concurrent
completions and new admissions. The formula is a minimum buffer for that bounded exposure set, not
proof that arbitrary or very-late provider overcharging is bounded. A late post-forfeiture overrun can
still exhaust it; exhaustion blocks the partition and requires manual reconciliation.

Exposure counters count unique financial obligations by `execution_id`, not execution-state labels.
An `admitted` or `dispatched` execution counts once as active. An `outcome_unknown` execution with
unresolved cost counts once as pending after its active worker ends. A completed or failed execution
with `pending_reconciliation` also counts once as pending. Moving among those categories neither drops
nor double-counts the obligation. Authoritative settlement or the specified
`reservation_forfeited` transition releases the exposure slot; retained financial evidence and a
later overrun may still debit contingency or block the partition under the rules below.

The response cost object is:

| Member | Requirement |
| --- | --- |
| `reserved_microusd` | Nonnegative integer |
| `settled_microusd` | Nonnegative integer or null |
| `settlement_status` | `settled`, `pending_reconciliation`, `reservation_forfeited`, or `settlement_overrun` |

When `settlement_status` is `settled`, `settled_microusd` is non-null and no greater than
`reserved_microusd`. When it is `pending_reconciliation`, `settled_microusd` is null and the full
reservation remains held. `settlement_overrun` appears only on an error receipt; its settled amount is
non-null and greater than the reservation. `reservation_forfeited` means the 24-hour reconciliation
deadline elapsed without authoritative cost; its settled amount equals the full reservation.

If cost is pending, a successful model candidate MAY still be returned when the provider response is
authoritative and all other checks pass. The calling synth does not retry that execution.
Content-free recovery continues without the caller or Tiamat management function being in the
synchronous path.

Reconciliation has a 24-hour deadline from dispatch. At that deadline an unresolved charge becomes
`reservation_forfeited`: the full reservation is treated as spent, the unresolved tombstone remains,
and an operator alert is recorded, but the partition does not block solely for that unresolved call.
Later authoritative cost may replace that accounting state with `settled` or
`settlement_overrun`. An overrun that exhausts the contingency reserve blocks the partition, pages an
operator, and permits no automatic resume. The forfeited idempotency tombstone follows the fixed
30-day retention from §11; longer financial evidence retention does not preserve replay or permit
re-execution.

### 13.1 Policy and budget distribution

The Tiamat management function may publish signed policy releases and bounded spending grants
asynchronously. The execution service validates and loads them before serving; it never calls the
management function to admit an individual request. Equivalent locally provisioned releases are
permitted during the initial seam proof.

Every policy and grant has `not_before`, `not_after`, environment, spending partition, release
identity, `budget_period_id`, and exact period start/end. New admission requires both a currently valid
grant and an applicable current budget period. A grant cannot authorize new spending after its period
ends merely because `not_after` has not elapsed, and crossing a period boundary never renews authority
automatically. Continuing through that boundary requires an already provisioned and activated grant
for the next period. Expired, premature, revoked, malformed, wrong-environment, period-inapplicable,
or exhausted authority fails closed as `spending_authority_exhausted`.

Initial grants remain valid for at least 36 hours from issuance and refresh no more than 12 hours
apart, producing a minimum intended 24-hour offline operating window only when sufficient budget and
applicable grants are already provisioned across every budget-period boundary within that window. No
contract guarantee extends beyond the last locally valid and period-applicable grant. Signature
validity alone does not provide offline spending authority.

A grant represents a period-based allowance, not a lifetime cumulative ceiling. A successor grant
inside the same `budget_period_id` replaces its predecessor; overlapping validity never adds ceilings
or replenishes spend. Settled spend, active reservations, pending reconciliation, forfeitures,
contingency exposure, and later credits carry into the successor's accounting before any new
authority is available. A successor for a new period renews the configured allowance, but every
unresolved reservation, external liability, pending charge, forfeiture, and contingency obligation
still carries forward and reduces effective available authority until resolved. If carried
obligations meet or exceed the successor ceiling, no new dispatch is admitted. Expiry or replacement
never releases an obligation. A later credit or released remainder is applied to the partition's
then-current accounting, not resurrected on an expired grant.

During overlap, the active release is the valid, non-revoked, period-applicable grant with the latest
`not_before` among grants not already superseded by an activated successor. Once a successor is
activated, no earlier grant is selectable regardless of remaining validity.
Activation records a monotonic predecessor-to-successor relationship for the spending partition. An
activated predecessor can never resume merely because its successor expires, is revoked, or is
exhausted while the predecessor's wall-clock validity remains. Rollback or resumption requires a newly
signed and explicitly activated release. Two candidate successors with equal `not_before` and no
explicit signed total-order value are conflicting and fail closed; a deployment may resolve the tie
only through a signed ordering field defined by the grant format and compared byte-for-byte.

Routine profile or policy replacement does not invalidate an already admitted execution: it may
finish under its pinned release, subject to current security/privacy eligibility and the checks below.
A cost/rate quarantine alone is handled separately below. Budget replacement carries that admitted
reservation and liability into current partition accounting.

The executor rechecks authoritative local eligibility immediately before provider dispatch. A route
or grant invalidation known after record creation but before dispatch prevents dispatch, commits
`failed`, releases the reservation at zero settled cost, and records `execution_aborted`.

The final security/privacy eligibility generation is rechecked atomically with the fenced
`completed` commit under §11. A security or privacy revocation activated before that commit suppresses
the candidate and follows the definitive-failure rules. A revocation activated after the completed
commit invalidates replay but cannot recall or suppress the original response. A routine profile
replacement alone does not suppress original delivery. A cost/rate quarantine caused by another
execution likewise does not suppress an already dispatched candidate; that execution settles under
its admitted rate, while its own settlement overrun still produces `cost_settlement_violation`.

Emergency revocation is a deployment/security operation outside this request protocol. Until a
mechanism mechanically enforces a bound, the initial one-hour emergency redeployment objective is an
operational target, not a protocol guarantee. The fail-closed expiry bound remains the active grant's
remaining validity.
<!-- END NORMATIVE EXTRACT: contract RC1 §§11-13.1 -->

## 4. Conformance relationship

A conforming implementation must pass both the wire-contract vectors and the execution-dependent recovery tests mapped to this companion. Schema validation alone cannot prove single dispatch, fencing, durable transition order, honest state-store failure, exposure accounting, settlement, period-boundary authority, or revocation ordering.

The freeze manifest identifies the complete contract digest, complete companion digest, and normative-extract digest. The conformance bundle must reproduce those values from raw UTF-8 bytes without executing a generator.

## 5. Authorization boundary

This companion authorizes no code changes, repositories, databases, migrations, provider calls, credentials, secrets, spending, infrastructure, deployment, traffic, or production activation.
