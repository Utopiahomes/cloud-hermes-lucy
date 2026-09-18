# Reviewer references for Tiamat Signed Release Draft 0.3

These are repository-local normative sources cited by the draft. Paths and line numbers refer to the
reviewed source tree; reviewers should verify the full files and their Git revision rather than treat
this excerpt as a substitute for the source.

## Shared Model Execution RC1

Source: `docs/stoin-shared-model-execution-contract-v1-rc1.md`

- §4 begins at line 88. It includes private authenticated non-streaming inference, caller-selected
  identity-allowlisted profiles, local privacy/routing/rate/cost enforcement, content-free recovery,
  and fail-closed behavior when route or spending authority is unavailable. It excludes synchronous
  management authorization and provider/model selection by the caller.
- §8 begins at line 348. Exact text establishes that a profile locally resolves one route/model,
  privacy restrictions, bounds, price data, maximum reservation, and release ID; profiles contain no
  caller facts or business rules; replacement requires activating a new policy release.
- §13.1 begins at line 859. Exact text establishes asynchronous signed policy/grant distribution,
  local request-time admission, simultaneous grant-validity and budget-period applicability, advance
  provisioning across offline period boundaries, same-period no-replenishment, new-period renewal
  with unresolved obligations carried, monotonic predecessor/successor activation, signed total
  ordering for conflicts, and the completed-commit revocation cutoff.
- Acceptance criteria 73–74, 78, and 80–81 begin at lines 1353, 1357, 1369, 1375, and 1378. They require
  non-resurrection, signed tie resolution, pinned in-flight completion, pre-provisioned next-period
  authority, predecessor replay invalidation, and an atomic eligibility/completed-commit fence.

The relevant §13.1 cutoff is:

> The final security/privacy eligibility generation is rechecked atomically with the fenced
> `completed` commit under §11. A security or privacy revocation activated before that commit suppresses
> the candidate and follows the definitive-failure rules. A revocation activated after the completed
> commit invalidates replay but cannot recall or suppress the original response.

## Policy-notary purpose

- Management Contract v1 §6.2 at `docs/stoin-utopia-management-contract-v1.md:110-117` reserves
  policy-notary as a separate key purpose and forbids management-key reuse. It does not define a
  versioned wire string.
- The exact established value comes from `src/lucy/contracts/security_v1_3.py:83-85`:

```python
class V13SigningKeyPurpose(StrEnum):
    OWNER_BROKER = "owner_broker_v13"
    POLICY_NOTARY = "policy_notary_v13"
```

The signed-release format adds exact use `tiamat-signed-release`; possession of another
`policy_notary_v13` key does not imply this use.

## Recovery mechanism

- `docs/tiamat-execution-ledger-recovery-rc1.md` defines mandatory external-generation invalidation
  and the nine-step offline reconciliation.
- `src/lucy/shared_execution/recovery.py` implements quarantine and exact-generation authorization.
- `tests/integration/test_tiamat_postgres_execution_ledger.py` contains the physical stale-snapshot,
  recovery-generation, transaction-loss, overrun, and tombstone proofs.
