# Security Baseline v1.3 — R1 final acceptance

## Decision

The Utopia single-realm R1 technical gate passed on 2026-09-11. R1-0 through R1-5
are complete for the commissioned Utopia boundary. Live customer activation is a
separate change: ordinary services remain suspended, admission remains quarantined,
paid inference is disabled, and transcript capture remains false.

The accepted result provides tenant/node identity, separate public/private scope,
realm-bound memory and evidence controls, durable public cost admission, independent
authority/cost recovery, protected activation handoff, and a concrete path to add a
second realm without sharing its content credentials, keys, database roles, or recovery
streams. It does not implement R2 or R3.

## Cumulative result

| Gate | Result | Principal evidence |
| --- | --- | --- |
| R1-0 reconcile | Passed | `docs/r1-repository-reconciliation.md` and frozen source/schema/deployment map |
| R1-1 identity/public | Passed | Synthetic Utopia publication, spoofing, withdrawal, visitor, and realm-isolation tests |
| R1-2 private/security | Passed | `docs/evidence/utopia-r1-2-cloud-acceptance-2026-09-10.json` |
| R1-3 cost admission | Passed | Focused contract, PostgreSQL concurrency/retry/rollover, restart, kill-switch, and no-call-without-reservation evidence |
| R1-4 recovery | Passed | `docs/evidence/utopia-r1-4-protected-recovery-2026-09-11.json` |
| R1-5 commissioned acceptance | Passed | `docs/evidence/utopia-r1-5-commissioned-acceptance-2026-09-11.json` and `docs/r1-coverage-registry.md` |

The final current checks were proportional to the changed/deployed boundary:

- 51 AWS checks passed for the exact account, terminated-protected stack, Render OIDC
  trusts, IAM policies, Lambda aliases/artifacts/runtime/concurrency, three KMS keys,
  eight DynamoDB tables with PITR/TTL, CloudTrail selectors, and log controls.
- Read-only PostgreSQL verification at migration `0050_r1_recovery_ack_receiver` passed
  actor/executor bindings, function ACL isolation, no unsafe role membership, removed
  schema-create power, direct-table denial, capture false, and quarantined admission.
  The temporary exact `/32` operator path was removed and the allow-list is empty.
- Eight Render identities were checked; no static AWS credentials or blank required
  values were present. Auto-deploy is disabled.
- 8,000 Render and 2,652 AWS log messages were scanned against prohibited plaintext,
  credential assignments, synthetic evidence markers, and 18 exact deployed secret
  values; no prohibited match remained.
- The focused cumulative run passed 74 tests plus Ruff and strict mypy. The current API
  allowlist proves R2/R3 and StoinNet execution endpoints are absent.

## Accepted artifacts and deployed revisions

- Verification/source commit: `df8902acae8de8d74d4388310871af15d50ad133`.
- Four suspended ordinary services: exact accepted R1-2 commit
  `9fb64891fa1703ba5ac526940d8a415e9e468a34`.
- Protected-recovery drill application commit:
  `d294b38990aa6553b169bff76d14ed14db7cfb3e`.
- Dockerfile SHA-256:
  `abb872cd5f619909cbf6f869c99ec26976f043456e740d6dd31f2e745c44eeae`.
- Base image:
  `python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f`.
- Realm AWS template SHA-256:
  `6a5c914bc727c6efca0ac37cfb0d8518d56d2a17d5181922fdbbd3e0f7c04e6e`.
- Recovery AWS template SHA-256:
  `de2b711426fb99d28a73f55678d3a0c53e87d46d1f10dcf27f17d6b3d800d9ac`.
- Render template SHA-256:
  `6ca2f692ed5dfc889b2de1a566e77388e3dcd750f217d7e4cf78311a9acd2070`.

Exact cloud resource IDs, secret values, and private witness commitments remain only in
the ignored operator evidence store. The logical identities and their blast radii are
recorded in `docs/r1-operations-and-activation.md`.

## Recovery, cost, and rollback

The protected drill restored a point before the durable revocation and cost event,
replayed both independent journal streams exactly once, recovered member generation 2
as revoked, retained one micro-USD of unresolved exposure, made no provider call, and
reopened only after the protected final handoff. Cleanup re-quarantined the drill,
destroyed the one-use activation login, restored the coordinator, removed temporary
environment/network access, and deleted the isolated restore.

The drill records a restore timestamp rather than a production RPO/RTO promise. Its RPO
for the exercised authority/cost events was zero relative to acknowledged independent
journal heads; an operator-grade RTO remains uncommitted until repeated production
exercises establish a defensible percentile.

Observed AWS account-wide unblended month-to-date cost was USD 0.864755, subject to
billing latency and not tag-isolated to Lucy. Current Render steady holding cost is an
estimated USD 66.20/month (Pro workspace, three recovery services, and one 5 GB
PostgreSQL database), before usage, traffic, cron runtime, and AWS. Activating the four
ordinary private services would make the same estimate USD 94.20/month before those
extras. These are list-price estimates, not a Render invoice.

Rollback is fail-closed: suspend routing/services, quarantine admission, keep capture
and paid inference disabled, preserve journals and ambiguous effects, and roll only to
an exact compatible accepted commit. Database downgrade or KMS/journal deletion is not
a rollback mechanism.

## Exceptions and residual risks

- A privileged Render, AWS, PostgreSQL, source-control, IdP, or deployment administrator
  remains an ultimate trust boundary.
- Plaintext structured memory accessible to normal realm Lucy is the accepted Phase 1
  residual confidentiality boundary; credentials/secrets remain excluded or quarantined.
- A fully compromised evidence executor may abuse known exact identifiers inside its
  own realm during the accepted grant window; it cannot enumerate tables or cross realms.
- An already issued grant can execute after a later revocation until its bounded
  admission/execution window closes; reconciliation records the actual outcome.
- Pre-released plaintext cannot be recalled from a compromised recipient. Operational
  deletion becomes cryptographically final only after the documented recovery-copy window.
- Customer IdP, DNS/ingress, numeric provider limits, provider credentials, live data,
  and capture are intentionally absent. Their absence keeps the system fail-closed and
  does not invalidate the technical R1 acceptance.

The activation checklist and quarantine route are in
`docs/r1-operations-and-activation.md`. A separate owner approval is required before
enabling any live transcript capture.
