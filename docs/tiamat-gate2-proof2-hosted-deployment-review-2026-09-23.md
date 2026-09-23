# Gate 2 Proof 2 — hosted deployment review (not an execute approval)

Scope: one disposable `staging` ledger, one synthetic Tiamat request and one restart/re-attestation. No real provider credential, public traffic, DNS change, commissioned database access, or commissioned anchor-item write. Proof 1's local PostgreSQL result is in `docs/evidence/tiamat-gate2-proof1-fresh-ledger-2026-09-23.json`. Control boundaries are in `docs/tiamat-gate2-proof2-control-decisions-2026-09-23.md`.

## Proposed resources and cost ceiling for review

In the existing `cloud-lucy / management-contract-staging` environment, Virginia:

| Resource | Minimum plan | Purpose and credential boundary |
|---|---|---|
| New disposable PostgreSQL 16 database | `0.1c-256mb` | Its own immutable ledger ID, blocked day-zero state, no external IP allowlist after bootstrap; TLS internal connections. Not the commissioned ledger. |
| Temporary bootstrap/migration private service | `0.5c-512mb` | Owner URL and bootstrap passwords only; no AWS role, release signer, provider credential, or served traffic. Suspend after migration/finalization. |
| Disposable recovery/launcher private service | `0.5c-512mb` | Recovery URL plus exact-key anchor reader and M4 writer-alias invocation through a new OIDC role tied to this Render service ID. No direct DynamoDB item write. |
| Disposable synthetic serving private service | `0.5c-512mb` | Runtime URL, exact-key anchor read through its own OIDC role, signed public trust, `TIAMAT_PROVIDER_TRANSPORT=synthetic`. No owner/recovery/release-manager URL or real provider key. |
| Temporary Control release-manager private service | `0.5c-512mb` | Release-manager URL only; pre-signed artifacts and approved public pin, with preview/digest confirmation. No AWS role, private signing key, or owner/recovery URL. Suspend after proof. |

At [Render's published rates](https://render.com/pricing), these minimum plans total approximately **$34/month while all five resources run** ($6 database + four $7 services), plus PostgreSQL storage at $0.30/GB-month and any metered usage. Compute is prorated while running; this is a short-lived proof, not a request to run all services for a month. The actual dashboard checkout price and service availability must be checked before creation. No automatic scale-up, high availability, or top-up is proposed.

## AWS policy delta (prepare and inspect before applying)

1. Create two new OIDC roles only after Render returns exact disposable service IDs. Trust each role only for its own service ID. The served role gets `GetItem` for `ENV#staging#LEDGER#<disposable-ledger-id>` and `DescribeTable`; the recovery role gets those reads plus `lambda:InvokeFunction` on the existing M4 `live` alias. Neither gets `PutItem` or another write API.
2. Extend the writer stack's invoke permission and attached invoke policy to the new disposable recovery role while retaining the commissioned coordinator's permissions unchanged. Extend `WriterRootsJson` with the disposable anchor key and distinct recovery root. Its published roots digest/version will change; review the complete CloudFormation change set and artifact checksum before execution. The table's writer-only resource policy remains unchanged.
3. Before and after any shared-writer change, strong-read and verify the commissioned anchor head and its root mapping. The disposable root may authorize only its own key. Review CloudTrail/alarms after the change. No direct coordinator DynamoDB write is reintroduced.

## Activation order and checks

1. Approve the exact paid-resource set and shared AWS change set; create the disposable database and four isolated private services. Keep them suspended or disabled until their narrowly scoped roles and secrets are verified.
2. Bootstrap and migrate the disposable database using Proof 1's sequence to revision `0017`; finalize roles, initialize blocked, run capabilities and readback. Verify the runtime alias grant from D5 and the release-manager login/TLS path from D4. Remove the owner URL and suspend the bootstrap service.
3. Install only this ledger's quarantined bootstrap anchor through M4, then its approved generation-one RELEASE inventory. D6's pin is required **before** first-inventory; no candidate-computed fingerprint is an approval.
4. Reconcile the empty ledger through pending and established transitions, issue a launcher claimant, create the partition, stage and activate the signed policy, profile and grant through the one-off Control runner. Each mutation previews and requires exact digest/identity confirmation and authoritative readback.
5. Start only the synthetic served process. Record one request's signed profile ID, receipt, ledger accounting and cost, then stop/restart and prove fresh attestation and idempotent replay. No real provider call.
6. Stop/suspend the services, preserve evidence and the disposable anchor history, and decide disposal separately. A failed or uncertain ceremony remains blocked/re-quarantined; do not rewrite the anchor or use the commissioned ledger as a shortcut.

No paid resource, IAM role, writer-root update, signature, or ledger transition is authorized by this document alone. The execute review must include exact Render IDs, immutable image/source revision, OIDC trust documents, IAM policy diff, CloudFormation change set, public key pins, and the observed dashboard price before those actions.
