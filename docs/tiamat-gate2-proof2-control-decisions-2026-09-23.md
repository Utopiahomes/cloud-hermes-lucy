# Gate 2 Proof 2 — Control-side decisions

Status: design decisions recorded; **not** authorization to provision, deploy, sign, or activate. Proof 1's local disposable-ledger result is recorded in `docs/evidence/tiamat-gate2-proof1-fresh-ledger-2026-09-23.json`. Proof 2 is one hosted **synthetic** execution on a different disposable ledger. The commissioned ledger and its anchor item remain out of scope.

## D1 — isolated Render boundary

Use a new disposable PostgreSQL database, a separate recovery/launcher runner, and a separate synthetic-only served service. Do not repoint the commissioned coordinator or reuse its database credentials. Pin every runner/service to the disposable ledger ID and exact Render service ID. The recovery runner may read only its anchor key and invoke the reviewed M4 writer alias; it has no direct DynamoDB write. The served service holds only the runtime database URL and disposable anchor-read role, never the recovery or owner URL, AWS static keys, or real provider credentials. Bootstrap/migration uses a temporary owner boundary. Disable external database access after bootstrap and suspend temporary services after evidence collection.

The shared M4 writer's roots and invocation policy must be changed to admit the disposable key and runner. This is a change to infrastructure also used by the commissioned environment even if its anchor item is unchanged. Before applying it, review the exact change set and capture a before/after strong read proving the commissioned anchor head and root mapping did not change. Paid Render provisioning and this shared-boundary deployment require their own explicit execution approval.

## D4 — Control release management

For this disposable ledger only, make `tiamat_release_manager` a login with its existing narrow grants. Supply its TLS-required database URL exclusively to a Control-operated, one-off release runner. Keep this runner separate from recovery, owner, serving, signing-key, and AWS-writer credentials. Feed it exact pre-signed inventory/release bytes and independently approved public pins; do not put private signing keys on Render. It previews by default; execution requires exact digest/scope confirmation, checks `current_user` and ledger identity, and performs authoritative readback after a write. Remove its credential and suspend the runner after Proof 2.

This is the normal authenticated local management action allowed by Signed Release RC1 §6, **not** an online activation API and not an offline recovery activation. An online endpoint would require the separate short-lived activation JWT contract. The operator path must verify the current inventory, signature, key status, scope, applicability time, predecessor and sequence immediately before activation; `activate_release()` alone is not a complete verifier. Stage and activate policy/profile before the grant, and activate nothing until continuity is established. No inference request may activate releases.

## D6 — staging RELEASE trust root

There is no approved staging RELEASE-root pin in the repository. A distinct offline Control/policy-notary RELEASE root and a signed generation-one inventory must be prepared; do not reuse the recovery root, a release-signing key, or a workload key. Control must authenticate the offline public-key provenance and approve the exact root key ID and SHA-256 of the **raw Ed25519 public bytes**, independently of the inventory installation invocation. Only then commit `deploy/postgres/tiamat-staging-release-root-pin.json` with exactly `format_version: "1"`, `environment: "staging"`, `root_key_id`, and `root_public_key_sha256`. The same approved key ID, public key and fingerprint must be pinned by reconciliation and the served process.

D6 blocks the **first-inventory** step, not just later release activation. No candidate's self-calculated digest is by itself approval. Private root custody stays in the offline Control boundary and requires a durable recovery copy; no private material goes in Git, Render, DynamoDB, job output, or this document. Key creation and signature are separate from this decision record.

## Proof 2 finish line and remaining gates

Claude may fix D5's missing runtime grant and prepare the operator runner/configuration locally while Control arranges D6. Before hosted execution: review the exact paid resources, IAM trust/policy diffs and shared-writer change set; finish the RELEASE-root approval; verify the release runner's complete activation path; and retain the explicit execute confirmations in the Phase B sequence. Then run one synthetic request plus one restart/re-attestation and record the receipt, accounting, and readbacks. Do not start a real provider, the commissioned-ledger ceremony, or a broad recovery matrix as part of this proof.
