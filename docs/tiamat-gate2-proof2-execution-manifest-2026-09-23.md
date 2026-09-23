# Gate 2 Proof 2 — proposed execution manifest

Status: **prepared for resource review, not approved or executed**. The proof is one hosted synthetic request and one restart on a new disposable Tiamat ledger. No commissioned-ledger access, commissioned-anchor item write, real provider key, public traffic or DNS change is in scope. Control decision and cost review: `tiamat-gate2-proof2-control-decisions-2026-09-23.md` and `tiamat-gate2-proof2-hosted-deployment-review-2026-09-23.md`.

## Creation-only phase

Create the following in `cloud-lucy / management-contract-staging`, Virginia, from one immutable **pushed** `codex/management-contract-v1` revision selected at the execution review. Auto-deploy off, one instance each, no real provider credentials, and no AWS role or database secrets until the later boundary review. Record the observed dashboard price before confirmation.

| Proposed name | Type/plan | Initial behavior | Credential allowed when separately commissioned |
|---|---|---|---|
| `tiamat-g2p2-ledger` | PostgreSQL 16, `0.1c-256mb`, 1 GB, no HA/autoscaling | New empty database; no use of `tiamat-staging-ledger` or the older M2 test database | Generated owner URL only in bootstrap boundary; service URLs restricted to respective roles; external IP allowlist emptied after bootstrap |
| `tiamat-g2p2-bootstrap` | private service, `0.5c-512mb` | Suspended/inert; one-off bootstrap/migration/finalization jobs only | `TIAMAT_BOOTSTRAP_DATABASE_URL`, runtime/recovery password inputs, then later owner URL for D1 finalization and D4 login enablement; no AWS or signing key |
| `tiamat-g2p2-recovery` | private service, `0.5c-512mb` | Suspended/inert; one-off M4 installer, recovery, launcher jobs only | `TIAMAT_RECOVERY_DATABASE_URL`; exact-key AWS reader plus M4 alias invoke role; public trust package; never owner or runtime URL |
| `tiamat-g2p2-served` | private service, `0.5c-512mb` | Suspended/inert; later `uvicorn --factory lucy.shared_execution.served_environment:create_app_from_environment --host 0.0.0.0 --port $PORT --workers 1` | `TIAMAT_RUNTIME_DATABASE_URL`, exact-key AWS read role, approved public trust, workload verification keys, idempotency digest key; no recovery, owner, release-manager or provider credential |
| `tiamat-g2p2-release-manager` | private service, `0.5c-512mb` | Suspended/inert; one-off `tiamat_release_runner_v1.py` jobs only | `TIAMAT_RELEASE_MANAGER_DATABASE_URL` and exact pre-signed public JWS files; no AWS, owner, recovery or private signing key |

The shared image explicitly includes the D1 finalizer, M4 reconciliation installer, launcher, release runner and committed staging RELEASE-root pin. The offline recovery-signing and RELEASE-signing private files stay outside the image and Render. A generated Render service ID is the OIDC trust subject; therefore those IDs must be captured after creation and **before** the separate IAM/shared-writer change review.

Local packaging verification on 2026-09-23: the focused Dockerfile boundary tests passed (9/9); a local `docker build --pull=false` succeeded; a no-network container confirmed all five Gate 2 files above are present and the four CLI entry points import with `--help`. This verifies the image recipe, **not** a Render deployment or its hosting permissions. It is invalidated by a relevant Dockerfile, lockfile, source or image-base change.

## Identity and authority still to be filled from the new database

Migration `0005` creates the immutable `ledger_id` inside PostgreSQL; it is not chosen by this manifest. Read it from the blocked database after bootstrap, then bind that **exact** UUID and the newly chosen storage-epoch UUID into the anchor key, trust document, Render configurations, OIDC leading-key policies and evidence. The signed RELEASE inventory has no ledger-ID field. Use unique Proof 2 `caller_id` and `realm` values incorporating the ledger UUID, and exact noncolliding subjects for one privacy policy, one execution profile and one spending partition. The inventory scopes are those three `(caller_id, realm, release_type, subject_id)` tuples only. The issuer is `stoin-control`. Use a synthetic-only route/profile, one-call concurrency, a small bounded grant and explicit validity windows; fix their exact values in a reviewed unsigned payload before offline signing. No wildcard or commissioned scope may be signed.

The deployed M4 alias is shared. Invocation is **not** restricted by IAM to one anchor key. The writer's exact key-to-recovery-root map and signed ledger identity are the cross-key boundary. Preserve the commissioned mapping for `ENV#staging#LEDGER#6177502f-3a93-429c-b68b-0ed726d1447f` exactly and append the disposable key with its distinct recovery root. Compare both mappings and the commissioned head before/after the writer change; test a disposable-root package against the commissioned key as a rejected negative case.

## Stop conditions and acceptance

- Stop before any credential, IAM or shared-writer action if the resource names/plans, generated IDs, source revision or checkout price differ from the approved creation packet.
- Stop with dispatch blocked if bootstrap, TLS, role finalization, pin verification, inventory installation, continuity, claimant or signed-release activation fails. Do not use the commissioned database or rewrite anchor history to recover.
- During the serialized disposable release ceremony, freeze inventory/key updates: D4 re-verifies immediately before a separate write transaction but does not transactionally fence a concurrent revocation. A concurrent authority change would require a focused fix before using that path.
- Accept Proof 2 only after one synthetic-only response has a receipt and settled ledger record, a restart produces a fresh claimant, and replay is idempotent. Record service/ledger IDs, pinned commit/image, exact public digests, before/after commissioned mapping and head, observations and disposition. Suspend temporary services afterward; database deletion requires a separate exact-target decision.
