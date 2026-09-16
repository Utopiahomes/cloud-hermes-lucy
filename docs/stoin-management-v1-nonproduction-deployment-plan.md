# Management Contract v1 — non-production deployment plan

Date: 2026-09-16. Prepared only; no service, credential, endpoint, or deployment
is authorized or created by this document.

## Finish line

Prove Management Contract v1 between two independently built and deployed
processes without placing Stoin Control in the guest request path:

1. Homes deploys adapter commit
   `c04a97a47c9bbecb9e45b882492f756eeaaed196` as a dedicated staging web
   service with public HTTPS and no database.
2. Control runs a one-shot job from the reviewed Control commit. The job calls
   only the adapter's four fixed read-only resources through
   `python -m lucy.management_commission`, emits content-free evidence, and exits.
3. The adapter remains suspended or is deleted after evidence capture. The
   private signing seed is destroyed. No polling service remains running.

This is a deployment-boundary proof, not product activation. It must not alter
Public Lucy, Private Lucy, the Homes website, DNS, a production environment,
guest capacity, any database, or any Business Contract.

## Topology and ownership

| Process | Owner | Repository/release | Network | Durable state |
| --- | --- | --- | --- | --- |
| Homes management adapter staging | Homes/Claude | `utopia-homes-management-adapter` at the exact reviewed commit | Public HTTPS, JWT protected; `/healthz` is liveness only | None |
| Control commissioning job | Stoin Control/Lyra | `cloud-hermes-lucy` at the exact reviewed commit | Outbound HTTPS only to one deployment-owned URL | None |

The services may use the same cloud vendor, but must not share an image,
repository, service identity, environment group, database, release lifecycle, or
autoscaling capacity. The adapter URL is fixed in the job environment and cannot
come from a request.

## Test credential

Generate one new Ed25519 keypair for this proof only:

- Control receives the 32-byte private seed as
  `STOIN_MANAGEMENT_JWT_PRIVATE_KEY_B64` and a non-secret key identifier as
  `STOIN_MANAGEMENT_JWT_KEY_ID`.
- Homes receives only the matching public PEM in
  `MANAGEMENT_ADAPTER_JWT_PUBLIC_KEYS_JSON`.
- The key is not reused for policy, receipts, deployment, customer identity,
  production management, or business calls.
- The seed must not appear in commands, logs, screenshots, evidence, source,
  shell history, or shared environment groups.
- After the proof, delete the job secret and adapter allowlist value. A later
  staging run gets a new pair.

## Staging configuration

Homes uses Claude's reviewed adapter configuration with these staging-specific
constraints:

- environment, deployment ID, runtime ID, release ID, artifact digest, and
  deployment timestamp identify the exact staging release;
- the sole advertised capability is enabled `guest.answer` v1.0;
- transitional health remains `unknown` with
  `health_coverage_limited` and an empty impaired set;
- auto-deploy is off, one instance maximum, and no production environment group,
  database, website secret, model key, or guest content is attached.

Control receives only:

- `STOIN_MANAGEMENT_PROVIDER_BASE_URL` — the exact HTTPS origin, with no path;
- `STOIN_MANAGEMENT_EXPECTED_PROVIDER_RELEASE_ID` — the exact staged release;
- `STOIN_MANAGEMENT_JWT_PRIVATE_KEY_B64`; and
- `STOIN_MANAGEMENT_JWT_KEY_ID`.

The Control image already contains the pinned RC3 bundle. The job requires no
database URL, OpenRouter key, AWS role, owner token, website token, transcript
setting, or Private Lucy configuration.

## Execution order

1. Push the two reviewed branches only after explicit push authorization.
2. Build the adapter image from the exact Homes commit and record its immutable
   artifact digest. Do not activate automatic deployment.
3. Create the isolated staging adapter and enter only its reviewed static config
   and public verification key.
4. Confirm `/healthz` reports process liveness. It is not business health.
5. Build the Control image from the exact Control commit.
6. Create a one-shot Control job with the four environment values above and
   command `python -m lucy.management_commission`.
7. Run it once. A pass is one JSON object containing only contract version,
   fixed synth/realm IDs, staged provider release, transitional health,
   `guest.answer`, resource count, and the RC3 digest.
8. Re-run once with a deliberately mismatched test key. It must exit nonzero and
   emit only `management commissioning failed`; do not retain the bad token.
9. Restore the valid key only if a repeatability run is explicitly desired.
10. Capture service IDs, exact source commits, image digests, timestamps, exit
    statuses, and the content-free pass/fail output.
11. Delete the private seed from the job, remove the public key from the adapter,
    and suspend or delete both staging workloads.

## Acceptance and rollback

Acceptance requires:

- independent Homes and Control deployment artifacts;
- matching canonical bundle digest
  `c3bc25e4ae7708aba2581282d933ddd431d5ed5d0277a66477cdbe7ecc39fe33`;
- four resources observed through HTTPS with the exact JWT profile;
- exact Homes synth and realm identity;
- provider release consistency across health and version;
- enabled `guest.answer`;
- transitional `unknown` plus `health_coverage_limited`;
- invalid-signature rejection; and
- no database, guest-path, website, Public Lucy, Private Lucy, or production
  change.

Rollback is deletion or suspension of the two non-production workloads and
destruction of the ephemeral key. Because there is no database, DNS record,
traffic route, scheduler, or product activation, rollback requires no data
migration or guest-facing action.

## Remaining authorization gate

The local implementations and two-process TLS proof are complete. The next
state-changing action is pushing the exact branches and creating isolated
staging workloads. That requires explicit deployment authorization naming the
commits, target environment, allowed spend, and permission to provision the
ephemeral key. Production activation remains a separate decision.
