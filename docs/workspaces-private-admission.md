# Utopia Workspaces private admission adapter

Status: implemented on `codex/workspaces-room-admission`. This includes a fail-closed private
service runtime and durable task-queue migration, but no deployed service or applied migration.
It does not expose a public endpoint, enable capture, or change AWS, Render, database, identity,
or channel configuration.

## Boundary

Utopia Workspaces is an experience surface. It cannot select Cloud Lucy authority. A Workspaces
request contains only a request identifier, room identifier, the fixed `workspaces` experience
mode, and a bounded list of requested capabilities. It cannot carry a node, realm, workspace,
channel, credential, prompt, query, or meeting-content field.

The adapter is constructed inside a realm process with:

- a `RealmInternalAdmissionService` whose deployment binding fixes the workload, node tenure,
  realm, Cloud Lucy workspace, channel, policy version, and allowed actions;
- a fixed Cloud Lucy workspace selector; and
- a deployment-owned Workspaces room capability allow-list.

`create_workspaces_admission_app` wraps that adapter in a deliberately small private HTTP surface:
health, content-free room preflight, approved-knowledge query, and task delegation. Every endpoint
authenticates the independent Workspaces transport token before parsing a bounded request body.
The Cloud Lucy authority credential remains in this service's configuration and is never accepted
from Workspaces.

The requested capability set can only narrow that configuration. Every requested capability is
then admitted against the server-selected Lucy service authority credential and current directory
authority. That service principal must be the principal named by the realm service binding and must
hold its own explicit, reviewed `member` membership in the fixed node workspace. The attendee's
invitation identity is never used as Cloud Lucy authority. Results from
a multi-capability preflight must agree on principal, scope, workspace, channel, execution binding,
and membership generations.

## Receipt and execution

A successful preflight returns only a content-free correlation receipt. It echoes the fixed
authority mode and reference so Workspaces can reject a response from the wrong private service.
The receipt is marked `usable_as_bearer: false`, contains no resolved node or realm context, and is
never accepted back by the adapter as authorization.

An operation invokes `WorkspacesExperienceGateway.execute`. It re-runs directory admission at the
time of the effect and passes the resolved execution context only to an in-process effect handler.
This means a prior preflight cannot bypass later membership revocation, channel withdrawal, node
authorization epoch change, or tool-policy removal.

Approved-knowledge queries use `ApprovedProjectionWorkspacesOperations`, which reads only through
the existing epoch-gated public projection reader and verifies the configured snapshot digest.
There is no fallback to private memory. Task delegation requires an explicitly injected queue;
without one, it returns a content-free unavailable response. The request UUID is passed to that
queue as the idempotency identity. The durable queue binds the admitted service, content scope,
workspace, channel, room correlation ID, request ID, and instruction digest. Exact retries return
the original task ID; a changed payload under the same request ID fails closed.

Workers claim tasks through an execute-only database function with `FOR UPDATE SKIP LOCKED`.
Claims receive an opaque lease token, expire after a bounded interval, and can be heartbeated only
with that exact live token. Completion is accepted once and exact terminal retries are replayed.
Expired claims can be retried up to the stored attempt limit; exhausted tasks become failed. An
immutable event table records enqueue, claim, heartbeat, completion, failure, and exhaustion.
Database functions independently require the fixed realm login to carry `task.delegate` or
`task.execute`; callers receive no direct task-table privileges.

Workspaces room IDs are correlation identifiers. They do not select authority. A prospect adapter
can be fixed to an approved sales/public knowledge projection without making the attendee a Cloud
Lucy principal. An internal Homes adapter can instead be fixed to the Homes node. For R1, each
adapter has one fixed Cloud Lucy workspace/channel binding, so one room cannot switch nodes.
Supporting several nodes requires separate trusted deployment bindings or a future directory-owned
router; caller-provided node switching remains forbidden.

## Data and availability

The contract is content-free. Workspaces operational telemetry can remain with the Workspaces
service, while transcripts, documents, decisions, approvals, generated proposals, and action
items remain node-owned content. No raw audio, video, transcript, archive, or Cloud Lucy database
credential crosses this admission request.

Task instructions and results are node-owned meeting content. They remain inside the fixed realm
database scope. The private service returns only a task ID and accepted status to Workspaces; it
does not expose task results or queue inspection through the Workspaces transport API.

Human LiveKit participation must remain independent of this adapter. Failure or withdrawal of
Cloud Lucy admission disables Lucy operations but must not terminate the human room.

## Private service configuration

The existing container can run this isolated service with `python -m lucy.workspaces_runtime`.
`deploy/render/workspaces-private-service.yaml.example` records the review-only private-service
shape with auto-deploy disabled; it is not connected to a live Blueprint.
Startup requires the following secret/configuration values and refuses to listen if capture is not
disabled, the database login differs from the fixed binding, migration `0068` is absent, the login
is elevated, required execute grants are missing, or direct task-table access exists:

- `LUCY_WORKSPACES_RUNTIME_BINDING_JSON`
- `LUCY_EXPECTED_DATABASE_LOGIN`
- `LUCY_WORKSPACES_DIRECTORY_DATABASE_URL`
- `LUCY_WORKSPACES_EXPECTED_DIRECTORY_LOGIN`
- `LUCY_WORKSPACES_TRANSPORT_TOKEN`
- `LUCY_WORKSPACES_AUTHORITY_TOKEN`
- `LUCY_WORKSPACES_AUTHORITY_SUBJECT`
- `LUCY_WORKSPACES_AUTHORITY_SESSION_ID`
- `LUCY_WORKSPACES_ROOM_CAPABILITIES_JSON`
- `LUCY_WORKSPACES_AUTHORITY_MODE=approved_knowledge`
- `LUCY_WORKSPACES_AUTHORITY_REF`
- `LUCY_WORKSPACES_PROJECTION_HOSTNAME`
- `LUCY_WORKSPACES_PROJECTION_STORAGE_EPOCH`
- `LUCY_WORKSPACES_PROJECTION_SNAPSHOT_DIGEST`
- `LUCY_TRANSCRIPT_CAPTURE_ENABLED=false`

The runtime binding must use the realm service issuer, name the bound service principal's subject,
allow workload identity, and include `memory.read`, `task.delegate`, and `task.execute` for the
current vertical slice. The production database role template grants only the required
security-definer functions, including the approved projection reader. Migration `0066` adds both
task actions only to active realm service bindings that already hold `memory.read`; migration
`0068` requires a service caller to be that exact bound service principal and admits the production
`private_realm` workspace kind. `provision_workspaces_authority_v1.py` creates the explicit service
membership only from a digest-bound manifest while admission is quarantined and capture remains
disabled. Applying migrations, provisioning that membership, creating service secrets, or adding a
Render service remains a separate reviewed deployment action.

## Verification ledger

| Check | Result | Evidence | Invalidated by |
| --- | --- | --- | --- |
| Cloud lint | Passed | `ruff check src tests migrations deploy` on 2026-09-12 | Relevant source, migration, deploy template, or test change |
| Cloud typing | Passed | Strict `mypy src` across 103 source files after the combined-head readiness correction on 2026-09-12 | Source or type configuration change |
| Adapter security tests | 18 passed | Focused admission, private API, operation, task, and runtime unit tests | Adapter, API, operation, task, runtime, or test change |
| Cloud unit and affected suite | Passed | Prior 906-unit combined suite plus 12 current Workspaces admission/runtime/provisioner tests; the full Windows rerun passed 906 tests and hit only the frozen AWS template's checkout newline hash | Relevant source, test, dependency, or checkout newline policy change |
| Fresh PostgreSQL migration | Passed | Clean `0001 -> 0068_workspaces_service_auth` migration plus `0068 -> 0067 -> 0068` reversal in an isolated PostgreSQL tmpfs container on 2026-09-12 | Migration or PostgreSQL image change |
| Directory, membership, queue, and role boundary | 6 passed | Exact service membership, service-principal equality, missing-membership denial, production `private_realm` admission, queue lifecycle, shared/private readiness, execute grants, and direct-table denial at migration `0068` | Directory, membership provisioner, queue migration/client, runtime readiness, or realm role template change |
| Workspaces backend suite | 83 passed | Full backend test suite plus Ruff on 2026-09-12 | Workspaces backend source or dependency change |
| Workspaces-to-Cloud contract smoke | Passed | In-process ASGI admission, knowledge, and task calls using the real Workspaces client and Cloud API models | Either side of the transport contract changes |
| Deployed Workspaces call | Not executed | Private API factory is intentionally not deployed | Requires approved realm construction and deployment gate |
