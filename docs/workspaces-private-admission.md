# Utopia Workspaces private admission adapter

Status: implemented and locally verified on `codex/workspaces-room-admission`. This includes a
private FastAPI factory but no deployed service. It does not expose a public endpoint, enable a
runtime, enable capture, or change AWS, Render, database, identity, or channel configuration.

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
`GET /health` and `POST /v1/workspaces/rooms/admit`. The endpoint authenticates the independent
Workspaces transport token before parsing a bounded request body. The Cloud Lucy authority
credential remains in this service's configuration and is never accepted from Workspaces.

The requested capability set can only narrow that configuration. Every requested capability is
then admitted against the server-selected Lucy/service authority credential and current directory
authority. The attendee's invitation identity is never used as Cloud Lucy authority. Results from
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

Human LiveKit participation must remain independent of this adapter. Failure or withdrawal of
Cloud Lucy admission disables Lucy operations but must not terminate the human room.

## Verification ledger

| Check | Result | Evidence | Invalidated by |
| --- | --- | --- | --- |
| Adapter lint | Passed | `ruff check src tests` on 2026-09-12 | Adapter or test change |
| Adapter typing | Passed | Strict `mypy src` across 88 source files | Adapter or type configuration change |
| Adapter security tests | 11 passed | Focused admission and private API tests | Adapter, API, admission contracts, or test change |
| Full Cloud Lucy suite | 799 passed, 248 environment-gated tests skipped | `pytest -q` on 2026-09-12; isolated databases were not configured | Any repository source or dependency change |
| Workspaces-to-Cloud contract smoke | Passed | In-process ASGI request using the real client and private API models | Either side of the transport contract changes |
| Deployed Workspaces call | Not executed | Private API factory is intentionally not deployed | Requires approved realm construction and deployment gate |
