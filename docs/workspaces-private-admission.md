# Utopia Workspaces private admission adapter

Status: implemented and locally verified on `codex/workspaces-room-admission`. This is an
inactive library boundary. It does not expose a public endpoint, enable a runtime, enable capture,
or change AWS, Render, database, identity, or channel configuration.

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

The requested capability set can only narrow that configuration. Every requested capability is
then admitted against the current customer identity and directory authority. Results from a
multi-capability preflight must agree on principal, scope, workspace, channel, execution binding,
and membership generations.

## Receipt and execution

A successful preflight returns only a content-free correlation receipt. The receipt is marked
`usable_as_bearer: false`, contains no resolved node or realm context, and is never accepted back
by the adapter as authorization.

An operation invokes `WorkspacesExperienceGateway.execute`. It re-runs directory admission at the
time of the effect and passes the resolved execution context only to an in-process effect handler.
This means a prior preflight cannot bypass later membership revocation, channel withdrawal, node
authorization epoch change, or tool-policy removal.

Workspaces room IDs are correlation identifiers. They do not select authority. For R1, one
deployed Workspaces adapter has one fixed Cloud Lucy workspace/channel binding, so one room cannot
switch nodes. Supporting several nodes requires separate trusted deployment bindings or a future
directory-owned router; caller-provided node switching remains forbidden.

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
| Adapter lint | Passed | `ruff check src/lucy/workspaces_admission.py tests/unit/test_workspaces_admission.py` | Adapter or test change |
| Adapter typing | Passed | `mypy src/lucy/workspaces_admission.py` | Adapter or type configuration change |
| Adapter security tests | 6 passed | `pytest -q tests/unit/test_workspaces_admission.py` | Adapter, admission contracts, or test change |
| Full Cloud Lucy suite | 794 passed, 248 environment-gated tests skipped | `pytest -q` on 2026-09-12; isolated databases were not configured | Any repository source or dependency change |
| Deployed Workspaces call | Not executed | Adapter intentionally has no endpoint yet | Requires approved private service wiring and deployment gate |
