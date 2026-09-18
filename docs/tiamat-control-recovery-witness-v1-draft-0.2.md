# Tiamat Control Recovery Witness v1 — Draft 0.3

## Purpose and boundary

This companion closes the remaining local-only gap in Tiamat Shared Model Execution RC1: a
database restore cannot establish its own freshness. Control is the authoritative management-plane
issuer of a content-free recovery witness; Tiamat is the data-plane verifier and remains fail-closed
when the witness is missing, stale, invalid, or inconsistent with its PostgreSQL restore gate.

The witness contains no prompts, messages, model output, customer facts, provider credentials, or
customer identifiers. It authorizes neither model dispatch nor release activation by itself. It only
attests the externally retained recovery generation and reviewed reconciliation position that must
already exist before Tiamat may load locally staged authority.

This draft implements the recovery requirement in
`docs/tiamat-signed-release-format-v1-rc1.md` §7 and the policy-notary key-purpose boundary in
Management Contract v1 §6.2. It is deliberately a new contract, not an extension of the signed
release packet.

## Trust and key separation

The witness is a compact Ed25519 JWS. It uses:

- protected header: exactly `{"alg":"EdDSA","kid":"...","typ":"stoin-tiamat-recovery-witness+jws"}`;
- signer purpose: `policy_notary_v13`;
- signer use: exactly `tiamat-recovery-witness`;
- a separate, root-signed recovery-witness trust inventory with the type
  `stoin-tiamat-recovery-witness-trust-inventory+jws`.

The recovery-witness inventory is distinct from the release trust inventory. A release-signing key
cannot sign a witness merely because it has the same high-level policy-notary purpose. Its inventory
record must explicitly authorize this use. The deployment root verifies the witness inventory from
outside the PostgreSQL backup/snapshot boundary. Root replacement, witness-key revocation, and
inventory generation changes are deployment recovery operations, not ordinary Control requests.

All compact-JWS handling follows the existing signed-release rules: exact received bytes are
verified and hashed; no re-serialization; maximum 131,072 bytes; no padding, unprotected fields,
duplicate JSON members, unknown protected-header members, or unknown format versions.

## Witness payload

```json
{
  "format_version": "1",
  "witness_id": "uuid-v4",
  "issuer": "stoin:control",
  "environment": "staging",
  "ledger_id": "uuid-v4",
  "storage_epoch": "uuid-v4",
  "recovery_generation": 8,
  "witness_revision": 1,
  "status": "reconciled",
  "issued_at": "2026-09-18T12:00:00Z",
  "not_before": "2026-09-18T12:00:00Z",
  "not_after": "2026-09-19T00:00:00Z",
  "inventory_generation": 12,
  "inventory_jws_sha256": "lowercase-sha256",
  "release_heads_sha256": "lowercase-sha256",
  "checkpoint_settlement_position_sha256": "lowercase-sha256",
  "checkpoint_digest": "lowercase-sha256"
}
```

The witness attests a reconciled checkpoint, not the database's continuously changing live state.
Successful inference, settlement, lease renewal, and ordinary spending may advance from that
checkpoint without obtaining another witness. An ordinary restart is eligible when the external
witness still authorizes the same ledger/epoch/generation and the local database's retained
checkpoint anchor matches it. A snapshot that predates ordinary work is not accepted after a
**supported** restore because the restore procedure invalidates the former external authorization
before the snapshot is attached.

`checkpoint_digest` is the RFC 8785 SHA-256 digest of this exact JSON object, whose keys are
serialized by RFC 8785 and whose arrays are sorted by the listed tuple fields:

```json
{
  "environment": "...",
  "ledger_id": "...",
  "storage_epoch": "...",
  "recovery_generation": 9,
  "inventory": {"generation": 12, "jws_sha256": "..."},
  "release_heads": [
    {"issuer":"...","caller_id":"...","realm":"...","release_type":"...",
     "subject_id":"...","active_jws_sha256":"...","head_state":"..."}
  ],
  "settlement_position": [
    {"partition_id":"...","budget_period_id":"...","settled_microusd":0,
     "reserved_microusd":0,"pending_reconciliation_count":0,
     "forfeited_microusd":0,"contingency_used_microusd":0,
     "external_liability_marker":"none"}
  ]
}
```

`release_heads` sorts lexicographically by `(issuer, caller_id, realm, release_type, subject_id)`.
`settlement_position` sorts lexicographically by `(partition_id, budget_period_id)`. All integer
amounts are non-negative micro-USD integers; no floats are permitted. Tiamat recomputes this exact
checkpoint digest at reconciliation. It never trusts a Control-supplied database write or arbitrary
digest value.

The separate `release_heads_sha256` is the RFC 8785 SHA-256 digest of the `release_heads` array
alone; `checkpoint_settlement_position_sha256` is the RFC 8785 SHA-256 digest of the
`settlement_position` array alone. Both reject duplicate logical keys before hashing and use the
same ordering and exact object members defined above. The three digests provide cheap independent
diagnostics; `checkpoint_digest` remains the authoritative combined binding.

`status` is either `quarantined` or `reconciled`. A quarantined witness always blocks dispatch.
Every change to recovery state or checkpoint receives a strictly higher `recovery_generation`.
Routine renewal of an unchanged reconciled checkpoint keeps that generation and increments the
positive integer `witness_revision`; it may change only `witness_id`, issuance/validity times, and
the JWS signature. Equal `(ledger_id, storage_epoch, recovery_generation, witness_revision)` is
accepted only for byte-identical replay. Renewal cannot clear quarantine, alter a checkpoint, or
extend an expired witness retroactively.

Generation increases only within one authorized storage epoch. Changing a storage epoch requires
an explicit deployment recovery transition that provisions a new witness; UUIDs identify epochs but
never order them. `ledger_id` names one independently recoverable Tiamat ledger, so multiple
databases in one environment cannot accidentally share witness authority.

## Retrieval and startup

When Control is reachable, Tiamat requests the current witness using a dedicated workload identity
with audience `stoin:control-recovery-witness`, exact scope `tiamat.recovery.witness.read`, a
maximum five-minute lifetime, and request binding. The Control endpoint returns only the exact JWS
bytes plus its root-signed trust-inventory bytes. Network/TLS/client authentication is defense in
depth; signature verification is mandatory.

Tiamat refreshes the witness at startup and at least every 30 seconds while Control is reachable.
Control may additionally deliver an authenticated immediate-quarantine notification to the same
private endpoint; receipt blocks new admission before acknowledgement. Known quarantine therefore
acts immediately, while an offline executor remains limited by its existing bounded offline window
and cannot react to an undiscovered later witness.

At startup and reconciliation, Tiamat verifies the trust inventory, witness
framing/signature/purpose/scope/times, ledger identity, restore gate, and exact checkpoint digest
before acquiring a coordinator generation. During an ordinary restart it verifies the retained local
checkpoint anchor and current witness; it does not require a live spending snapshot to equal the
older checkpoint. Any mismatch keeps dispatch blocked. A valid release, grant, or prior witness
cannot override a newer quarantined witness.

When Control is unavailable, an ordinary restart is permitted only for the bounded offline window
already covered by locally current signed authority, every intervening budget period, and an
unexpired, `reconciled`, externally retained witness matching the local checkpoint anchor. Absence
or uncertainty is a quarantine, not a degraded dispatch mode.

Control renews a healthy witness before expiry by issuing a higher `witness_revision` over the same
reconciled checkpoint. Tiamat atomically replaces its externally retained witness cache only after
verification. This renewal does not reset spending, alter the PostgreSQL recovery generation, or
require restore reconciliation. A later management outage may therefore permit an ordinary restart
from the retained checkpoint until the renewed witness or signed budget authority expires.

## Reconciliation sequence

1. Control creates a newer external `quarantined` generation before a candidate restore is attached,
   thereby invalidating every prior recovery authorization.
2. Before acknowledging quarantine, the live Tiamat process calls the existing recovery gate:
   it blocks new admission, increments the coordinator generation, and fences every admitted worker
   before its durable `admitted → dispatched` transition. Already-dispatched calls remain content-free
   possible liabilities; they are reaped or reconciled rather than declared cancelled.
3. Tiamat/operations stop or isolate old workers, then attach the restore with dispatch blocked.
4. Control compares the inventory, active release heads, settlement position, and liabilities.
5. After review, Control writes a `reconciled` witness with a strictly higher generation.
6. The separately held recovery role calls the existing offline
   `authorize_reconciled_state` operation with the verified values.
7. Tiamat rereads and verifies the exact witness, the retained checkpoint anchor, and local state
   before acquiring a coordinator
   generation.

No normal inference endpoint, Control request, restored database, or signed release can skip these
steps.

This protection applies only to supported restore, clone, rollback, and potentially data-losing
failover procedures that invoke this recovery gate before attaching the candidate database and do
not issue serving credentials to old workers afterward. A silently substituted older snapshot that
bypasses every deployment and recovery control is outside v1's detectable threat boundary; the
deployment must enforce and test those supported paths.

## Required proof before deployment

- Tampered signature, unknown/retired/revoked key, wrong purpose/use/environment, unknown version,
  expired/future witness, duplicate JSON member, and mismatched digest all fail closed.
- A newer external quarantined generation blocks both a live and a stale restored database once
  delivered; the refresh/notification delay is bounded and offline behavior follows the stated
  offline window.
- A byte-identical witness is replayable; conflicting equal-generation witnesses fail closed.
- Normal spending, routine witness renewal, management outage, and ordinary restart succeed without
  resetting spending or performing restore reconciliation.
- Normal post-checkpoint spending and settlement permit an ordinary restart without Control.
- A release-head, inventory, or settlement mismatch at the *reconciled checkpoint* blocks startup.
- A Control outage uses only a matching, unexpired reconciled witness and never crosses an uncovered
  budget period.
- A quarantine racing an admitted execution fences its worker before dispatch; an in-flight provider
  call remains a pending liability, and an old worker reconnecting after restore cannot dispatch or
  write into the replacement ledger.
- Two independently deployed processes prove that Control cannot write Tiamat's database directly
  and Tiamat cannot mint, alter, or select a witness.
