# Tiamat Control Recovery Witness v1 — Draft 0.1

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
  "storage_epoch": "uuid-v4",
  "recovery_generation": 8,
  "status": "reconciled",
  "issued_at": "2026-09-18T12:00:00Z",
  "not_before": "2026-09-18T12:00:00Z",
  "not_after": "2026-09-19T00:00:00Z",
  "inventory_generation": 12,
  "inventory_jws_sha256": "lowercase-sha256",
  "release_heads_sha256": "lowercase-sha256",
  "settlement_position_sha256": "lowercase-sha256",
  "reconciliation_digest": "lowercase-sha256"
}
```

`reconciliation_digest` is the RFC 8785 SHA-256 digest of the canonical content-free tuple:

```text
environment, storage_epoch, recovery_generation,
inventory_generation, inventory_jws_sha256, release_heads_sha256,
settlement_position_sha256
```

`release_heads_sha256` covers the sorted current `(issuer, caller_id, realm, release_type,
subject_id, active_jws_sha256, head_state)` set. `settlement_position_sha256` covers the sorted,
content-free current spending position: partition/budget-period heads, settled spend, reservations,
pending reconciliation, forfeitures, contingency use, and external-liability markers. Tiamat
recomputes these digests from its own PostgreSQL state; it never trusts a Control-supplied database
write or arbitrary digest value.

`status` is either `quarantined` or `reconciled`. A quarantined witness always blocks dispatch.
Witnesses are monotonic by `(storage_epoch, recovery_generation)`; equal generation is accepted only
for byte-identical authoritative replay, never to reopen a prior quarantine.

## Retrieval and startup

When Control is reachable, Tiamat requests the current witness using a dedicated workload identity
with audience `stoin:control-recovery-witness`, exact scope `tiamat.recovery.witness.read`, a
maximum five-minute lifetime, and request binding. The Control endpoint returns only the exact JWS
bytes plus its root-signed trust-inventory bytes. Network/TLS/client authentication is defense in
depth; signature verification is mandatory.

Tiamat verifies the trust inventory, witness framing/signature/purpose/scope/times, and every local
digest before acquiring a coordinator generation. Any mismatch keeps dispatch blocked. A valid
release, grant, or prior witness cannot override a newer quarantined witness.

When Control is unavailable, startup is permitted only for the bounded offline window already covered
by locally current signed authority and an unexpired, `reconciled`, externally stored witness that
matches the exact local state and every intervening budget period. Absence or uncertainty is a
quarantine, not a degraded dispatch mode.

## Reconciliation sequence

1. Control creates a newer external `quarantined` generation before a candidate restore is attached.
2. Tiamat/operations attach the restore with dispatch blocked.
3. Control compares the inventory, active release heads, settlement position, and liabilities.
4. After review, Control writes a `reconciled` witness for that already-created generation.
5. The separately held recovery role calls the existing offline
   `authorize_reconciled_state` operation with the verified values.
6. Tiamat rereads and verifies the exact witness and local state before acquiring a coordinator
   generation.

No normal inference endpoint, Control request, restored database, or signed release can skip these
steps.

## Required proof before deployment

- Tampered signature, unknown/retired/revoked key, wrong purpose/use/environment, unknown version,
  expired/future witness, duplicate JSON member, and mismatched digest all fail closed.
- A newer external quarantined generation blocks both a live and a stale restored database.
- A byte-identical witness is replayable; conflicting equal-generation witnesses fail closed.
- A release-head, inventory, or settlement change after witness issuance blocks startup.
- A Control outage uses only a matching, unexpired reconciled witness and never crosses an uncovered
  budget period.
- Two independently deployed processes prove that Control cannot write Tiamat's database directly
  and Tiamat cannot mint, alter, or select a witness.
