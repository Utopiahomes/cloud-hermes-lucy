# Telegram conversation archive

Updated: 2026-08-31

Status: local implementation under security hardening; **not accepted for live
capture**. The original acceptance claims below are bounded by the remaining
gaps in [the current recovery checkpoint](deletion-recovery-2026-08-31.md).
This document is not evidence of a deployed or approved retention configuration.

## Product policy

After final acceptance and explicit activation, the allowlisted owner's Telegram
exchanges with Lucy are intended to be captured by default. The revised server
defaults to capture disabled; `LUCY_TRANSCRIPT_CAPTURE_ENABLED=true` is required
but is not a substitute for the acceptance process.
Capture preserves what happened; it does not silently promote every sentence
to a fact, instruction, authorization, or durable belief.

The conceptual chain is:

```text
Archive -> Evidence -> Memory -> Belief or decision
```

Lucy selectively proposes durable facts, preferences, commitments, and
corrections as provenance-linked memory. A proposal remains pending until a
human owner approves it. Working context is a disposable projection rather than
a second archive.

## Envelope encryption

Each message receives a random 256-bit data-encryption key (DEK). AES-256-GCM
encrypts the versioned message envelope, and a separate key-encryption key (KEK)
wraps the DEK. PostgreSQL contains ciphertext, nonce, metadata, a reference to
the wrapped DEK, and an HMAC-SHA256 keyed commitment. It contains neither
plaintext nor the wrapped DEK.

The keyed commitment supports idempotency and integrity checking without
leaving a deterministic plaintext SHA-256 fingerprint that permits offline
guess testing. KEK and commitment-key material remain outside PostgreSQL.

`SqliteArchiveKeyStore` is a local acceptance adapter only. Production uses AWS
KMS through Render OIDC plus a narrowly scoped DynamoDB wrapped-key registry.
See [`render-aws-kms-acceptance.md`](render-aws-kms-acceptance.md).

## Owner-sovereign deletion

An authorized "forget the last message" operation pins the chosen evidence ID
in its permit. Retries do not select a newer message. It destroys the wrapped
DEK before removing ciphertext. Gateway permit issuance is currently quarantined
until independently verified owner-event authorization exists; the direct owner
API still requires owner authentication and an exact-record signed permit.
The append-only evidence envelope remains as a non-plaintext tombstoned record
so audit and provenance history do not silently disappear.

Deletion also traces and neutralizes derived state:

- derived encrypted replies lose their keys and ciphertext through the full
  registered evidence closure;
- multi-source claims and superseding descendants are invalidated and redacted;
- graph relationships are closed and redacted;
- proposals and corrections are rejected and redacted;
- associated approval payloads are scrubbed and pending approvals denied;
- entities with no remaining live references are redacted;
- disposable working contexts are purged; and
- affected conversation-turn commits are marked redacted.

The source graph now covers current inputs, retained conversation history and
observed memory/evidence tool results. Hidden Hermes history, safe resumption
after excluded/deleted/unfinished turns, and independent cross-store deletion
recovery remain capture blockers. See the provenance checkpoint for the exact
guarantees and the conservative clean-history refusal behavior.

Wrapped DEKs are outside PostgreSQL, so restoring that database alone does not
restore a destroyed raw-transcript key. The [local recovery protocol](deletion-recovery-2026-08-31.md)
now fences HTTP service access to restored plaintext projections when the
independent accepted-deletion journal does not match database receipts. Explicit
offline maintenance can finish only previously accepted intents, never infer
authority from missing keys. Normal service startup is read-only and does not
scan the key registry or perform recovery. Real-cloud compound restore, journal
identity/permissions and freshness still require acceptance. This is not a
defense against direct SQL credentials or a coordinated rollback of all stores.
The 30-day encrypted-backup window is a requirement, not provisioned or verified
production behavior. Restoring a previously destroyed wrapped key is forbidden.

## Raw evidence retrieval

Ordinary recall uses structured memory. Lucy has one narrowly bounded evidence
tool for exceptional cases: verifying exact wording, resolving ambiguity, or
recovering context missed during extraction. Autonomous retrieval requires the
exact evidence UUID, a current provenance-linked claim UUID, an active
allowlisted owner interaction, and a five-minute single-use
`SensitiveActionPermitV1`. It returns only one source message, and every
successful access is audited. Gateway minting is disabled pending owner-event
verification. Reads are single-disclosure: even an identical successful retry
requires a fresh permit and delivery key. `max_bytes` limits the decrypted
canonical source-record bytes (including its envelope), not just character count.
Application permission, missing-record, and validation denials are recorded in
separate content-free audit transactions; infrastructure failures may prevent
auditing and still fail closed.

The owner API permits single-record review with owner authentication and the
same signed-permit boundary. Owner export and bulk archive search are not
implemented. There is no model-visible approval or deletion tool.

## Off the record

The exact commands "off the record" and "back on the record" change a durable,
audited conversation state. While capture is disabled, every Lucy response is
prefixed with a visible notice. The transition into off-record mode and all
subsequent exchange content are excluded from Lucy's archive.

A content-free receipt records each turn's consent generation before processing.
Excluded turns cannot become retained through a later retry or restart. Toggling
capture invalidates older in-flight generations; those turns require a new
delivery rather than retroactive consent. Memory proposals enforce this at both
submission and promotion. Unknown consent blocks model processing.

Off the record means *not archived by Lucy*. Telegram, Hermes, and the configured
model provider still necessarily process the exchange under their own policies.

## Hermes synchronization invariant

The PostgreSQL turn record becomes `committed` only after both the owner's
message and Lucy's finalized response are durably archived. Once committed,
PostgreSQL is authoritative for autobiographical history. Hermes `/opt/data` is
runtime state and a retry cache, never the authoritative archive. Purging it
must not lose committed autobiographical data.

An on-record assistant response is withheld if its archive write cannot complete
the turn. Stable platform, conversation, turn, message, and role identities make
retries exactly-once. Off-record content is intentionally absent from the
authoritative archive and is allowed to disappear when Hermes runtime state is
purged.

## Acceptance and deployment gate

Local tests cover encrypted storage, keyed commitments, idempotent turn commits,
activation and off-record behavior, bounded audited retrieval, direct-source
deletion fences, and restart-safe replay. They do not establish full derivation
closure or cloud recovery safety. Separate real PostgreSQL logins now prove the
local four-role capability matrix, not deployed Render/AWS isolation. The pinned
Hermes middleware/registry and output-hook compatibility probe uses only
synthetic data with networking disabled.

Transcript capture must remain disabled in the live gateway until:

1. the complete unit, static, migration, and PostgreSQL integration suites pass;
2. the pinned Hermes plugin compatibility check passes without a core patch;
3. the Render-to-AWS OIDC/KMS/DynamoDB acceptance path passes with no static AWS
   credentials; and
4. the owner completes a final acceptance review.
