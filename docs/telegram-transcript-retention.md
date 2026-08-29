# Telegram conversation archive

Date: 2026-08-28

Status: implemented and tested, but deliberately not enabled in the live
Telegram gateway pending owner acceptance.

## Product policy

The allowlisted owner's Telegram exchanges with Lucy are captured by default.
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

"Forget the last message" selects the most recent still-decryptable message in
the conversation and destroys its wrapped DEK before removing its ciphertext.
The append-only evidence envelope remains as a non-plaintext tombstoned record
so audit and provenance history do not silently disappear.

Deletion also traces and neutralizes derived state:

- directly derived claims and superseding descendants are invalidated and
  redacted;
- graph relationships are closed and redacted;
- proposals and corrections are rejected and redacted;
- associated approval payloads are scrubbed and pending approvals denied;
- entities with no remaining live references are redacted;
- disposable working contexts are purged; and
- affected conversation-turn commits are marked redacted.

A database backup alone cannot resurrect deleted plaintext because wrapped DEKs
are outside PostgreSQL. Production PostgreSQL backups are encrypted and retained
for no more than 30 days. Key-registry recovery must honor the permanent
destruction record; restoring an old wrapped key is forbidden.

## Raw evidence retrieval

Ordinary recall uses structured memory. Lucy has one narrowly bounded evidence
tool for exceptional cases: verifying exact wording, resolving ambiguity, or
recovering context missed during extraction. Autonomous retrieval requires the
exact evidence UUID and a current provenance-linked claim UUID. It returns only
one source message, and every successful access is audited.

The owner API permits broader single-record review or export with owner
authentication. There is no model-visible archive search, bulk export,
approval, or deletion tool.

## Off the record

The exact commands "off the record" and "back on the record" change a durable,
audited conversation state. While capture is disabled, every Lucy response is
prefixed with a visible notice. The transition into off-record mode and all
subsequent exchange content are excluded from Lucy's archive.

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

Automated acceptance proves encrypted-at-rest storage, keyed commitments,
idempotent turn commits, default-on and visible off-record behavior, narrowly
audited retrieval, owner retrieval, cryptographic deletion, cascading derived
data invalidation, and restart-safe replay.

Transcript capture must remain disabled in the live gateway until:

1. the complete unit, static, migration, and PostgreSQL integration suites pass;
2. the pinned Hermes plugin compatibility check passes without a core patch;
3. the Render-to-AWS OIDC/KMS/DynamoDB acceptance path passes with no static AWS
   credentials; and
4. the owner completes a final acceptance review.
