# Hermes memory tools acceptance

Date: 2026-08-28

## Result

Lucy control plugin 1.1.0 exposes two first-class tools to the pinned Hermes
Telegram and CLI profiles:

- `lucy_memory_lookup` searches a bounded projection of current claims.
- `lucy_memory_propose` creates a provenance-linked candidate that remains
  pending human approval.

Hermes core is unmodified. The tools call the existing bearer-authenticated
Lucy companion over the private Compose network and are unavailable when either
the companion URL or adapter credential is absent.

## Read boundary

Lookup accepts one trimmed query of at most 200 characters. It returns at most
the companion's bounded claim limit and requires the response to assert
`read_only: true`. Claims contain interpretation fields plus claim ID, evidence
ID, evidence SHA-256, confidence, status, and relationship version. Raw archive
content is never returned. The tool labels every successful result as context,
not authorization, and fails closed on an unavailable or malformed companion
response.

The live handler reached the READY companion and returned a valid read-only
projection. The current live database contains no accepted claims, so the
correct result contained zero claims; no synthetic fact was inserted merely to
make the demonstration nonempty.

## Proposal boundary

Proposal requires an immutable evidence UUID, bounded subject/predicate/object,
and confidence from zero through one. The model cannot supply its own replay
identity: the plugin derives a deterministic SHA-256 idempotency key from the
canonical candidate. It accepts a companion response only when status is
`pending`, an approval ID exists, and `claim_id` remains null. The result says
explicitly that the candidate is neither remembered nor applied.

There is no tool for approval decisions, proposal application, archive access,
correction application, database access, or administrative operations. The
existing isolated PostgreSQL integration suite proves successful pending
submission, exact replay, refusal before human approval, human-approved apply,
and provenance linkage. A live negative check used a nonexistent evidence UUID;
the tool failed closed and both proposal and claim counts remained zero.

## Tool-surface evidence

Pinned-container plugin doctor passed manifest parsing, import, registration,
and exactly two tool registrations. The live Telegram tool listing showed only
`clarify` and `lucy_memory` enabled. Terminal, file operations, code execution,
web/browser access, built-in memory, delegation, cron, and all other privileged
toolsets remained disabled.

Automated checks cover registration metadata, environment requirements,
read-only response validation, companion failure, deterministic proposal replay
identity, pending-only results, rejection of applied responses, provider-policy
enforcement, and the profile's explicit per-platform tool allowlist.
