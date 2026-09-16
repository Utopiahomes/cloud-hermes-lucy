# Utopia Homes Business Contract `guest.answer@1.0` — Tier A checkpoint

Date: 2026-09-16. The RC2 wire contract and its deterministic Tier A conformance bundle are
frozen for implementation. This checkpoint records an artifact pin and verification evidence; it
does not authorize provider code, website changes, credentials, deployment, model spending, or
production traffic.

## Frozen inputs

| Item | Canonical value |
| --- | --- |
| Contract | `docs/stoin-utopia-business-contract-guest-answer-rc2.md` |
| Contract commit | `daf99943abf177f2209a6efb00e03c087bc542c6` |
| Capability | `guest.answer@1.0` |
| Tier A source commit | `06f54e0e2e3a85bdc925074c9c96f14f3cd2593b` |
| Tier A content digest | `sha256:50492b998b393a25322cb9b76e4a8fbd7199905b8457450b8aa48ae00149ad4c` |
| Vendored artifact | `contracts/stoin-business-guest-answer-v1-bundle/` |
| Artifact size | 218 hashed files |
| Deterministic checks | 250 passed |

The vendored tree was exported from the exact Tier A source commit with `git archive`. It excludes
source-repository metadata and ignored runtime artifacts. `MANIFEST.json` and `DIGEST.txt` identify
the frozen content; archive hashes are not canonical because archive metadata can vary.

## Independent verification ledger

| Check | Result | Evidence | Invalidated by |
| --- | --- | --- | --- |
| Exact source revision | Passed | Local Tier A repository resolved to `06f54e0e2e3a85bdc925074c9c96f14f3cd2593b` with a clean worktree | Source commit or worktree content changes |
| Pinned verifier dependencies | Passed | `tools/requirements.txt` installed into an isolated temporary Python 3.12 dependency directory | Dependency pin or interpreter compatibility changes |
| Complete Tier A verifier | Passed, 250 checks | Schemas, complete-state and violation gates, RFC 8785 vectors, auth and replay, headers, request/response transport limits, exchanges, strict/lenient parsing, and retry fixtures all passed | Any artifact or verifier change |
| Independent content digest | Passed | Separate PowerShell raw-byte implementation computed `50492b998b393a25322cb9b76e4a8fbd7199905b8457450b8aa48ae00149ad4c` over 218 files | Any included byte or path changes |
| Manifest integrity | Passed | All 218 manifest entries matched their independently computed SHA-256 values | Any included byte, path, manifest, or digest change |
| Coreutils reproduction | Passed | Corrected documented command, including `.git` and `__pycache__` exclusions, reproduced the canonical digest | Digest algorithm, command, line endings, path ordering, or artifact changes |
| Fresh archive extraction | Passed, 250 checks | Verifier and digest check passed from a fresh `git archive` extraction of the frozen source commit | Source commit, dependencies, verifier, or extraction behavior changes |

## Ownership and implementation boundary

- Claude owns the Utopia Homes Prime provider implementation, the Homes-side artifact pin, and the
  Utopia Homes website consumer implementation.
- Lyra owns Stoin Control. Control may advertise the capability through the separate Management
  Contract, but it must not proxy, authorize, route, supply knowledge to, or otherwise enter the
  guest request path.
- Shared Model Execution remains a private provider-neutral dependency behind Homes Prime. It does
  not own Homes prompts, knowledge, business rules, or answers.
- Tier A proves deterministic protocol behavior only. It does not prove conversational usefulness,
  grounding quality, latency, cost, privacy of a deployed provider route, or the Tier B acceptance
  conversations.

## Authorized next implementation sequence

1. Pin the exact contract commit and Tier A content digest in the Homes Prime/provider repository
   and the website consumer repository without copying Control runtime code.
2. Implement the Homes Prime provider boundary and make it pass the strict provider, authentication,
   replay, transport, invariant, privacy, and failure vectors.
3. Implement the website consumer with tolerant additive response parsing, bounded browser-memory
   history, server-side credentials, and the specified retry and presentation behavior.
4. Exercise the two independently deployed processes in an isolated conformance preview. Control
   must be blocked or unavailable during the guest-path isolation proof.
5. Build and run Tier B semantic and grounding evaluation against the exact provider, model route,
   Homes behavior release, knowledge release, and evaluation configuration.
6. Return measured correctness, support, correction quality, latency, cost, failure, and rollback
   evidence for joint review before any activation decision.

No database, migration, production key, deployment, DNS change, public traffic, or model-spending
authorization is implied by this checkpoint.
