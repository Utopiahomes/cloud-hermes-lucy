# Hermes compatibility spike

- Date: 2026-08-26
- Result: passed
- Hermes release: `v2026.8.19` / `v0.20.5`
- Image manifest: `sha256:3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09`
- Linux AMD64 manifest: `sha256:f3cba6abf5ed80d47a271498d663ace5dda87f45000552afb8be8370a35df1b5`
- Source commit: `fcbd1076a93841fa88855acce810e342a5b78101`
- Target: Docker Desktop Linux AMD64

## Acceptance evidence

| Requirement | Result | Evidence |
| --- | --- | --- |
| Pinned Hermes container starts | Passed | `hermes --version` reports v0.20.5 (2026.8.19), Docker install, Python 3.13.5 |
| Secret-free Lucy profile loads | Passed | Hermes lists `lucy-memory` as a local enabled skill |
| Companion API is privately reachable | Passed | Adapter receives JSON from `http://lucy-api:8080` on the project network |
| Read-only memory lookup works | Passed | Response asserts `{"claims":[],"query":"tea","read_only":true}` |
| No Hermes core modification | Passed | Runtime UID 10000 cannot write `/opt/hermes` |
| `/opt/data` persists | Passed | Seed marker, SOUL, config, and Lucy skill survive separate one-shot containers; UID 10000 can write the volume |

The test used no model provider, API key, Telegram token, real conversation, or
private memory. The companion lookup endpoint intentionally returned no claims.

## Integration pattern

The versioned profile under `profiles/lucy` is mounted read-only into a one-shot
seed container. That container copies it into a named `/opt/data` volume and hands
ownership to Hermes UID/GID 10000. Hermes then receives only the writable named
volume. Mounting individual profile files read-only inside `/opt/data` is not
compatible: Hermes migrates config and maintains its skill hub within that tree.

## Findings

1. The documented `hermes version` form is not accepted by this release;
   `hermes --version` is the compatible command.
2. Config schema `12` is only an old migratable baseline. This release uses
   `_config_version: 38`.
3. The release tag is annotated. `b05e680e...` is the tag object; the peeled
   source commit is `fcbd1076...`. The image OCI revision matches the latter.
4. The stock image synchronizes and enables a broad set of bundled skills. Before
   any real model or messaging credentials are added, Lucy must define and verify
   an explicit minimum skill/tool allowlist.

## Reproduction

Use `compose.yaml` plus `compose.hermes-spike.yaml`. The spike override is local
and secret-free. It seeds the profile, launches the pinned image, and shares only
the project-scoped Docker network with the companion API and PostgreSQL.

