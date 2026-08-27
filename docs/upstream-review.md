# Hermes upstream review and upgrade gate

## Current baseline

- Repository: `https://github.com/NousResearch/hermes-agent.git`
- Release: `v2026.8.19` (Hermes Agent `v0.20.5`)
- Source commit: `fcbd1076a93841fa88855acce810e342a5b78101`
- Annotated tag object: `b05e680e63d39d5a8e3ec0f5842a41d1c4209c03`
- Release published: 2026-08-21
- Pin verified: 2026-08-26

The release is a stable patch release. The annotated tag object and its peeled
source commit are recorded separately. The pinned Docker image reports the same
source commit in `org.opencontainers.image.revision`. `hermes.lock` is the
deployment source of truth.

## Upgrade procedure

1. Select a non-draft, non-prerelease upstream tag; never select `main` or `latest`.
2. Resolve the annotated tag from the official Git remote and record both the tag
   object SHA and the full peeled source commit SHA.
3. Review changes since the current pin, prioritizing gateway authentication,
   approvals, terminal/tool execution, cron, persistence, plugins/MCP, updater,
   dependency locks, and secret handling.
4. Run Lucy contract, migration, recovery, and adversarial tests against the candidate.
5. Build artifacts from the commit and record checksums/SBOM and test evidence.
6. Exercise backup restoration and rollback to the prior pin.
7. Update `hermes.lock` in a dedicated reviewed change. Deploy first to a
   non-production profile and observe before promotion.

The standard Hermes installer tracks upstream behavior and is not itself the pin.
A deployment script must verify that the checked-out `HEAD` exactly equals the
commit in `hermes.lock` before starting Hermes.

Container provenance—including the human-readable tags, multi-architecture
manifest digests, and exact Linux AMD64 manifests—is recorded in
`deploy/images.lock`. Upgrades update source and image pins together and retain
the prior digests as the rollback target in deployment history.
