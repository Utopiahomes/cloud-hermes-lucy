# Tiamat signed release v1 — RC1 conformance bundle

This review packet accompanies
`docs/tiamat-signed-release-format-v1-rc1.md`. It contains no
private key, valid production signature, provider credential, or spending authorization.

- `schemas/release-payload.schema.json` defines all four exact release payloads.
- `schemas/trust-inventory.schema.json` defines release-verification keys and their exact authorized
  caller/realm/type/subject scopes.
- `examples/*.json` are schema-valid unsigned release or trust-inventory payloads. Each release
  `content_digest` is SHA-256 over RFC 8785 canonical content and has been recomputed with the
  repository's independent canonicalizer.

Compact JWS vectors, negative vectors, an independent verifier, raw-content manifest, and the frozen
digest are generated and checked by the tools in this bundle.
