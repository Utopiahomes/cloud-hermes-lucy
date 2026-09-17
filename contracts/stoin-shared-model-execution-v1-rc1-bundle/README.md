# Stoin Shared Model Execution v1 RC1 — conformance bundle

This is the deterministic Tier A artifact for the frozen Shared Model Execution contract. It pins
the wire schemas, all 29 exact error tuples, representative positive/boundary/negative vectors,
cross-field invariants, header and JWT fixtures, state-transition fixtures, and an explicit
classification of all 85 acceptance criteria.

The bundle **does not claim production conformance**. `COVERAGE.json` marks criteria needing a
running durable executor, failure injection, multi-replica testing, timing observation, or external
provider evidence as `executor-proof-required`. Those become Tier B evidence.

## Verify

```text
python tools/build_bundle.py
python tools/verify_bundle.py
python tools/compute_digest.py --check
```

Generation and verification share no Python modules. The verifier evaluates the generated schemas
and vectors independently. The digest can also be recomputed with coreutils from the bundle root:

```sh
find . -type f ! -name MANIFEST.json ! -name DIGEST.txt -printf '%P\n' \
  | LC_ALL=C sort | xargs -d'\n' sha256sum | sha256sum
```

Hash raw bytes; line endings are part of the artifact. Pin `DIGEST.txt`, not a gzip archive hash.

## Strict provider, tolerant consumer

The JSON schemas use `additionalProperties: false` to test an RC1 provider. Runtime consumers must
remain tolerant of unknown response members introduced by a compatible minor release; they must not
use these strict schemas as a forward-compatibility gate.

## Authority

This artifact authorizes no provider call, credential, budget, deployment, or production change.
The frozen prose contract remains authoritative if the bundle is wrong.
