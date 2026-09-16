# Official RFC 8785 (JCS) reference test vectors

Fetched from `github.com/cyberphone/json-canonicalization` — the reference implementation
repository maintained by Anders Rundgren, RFC 8785's co-author — on 2026-09-16, via:

```sh
curl -s "https://raw.githubusercontent.com/cyberphone/json-canonicalization/master/testdata/input/<name>.json"
curl -s "https://raw.githubusercontent.com/cyberphone/json-canonicalization/master/testdata/output/<name>.json"
```

for `<name>` in `arrays`, `french`, `structures`, `values`, `weird`. Vendored verbatim, byte for
byte, as external evidence that `rfc8785` (the third-party library `check_invariants_impl.py`
actually relies on) and `tools/jcs_reference.py` (this bundle's own independent from-scratch
implementation, used only to cross-check the library, never to replace it) are both faithful to
the published spec — not just self-consistent with each other.

`tools/verify_bundle.py`'s `check_jcs_against_official_vectors()` re-derives every `output/*`
file from the matching `input/*` file using both implementations at verification time; nothing
here is trusted without that independent re-check.

`structures.json` and `values.json` exercise RFC 8785's number-formatting rule (ES6
`Number.toString()` semantics), which `jcs_reference.py` deliberately does not implement — see
that file's module docstring for why. Only `rfc8785` is checked against those two; all three
libraries/implementations agree on `arrays`, `french`, and `weird`.
