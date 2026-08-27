"""Read-only Lucy memory lookup adapter for the Hermes compatibility spike."""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlencode
from urllib.request import urlopen


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("usage: lookup.py QUERY", file=sys.stderr)
        return 2
    base_url = os.environ.get("LUCY_COMPANION_URL", "http://lucy-api:8080").rstrip("/")
    url = f"{base_url}/v1/memory/lookup?{urlencode({'query': sys.argv[1]})}"
    with urlopen(url, timeout=5) as response:  # noqa: S310 - fixed private service base
        payload = json.load(response)
    if payload.get("read_only") is not True:
        raise RuntimeError("companion response did not assert read-only behavior")
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

