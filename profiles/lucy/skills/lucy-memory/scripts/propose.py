"""Submit a gated memory candidate; never applies it."""

from __future__ import annotations

import json
import os
import sys
from urllib.request import Request, urlopen


def main() -> int:
    if len(sys.argv) != 7:
        print(
            "usage: propose.py EVIDENCE_ID SUBJECT PREDICATE OBJECT CONFIDENCE IDEMPOTENCY_KEY",
            file=sys.stderr,
        )
        return 2
    token = os.environ.get("LUCY_ADAPTER_TOKEN")
    if not token:
        raise RuntimeError("LUCY_ADAPTER_TOKEN is required")
    body = json.dumps(
        {
            "evidence_id": sys.argv[1], "subject": sys.argv[2],
            "predicate": sys.argv[3], "object": sys.argv[4],
            "confidence": float(sys.argv[5]),
        }
    ).encode()
    base = os.environ.get("LUCY_COMPANION_URL", "http://lucy-api:8080").rstrip("/")
    request = Request(
        f"{base}/v1/memory/proposals", data=body, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Idempotency-Key": sys.argv[6], "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=5) as response:  # noqa: S310 - fixed private service base
        payload = json.load(response)
    if payload.get("status") != "pending" or not payload.get("approval_id"):
        raise RuntimeError("companion did not return a pending human approval")
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
