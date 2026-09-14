"""Ephemeral, fail-closed runner for commissioned recovery-boundary drills.

This module is intentionally independent of Lucy's normal runtime.  Its dedicated
container entrypoint cannot be replaced by Render's Docker command semantics.
"""

from __future__ import annotations

import json
import os
import urllib.request
import uuid
from typing import Any

_READY_TARGETS = {
    "authority": ("http://lucy-authority-writer:10000/ready", "authority"),
    "cost": ("http://lucy-cost-writer:10000/ready", "cost"),
    "coordinator": ("http://lucy-recovery-coordinator:10000/ready", None),
}


def _json_request(url: str, *, token: str | None = None) -> dict[str, Any]:
    method = "POST" if token is not None else "GET"
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    request = urllib.request.Request(
        url,
        data=b"" if token is not None else None,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("recovery endpoint returned a non-object response")
    return value


def readiness(nonce: str) -> dict[str, str]:
    uuid.UUID(nonce)
    result: dict[str, str] = {}
    for name, (url, stream) in _READY_TARGETS.items():
        value = _json_request(url)
        if value.get("status") != "ready":
            raise RuntimeError(f"{name} recovery endpoint is not ready")
        if stream is not None and value.get("stream_kind") != stream:
            raise RuntimeError(f"{name} recovery endpoint stream differs")
        result[name] = "ready"
    return result


def invoke() -> dict[str, int | str]:
    authority_event = str(uuid.UUID(os.environ["AUTHORITY_EVENT_ID"]))
    cost_event = str(uuid.UUID(os.environ["COST_EVENT_ID"]))
    authority_writer = _json_request(
        f"http://lucy-authority-writer:10000/v1/recovery/events/{authority_event}",
        token=os.environ["AUTHORITY_WRITER_TOKEN"],
    )
    cost_writer = _json_request(
        f"http://lucy-cost-writer:10000/v1/recovery/events/{cost_event}",
        token=os.environ["COST_WRITER_TOKEN"],
    )
    authority_ack = _json_request(
        "http://lucy-recovery-coordinator:10000/v1/recovery/authority/"
        f"acknowledgements/{authority_event}",
        token=os.environ["AUTHORITY_ACK_TOKEN"],
    )
    cost_ack = _json_request(
        "http://lucy-recovery-coordinator:10000/v1/recovery/cost/"
        f"acknowledgements/{cost_event}",
        token=os.environ["COST_ACK_TOKEN"],
    )
    if authority_writer.get("stream_kind") != "authority":
        raise RuntimeError("authority writer stream differs")
    if cost_writer.get("stream_kind") != "cost":
        raise RuntimeError("cost writer stream differs")
    if authority_ack.get("stream_kind") != "authority":
        raise RuntimeError("authority acknowledgement stream differs")
    if cost_ack.get("stream_kind") != "cost":
        raise RuntimeError("cost acknowledgement stream differs")
    if authority_ack.get("state") != "DURABLY_RECORDED":
        raise RuntimeError("authority transition is not durably recorded")
    if cost_ack.get("state") != "ADMITTED":
        raise RuntimeError("cost reservation is not admitted")
    authority_sequence = authority_writer.get("sequence")
    cost_sequence = cost_writer.get("sequence")
    if (
        not isinstance(authority_sequence, int)
        or isinstance(authority_sequence, bool)
        or authority_sequence < 1
        or not isinstance(cost_sequence, int)
        or isinstance(cost_sequence, bool)
        or cost_sequence < 1
    ):
        raise RuntimeError("recovery writer returned an invalid sequence")
    return {
        "authority_writer": authority_sequence,
        "cost_writer": cost_sequence,
        "authority_ack": "DURABLY_RECORDED",
        "cost_ack": "ADMITTED",
    }


def main() -> None:
    mode = os.environ.get("LUCY_RECOVERY_CRON_MODE")
    if mode == "readiness":
        nonce = os.environ["LUCY_RECOVERY_CRON_NONCE"]
        result: dict[str, object] = {
            "contract": "lucy.r1.recovery-cron-readiness.v1",
            "nonce": nonce,
            "services": readiness(nonce),
        }
    elif mode == "invoke":
        result = {
            "contract": "lucy.r1.recovery-private-invocation.v1",
            "result": invoke(),
        }
    else:
        raise SystemExit("recovery cron mode is missing or invalid")
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
