"""Invoke the M4 writer's ``live`` alias with one prepared probe event, as this principal.

Run it as the recovery coordinator from its Render service: after the boundary moves, invoking
the alias is the coordinator's only way to write the anchor, and this exercises that path end to
end on a disposable key. It reports who it ran as and the writer's content-free answer. Exit
status is 0 only if the answer is ``installed`` or ``already_installed``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3  # type: ignore[import-untyped]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function-name", required=True, help="the writer function's name")
    parser.add_argument("--event-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    event = json.loads(args.event_file.read_text(encoding="utf-8"))
    caller = boto3.client("sts", region_name=args.region).get_caller_identity()["Arn"]
    response = boto3.client("lambda", region_name=args.region).invoke(
        FunctionName=args.function_name,
        Qualifier="live",
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode("utf-8"),
    )
    answer = json.loads(response["Payload"].read())
    report = {
        "caller": caller,
        "anchor_key": event.get("anchor_key"),
        "function_error": response.get("FunctionError"),
        "answer": answer,
    }
    print(json.dumps(report, sort_keys=True))
    ok = not response.get("FunctionError") and isinstance(answer, dict)
    return 0 if ok and answer.get("status") in {"installed", "already_installed"} else 1


if __name__ == "__main__":
    sys.exit(main())
