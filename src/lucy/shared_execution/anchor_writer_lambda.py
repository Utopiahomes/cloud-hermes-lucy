"""AWS Lambda entry point for the M4 anchor writer, and the client callers use to reach it.

The function's configuration is its own: the table, the region and, per anchor key, the root it
trusts come from its environment, set by its CloudFormation stack. A request carries only signed
bytes. Responses are content-free: an outcome, and on success the digest and version read back.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
from collections.abc import Mapping
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

from lucy.shared_execution.anchor_writer import (
    AnchorWriter,
    AnchorWriteRefused,
    AnchorWriteRequest,
    AnchorWriteResult,
    WriterRoot,
)
from lucy.shared_execution.recovery_anchor import RecoveryAnchorRejected

logger = logging.getLogger(__name__)

_ROOT_FIELDS = {"root_key_id", "root_public_key_b64", "root_public_key_sha256"}
_REQUEST_FIELDS = {"anchor_key", "transition_jws_b64", "witness_jws_b64", "inventory_jws_b64"}


def writer_from_environment(
    values: Mapping[str, str] | None = None, *, client: Any | None = None
) -> AnchorWriter:
    environment = os.environ if values is None else values
    table_name = environment.get("TIAMAT_RECOVERY_ANCHOR_TABLE", "")
    region = environment.get("AWS_REGION", "")
    raw_roots = environment.get("TIAMAT_ANCHOR_WRITER_ROOTS", "")
    if hashlib.sha256(raw_roots.encode("utf-8")).hexdigest() != environment.get(
        "TIAMAT_ANCHOR_WRITER_ROOTS_SHA256", ""
    ):
        # The published version names this digest; a configuration that does not match it is
        # not the reviewed one.
        raise ValueError("anchor writer configuration is invalid")
    try:
        document = json.loads(raw_roots)
        roots = {
            str(anchor_key): WriterRoot(**{field: str(entry[field]) for field in _ROOT_FIELDS})
            for anchor_key, entry in document.items()
            if set(entry) == _ROOT_FIELDS
        }
        if not table_name or not region or not roots or len(roots) != len(document):
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("anchor writer configuration is invalid") from exc
    return AnchorWriter(
        roots=roots,
        client=client or boto3.client("dynamodb", region_name=region),
        table_name=table_name,
    )


_writer: AnchorWriter | None = None


def handler(event: Any, _context: Any) -> dict[str, Any]:
    """Install one transition, or refuse with a reason code. Never raises to the caller."""

    global _writer
    try:
        request = _request(event)
        if _writer is None:
            try:
                _writer = writer_from_environment()
            except ValueError:
                # The deployed roots or table settings are not the reviewed ones: say so, since
                # this is the one refusal an operator fixes in configuration, not in a request.
                return {"status": "refused", "reason": "recovery_anchor_writer_misconfigured"}
        result = _writer.write(request)
    except AnchorWriteRefused as exc:
        return {"status": "refused", "reason": str(exc)}
    except Exception:  # noqa: BLE001 - nothing but a reason code may leave the writer
        logger.exception("tiamat_anchor_writer_failed")
        return {"status": "refused", "reason": "recovery_anchor_writer_failed"}
    return {
        "status": result.outcome,
        "transition_sha256": result.transition_sha256,
        "transition_version": result.transition_version,
    }


def _request(event: Any) -> AnchorWriteRequest:
    if not isinstance(event, dict) or not set(event) >= _REQUEST_FIELDS:
        raise AnchorWriteRefused("recovery_anchor_writer_request_invalid")
    if set(event) - _REQUEST_FIELDS - {"head_inventory_jws_b64"}:
        raise AnchorWriteRefused("recovery_anchor_writer_request_invalid")

    def decoded(name: str) -> bytes:
        try:
            return base64.b64decode(str(event[name]), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AnchorWriteRefused("recovery_anchor_writer_request_invalid") from exc

    return AnchorWriteRequest(
        anchor_key=str(event["anchor_key"]),
        transition_jws=decoded("transition_jws_b64"),
        witness_jws=decoded("witness_jws_b64"),
        inventory_jws=decoded("inventory_jws_b64"),
        head_inventory_jws=(
            decoded("head_inventory_jws_b64") if "head_inventory_jws_b64" in event else None
        ),
    )


class LambdaAnchorWriterClient:
    """What the coordinator holds instead of PutItem: permission to invoke the writer."""

    def __init__(self, *, function_name: str, client: Any) -> None:
        if not function_name:
            raise ValueError("anchor writer function name is required")
        self._function_name = function_name
        self._client = client

    def write(self, request: AnchorWriteRequest) -> AnchorWriteResult:
        event: dict[str, str] = {
            "anchor_key": request.anchor_key,
            "transition_jws_b64": base64.b64encode(request.transition_jws).decode("ascii"),
            "witness_jws_b64": base64.b64encode(request.witness_jws).decode("ascii"),
            "inventory_jws_b64": base64.b64encode(request.inventory_jws).decode("ascii"),
        }
        if request.head_inventory_jws is not None:
            event["head_inventory_jws_b64"] = base64.b64encode(
                request.head_inventory_jws
            ).decode("ascii")
        try:
            response = self._client.invoke(
                FunctionName=self._function_name,
                InvocationType="RequestResponse",
                Payload=json.dumps(event).encode("utf-8"),
            )
            if response.get("FunctionError"):
                raise RecoveryAnchorRejected("recovery_anchor_writer_unavailable")
            answer = json.loads(response["Payload"].read())
        except (BotoCoreError, ClientError, KeyError, ValueError) as exc:
            # An invocation whose outcome is unknown: the caller rereads, then may retry the
            # identical request, which the writer treats as success if it already landed.
            raise RecoveryAnchorRejected("recovery_anchor_writer_unavailable") from exc
        status = answer.get("status") if isinstance(answer, dict) else None
        if status in {"installed", "already_installed"}:
            return AnchorWriteResult(
                outcome=status,
                transition_sha256=str(answer["transition_sha256"]),
                transition_version=int(answer["transition_version"]),
            )
        reason = answer.get("reason") if isinstance(answer, dict) else None
        raise RecoveryAnchorRejected(str(reason or "recovery_anchor_writer_unavailable"))
