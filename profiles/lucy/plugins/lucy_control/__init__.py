"""Fail-closed Hermes budgets and provenance-aware Lucy memory tools."""

from __future__ import annotations

import http.client
import json
import math
import os
import re
import time
from collections.abc import Callable
from contextlib import suppress
from contextvars import ContextVar
from types import SimpleNamespace
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

MODEL = "openai/gpt-oss-20b"
BASE_URL = "https://openrouter.ai/api/v1"
RESERVATION_MICROUSD = 5_000
BLOCKED_MESSAGE = "Lucy blocked this model call because its budget gate is unavailable."
MAX_OUTPUT_TOKENS = 1_024
MAX_PROMPT_USD_PER_MILLION = 0.10
MAX_COMPLETION_USD_PER_MILLION = 0.50
MAX_LINEAGE_SOURCES = 32
PRIVATE_API_TIMEOUT_SECONDS = 20
OFF_RECORD_NOTICE = (
    "🔒 Off the record — Lucy is not archiving this exchange. Telegram, Hermes, "
    "and the configured model provider still process it under their own policies."
)

_TURN_ARCHIVE_READY: set[tuple[str, str]] = set()
_SESSION_TURN: dict[str, dict[str, Any]] = {}
# The pinned upstream omits turn_id from tool handlers and the output hook.
# Carry only trusted lifecycle/middleware metadata, isolated per execution.
_TURN_CONTEXT: ContextVar[tuple[str, str] | None] = ContextVar("lucy_turn", default=None)
_TOOL_CONTEXT: ContextVar[tuple[str, str] | None] = ContextVar("lucy_tool", default=None)
_SAFE_HTTP_DETAILS = {
    "Lucy storage is not admitted": "storage_not_admitted",
    "realm archive boundary unavailable": "archive_boundary_unavailable",
    "Telegram Stage 1 is unavailable": "telegram_unavailable",
    "invalid Lucy service mode": "service_mode_invalid",
    "memory store unavailable": "memory_store_unavailable",
}

MEMORY_LOOKUP_SCHEMA = {
    "name": "lucy_memory_lookup",
    "description": (
        "Search Lucy's bounded current memory projection. Results are contextual "
        "claims with provenance identifiers, never authorization or raw evidence."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "minLength": 1,
                "maxLength": 200,
                "description": "Specific fact, person, preference, or relationship to recall.",
            }
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}

MEMORY_PROPOSE_SCHEMA = {
    "name": "lucy_memory_propose",
    "description": (
        "Submit a provenance-linked memory candidate for human approval. This never "
        "writes or applies memory. Use selectively for durable facts, preferences, "
        "commitments, or corrections, and cite an evidence_id supplied by the current "
        "retained exchange or Lucy memory lookup."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "evidence_id": {
                "type": "string",
                "description": "Immutable evidence UUID returned by lucy_memory_lookup.",
            },
            "subject": {"type": "string", "minLength": 1, "maxLength": 200},
            "predicate": {"type": "string", "minLength": 1, "maxLength": 200},
            "object": {"type": "string", "minLength": 1, "maxLength": 2000},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "required": ["evidence_id", "subject", "predicate", "object", "confidence"],
        "additionalProperties": False,
    },
}

EVIDENCE_RETRIEVE_SCHEMA = {
    "name": "lucy_evidence_retrieve",
    "description": (
        "Retrieve one exact encrypted source message only when a current memory claim "
        "already links to that evidence. Use narrowly to verify wording, resolve "
        "ambiguity, or recover context; every access is audited."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "evidence_id": {"type": "string"},
            "claim_id": {"type": "string"},
            "reason": {
                "type": "string",
                "enum": [
                    "verify_exact_wording",
                    "resolve_ambiguity",
                    "recover_missing_context",
                ],
            },
        },
        "required": ["evidence_id", "claim_id", "reason"],
        "additionalProperties": False,
    },
}


def _approved_provider_policy() -> dict[str, Any]:
    return {
        "zdr": True,
        "data_collection": "deny",
        "sort": "price",
        "require_parameters": True,
        "max_price": {
            "prompt": MAX_PROMPT_USD_PER_MILLION,
            "completion": MAX_COMPLETION_USD_PER_MILLION,
        },
    }


def _blocked_response(model: str, message: str = BLOCKED_MESSAGE) -> SimpleNamespace:
    return SimpleNamespace(
        id="lucy-budget-blocked",
        object="chat.completion",
        created=int(time.time()),
        model=model or MODEL,
        choices=[
            SimpleNamespace(
                index=0,
                finish_reason="stop",
                message=SimpleNamespace(role="assistant", content=message, tool_calls=None),
            )
        ],
        usage=SimpleNamespace(
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            model_extra={},
        ),
    )


def _post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    return _request_json(path, method="POST", payload=payload)


def _request_json(
    path: str,
    *,
    method: str,
    payload: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    base_url = os.environ.get("LUCY_COMPANION_URL", "").rstrip("/")
    token = os.environ.get("LUCY_ADAPTER_TOKEN", "")
    if not base_url or not token:
        raise RuntimeError("Lucy companion configuration is missing")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    headers.update(extra_headers or {})
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers=headers,
    )
    # Keep private control and archive calls bounded. Ambiguous archive outcomes
    # are recovered once through the stable idempotency key below.
    with urlopen(request, timeout=PRIVATE_API_TIMEOUT_SECONDS) as response:  # noqa: S310
        result: dict[str, Any] = json.load(response)
        return result


def _request_json_retry_safe(
    path: str,
    *,
    method: str,
    payload: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    retention_role: str | None = None,
) -> dict[str, Any]:
    """Recover one ambiguous private-network response with the exact request."""

    for attempt in range(2):
        try:
            return _request_json(
                path, method=method, payload=payload, extra_headers=extra_headers
            )
        except HTTPError as exc:
            # A completed HTTP response is not transport ambiguity. In particular,
            # retrying a 409 can hide the first definitive application failure.
            _retention_event(
                "archive_http_error",
                role=retention_role,
                status=exc.code,
                attempt=attempt + 1,
                reason=_safe_http_reason(exc),
            )
            raise
        except (OSError, TimeoutError, json.JSONDecodeError, http.client.HTTPException):
            if attempt:
                raise
            time.sleep(0.25)
    raise AssertionError("retry loop did not return or raise")


def _retention_event(
    code: str,
    *,
    role: str | None = None,
    error: str | None = None,
    status: int | None = None,
    attempt: int | None = None,
    reason: str | None = None,
) -> None:
    """Emit only content-free archive lifecycle metadata."""

    payload: dict[str, Any] = {"component": "lucy-retention", "code": code}
    if role in {"user", "assistant"}:
        payload["role"] = role
    if error:
        payload["error_type"] = error
    if isinstance(status, int) and 400 <= status <= 599:
        payload["http_status"] = status
    if attempt in {1, 2}:
        payload["attempt"] = attempt
    if reason in {*_SAFE_HTTP_DETAILS.values(), "unclassified"}:
        payload["reason"] = reason
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def _safe_http_reason(error: HTTPError) -> str:
    """Classify an allowlisted API detail without ever forwarding its body."""

    try:
        payload = json.loads(error.read(2048))
        detail = payload.get("detail") if isinstance(payload, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        detail = None
    return _SAFE_HTTP_DETAILS.get(detail, "unclassified") if isinstance(
        detail, str
    ) else "unclassified"


def _request_boundary_json(
    boundary: str,
    path: str,
    *,
    method: str,
    payload: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Use a distinct private service/token when production separation is active."""

    base_url = os.environ.get(f"LUCY_{boundary}_URL", "").rstrip("/")
    token = os.environ.get(f"LUCY_{boundary}_TOKEN", "")
    if not base_url and not token and os.getenv("LUCY_ALLOW_LOCAL_BOUNDARY_FALLBACK") == "true":
        return _request_json(path, method=method, payload=payload, extra_headers=extra_headers)
    if not base_url or not token:
        raise RuntimeError(f"Lucy {boundary.lower()} boundary is incomplete")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    headers.update(extra_headers or {})
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers=headers,
    )
    with urlopen(request, timeout=5) as response:  # noqa: S310 - private URL
        result: dict[str, Any] = json.load(response)
        return result


def _issue_sensitive_permit(
    *,
    action: str,
    evidence_id: str,
    reason: str,
    session_id: str,
    turn_id: str,
) -> dict[str, Any]:
    return _request_boundary_json(
        "POLICY",
        "/internal/v1/sensitive-action-permits",
        method="POST",
        payload={
            "action": action,
            "platform": "telegram",
            "source_conversation_id": session_id,
            "source_turn_id": turn_id,
            "evidence_ids": [evidence_id],
            "reason": reason,
            "max_bytes": 65_536,
        },
        extra_headers={"Idempotency-Key": f"gateway-permit:{uuid4()}"},
    )


def _tool_result(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _tool_failure(code: str) -> str:
    return _tool_result({"ok": False, "error": code})


def _archive_conversation_message(
    *,
    role: str,
    content: Any,
    session_id: Any,
    turn_id: Any,
    platform: Any,
) -> dict[str, Any] | None:
    """Archive one Telegram message without logging its content on failure."""

    if platform != "telegram" or role not in {"user", "assistant"}:
        return None
    identity = (content, session_id, turn_id)
    if not all(isinstance(value, str) and value.strip() for value in identity):
        return None
    source_message_id = f"{turn_id}:{role}"
    turn = _SESSION_TURN.get(session_id)
    sources = sorted(turn.get("source_evidence_ids", set())) if (
        role == "assistant" and turn is not None and turn.get("turn_id") == turn_id
    ) else []
    current_input_evidence_id = (
        turn.get("current_input_evidence_id")
        if role == "assistant" and turn is not None and turn.get("turn_id") == turn_id
        else None
    )
    try:
        result = _request_json_retry_safe(
            "/internal/v1/conversations/messages",
            method="POST",
            payload={
                "platform": platform,
                "source_conversation_id": session_id,
                "source_turn_id": turn_id,
                "source_message_id": source_message_id,
                "role": role,
                "content": content,
                "source_evidence_ids": sources,
                "current_input_evidence_id": current_input_evidence_id,
            },
            extra_headers={
                "Idempotency-Key": (
                    f"hermes-transcript:{platform}:{session_id}:{source_message_id}"
                )
            },
            retention_role=role,
        )
    except Exception as exc:
        _retention_event(
            "archive_request_failed", role=role, error=type(exc).__name__
        )
        return None
    _retention_event(
        "archive_request_completed"
        if result.get("archived") is True
        else "archive_request_rejected",
        role=role,
    )
    if result.get("archived") is not True:
        return result if result.get("capture_enabled") is False else None
    # Legacy archive responses include the keyed commitment; the realm archive
    # deliberately keeps it inside its AWS envelope.  Both must return one
    # durable operation identity and evidence identity.
    if not result.get("evidence_id") or not (
        result.get("keyed_commitment") or result.get("operation_id")
    ):
        return None
    return result


def _normalized_command(content: str) -> str:
    normalized = re.sub(r"[.!?]+$", "", content.strip().casefold())
    return re.sub(r"^lucy[, :]\s*", "", normalized)


def _capture_command(content: str) -> bool | None:
    normalized = _normalized_command(content)
    if normalized == "off the record":
        return False
    if normalized == "back on the record":
        return True
    return None


def _forget_last_message(*, session_id: str, turn_id: str) -> bool:
    try:
        latest = _request_boundary_json(
            "DELETION",
            "/internal/v1/conversations/latest-retained-evidence"
            + "?"
            + urlencode({"source_conversation_id": session_id}),
            method="GET",
        )
        evidence_id = str(UUID(str(latest.get("evidence_id", ""))))
        permit = _issue_sensitive_permit(
            action="evidence.delete",
            evidence_id=evidence_id,
            reason="owner_request",
            session_id=session_id,
            turn_id=turn_id,
        )
        result = _request_boundary_json(
            "DELETION",
            "/internal/v1/conversations/forget-last",
            method="POST",
            payload={
                "platform": "telegram",
                "source_conversation_id": session_id,
                "reason": "owner_request",
                "permit": permit,
            },
            extra_headers={
                "Idempotency-Key": (f"hermes-forget-last:telegram:{session_id}:{turn_id}")
            },
        )
    except Exception:
        return False
    return result.get("deleted") is True and result.get("key_destroyed") is True


def _capture_mode(session_id: str) -> bool | None:
    try:
        result = _request_json(
            "/internal/v1/conversations/capture-mode?"
            + urlencode({"source_conversation_id": session_id}),
            method="GET",
        )
    except Exception:
        return None
    value = result.get("capture_enabled")
    return value if isinstance(value, bool) else None


def _accept_turn(session_id: str, turn_id: str) -> bool | None:
    try:
        result = _request_json_retry_safe(
            "/internal/v1/conversations/accept-turn", method="POST",
            payload={"platform": "telegram", "source_conversation_id": session_id,
                     "source_turn_id": turn_id},
        )
    except Exception:
        return None
    value = result.get("capture_enabled")
    previous = _SESSION_TURN.get(session_id)
    if value is True and result.get("replayed") is True and (
        previous is None or previous.get("turn_id") != turn_id or not previous.get("active")
    ):
        # A restarted gateway cannot reconstruct uncommitted tool-result exposure
        # from an in-memory set. Do not regenerate/retain from unknown history.
        return None
    return value if isinstance(value, bool) else None


def _set_capture_mode(*, session_id: str, turn_id: str, capture_enabled: bool) -> bool:
    try:
        stage2 = os.getenv("LUCY_TELEGRAM_STAGE") == "2"
        result = _request_json_retry_safe(
            "/internal/v1/conversations/capture-mode-and-accept"
            if stage2
            else "/internal/v1/conversations/capture-mode",
            method="POST",
            payload={
                "platform": "telegram",
                "source_conversation_id": session_id,
                **({"source_turn_id": turn_id} if stage2 else {}),
                "capture_enabled": capture_enabled,
            },
            extra_headers={
                "Idempotency-Key": (f"hermes-capture-mode:telegram:{session_id}:{turn_id}")
            },
        )
    except Exception:
        return False
    return result.get("capture_enabled") is capture_enabled


def _pre_llm_call(
    *,
    user_message: Any = None,
    session_id: Any = None,
    turn_id: Any = None,
    platform: Any = None,
    **_: Any,
) -> dict[str, str] | None:
    _TURN_CONTEXT.set(None)
    if (
        platform != "telegram"
        or not isinstance(user_message, str)
        or not isinstance(session_id, str)
        or not isinstance(turn_id, str)
        or not user_message.strip()
        or not session_id.strip()
        or not turn_id.strip()
    ):
        return None
    _TURN_CONTEXT.set((session_id, turn_id))
    _TURN_ARCHIVE_READY.discard((session_id, turn_id))
    telegram_stage = os.getenv("LUCY_TELEGRAM_STAGE")
    forget_last = _normalized_command(user_message) == "forget the last message"
    command = _capture_command(user_message)
    # The transition into off-record mode is itself excluded. Commands which
    # restore capture or delete prior evidence are archived only after their
    # control operation succeeds, so their on-record turns can commit normally.
    skip_user_archive = command is False
    forgot = False
    archive_result: dict[str, Any] | None = None
    ready = True
    if forget_last and telegram_stage == "2":
        # The first Stage 2 boundary gives the gateway only its routine archive
        # credential.  Do not let a phrase silently expand it into policy,
        # evidence, or deletion authority.
        ready = False
    elif forget_last:
        forgot = _forget_last_message(session_id=session_id, turn_id=turn_id)
        ready = forgot
    elif command is not None:
        ready = _set_capture_mode(
            session_id=session_id,
            turn_id=turn_id,
            capture_enabled=command,
        )
    capture_enabled = (
        command if command is not None and telegram_stage == "2" and ready
        else _accept_turn(session_id, turn_id)
    )
    if capture_enabled is None:
        ready = False
        capture_enabled = True
    if ready and capture_enabled and not skip_user_archive:
        archive_result = _archive_conversation_message(
            role="user", content=user_message, session_id=session_id,
            turn_id=turn_id, platform=platform,
        )
        ready = archive_result is not None and archive_result.get("archived") is True
    previous = _SESSION_TURN.get(session_id, {})
    current_sources = (
        previous.get("source_evidence_ids", set())
        if previous.get("turn_id") == turn_id
        else set()
    )
    if archive_result is not None and archive_result.get("evidence_id"):
        current_sources = current_sources | {str(archive_result["evidence_id"])}
    _SESSION_TURN[session_id] = {
        "turn_id": turn_id,
        "capture_enabled": capture_enabled,
        "skip_user_archive": skip_user_archive,
        "active": ready,
        "proposal_keys": previous.get("proposal_keys", {})
        if previous.get("turn_id") == turn_id else {},
        "source_evidence_ids": current_sources,
        "current_input_evidence_id": (
            str(archive_result["evidence_id"])
            if archive_result is not None and archive_result.get("evidence_id")
            else previous.get("current_input_evidence_id")
            if previous.get("turn_id") == turn_id
            else None
        ),
    }
    if ready:
        _TURN_ARCHIVE_READY.add((session_id, turn_id))
    if not ready:
        return {"context": "The requested retention operation was not confirmed. "
                           "Do not claim capture or deletion succeeded."}
    if not capture_enabled:
        suffix = (
            " The preceding retained message was deleted with its derived data." if forgot else ""
        )
        return {"context": OFF_RECORD_NOTICE + suffix}
    if forget_last:
        if forgot:
            return {
                "context": (
                    "The preceding retained message, its decryption key, and its "
                    "derived memory artifacts were deleted. Clearly acknowledge this."
                )
            }
        return {
            "context": (
                "The requested deletion could not be completed safely. Say that no "
                "deletion was confirmed."
            )
        }
    if command is True:
        return {
            "context": (
                "Capture is back on. Clearly acknowledge that Lucy is archiving "
                "new exchanges again. The current retained evidence_id is "
                f"{archive_result.get('evidence_id') if archive_result else 'unavailable'}."
            )
        }
    if archive_result is not None and archive_result.get("evidence_id"):
        return {
            "context": (
                "This user message was retained as encrypted source evidence with "
                f"evidence_id {archive_result['evidence_id']}. Propose only genuinely "
                "durable memories from it; proposals require human approval."
            )
        }
    return None


def _transform_llm_output(
    *,
    response_text: Any = None,
    session_id: Any = None,
    turn_id: Any = None,
    platform: Any = None,
    **_: Any,
) -> str | None:
    if platform != "telegram" or not isinstance(session_id, str):
        return None
    context = _TURN_CONTEXT.get()
    if turn_id is None and context is not None and context[0] == session_id:
        turn_id = context[1]
    if context == (session_id, turn_id):
        _TURN_CONTEXT.set(None)
    turn = _SESSION_TURN.get(session_id)
    if turn is None or turn.get("turn_id") != turn_id:
        return "Lucy could not verify this reply's conversation turn; no reply was archived."
    if turn.get("active") is not True:
        # The execution middleware already produced a safe blocked response.
        # Never turn a failed inbound capture receipt into a second outbound
        # archive attempt without retained current-input provenance.
        return None
    turn["active"] = False
    turn.get("proposal_keys", {}).clear()
    if not isinstance(response_text, str) or not response_text.strip():
        return None
    if turn["capture_enabled"] is False:
        return f"{OFF_RECORD_NOTICE}\n\n{response_text}"
    result = _archive_conversation_message(
        role="assistant",
        content=response_text,
        session_id=session_id,
        turn_id=turn["turn_id"],
        platform=platform,
    )
    if result is None or result.get("turn_committed") is not True:
        turn["delivery_blocked"] = True
        _retention_event(
            "assistant_delivery_blocked",
            role="assistant",
            error="missing_result" if result is None else "turn_not_committed",
        )
        return (
            "Lucy could not durably retain this reply, so its substantive content "
            "was not delivered. Please retry after the archive is healthy."
        )
    return None


def _post_llm_call(
    *,
    user_message: Any = None,
    assistant_response: Any = None,
    session_id: Any = None,
    turn_id: Any = None,
    platform: Any = None,
    **_: Any,
) -> None:
    if platform != "telegram" or not isinstance(session_id, str):
        return
    turn = _SESSION_TURN.get(session_id)
    if turn is None or turn.get("turn_id") != turn_id or turn.get("capture_enabled") is False:
        return
    if turn.get("delivery_blocked") is True:
        _retention_event("post_hook_skipped_blocked_delivery", role="assistant")
        return
    # Retry the inbound write before preserving the reply. The companion's
    # stable idempotency key makes this safe and heals a transient pre-call
    # failure without duplicating evidence.
    if not turn.get("skip_user_archive"):
        _archive_conversation_message(
            role="user",
            content=user_message,
            session_id=session_id,
            turn_id=turn_id,
            platform=platform,
        )
    _archive_conversation_message(
        role="assistant",
        content=assistant_response,
        session_id=session_id,
        turn_id=turn_id,
        platform=platform,
    )


def _on_session_end(*, session_id: Any = None, turn_id: Any = None, **_: Any) -> None:
    if _TURN_CONTEXT.get() == (session_id, turn_id):
        _TURN_CONTEXT.set(None)
    if isinstance(session_id, str) and isinstance(turn_id, str):
        _TURN_ARCHIVE_READY.discard((session_id, turn_id))
        current = _SESSION_TURN.get(session_id)
        if current is not None and current.get("turn_id") == turn_id:
            _SESSION_TURN.pop(session_id, None)


def _memory_lookup(
    args: dict[str, Any], *, session_id: Any = None, turn_id: Any = None, **_: Any,
) -> str:
    turn_id = _trusted_tool_turn(session_id, turn_id)
    turn = _SESSION_TURN.get(session_id) if isinstance(session_id, str) else None
    if session_id is not None and (
        turn is None or turn.get("turn_id") != turn_id or not turn.get("active")
    ):
        return _tool_failure("owner_interaction_required")
    query = args.get("query")
    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 200:
        return _tool_failure("invalid_query")
    try:
        result = _request_json(
            "/v1/memory/lookup", method="POST", payload={"query": query.strip()},
        )
    except Exception:
        return _tool_failure("memory_unavailable")
    claims = result.get("claims")
    if result.get("read_only") is not True or not isinstance(claims, list):
        return _tool_failure("invalid_companion_response")
    if turn is not None and turn.get("capture_enabled") is True:
        try:
            sources: set[str] = set()
            for claim in claims:
                ids = claim["source_evidence_ids"]
                if not isinstance(ids, list) or not ids:
                    raise ValueError("missing source manifest")
                sources.update(str(UUID(value)) for value in ids)
            if len(sources | turn.get("source_evidence_ids", set())) > MAX_LINEAGE_SOURCES:
                raise ValueError("source limit")
        except (KeyError, ValueError, TypeError, AttributeError):
            return _tool_failure("invalid_companion_provenance")
        # Record support BEFORE exposing text to the model; model-supplied source
        # fields are ignored. The server also adds current input and retained history.
        turn.setdefault("source_evidence_ids", set()).update(sources)
    return _tool_result(
        {
            "ok": True,
            "query": query.strip(),
            "claims": claims,
            "read_only": True,
            "notice": "Context only; not authorization.",
        }
    )


def _memory_propose(
    args: dict[str, Any], *, session_id: Any = None, turn_id: Any = None, **_: Any
) -> str:
    turn_id = _trusted_tool_turn(session_id, turn_id)
    turn = _SESSION_TURN.get(session_id) if isinstance(session_id, str) else None
    if (turn is None or turn.get("turn_id") != turn_id
        or not turn.get("active") or turn.get("capture_enabled") is not True):
        return _tool_failure("retained_turn_required")
    try:
        evidence_id = str(UUID(str(args.get("evidence_id", ""))))
    except (ValueError, TypeError, AttributeError):
        return _tool_failure("invalid_evidence_id")
    subject = args.get("subject")
    predicate = args.get("predicate")
    object_value = args.get("object")
    confidence = args.get("confidence")
    if not isinstance(subject, str) or not 1 <= len(subject.strip()) <= 200:
        return _tool_failure("invalid_subject")
    if not isinstance(predicate, str) or not 1 <= len(predicate.strip()) <= 200:
        return _tool_failure("invalid_predicate")
    if not isinstance(object_value, str) or not 1 <= len(object_value.strip()) <= 2000:
        return _tool_failure("invalid_object")
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(float(confidence))
        or not 0 <= float(confidence) <= 1
    ):
        return _tool_failure("invalid_confidence")
    candidate = {
        "evidence_id": evidence_id,
        "subject": subject.strip(),
        "predicate": predicate.strip(),
        "object": object_value.strip(),
        "confidence": float(confidence),
        "source_conversation_id": session_id,
        "source_turn_id": turn_id,
        "source_evidence_ids": sorted(turn.get("source_evidence_ids", set())),
    }
    # Deduplicate only within the active turn. Persist an opaque identifier, not
    # a deterministic fingerprint of a private fact (even a rejected secret).
    canonical = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
    keys = turn.setdefault("proposal_keys", {})
    idempotency_key = keys.setdefault(canonical, f"hermes-memory-proposal:{uuid4()}")
    try:
        result = _request_json(
            "/v1/memory/proposals",
            method="POST",
            payload=candidate,
            extra_headers={"Idempotency-Key": idempotency_key},
        )
    except Exception:
        return _tool_failure("proposal_unavailable")
    if (
        result.get("status") != "pending"
        or not result.get("proposal_id")
        or not result.get("approval_id")
        or result.get("claim_id") is not None
    ):
        return _tool_failure("invalid_companion_response")
    return _tool_result(
        {
            "ok": True,
            "proposal_id": result["proposal_id"],
            "approval_id": result["approval_id"],
            "status": "pending",
            "applied": False,
            "replayed": bool(result.get("replayed", False)),
            "notice": "Pending human approval; not remembered or applied.",
        }
    )


def _evidence_retrieve(
    args: dict[str, Any], *, session_id: Any = None, turn_id: Any = None, **_: Any
) -> str:
    turn_id = _trusted_tool_turn(session_id, turn_id)
    try:
        evidence_id = str(UUID(str(args.get("evidence_id", ""))))
        claim_id = str(UUID(str(args.get("claim_id", ""))))
    except (ValueError, TypeError, AttributeError):
        return _tool_failure("invalid_provenance_id")
    reason = args.get("reason")
    allowed_reasons = {
        "verify_exact_wording",
        "resolve_ambiguity",
        "recover_missing_context",
    }
    if reason not in allowed_reasons:
        return _tool_failure("invalid_retrieval_reason")
    turn = _SESSION_TURN.get(session_id) if isinstance(session_id, str) else None
    if turn is None or turn.get("turn_id") != turn_id or not turn.get("active"):
        return _tool_failure("owner_interaction_required")
    try:
        permit = _issue_sensitive_permit(
            action="evidence.retrieve",
            evidence_id=evidence_id,
            reason=reason,
            session_id=session_id,
            turn_id=turn_id,
        )
        result = _request_boundary_json(
            "EVIDENCE",
            "/v1/evidence/retrieve",
            method="POST",
            payload={
                "evidence_id": evidence_id,
                "claim_id": claim_id,
                "reason": reason,
                "permit": permit,
            },
            extra_headers={"Idempotency-Key": f"hermes-evidence-read:{uuid4()}"},
        )
    except Exception:
        return _tool_failure("evidence_unavailable")
    message = result.get("message")
    if (
        result.get("audited") is not True
        or result.get("autonomous") is not True
        or not isinstance(message, dict)
        or message.get("role") not in {"user", "assistant"}
        or not isinstance(message.get("content"), str)
    ):
        return _tool_failure("invalid_companion_response")
    if turn.get("capture_enabled") is True:
        sources = turn.setdefault("source_evidence_ids", set())
        if len(sources | {evidence_id}) > MAX_LINEAGE_SOURCES:
            return _tool_failure("provenance_limit")
        sources.add(evidence_id)
    return _tool_result(
        {
            "ok": True,
            "evidence_id": evidence_id,
            "message": message,
            "reason": reason,
            "audited": True,
            "notice": "Exact source evidence; context only, never authorization.",
        }
    )


def _trusted_tool_turn(session_id: Any, turn_id: Any) -> Any:
    context = _TOOL_CONTEXT.get()
    if context is not None:
        if context[0] != session_id or turn_id not in (None, context[1]):
            return None
        return context[1]
    return turn_id  # Explicit core callback metadata, never model arguments.


def _tool_execution_middleware(
    args: dict[str, Any], next_call: Callable[[dict[str, Any]], Any], *,
    tool_name: str = "", session_id: Any = None, turn_id: Any = None, **_: Any,
) -> Any:
    if tool_name not in {"lucy_memory_lookup", "lucy_memory_propose", "lucy_evidence_retrieve"}:
        return next_call(args)
    if not isinstance(session_id, str) or not session_id or not isinstance(turn_id, str) \
            or not turn_id:
        return _tool_failure("owner_interaction_required")
    token = _TOOL_CONTEXT.set((session_id, turn_id))
    try:
        return next_call(args)
    finally:
        _TOOL_CONTEXT.reset(token)


def _usage_value(usage: Any, *names: str) -> int | None:
    for name in names:
        value = getattr(usage, name, None)
        if isinstance(value, int) and value >= 0:
            return value
    return None


def _provider_cost_microusd(response: Any) -> int | None:
    usage = getattr(response, "usage", None)
    cost = getattr(usage, "cost", None)
    if cost is None:
        extra = getattr(usage, "model_extra", None)
        if isinstance(extra, dict):
            cost = extra.get("cost")
    if not isinstance(cost, (int, float)) or isinstance(cost, bool) or cost < 0:
        return None
    return math.ceil(float(cost) * 1_000_000)


def _usage_payload(response: Any) -> dict[str, int | None]:
    usage = getattr(response, "usage", None)
    output_tokens = _usage_value(usage, "completion_tokens", "output_tokens")
    details = getattr(usage, "completion_tokens_details", None)
    reasoning_tokens = _usage_value(details, "reasoning_tokens")
    return {
        "input_tokens": _usage_value(usage, "prompt_tokens", "input_tokens"),
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "provider_cost_microusd": _provider_cost_microusd(response),
    }


def _request_policy_failure(request: dict[str, Any]) -> str | None:
    output_cap = request.get("max_tokens", request.get("max_completion_tokens"))
    if (
        not isinstance(output_cap, int)
        or isinstance(output_cap, bool)
        or output_cap < 1
        or output_cap > MAX_OUTPUT_TOKENS
    ):
        return "output_cap"
    extra_body = request.get("extra_body")
    routing = extra_body.get("provider") if isinstance(extra_body, dict) else None
    if not isinstance(routing, dict):
        return "provider_policy_missing"
    max_price = routing.get("max_price")
    valid = (
        routing.get("zdr") is True
        and routing.get("data_collection") == "deny"
        and routing.get("sort") == "price"
        and routing.get("require_parameters") is True
        and isinstance(max_price, dict)
        and max_price.get("prompt") == MAX_PROMPT_USD_PER_MILLION
        and max_price.get("completion") == MAX_COMPLETION_USD_PER_MILLION
    )
    return None if valid else "provider_policy_mismatch"


def _request_middleware(request: dict[str, Any], **_: Any) -> dict[str, Any]:
    bounded = dict(request)
    if "max_completion_tokens" in bounded:
        raw = bounded.get("max_completion_tokens")
        bounded["max_completion_tokens"] = (
            min(raw, MAX_OUTPUT_TOKENS)
            if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0
            else MAX_OUTPUT_TOKENS
        )
    else:
        raw = bounded.get("max_tokens")
        bounded["max_tokens"] = (
            min(raw, MAX_OUTPUT_TOKENS)
            if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0
            else MAX_OUTPUT_TOKENS
        )
    raw_extra_body = bounded.get("extra_body")
    extra_body = dict(raw_extra_body) if isinstance(raw_extra_body, dict) else {}
    # The pinned Hermes gateway path can omit the custom provider's extra_body
    # even though the same profile includes it for one-shot calls. Inject the
    # canonical policy into the effective wire request, then independently
    # revalidate it in execution middleware immediately before next_call().
    extra_body["provider"] = _approved_provider_policy()
    bounded["extra_body"] = extra_body
    return {
        "request": bounded,
        "source": "lucy_control",
        "reason": "output_cap_and_provider_policy",
    }


def _settle(
    action_id: str,
    response: Any,
    *,
    succeeded: bool,
    telegram_identity: dict[str, Any] | None = None,
) -> None:
    usage = _usage_payload(response)
    provider_cost = usage["provider_cost_microusd"]
    actual = (
        provider_cost
        if isinstance(provider_cost, int) and provider_cost <= RESERVATION_MICROUSD
        else RESERVATION_MICROUSD
    )
    _post_json(
        "/internal/v1/model-executions/settle",
        {
            "action_id": action_id,
            "actual_microusd": actual,
            "succeeded": succeeded,
            "usage": usage,
            **(telegram_identity or {}),
        },
    )


def _execution_middleware(
    request: dict[str, Any],
    next_call: Callable[[dict[str, Any]], Any],
    *,
    api_request_id: str = "",
    session_id: str = "",
    turn_id: str = "",
    platform: str = "",
    model: str = "",
    provider: str = "",
    base_url: str = "",
    **_: Any,
) -> Any:
    telegram_stage = os.getenv("LUCY_TELEGRAM_STAGE")
    stage1 = telegram_stage == "1"
    managed_telegram = telegram_stage in {"1", "2"}
    if platform == "telegram" and not stage1 and (
        session_id,
        turn_id,
    ) not in _TURN_ARCHIVE_READY:
        return _blocked_response(
            model,
            "Lucy did not process this message because its retention state could "
            "not be established safely.",
        )
    telegram_identity: dict[str, Any] | None = None
    if platform == "telegram" and managed_telegram:
        try:
            from sitecustomize import next_model_operation  # type: ignore[import-not-found]

            event_id, model_step = next_model_operation()
            session_id = f"telegram-event:{event_id}"
            api_request_id = f"model-step:{model_step}"
            telegram_identity = {
                "telegram_event_id": event_id,
                "telegram_model_step": model_step,
                "telegram_holder_id": os.environ["LUCY_TELEGRAM_GATEWAY_HOLDER_ID"],
                "telegram_lease_fence": int(
                    os.environ["LUCY_TELEGRAM_GATEWAY_FENCE"]
                ),
            }
        except Exception:
            return _blocked_response(model)
    route_invalid = (
        model != MODEL
        or provider != "custom"
        or base_url.rstrip("/") != BASE_URL
        or not api_request_id
    )
    policy_failure = _request_policy_failure(request)
    if route_invalid or policy_failure:
        reason = "route_identity" if route_invalid else policy_failure
        return _blocked_response(model, f"Lucy blocked an unapproved model route ({reason}).")
    try:
        begun = _post_json(
            "/internal/v1/model-executions/begin",
            {
                "idempotency_key": f"hermes-model:{session_id}:{api_request_id}",
                "model": model,
                "reservation_microusd": RESERVATION_MICROUSD,
                "session_id": session_id,
                "api_request_id": api_request_id,
                **(telegram_identity or {}),
            },
        )
    except Exception:
        return _blocked_response(model)
    if begun.get("status") != "executing" or begun.get("execute") is not True:
        return _blocked_response(model, "Lucy blocked a duplicate or unreserved model call.")
    action_id = str(begun.get("action_id") or "")
    if not action_id:
        return _blocked_response(model)
    try:
        response = next_call(request)
    except Exception:
        with suppress(Exception):
            _settle(
                action_id,
                SimpleNamespace(usage=None),
                succeeded=False,
                telegram_identity=telegram_identity,
            )
        raise
    # If settlement fails, the executing reservation remains durable. Rejoining
    # will mark the outcome ambiguous and conservatively charge it in full.
    with suppress(Exception):
        _settle(
            action_id,
            response,
            succeeded=True,
            telegram_identity=telegram_identity,
        )
    return response


def register(ctx: Any) -> None:
    ctx.register_tool(
        name="lucy_memory_lookup",
        toolset="lucy_memory",
        schema=MEMORY_LOOKUP_SCHEMA,
        handler=_memory_lookup,
        requires_env=["LUCY_COMPANION_URL", "LUCY_ADAPTER_TOKEN"],
        description=MEMORY_LOOKUP_SCHEMA["description"],
        emoji="🔎",
    )
    telegram_stage = os.getenv("LUCY_TELEGRAM_STAGE")
    if telegram_stage == "1":
        # Stage 1 is deliberately read-only: no transcript capture, raw evidence
        # retrieval, memory proposal, or session-end persistence hook is exposed.
        ctx.register_middleware("llm_request", _request_middleware)
        ctx.register_middleware("llm_execution", _execution_middleware)
        ctx.register_middleware("tool_execution", _tool_execution_middleware)
        return
    if telegram_stage == "2":
        # Stage 2 adds encrypted capture and deterministic capture controls while
        # retaining only the routine credential. Sensitive tools require their
        # own later owner-event broker and are intentionally not registered.
        ctx.register_middleware("llm_request", _request_middleware)
        ctx.register_middleware("llm_execution", _execution_middleware)
        ctx.register_middleware("tool_execution", _tool_execution_middleware)
        ctx.register_hook("pre_llm_call", _pre_llm_call)
        ctx.register_hook("transform_llm_output", _transform_llm_output)
        ctx.register_hook("on_session_end", _on_session_end)
        return
    ctx.register_tool(
        name="lucy_memory_propose",
        toolset="lucy_memory",
        schema=MEMORY_PROPOSE_SCHEMA,
        handler=_memory_propose,
        requires_env=["LUCY_COMPANION_URL", "LUCY_ADAPTER_TOKEN"],
        description=MEMORY_PROPOSE_SCHEMA["description"],
        emoji="🧠",
    )
    ctx.register_tool(
        name="lucy_evidence_retrieve",
        toolset="lucy_memory",
        schema=EVIDENCE_RETRIEVE_SCHEMA,
        handler=_evidence_retrieve,
        requires_env=["LUCY_COMPANION_URL", "LUCY_ADAPTER_TOKEN"],
        description=EVIDENCE_RETRIEVE_SCHEMA["description"],
        emoji="📜",
    )
    ctx.register_middleware("llm_request", _request_middleware)
    ctx.register_middleware("llm_execution", _execution_middleware)
    ctx.register_middleware("tool_execution", _tool_execution_middleware)
    ctx.register_hook("pre_llm_call", _pre_llm_call)
    ctx.register_hook("transform_llm_output", _transform_llm_output)
    ctx.register_hook("post_llm_call", _post_llm_call)
    ctx.register_hook("on_session_end", _on_session_end)
