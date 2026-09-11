"""Content-free parent supervisor for the pinned private Telegram gateway."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from uuid import uuid4

LEASE_SECONDS = 30
HEARTBEAT_SECONDS = 10
_PRIVATE_HOSTPORT = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:[0-9]{2,5}\Z")
_RETENTION_CODES = {
    "archive_request_failed",
    "archive_request_completed",
    "archive_request_rejected",
    "assistant_delivery_blocked",
    "post_hook_skipped_blocked_delivery",
}
_SAFE_ERROR_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,80}\Z")


def _event(code: str) -> None:
    print(json.dumps({"component": "lucy-telegram-stage1", "code": code}), flush=True)


def _forward_content_free_child_events(stream: Any) -> None:
    """Drain child stdout while forwarding only an explicit safe event schema."""

    for raw_line in stream:
        try:
            line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
            payload = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            continue
        if (
            not isinstance(payload, dict)
            or payload.get("component") != "lucy-retention"
            or payload.get("code") not in _RETENTION_CODES
        ):
            continue
        safe: dict[str, str] = {
            "component": "lucy-retention",
            "code": payload["code"],
        }
        if payload.get("role") in {"user", "assistant"}:
            safe["role"] = payload["role"]
        error_type = payload.get("error_type")
        if isinstance(error_type, str) and _SAFE_ERROR_TYPE.fullmatch(error_type):
            safe["error_type"] = error_type
        print(json.dumps(safe, sort_keys=True, separators=(",", ":")), flush=True)


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError("configuration_missing")
    return value


def _validate_stage_mode() -> str:
    """Bind capture authority to one explicit Telegram release stage."""

    stage = _required("LUCY_TELEGRAM_STAGE")
    capture = os.environ.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED")
    if stage == "1" and capture == "false":
        return stage
    if stage == "2" and capture == "true":
        return stage
    raise RuntimeError("telegram_stage_capture_mismatch")


def _companion_url() -> str:
    configured = os.environ.get("LUCY_COMPANION_URL", "").strip().rstrip("/")
    if configured:
        return configured
    hostport = _required("LUCY_COMPANION_HOSTPORT")
    if _PRIVATE_HOSTPORT.fullmatch(hostport) is None:
        raise RuntimeError("companion_boundary_invalid")
    return f"http://{hostport}"


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        f"{_companion_url()}{path}",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {_required('LUCY_ADAPTER_TOKEN')}",
            "Content-Type": "application/json",
        },
    )
    with urlopen(request, timeout=8) as response:  # noqa: S310 - fixed private service URL
        result: dict[str, Any] = json.load(response)
    return result


def _require_tmpfs(path: Path) -> None:
    mounts = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
    if not any(
        parts[1] == "/dev/shm" and parts[2] == "tmpfs"
        for line in mounts
        if len(parts := line.split()) >= 3
    ):
        raise RuntimeError("ram_boundary_unavailable")
    path.mkdir(mode=0o700, parents=True)


def _prepare_managed_home(path: Path) -> None:
    """Create only the ephemeral directories required by pinned managed Hermes."""

    # copytree preserves the immutable image profile's read-only root mode.
    # Restore writability only on this per-start tmpfs copy.
    if os.name != "nt":
        path.chmod(0o700)
    for relative in ("cron", "sessions", "logs", "memories"):
        directory = path / relative
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            directory.chmod(0o700)


def _preflight(environment: dict[str, str], scratch: Path) -> None:
    for label, command in (
        ("hermes_config", ["/opt/hermes/.venv/bin/hermes", "config", "check"]),
        (
            "lucy_plugin",
            ["/opt/hermes/.venv/bin/hermes", "plugins", "doctor", "--ci", "lucy_control"],
        ),
    ):
        result = subprocess.run(  # noqa: S603 - immutable commands in a pinned image
            command,
            env=environment,
            cwd=scratch,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            _event(f"{label}_failed")
            raise RuntimeError(f"{label}_failed")
        _event(f"{label}_passed")


def main() -> int:
    _validate_stage_mode()
    token = _required("TELEGRAM_BOT_TOKEN")
    bot_prefix, separator, _secret = token.partition(":")
    if not separator or not bot_prefix.isdecimal() or int(bot_prefix) <= 0:
        raise RuntimeError("bot_identity_invalid")
    owner = _required("TELEGRAM_ALLOWED_USERS")
    home = _required("TELEGRAM_HOME_CHANNEL")
    if not owner.isdecimal() or owner != home:
        raise RuntimeError("owner_binding_invalid")
    _event("configuration_validated")

    scratch = Path(f"/dev/shm/lucy-hermes-{uuid4().hex}")
    _require_tmpfs(scratch)
    _event("ram_boundary_validated")
    holder_id = str(uuid4())
    stop = threading.Event()
    heartbeat_failed = threading.Event()
    lease_acquired = False
    child: subprocess.Popen[bytes] | None = None
    return_code = 78

    try:
        shutil.copytree("/opt/lucy-profile", scratch, dirs_exist_ok=True)
        _prepare_managed_home(scratch)
        _event("profile_staged")
        child_env = dict(os.environ)
        child_env.update(
            {
                "HOME": str(scratch),
                "HERMES_HOME": str(scratch),
                "TERMINAL_CWD": str(scratch),
                "HERMES_MANAGED": "render",
                "PYTHONDONTWRITEBYTECODE": "1",
                "LUCY_TELEGRAM_BOT_ID": bot_prefix,
                "LUCY_TELEGRAM_GATEWAY_HOLDER_ID": holder_id,
                "PYTHONPATH": "/opt/lucy-stage1:/opt/hermes",
            }
        )
        child_env["LUCY_COMPANION_URL"] = _companion_url()
        _preflight(child_env, scratch)
        _event("preflight_passed")
        lease = _post(
            "/internal/v1/telegram-stage1/lease/acquire",
            {"holder_id": holder_id, "lease_seconds": LEASE_SECONDS},
        )
        if lease.get("acquired") is not True or int(lease.get("fence", 0)) < 1:
            raise RuntimeError("gateway_lease_denied")
        lease_acquired = True
        _event("lease_acquired")
        child_env["LUCY_TELEGRAM_GATEWAY_FENCE"] = str(lease["fence"])

        def heartbeat() -> None:
            while not stop.wait(HEARTBEAT_SECONDS):
                try:
                    result = _post(
                        "/internal/v1/telegram-stage1/lease/heartbeat",
                        {"holder_id": holder_id, "lease_seconds": LEASE_SECONDS},
                    )
                    if result.get("acquired") is not True:
                        raise RuntimeError("lease_lost")
                except Exception:
                    heartbeat_failed.set()
                    return

        thread = threading.Thread(target=heartbeat, name="stage1-lease", daemon=True)
        thread.start()
        child = subprocess.Popen(
            ["/opt/hermes/.venv/bin/hermes", "gateway", "run"],
            env=child_env,
            cwd=scratch,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert child.stdout is not None
        child_output = threading.Thread(
            target=_forward_content_free_child_events,
            args=(child.stdout,),
            name="stage2-safe-child-events",
            daemon=True,
        )
        child_output.start()

        def terminate(_signum: int, _frame: object) -> None:
            stop.set()
            if child is not None:
                child.terminate()

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        _event("gateway_started")
        while child.poll() is None:
            if heartbeat_failed.wait(1):
                child.terminate()
                _event("lease_lost")
                break
        return_code = child.wait(timeout=20)
    finally:
        stop.set()
        if child is not None and child.poll() is None:
            with suppress(Exception):
                child.terminate()
                child.wait(timeout=20)
        if lease_acquired:
            with suppress(Exception):
                _post(
                    "/internal/v1/telegram-stage1/lease/release",
                    {"holder_id": holder_id, "lease_seconds": LEASE_SECONDS},
                )
        shutil.rmtree(scratch, ignore_errors=True)
    _event("gateway_stopped")
    return return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        _event("startup_failed")
        raise SystemExit(78) from None
