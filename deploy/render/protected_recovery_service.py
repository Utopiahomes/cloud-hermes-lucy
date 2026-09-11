"""One-use Render entrypoint for an operator-authorized protected recovery."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NoReturn

from deploy.postgres.run_protected_recovery_v1_3 import (
    ProtectedRecoveryConfig,
    ProtectedRecoveryError,
    run,
)
from lucy.recovery_journal import RecoveryJournalError


class _ReadyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/ready":
            self.send_error(404)
            return
        body = b'{"status":"recovery-complete"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def _serve() -> NoReturn:
    port = int(os.environ.get("PORT", "10000"))
    ThreadingHTTPServer(("0.0.0.0", port), _ReadyHandler).serve_forever()
    raise AssertionError("HTTP server returned")


def main() -> None:
    try:
        report = run(ProtectedRecoveryConfig.from_environment())
    except (ProtectedRecoveryError, RecoveryJournalError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True), flush=True)
        raise SystemExit(1) from exc
    except Exception as exc:
        print(
            json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True),
            flush=True,
        )
        raise SystemExit(1) from exc
    print(json.dumps(report, sort_keys=True), flush=True)
    _serve()


if __name__ == "__main__":
    main()
