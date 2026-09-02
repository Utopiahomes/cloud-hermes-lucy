"""Inert Render bootstrap used only to obtain immutable resource identities.

The Security Baseline v1.2 AWS trust policy needs exact Render service IDs.
Those IDs do not exist until Render creates the services, while the production
runtime correctly refuses to start before its AWS and PostgreSQL boundaries
exist.  This module breaks only that provisioning cycle: it opens a private
HTTP socket that always returns 503 and initializes no Lucy capability.

The Blueprint command override must be removed before cloud acceptance.  If it
is accidentally left in place, the failure mode is loss of availability, not a
bypass of the production readiness gates.
"""

from __future__ import annotations

import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ACKNOWLEDGEMENT = "resource-id-only"
_ALLOWED_MODES = {"routine", "policy", "evidence", "deletion"}
_BODY = b"Lucy provisioning hold: no application capability enabled\n"


def _validate_environment() -> tuple[str, int]:
    if os.getenv("LUCY_RESOURCE_ID_BOOTSTRAP_HOLD") != _ACKNOWLEDGEMENT:
        raise SystemExit("Lucy provisioning hold was not explicitly acknowledged")
    if os.getenv("LUCY_ENVIRONMENT") != "production":
        raise SystemExit("Lucy provisioning hold is production-only")
    if os.getenv("LUCY_SERVICE_MODE") not in _ALLOWED_MODES:
        raise SystemExit("Lucy provisioning hold has an invalid service mode")
    if os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false") != "false":
        raise SystemExit("Lucy provisioning hold requires transcript capture disabled")
    if any(
        os.getenv(name)
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
    ):
        raise SystemExit("Lucy provisioning hold forbids static AWS credentials")

    host = "0.0.0.0"
    try:
        port = int(os.getenv("PORT", "8080"))
    except ValueError:
        raise SystemExit("Lucy provisioning hold received an invalid port") from None
    if not 1 <= port <= 65_535:
        raise SystemExit("Lucy provisioning hold received an invalid port")
    return host, port


class _UnavailableHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _unavailable(self, *, include_body: bool = True) -> None:
        self.send_response(HTTPStatus.SERVICE_UNAVAILABLE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(_BODY)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._unavailable()

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._unavailable(include_body=False)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._unavailable()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._unavailable()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._unavailable()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._unavailable()

    def log_message(self, format: str, *args: object) -> None:
        # Requests and headers are intentionally absent from bootstrap logs.
        return


def main() -> None:
    address = _validate_environment()
    print(
        "Lucy provisioning hold active; no database, AWS, or transcript "
        "capability enabled",
        flush=True,
    )
    ThreadingHTTPServer(address, _UnavailableHandler).serve_forever()


if __name__ == "__main__":
    main()
