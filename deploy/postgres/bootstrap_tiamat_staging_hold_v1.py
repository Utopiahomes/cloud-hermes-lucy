"""Fail-closed HTTP hold process for the disposable Tiamat staging bootstrap runner.

Render private services must bind a port to be considered healthy.  This process exists solely to
keep the temporary runner inert between explicitly invoked bootstrap jobs.  It deliberately does
not import the database, AWS, signing, or executor code, and it emits no request data to logs.
"""

from __future__ import annotations

import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_BODY = b"Tiamat staging bootstrap runner is idle; no capability is enabled.\n"


def _address() -> tuple[str, int]:
    try:
        port = int(os.environ.get("PORT", "10000"))
    except ValueError:
        raise SystemExit("bootstrap hold received an invalid port") from None
    if not 1 <= port <= 65_535:
        raise SystemExit("bootstrap hold received an invalid port")
    return "0.0.0.0", port


class _HoldHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, *, include_body: bool) -> None:
        self.send_response(HTTPStatus.SERVICE_UNAVAILABLE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(_BODY)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        self._respond(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib hook
        self._respond(include_body=False)

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook
        self._respond(include_body=True)

    def do_PUT(self) -> None:  # noqa: N802 - stdlib hook
        self._respond(include_body=True)

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib hook
        self._respond(include_body=True)

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib hook
        self._respond(include_body=True)

    def log_message(self, format: str, *args: object) -> None:
        # Request metadata must not become a staging bootstrap log stream.
        return


def main() -> None:
    print("tiamat_staging_bootstrap_hold active dispatch_enabled=false", flush=True)
    ThreadingHTTPServer(_address(), _HoldHandler).serve_forever()


if __name__ == "__main__":
    main()
