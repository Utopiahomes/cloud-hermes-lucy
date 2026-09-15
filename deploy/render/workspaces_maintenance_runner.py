"""Run one approved maintenance payload and expose a health endpoint afterward."""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import sys


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path not in {"/", "/health"}:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"maintenance receipt retained\n")

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    encoded = os.environ["LUCY_ONE_SHOT"]
    payload = base64.b64decode(encoded, validate=True)
    print("workspaces maintenance payload starting", file=sys.stderr, flush=True)
    exec(compile(payload, "<workspaces-maintenance-payload>", "exec"), {})
    print("workspaces maintenance payload completed", file=sys.stderr, flush=True)
    port = int(os.environ.get("PORT", "10000"))
    ThreadingHTTPServer(("0.0.0.0", port), _HealthHandler).serve_forever()


if __name__ == "__main__":
    main()
