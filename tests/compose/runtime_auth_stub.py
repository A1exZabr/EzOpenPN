from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

_RUNTIME_ID = "p_abcdefghijklmnopqrstuvwx23"
_MAX_BODY = 4096


class Handler(BaseHTTPRequestHandler):
    allow_profiles = True
    state_lock = Lock()

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _json(self, status: int, body: dict[str, object]) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return
        self._json(404, {"status": "missing"})

    def do_POST(self) -> None:
        if self.path == "/test/block":
            with self.state_lock:
                type(self).allow_profiles = False
            self._json(200, {"status": "blocked"})
            return
        if self.path != "/internal/hysteria/auth":
            self._json(404, {"ok": False, "id": ""})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 1 <= length <= _MAX_BODY:
            self._json(200, {"ok": False, "id": ""})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(200, {"ok": False, "id": ""})
            return
        presented = body.get("auth", "") if isinstance(body, dict) else ""
        expected = os.environ.get("TEST_AUTH_VALUE", "")
        with self.state_lock:
            enabled = type(self).allow_profiles
        allowed = enabled and (
            isinstance(presented, str)
            and bool(expected)
            and hmac.compare_digest(presented, expected)
        )
        self._json(200, {"ok": allowed, "id": _RUNTIME_ID if allowed else ""})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
