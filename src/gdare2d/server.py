"""Loopback HTTP server for the gdare2 op protocol."""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from gdare2 import __version__
from gdare2.protocol import decode_bytes, health_payload
from gdare2d.context import Context
from gdare2d.dispatch import as_error, invoke
from gdare2d.executor import Executor

log = logging.getLogger("gdare2d.server")

MAX_BODY = 16 * 1024 * 1024


class GdarHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, token: str, runtime, executor: Executor) -> None:
        super().__init__(address, handler)
        self.token = token
        self.runtime = runtime
        self.executor = executor
        self.last_activity = time.monotonic()
        self.shutting_down = threading.Event()
        self.started_at = time.time()

    def touch(self) -> None:
        self.last_activity = time.monotonic()


class Handler(BaseHTTPRequestHandler):
    server: GdarHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("http: " + fmt, *args)

    def do_GET(self) -> None:  # noqa: N802
        self.server.touch()
        if self.path == "/health":
            self._json(health_payload(self.server.runtime.state, __version__))
            return
        if not self._authorized():
            return
        if self.path == "/info":
            self._json(
                {
                    "ok": True,
                    "version": __version__,
                    "instance_id": getattr(self.server.runtime, "instance_id", ""),
                    "state": self.server.runtime.state,
                    "summary": self.server.runtime.summary,
                    "executor": self.server.executor.properties(),
                    "started_at": self.server.started_at,
                }
            )
            return
        if self.path == "/sessions":
            self._json({"ok": True, "sessions": self.server.runtime.session_list()})
            return
        self._json({"ok": False, "error": {"code": "NOT_FOUND", "message": "no such endpoint"}}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        self.server.touch()
        if not self._authorized():
            return
        if self.path == "/shutdown":
            body = self._read_json() or {}
            if "save" in body:
                self.server.runtime.save_on_close = bool(body["save"])
            self.server.runtime.state = "draining"
            self.server.shutting_down.set()
            self._json({"ok": True, "result": {"closing": True}})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if self.path != "/rpc":
            self._json({"ok": False, "error": {"code": "NOT_FOUND", "message": "no such endpoint"}}, status=404)
            return
        request = self._read_json()
        if request is None:
            return
        op = request.get("op")
        args = request.get("args", {})
        try:
            args = decode_bytes(args)
        except ValueError:
            args = None
        if not isinstance(op, str) or not isinstance(args, dict):
            self._json({"ok": False, "error": {"code": "BAD_ARGS", "message": "invalid envelope"}}, status=400)
            return
        context = Context(
            runtime=self.server.runtime,
            readonly=bool(self.server.runtime.readonly),
            allow_writes=bool(request.get("allow_writes", False)),
        )
        try:
            result = self.server.executor.submit(
                lambda: invoke(context, op, args, allow_writes=context.allow_writes)
            )
            self._json({"ok": True, "result": _encode(result)})
        except Exception as exc:
            self._json(as_error(exc))

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.token}"
        if not hmac.compare_digest(header, expected):
            self._json({"ok": False, "error": {"code": "UNAUTHORIZED", "message": "bad token"}}, status=401)
            return False
        return True

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._json({"ok": False, "error": {"code": "BAD_ARGS", "message": "invalid body size"}}, status=400)
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (OSError, ValueError):
            self._json({"ok": False, "error": {"code": "BAD_ARGS", "message": "invalid JSON"}}, status=400)
            return None

    def _json(self, payload: dict, *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def _encode(value: Any) -> Any:
    from gdare2.protocol import encode_bytes

    return encode_bytes(value)
