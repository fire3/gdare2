"""r2pipe-compatible command channel.

``--pipe-listen [host:]port`` serves the two wire protocols the ``r2pipe``
client library speaks, reusing the full gdare2 command pipeline (parser,
``@``/``~``/``|``, macros, flags, variables) so existing r2pipe scripts drive
a gdare2 session unchanged:

- raw TCP (``tcp://``): one command per connection, framed either by a
  trailing newline (persistent, our own extension) or by the end of the
  request (r2pipe's framing).  Responses are NUL-terminated; the connection
  closes after a newline-free command because r2pipe reads until EOF.
- HTTP (``http://``): the request path is the URL-encoded command; the body
  is the raw output.  This is the mode r2pipe uses for long scripts
  (``r2pipe.open("http://127.0.0.1:9090/")``).

The server is opt-in and defaults to loopback; write commands stay gated by
the usual ``-w`` rules because they run through the same
:class:`~gdare2.session.Session`.
"""

from __future__ import annotations

import socket
import socketserver
import threading
from urllib.parse import unquote

from gdare2.errors import GdarError
from gdare2.session import Session


def _run_command(session: Session, raw: bytes) -> bytes:
    """Run one command and return its output as UTF-8 bytes."""
    text = raw.decode("utf-8", "replace").rstrip("\r\n").strip()
    if not text:
        return b""
    try:
        output = session.run(text)
        return ("\n".join(output) + ("\n" if output else "")).encode(
            "utf-8", "replace"
        )
    except GdarError as exc:
        return f"ERROR: {exc}\n".encode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - keep the server alive
        return f"ERROR: {exc}\n".encode("utf-8", "replace")


class _R2PipeHandler(socketserver.StreamRequestHandler):
    timeout = 0.25

    def handle(self) -> None:  # noqa: D102
        server = self.server
        assert isinstance(server, R2PipeServer)
        try:
            chunk = self.request.recv(4096)
        except OSError:
            return
        if not chunk:
            return
        if chunk.startswith((b"GET ", b"POST ")):
            self._handle_http(server, chunk)
            return
        self._handle_raw(server, chunk)

    # -- HTTP ----------------------------------------------------------------
    def _handle_http(self, server: R2PipeServer, first: bytes) -> None:
        """Answer r2pipe's HTTP mode: the path is the URL-encoded command."""
        try:
            self.request.settimeout(2.0)
            buffer = first
            while b"\r\n\r\n" not in buffer:
                extra = self.request.recv(4096)
                if not extra:
                    break
                buffer += extra
        except OSError:
            return
        line = buffer.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        path = parts[1] if len(parts) > 1 else "/"
        command = unquote(path.lstrip("/"))
        # r2pipe builds "<host>/cmd/<command>" like r2's own HTTP server.
        if command.startswith("cmd/"):
            command = command[4:]
        payload = _run_command(server.session, command.encode("utf-8"))
        body = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
        try:
            self.wfile.write(
                body + str(len(payload)).encode() + b"\r\n\r\n" + payload
            )
            self.wfile.flush()
        except OSError:
            return
        self._check_quit(server)

    # -- raw TCP ---------------------------------------------------------------
    def _handle_raw(self, server: R2PipeServer, first: bytes) -> None:
        # r2's own TCP server answers one command per connection; r2pipe's
        # tcp:// client sends the command WITHOUT a trailing newline and reads
        # until the peer closes.  Our tests and interactive clients send
        # "\n"-terminated commands and keep the connection open.
        newline_framed = b"\n" in first
        if newline_framed:
            pending = bytearray(first)
            while not server.closed.is_set():
                while b"\n" in pending:
                    index = pending.index(b"\n")
                    line = bytes(pending[:index])
                    del pending[: index + 1]
                    if line.strip():
                        self._answer(server, line, close_after=False)
                    if server.closed.is_set() or server.session.quit_requested:
                        return
                try:
                    chunk = self.request.recv(4096)
                except TimeoutError:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                pending.extend(chunk)
            return
        payload = _run_command(server.session, first)
        try:
            self.wfile.write(payload + b"\x00")
            self.wfile.flush()
            # r2pipe reads until EOF: answer one command, then close.
            self.request.shutdown(socket.SHUT_WR)
        except OSError:
            return
        while True:
            try:
                if not self.request.recv(4096):
                    return
            except OSError:
                return

    def _answer(self, server: R2PipeServer, line: bytes, *, close_after: bool) -> None:
        payload = _run_command(server.session, line)
        try:
            self.wfile.write(payload + b"\x00")
            self.wfile.flush()
        except OSError:
            return
        self._check_quit(server)

    def _check_quit(self, server: R2PipeServer) -> None:
        if server.session.quit_requested:
            server.closed.set()


class R2PipeServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, session: Session) -> None:
        super().__init__(address, _R2PipeHandler)
        self.session = session
        self.closed = threading.Event()

    def serve_until_closed(self) -> None:
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def shutdown_and_close(self) -> None:
        self.closed.set()
        self.shutdown()
        self.server_close()


def serve_r2pipe(session: Session, address: tuple[str, int]) -> R2PipeServer:
    """Start an r2pipe-compatible server (raw TCP + HTTP) for ``session``."""
    server = R2PipeServer(address, session)
    server.serve_until_closed()
    return server
