from __future__ import annotations

import socket
import time

from test_session import make_session


def _roundtrip(session, command: str) -> str:
    from gdare2.r2pipe_server import serve_r2pipe

    server = serve_r2pipe(session, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall((command + "\n").encode())
            deadline = time.monotonic() + 5
            chunks = []
            while b"\x00" not in b"".join(chunks) and time.monotonic() < deadline:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace").rstrip("\x00")
    finally:
        server.shutdown_and_close()


def test_r2pipe_protocol_executes_commands():
    session, _client = make_session()
    output = _roundtrip(session, "?e hello")
    assert output.strip() == "hello"
    seeked = _roundtrip(session, "s")
    # "?e hello" ran on the same session; the seek is unchanged.
    assert seeked.strip() == "0x0000000000001000"


def test_r2pipe_reports_errors_and_keeps_serving():
    session, _client = make_session()
    first = _roundtrip(session, "this-is-not-a-command")
    assert "ERROR" in first or first == ""
    second = _roundtrip(session, "?e still-alive")
    assert second.strip() == "still-alive"


def _http_roundtrip(session, command: str) -> str:
    from urllib.parse import quote
    from urllib.request import urlopen

    from gdare2.r2pipe_server import serve_r2pipe

    server = serve_r2pipe(session, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        with urlopen(f"http://127.0.0.1:{port}/{quote(command)}", timeout=5) as resp:
            return resp.read().decode("utf-8", "replace")
    finally:
        server.shutdown_and_close()


def test_r2pipe_http_mode_runs_commands():
    session, _client = make_session()
    output = _http_roundtrip(session, "?e http-works")
    assert output.strip() == "http-works"
    seeked = _http_roundtrip(session, "s")
    assert seeked.strip() == "0x0000000000001000"


def test_r2pipe_raw_without_newline_closes_after_answer():
    session, _client = make_session()
    from gdare2.r2pipe_server import serve_r2pipe

    server = serve_r2pipe(session, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(b"?e raw-ok")
            deadline = time.monotonic() + 5
            chunks = []
            while time.monotonic() < deadline:
                try:
                    data = sock.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                chunks.append(data)
        joined = b"".join(chunks)
        assert joined.startswith(b"raw-ok")
        assert joined.endswith(b"\x00")
    finally:
        server.shutdown_and_close()
