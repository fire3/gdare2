from __future__ import annotations

from gdare2 import registry
from gdare2.client import Client


def test_http_host_maps_wildcards_to_loopback():
    assert registry.http_host(None) == "127.0.0.1"
    assert registry.http_host("") == "127.0.0.1"
    assert registry.http_host("0.0.0.0") == "127.0.0.1"
    assert registry.http_host("::") == "[::1]"
    assert registry.http_host("::1") == "[::1]"
    assert registry.http_host("127.0.0.2") == "127.0.0.2"


def test_client_uses_registered_host():
    client = Client(
        {
            "instance_id": "id",
            "host": "0.0.0.0",
            "port": 1234,
            "token": "token",
        }
    )
    assert client.host == "127.0.0.1"


def test_server_swallows_a_client_that_hangs_up(monkeypatch):
    """A killed client must not print a traceback into the daemon log."""
    from gdare2d.server import GdarHTTPServer

    logged: list[str] = []
    monkeypatch.setattr("gdare2d.server.log.debug",
                        lambda fmt, *args: logged.append(fmt % args)
                        if args else logged.append(fmt))

    class _Server(GdarHTTPServer):
        def __init__(self):  # no sockets: only the error hook is under test
            pass

    server = _Server()
    server.handle_error(None, ("127.0.0.1", 1234))
    assert logged == []

    import sys

    try:
        raise BrokenPipeError(32, "Broken pipe")
    except BrokenPipeError:
        server.handle_error(None, ("127.0.0.1", 1234))
    assert any("went away" in line for line in logged)
    assert sys.exc_info()[0] is None
