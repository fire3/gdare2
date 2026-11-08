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
