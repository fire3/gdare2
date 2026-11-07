from __future__ import annotations

from gdare2 import protocol


def test_nested_bytes_round_trip():
    value = {"raw": b"\x00\xff", "items": [b"a", {"nested": b"b"}]}
    encoded = protocol.encode_bytes(value)
    assert encoded["raw"][protocol.BYTES_KEY] == "AP8="
    assert protocol.decode_bytes(encoded) == value


def test_exact_shape_only():
    value = {protocol.BYTES_KEY: "AP8=", "extra": 1}
    assert protocol.decode_bytes(value) == value


def test_error_envelope():
    payload = protocol.error("BAD_ARGS", "bad")
    assert payload["ok"] is False
    assert payload["error"]["code"] == "BAD_ARGS"
