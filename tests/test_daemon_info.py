from __future__ import annotations

from gdare2d.ops.session import info


class FakeRuntime:
    summary = {"program": "demo", "arch": "x86", "readonly": False}
    state = "ready"
    instance_id = "0123456789abcdef"
    pid = 1234
    port = 4567
    error = None


class FakeContext:
    runtime = FakeRuntime()
    program = object()


def test_info_includes_daemon_state():
    payload = info(FakeContext())
    assert payload["program"] == "demo"
    assert payload["instance_id"] == "0123456789abcdef"
    assert payload["state"] == "ready"
    assert payload["pid"] == 1234
    assert payload["port"] == 4567
    assert payload["error"] is None
