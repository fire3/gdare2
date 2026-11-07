from __future__ import annotations

import json
from pathlib import Path

from gdare2 import registry


def test_instance_id_changes_with_import_options(tmp_path):
    target = tmp_path / "blob"
    target.write_bytes(b"hello")
    first = registry.instance_id(str(target))
    second = registry.instance_id(str(target), import_options={"arch": "arm"})
    assert first != second
    assert len(first) == 16


def test_state_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    state = {
        "instance_id": "abc123",
        "pid": 123,
        "port": 4567,
        "token": "secret",
        "target": "/bin/ls",
        "state": "ready",
    }
    registry.write_state(state)
    assert registry.read_state("abc123") == state
    registry.remove_state("abc123")
    assert registry.read_state("abc123") is None


def test_state_file_is_private(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    path = registry.write_state({"instance_id": "private", "pid": 1, "port": 1, "token": "t"})
    assert (path.stat().st_mode & 0o777) == 0o600
