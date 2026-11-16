from __future__ import annotations

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


def test_ghidra_safe_path_matches_project_locator_rules(tmp_path):
    assert registry.ghidra_safe_path(tmp_path / "plain-data")
    assert registry.ghidra_safe_path(tmp_path / "has space(1)[2]@x=1+2~3")
    # Every element is checked: a '#', '%' or leading dot anywhere fails.
    assert not registry.ghidra_safe_path(tmp_path / "hello#scenario" / "data")
    assert not registry.ghidra_safe_path(tmp_path / "100%-done")
    assert not registry.ghidra_safe_path(tmp_path / ".hidden" / "data")


def test_data_dir_falls_back_when_the_override_is_not_a_project_path(
    monkeypatch, tmp_path
):
    unsafe = tmp_path / "hello#scenario" / "data"
    monkeypatch.setenv("GDARE2_DATA_DIR", str(unsafe))
    chosen = registry.data_dir()
    assert chosen != unsafe
    assert registry.ghidra_safe_path(chosen)
    assert chosen.is_dir()
    # The fallback is deterministic for the same configured directory.
    assert registry.data_dir() == chosen


def test_data_dir_keeps_a_usable_override(monkeypatch, tmp_path):
    usable = tmp_path / "gdare2 data"
    monkeypatch.setenv("GDARE2_DATA_DIR", str(usable))
    assert registry.data_dir() == usable
    assert usable.is_dir()
