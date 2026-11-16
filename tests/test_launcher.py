from __future__ import annotations

import pytest

from gdare2 import argv, launcher
from gdare2.errors import NotFoundError, RemoteError


def test_ensure_missing_target_is_not_found(monkeypatch, tmp_path):
    """A missing path is r2's exit-1 case, not a daemon start failure."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    options = argv.parse([str(tmp_path / "absent.bin")])
    with pytest.raises(NotFoundError, match="cannot open"):
        launcher.ensure(options)
    # The check happens before any daemon/project directory is created.
    assert not (tmp_path / "run").exists()


def test_wait_for_ready_reports_the_daemon_error_code(monkeypatch, tmp_path):
    """A pre-serve failure must keep its code (BAD_ARGS), not become exit 3."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    state = {
        "instance_id": "0123456789abcdef",
        "pid": 1,
        "target": "/tmp/blob.bin",
        "state": "error",
        "error": "raw binaries need a Ghidra language",
        "error_code": "BAD_ARGS",
    }
    monkeypatch.setattr(launcher.registry, "read_state", lambda ingest_id: state)
    options = argv.parse(["--startup-timeout", "5", "/tmp/blob.bin"])
    with pytest.raises(RemoteError) as caught:
        launcher._wait_for_ready(options, "0123456789abcdef")
    assert caught.value.code == "BAD_ARGS"
    assert caught.value.exit_code == 2


def test_report_startup_failure_leaves_the_error_code(monkeypatch, tmp_path):
    from gdare2.errors import UsageError
    from gdare2d.__main__ import _report_startup_failure

    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    written: dict[str, object] = {}
    removed: list[str] = []
    monkeypatch.setattr(
        launcher.registry, "write_state", lambda state: written.update(state)
    )
    monkeypatch.setattr(
        launcher.registry, "remove_state", lambda ingest_id: removed.append(ingest_id)
    )
    import gdare2d.__main__ as daemon_main

    monkeypatch.setattr(daemon_main.time, "sleep", lambda seconds: None)
    _report_startup_failure(
        "0123456789abcdef", "/tmp/blob.bin", UsageError("raw binaries need a language")
    )
    assert written["state"] == "error"
    assert written["error_code"] == "BAD_ARGS"
    assert written["error"] == "raw binaries need a language"
    assert removed == ["0123456789abcdef"]


def test_spawn_forwards_listen(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    captured: dict[str, list[str]] = {}

    class FakePopen:
        def __init__(self, command, **_kwargs):
            captured["command"] = command

    monkeypatch.setattr(launcher.subprocess, "Popen", FakePopen)
    options = argv.parse(
        [
            "--listen",
            "0.0.0.0",
            "--project",
            str(tmp_path / "project"),
            "/bin/ls",
        ]
    )
    launcher._spawn(options, "/bin/ls", "0123456789abcdef")
    command = captured["command"]
    assert "--listen" in command
    assert command[command.index("--listen") + 1] == "0.0.0.0"


def test_spawn_uses_project_name_derived_from_instance_id(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    captured: dict[str, list[str]] = {}

    class FakePopen:
        def __init__(self, command, **_kwargs):
            captured["command"] = command

    monkeypatch.setattr(launcher.subprocess, "Popen", FakePopen)
    options = argv.parse(["--project", str(tmp_path / "project"), "/bin/ls"])
    launcher._spawn(options, "/bin/ls", "0123456789abcdef")
    command = captured["command"]
    name = command[command.index("--project-name") + 1]
    assert name == "ls-01234567"


def test_ensure_attach_does_not_require_a_target(monkeypatch):
    state = {"instance_id": "0123456789abcdef"}
    monkeypatch.setattr(launcher, "attach", lambda options: state)
    assert launcher.ensure(argv.parse(["--attach", "0123456789abcdef"])) is state


def test_spawn_forwards_daemon_readonly(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    captured: dict[str, list[str]] = {}

    class FakePopen:
        def __init__(self, command, **_kwargs):
            captured["command"] = command

    monkeypatch.setattr(launcher.subprocess, "Popen", FakePopen)
    options = argv.parse(
        ["--daemon-readonly", "--project", str(tmp_path / "project"), "/bin/ls"]
    )
    launcher._spawn(options, "/bin/ls", "0123456789abcdef")
    assert "--readonly" in captured["command"]


def test_spawn_forwards_allow_exec(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    captured: dict[str, list[str]] = {}

    class FakePopen:
        def __init__(self, command, **_kwargs):
            captured["command"] = command

    monkeypatch.setattr(launcher.subprocess, "Popen", FakePopen)
    options = argv.parse(
        ["--allow-exec", "--project", str(tmp_path / "project"), "/bin/ls"]
    )
    launcher._spawn(options, "/bin/ls", "0123456789abcdef")
    assert "--allow-exec" in captured["command"]


def test_spawn_forwards_endian_from_r2_config(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    captured: dict[str, list[str]] = {}

    class FakePopen:
        def __init__(self, command, **_kwargs):
            captured["command"] = command

    monkeypatch.setattr(launcher.subprocess, "Popen", FakePopen)
    options = argv.parse(
        ["-e", "arch.endian=big", "--project", str(tmp_path / "project"), "/bin/ls"]
    )
    launcher._spawn(options, "/bin/ls", "0123456789abcdef")
    command = captured["command"]
    assert command[command.index("--endian") + 1] == "big"


def test_spawn_omits_analysis_timeout_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    captured: dict[str, list[str]] = {}

    class FakePopen:
        def __init__(self, command, **_kwargs):
            captured["command"] = command

    monkeypatch.setattr(launcher.subprocess, "Popen", FakePopen)
    options = argv.parse(["--project", str(tmp_path / "project"), "/bin/ls"])
    launcher._spawn(options, "/bin/ls", "0123456789abcdef")
    # No analysis cutoff by default: slow-arch first imports must run to completion.
    assert "--analysis-timeout" not in captured["command"]


def test_spawn_forwards_analysis_timeout(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    captured: dict[str, list[str]] = {}

    class FakePopen:
        def __init__(self, command, **_kwargs):
            captured["command"] = command

    monkeypatch.setattr(launcher.subprocess, "Popen", FakePopen)
    options = argv.parse(
        ["--analysis-timeout", "300", "--project", str(tmp_path / "project"), "/bin/ls"]
    )
    launcher._spawn(options, "/bin/ls", "0123456789abcdef")
    assert "--analysis-timeout" in captured["command"]
    assert captured["command"][captured["command"].index("--analysis-timeout") + 1] == "300.0"


def test_daemon_default_analysis_timeout_is_disabled():
    from gdare2d.__main__ import parser

    assert parser().get_default("analysis_timeout") == 0.0
