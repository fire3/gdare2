from __future__ import annotations

import pytest

from gdare2 import argv, launcher


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
