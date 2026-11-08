from __future__ import annotations

import types

from gdare2 import completion, rc
from gdare2.cli import _command_lines, _run_rc


def test_rc_paths_load_order_and_skip(monkeypatch, tmp_path):
    home = tmp_path / "home"
    config = tmp_path / "config"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    system = config / "gdare2" / "rc"
    system.parent.mkdir(parents=True)
    system.write_text("# system\ne scr.color=1\n", encoding="utf-8")
    user = home / ".gdare2rc"
    user.parent.mkdir(parents=True)
    user.write_text("\n# user\ne scr.null=true\n", encoding="utf-8")

    assert rc.load(0) == ["e scr.color=1", "e scr.null=true"]
    assert rc.load(1) == ["e scr.color=1"]
    assert rc.load(2) == []
    assert [path.name for path in rc.rc_paths(0)] == ["rc", ".gdare2rc"]


def test_completion_candidates():
    assert {"w", "wx", "w0", "wf", "wd", "wc+", "wq"} <= set(completion.complete_line("", "w"))
    assert "aF" in completion.complete_line("af", "aF")
    assert {"scr.color", "scr.null"} <= set(completion.complete_line("e scr", "scr"))
    assert "pdc" in completion.complete_line("pd", "pd")


def test_history_path_uses_xdg_state(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert completion.history_path() == tmp_path / "state" / "gdare2" / "history"


def test_command_lines_order_pre_commands_post(tmp_path):
    pre = tmp_path / "pre.rc"
    post = tmp_path / "post.rc"
    pre.write_text("e scr.color=1\n", encoding="utf-8")
    post.write_text("q\n", encoding="utf-8")
    options = types.SimpleNamespace(
        pre_scripts=[str(pre)],
        commands=["pd 1"],
        post_scripts=[str(post)],
    )
    assert _command_lines(options) == ["e scr.color=1", "pd 1", "q"]


def test_rc_errors_do_not_mark_the_session_failed(monkeypatch):
    monkeypatch.setattr(rc, "load", lambda skip: ["bad-command"])
    session = types.SimpleNamespace(
        failed=False,
        last_error=None,
        quit_requested=False,
        calls=[],
    )

    def run(line):
        session.calls.append(line)
        session.failed = True
        session.last_error = ValueError("boom")
        return []

    session.run = run
    _run_rc(session, types.SimpleNamespace(skip_rc=0))
    assert session.calls == ["bad-command"]
    assert session.failed is False
    assert session.last_error is None
