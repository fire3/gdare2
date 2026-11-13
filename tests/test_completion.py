"""Tab completion for commands, flags/functions and ``$`` variables."""

from __future__ import annotations

from test_session import make_session

from gdare2 import completion


def test_command_and_config_completion():
    assert {"w", "wx", "w0", "wf", "wd", "wq"} <= set(completion.complete_line("", "w"))
    assert "aF" in completion.complete_line("af", "aF")
    assert {"scr.color", "scr.null"} <= set(completion.complete_line("e scr", "scr"))
    assert "pdc" in completion.complete_line("pd", "pd")


def test_argument_completion_offers_flags_and_functions():
    session, _ = make_session()
    session.run("f localflag 4 @ 0x3000")
    candidates = completion.complete_line("f- local", "local", session)
    assert candidates == ["localflag"]
    # functions are seeded into the flag store by load_flags()
    assert "main" in completion.complete_line("s ma", "ma", session)
    assert "helper" in completion.complete_line("s hel", "hel", session)


def test_dollar_variable_completion():
    session, _ = make_session()
    session.vars["myvar"] = 0x10
    session.run("f localflag 4 @ 0x3000")
    assert completion.complete_line("s $m", "$m", session) == ["$myvar"]


def test_no_session_keeps_command_completion_only():
    assert completion.complete_line("s ma", "ma", None) == []
