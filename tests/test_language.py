"""Tests for the v3 command-language layer: @ modifiers, macros and .cmd."""

from __future__ import annotations

import pytest
from test_session import FakeClient, make_session

from gdare2 import parser
from gdare2.errors import UnsupportedError, UsageError


class LanguageClient(FakeClient):
    """FakeClient extended with the ops the @ modifiers need."""

    def call(self, op, **args):
        if op == "disasm_back":
            return [
                {"addr": args["ea"] - 2 * index, "size": 2, "text": "NOP"}
                for index in range(int(args.get("count", 1)), 0, -1)
            ]
        if op == "basic_block":
            return {
                "start": args["ea"] - 4,
                "end": args["ea"] + 8,
                "successors": [],
            }
        if op == "search":
            return {"hits": [0x5555], "meta": {"total": 1}}
        return super().call(op, **args)


@pytest.fixture
def session():
    session, _client = make_session(LanguageClient())
    return session


def _statement(text):
    return parser.parse_statement(text)


# --- @ modifiers ------------------------------------------------------------


def test_tmpseek_symbol_and_value(session):
    assert session.run("s @s:main") == ["0x0000000000002000"]
    assert session.run("s @v:0x3001") == ["0x0000000000003001"]
    assert session.seek == 0x1000


def test_tmpseek_restored_after_command(session):
    session.run("pd 1 @s:main")
    assert session.seek == 0x1000


def test_tmpseek_instruction_offsets(session):
    assert session.run("s @i:1") == ["0x0000000000001002"]
    assert session.run("s @i:-1") == ["0x0000000000000ffe"]
    assert session.seek == 0x1000


def test_tmpseek_block_instruction(session):
    assert session.run("s @B:1") == ["0x0000000000000ffe"]


def test_tmpseek_command_output_and_hexpairs(session):
    assert session.run("s @c:?e 0x00001234") == ["0x0000000000001234"]
    assert session.run("s @x:9090") == ["0x0000000000005555"]
    assert session.seek == 0x1000


def test_tmpseek_environment(session):
    session.env["GDAR_ADDR"] = "0x3999"
    assert session.run("s @%GDAR_ADDR") == ["0x0000000000003999"]
    assert session.seek == 0x1000


def test_tmpseek_temporary_config(session, capsys):
    assert session.config.get("hex.cols") == 16
    session.run("px 1 @e:hex.cols=8")
    assert session.config.get("hex.cols") == 16
    assert "hex.cols=8" not in capsys.readouterr().err


def test_tmpseek_temporary_flag_space(session):
    session.load_flags()
    session.flag_store.set_space("custom")
    session.run("f myflag 4 @ 0x5000")
    assert [flag.name for flag in session.flag_store.values()] == ["myflag"]
    session.run("f myflag 4 @ 0x5000")  # back in the default space now
    session.run_statement(_statement("f @F:custom"))
    assert [flag.name for flag in session.flag_store.values()] == ["myflag"]
    session.run_statement(_statement("f @F:*"))
    assert [flag.name for flag in session.flag_store.values()] == ["myflag"]


def test_tmpseek_unsupported_modifiers_are_explicit(session):
    for spec in ("a:x86", "r:PC", "k:some.key", "f:/etc/hosts"):
        with pytest.raises((UnsupportedError, UsageError)):
            session.run_statement(_statement(f"s @{spec}"))


# --- macros -----------------------------------------------------------------


def test_macro_define_call_list_delete(session):
    session.run("(hello; ?e world)")
    assert session.run(".(hello)") == ["world"]
    listed = session.run("(*")
    assert listed == ["(hello ; ?e world)"]
    assert session.run("(-hello)") == []
    assert session.run("(*") == []
    with pytest.raises(UsageError):
        session.run_statement(_statement(".(hello)"))


def test_macro_arguments_substitution(session):
    session.run("(sub2 a b; ?v $0-$1)")
    assert session.run(".(sub2 5 3)") == ["0x2"]
    with pytest.raises(UsageError):
        session.run_statement(_statement(".(sub2 1 2 3)"))


def test_macro_body_keeps_semicolons(session):
    session.run("(two; ?e one; ?e two)")
    assert session.run(".(two)") == ["one", "two"]


def test_macro_definition_is_not_split_by_semicolon(session):
    session.run("(three; ?e a; ?e b; ?e c)")
    assert session.macros["three"] == ((), ["?e a", "?e b", "?e c"])
    assert session.run(".(three)") == ["a", "b", "c"]


# --- .cmd / .!cmd -----------------------------------------------------------


def test_dot_command_interprets_output(session):
    session.run(".?e s 0x4444")
    assert session.seek == 0x4444


def test_dot_shell_interprets_output(session):
    session.run(".!echo s 0x5555")
    assert session.seek == 0x5555


def test_dot_extension_commands_still_work(session):
    lines = session.run(".g")
    assert lines and lines[0].startswith("instance_id:")
    with pytest.raises(UnsupportedError):
        session.run_statement(_statement(".gnope"))
