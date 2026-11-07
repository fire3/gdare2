from __future__ import annotations

from gdare2 import parser


def test_semicolons_and_quotes():
    statements = parser.parse("?e one; ?e 'two;three'")
    assert [statement.cmd for statement in statements] == ["?e", "?e"]


def test_filter_and_tmpseek():
    statement = parser.parse_statement("pd 5 @ main~call")
    assert statement.cmd == "pd"
    assert statement.args == "5"
    assert statement.tmpseek == "main"
    assert statement.filter == "call"


def test_redirect_and_pipe():
    statement = parser.parse_statement("pd 3 | head -1 > /tmp/out")
    assert statement.cmd == "pd"
    assert statement.pipe == "head -1"
    assert statement.redirect == "/tmp/out"
    assert statement.append is False


def test_bare_number_means_seek():
    statement = parser.parse_statement("0x1000")
    assert statement.cmd == "s"
    assert statement.args == "0x1000"


def test_command_help_marker():
    statement = parser.parse_statement("pd?")
    assert statement.cmd == "pd"
    assert statement.help is True


def test_repeat_prefix():
    statement = parser.parse_statement("3pd 1")
    assert statement.repeat == 3
    assert statement.cmd == "pd"
