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


def test_filter_keeps_backslash_escapes_and_quoted_delimiters():
    statement = parser.parse_statement(r"iS*~\.text")
    assert statement.cmd == "iS*"
    assert statement.filter == r"\.text"

    statement = parser.parse_statement(r"pd 1~@{0x10 0x20}")
    assert statement.cmd == "pd"
    assert statement.filter == "@{0x10 0x20}"

    statement = parser.parse_statement(r"pd 1 | grep '~'")
    assert statement.pipe == "grep '~'"
    assert statement.filter is None


def test_escaped_redirection_is_not_a_redirect():
    statement = parser.parse_statement(r"?e a\>b")
    assert statement.redirect is None
    assert statement.cmd == "?e"


def test_leading_quote_makes_the_command_literal():
    statement = parser.parse_statement("'?e a~b@c")
    assert statement.literal is True
    assert statement.cmd == "?e"
    assert statement.args == "a~b@c"
    assert statement.filter is None
    assert statement.tmpseek is None

    statement = parser.parse_statement('"?e a|b>c')
    assert statement.literal is True
    assert statement.args == "a|b>c"
    assert statement.pipe is None
    assert statement.redirect is None
