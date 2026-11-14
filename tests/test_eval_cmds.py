from __future__ import annotations

import json

import pytest
from test_session import make_session


@pytest.fixture
def session():
    session, _client = make_session()
    return session


def test_question_evaluates_and_sets_last_result(session):
    lines = session.run("? 5+5")
    assert lines == ["10"]
    assert session.last_result == 10


def test_question_without_args_lists_help(session):
    lines = session.run("?")
    assert lines and lines[0].startswith("Usage:")


def test_question_value_formats(session):
    assert session.run("?v 5+5") == ["0xa"]
    assert session.run("?vx 0x1234") == ["0x00001234"]
    assert session.run("?X 0x1234") == ["1234"]
    assert session.run("?vi 300") == ["300"]
    assert session.run("?vi1 300") == ["44"]
    assert session.run("?vi2 70000") == ["4464"]
    assert session.run("?vi8 -5") == ["-5"]
    assert session.last_result == -5


def test_question_string_conversions(session):
    assert session.run("?x hello") == ["68656c6c6f"]
    assert session.run("?x-4142") == ["AB"]
    assert session.run("?x+0x4142") == ["4241"]
    assert session.run("?b 10") == ["1010b"]
    assert session.run("?o 10") == ["012"]
    assert session.run("?u 1234567") == ["1.2M"]
    assert session.run("?u 1073741824") == ["1G"]
    assert session.run("?u 0") == ["0"]
    assert session.run("?l hello") == ["5"]
    assert session.run("?lq hello") == []
    assert session.last_result == 5


def test_question_echo_and_sequence(session):
    assert session.run("?e hi there") == ["hi there"]
    assert session.run("?s 1 5 2") == ["1 3 5"]
    assert session.run("?s 5 1") == [""]
    from gdare2 import parser
    from gdare2.errors import UsageError

    with pytest.raises(UsageError):
        session.run_statement(parser.parse_statement("?s 1"))


def test_question_quiet_and_control(session):
    assert session.run("?q 42") == ["42"]
    assert session.last_result == 42
    assert session.run("?= 7") == []
    assert session.last_result == 7
    assert session.run("?== abc abc") == []
    assert session.last_result == 0
    assert session.run("?== abc abd") == []
    assert session.last_result == 1
    assert session.run("?btw 1 2 3") == ["1"]
    assert session.run("?btw 2 1 3") == ["0"]


def test_question_conditional_runs(session):
    session.last_result = 0
    assert session.run("?eq ?e yes") == ["yes"]
    assert session.run("?ne ?e no") == []
    session.last_result = 1
    assert session.run("?eq ?e yes") == []
    assert session.run("?ne ?e no") == ["no"]
    assert session.run("?ge ?e over") == ["over"]
    assert session.run("?le ?e under") == []


def test_question_json(session):
    payload = json.loads("\n".join(session.run("?j 10")))
    assert payload["int32"] == "10"
    assert payload["hex"].startswith("0x")
    assert payload["binary"].startswith("0b")


def test_question_base64_and_ascii(session):
    import base64

    encoded = session.run("?b64 hello")[0]
    assert base64.b64decode(encoded) == b"hello"
    assert session.run("?b64- aGVsbG8=") == ["hello"]
    assert session.run("?a")[0].startswith("  ")


def test_question_random_in_range(session):
    value = int(session.run("?r 1 10")[0], 16)
    assert 1 <= value <= 10


def test_repeat_prefix_runs_command_n_times():
    session, _client = make_session()
    assert session.run("3?e repeat") == ["repeat", "repeat", "repeat"]
