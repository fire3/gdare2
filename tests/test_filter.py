from __future__ import annotations

from gdare2 import filter as grep


LINES = [
    "0x1000  MOV EAX, 1",
    "0x1002  CALL foo",
    "0x1004  PUSH RBP",
    "0x1005  CALL bar",
]


def test_substring_grep():
    assert grep.apply_spec(LINES, "CALL") == [LINES[1], LINES[3]]


def test_ignore_case():
    assert grep.apply_spec(LINES, "+call") == [LINES[1], LINES[3]]


def test_negate():
    assert grep.apply_spec(LINES, "!CALL") == [LINES[0], LINES[2]]


def test_line_range():
    assert grep.apply_spec(LINES, ":0") == [LINES[0]]
    assert grep.apply_spec(LINES, ":1-3") == LINES[1:3]


def test_column():
    assert grep.apply_spec(LINES, "CALL[1]") == ["CALL", "CALL"]


def test_count():
    assert grep.apply_spec(LINES, "?CALL") == ["2"]
