from __future__ import annotations

import pytest

from gdare2 import filter as grep
from gdare2.errors import UsageError

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


def test_multi_and_negative_columns():
    assert grep.apply_spec(LINES, "[0,2]") == [
        "0x1000 EAX,",
        "0x1002 foo",
        "0x1004 RBP",
        "0x1005 bar",
    ]
    assert grep.apply_spec(LINES, "[-1]") == ["1", "foo", "RBP", "bar"]
    assert grep.apply_spec(LINES, "[0-1]") == [
        "0x1000 MOV",
        "0x1002 CALL",
        "0x1004 PUSH",
        "0x1005 CALL",
    ]
    assert grep.apply_spec(LINES, "[2-]") == ["EAX, 1", "foo", "RBP", "bar"]


def test_column_sorting():
    lines = ["b 3", "c 1", "a 2", "d 0"]
    assert grep.apply_spec(lines, "$") == ["a 2", "b 3", "c 1", "d 0"]
    assert grep.apply_spec(lines, "$!") == ["d 0", "c 1", "b 3", "a 2"]
    assert grep.apply_spec(lines, "$!!") == ["d 0", "a 2", "c 1", "b 3"]
    assert grep.apply_spec(lines, "$:1") == ["d 0", "c 1", "a 2", "b 3"]
    assert grep.apply_spec(lines, "$:1!") == ["b 3", "a 2", "c 1", "d 0"]
    assert grep.apply_spec(lines, "$:-1") == ["d 0", "c 1", "a 2", "b 3"]


def test_negative_line_ranges():
    lines = ["a", "b", "c", "d"]
    assert grep.apply_spec(lines, ":0") == ["a"]
    assert grep.apply_spec(lines, ":1-") == ["b", "c", "d"]
    assert grep.apply_spec(lines, ":0-1") == ["a"]
    assert grep.apply_spec(lines, ":-1") == ["d"]
    assert grep.apply_spec(lines, ":-2") == ["c"]


def test_json_pretty_and_invalid_json():
    lines = ['{"a":1,"b":[2,3]}']
    assert grep.apply_spec(lines, "{") == lines
    pretty = grep.apply_spec(lines, "{}")
    assert pretty == [
        "{",
        '  "a": 1,',
        '  "b": [',
        "    2,",
        "    3",
        "  ]",
        "}",
    ]
    assert grep.apply_spec(lines, "{}:0") == ["{"]
    with pytest.raises(UsageError):
        grep.apply_spec(["not json"], "{}")
    with pytest.raises(UsageError):
        grep.apply_spec(lines, "{:2")


def test_unsupported_filter_formats_fail_loudly():
    for spec in ("?ea", "<>", ":}", ":)", ":))"):
        with pytest.raises(UsageError):
            grep.apply_spec(LINES, spec)


def test_bad_column_selector():
    with pytest.raises(UsageError):
        grep.apply_spec(LINES, "[a]")
