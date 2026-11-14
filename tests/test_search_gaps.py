"""V12: remaining ``/`` search commands (backward, file, explicit rejects)."""

from __future__ import annotations

import json

import pytest
from test_session import make_session

from gdare2 import parser
from gdare2.cmd.search import DEFAULT_LIMIT
from gdare2.errors import UnsupportedError

COMMON_ARGS = (
    "data",
    "mask",
    "scope",
    "from_addr",
    "to_addr",
    "limit",
    "offset",
    "ignore_case",
    "delta",
)


def test_search_backward_is_forward_dual():
    session, client = make_session()
    session.run("s 0x2000")
    assert session.run("/b 9090") == ["0x0000000000001000", "0x0000000000001004"]
    assert client.calls[-1][0] == "search"
    backward = client.calls[-1][1]
    assert backward["forward"] is False
    assert backward["cursor"] == 0x2000
    assert backward["data"] == b"\x90\x90"
    assert session.seek == 0x1000

    session.run("/x 9090")
    forward = client.calls[-1][1]
    assert forward["forward"] is True
    assert {key: backward[key] for key in COMMON_ARGS} == {
        key: forward[key] for key in COMMON_ARGS
    }


def test_search_backward_mask_json_and_raw_scope():
    session, client = make_session()
    session.run("s 0x2000")
    payload = json.loads("\n".join(session.run("/bj 90?f")))
    assert payload["hits"] == [0x1000, 0x1004]
    args = client.calls[-1][1]
    assert args["data"] == b"\x90\x0f"
    assert args["mask"] == b"\xff\x0f"
    assert args["forward"] is False

    session.config.set("search.in", "raw")
    session.run("s 0x24")
    session.run("/b 9090")
    assert client.calls[-1][0] == "search_raw"
    assert client.calls[-1][1]["forward"] is False
    assert client.calls[-1][1]["cursor"] == 0x24


def test_search_backward_then_repeat_backward():
    session, client = make_session()
    session.run("s 0x2000")
    session.run("/b 9090")
    session.run("/-")
    args = client.calls[-1][1]
    assert args["forward"] is False
    assert args["cursor"] == 0x0FFF


def test_search_backward_requires_hexpairs():
    session, _ = make_session()
    session.run("/b")
    assert session.failed and "hexpairs" in str(session.last_error)
    session.failed = False
    session.run("/b zz")
    assert session.failed and "hex digit" in str(session.last_error)


def test_search_file_contents(tmp_path):
    source = tmp_path / "needle.bin"
    source.write_bytes(b"AAAneedleBB")
    session, client = make_session()
    assert session.run(f"/F {source}") == ["0x0000000000001000", "0x0000000000001004"]
    assert client.calls[-1][0] == "search"
    assert client.calls[-1][1]["data"] == b"AAAneedleBB"
    session.run(f"/F {source} 3 6")
    assert client.calls[-1][1]["data"] == b"needle"
    session.run(f"/F {source} 3")
    assert client.calls[-1][1]["data"] == b"needleBB"


def test_search_file_json_and_errors(tmp_path):
    source = tmp_path / "needle.bin"
    source.write_bytes(b"needle")
    session, _ = make_session()
    assert json.loads("\n".join(session.run(f"/Fj {source}")))["hits"] == [0x1000, 0x1004]

    session.run("/F")
    assert session.failed and "needs a file path" in str(session.last_error)
    session.failed = False
    session.run(f"/F {tmp_path / 'missing.bin'}")
    assert session.failed and "cannot read" in str(session.last_error)
    session.failed = False
    session.run(f"/F {source} x 4")
    assert session.failed and "must be numeric" in str(session.last_error)
    session.failed = False
    session.run(f"/F {source} -1")
    assert session.failed and "must not be negative" in str(session.last_error)


@pytest.mark.parametrize(
    ("command_line", "needle"),
    [
        ("/e", "regex byte search"),
        ("/E", "wildcard mask"),
        ("/f", "forward-search modifier"),
        ("/g", "gadget"),
        ("/gR", "gadget"),
        ("/gC", "gadget"),
        ("/h", "digest"),
        ("/o", "instruction-offset"),
        ("/O", "instruction-offset"),
        ("/P", "similar-block"),
        ("/s", "entropy"),
        ("/sj", "entropy"),
        ("/V", "value-in-range"),
        ("/V4", "value-in-range"),
        ("/!", "inverse search"),
    ],
)
def test_unsupported_search_commands(command_line, needle):
    session, client = make_session()
    with pytest.raises(UnsupportedError) as excinfo:
        session.run_statement(parser.parse_statement(command_line))
    assert needle in str(excinfo.value)
    assert client.calls == []


def test_search_maxhits_caps_results():
    session, client = make_session()
    session.config.set("search.maxhits", 1)
    session.run("/j hello")
    assert client.calls[-1][1]["limit"] == 1
    session.config.set("search.maxhits", 0)
    session.run("/j hello")
    assert client.calls[-1][1]["limit"] == DEFAULT_LIMIT
