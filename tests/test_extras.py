"""Yank, environment, pointer, compare, text log and session projects."""

from __future__ import annotations

import json
import os

from test_session import FakeClient, make_session

from gdare2 import cmd as cmd_module  # noqa: F401  (loads command modules lazily)
from gdare2.errors import UsageError


def test_yank_and_paste_variants(tmp_path):
    session, client = make_session()
    assert session.run("y 4") == ["-- yanked 4 byte(s) --"]
    assert session.yank == b"ABCD"

    session.readonly = False
    assert session.run("yy") == ["-- pasted 4 byte(s) --"]
    assert (
        "write_bytes",
        {"allow_writes": True, "ea": 0x1000, "data": b"ABCD"},
    ) in client.calls

    assert session.run("yx 41 42") == []
    assert session.yank == b"AB"
    assert session.run("yt hello") == []
    assert session.yank == b"hello"
    source = tmp_path / "source.bin"
    source.write_bytes(b"\x90\x90")
    assert session.run(f"yf {source}") == []
    assert session.yank == b"\x90\x90"
    assert session.run("y-") == []
    assert session.yank == b""
    session.run("yy")
    assert session.failed and "nothing yanked" in str(session.last_error)


def test_yank_requires_writes_for_paste():
    session, _ = make_session()
    session.run("yx 4142")
    session.run("yy")
    assert session.failed
    assert isinstance(session.last_error, Exception)
    assert "read-only" in str(session.last_error)


def test_environment_commands():
    session, _ = make_session()
    assert session.run("%FOO=bar") == []
    assert session.run("%FOO") == ["bar"]
    assert "FOO=bar" in session.run("%")
    assert "%FOO=bar" in session.run("%*")
    assert json.loads(session.run("%j")[0])["FOO"] == "bar"
    session.run("%MISSING")
    assert session.failed and "no environment variable" in str(session.last_error)
    assert os.environ  # env is seeded for r2 compatibility


def test_pointer_read_and_write():
    session, client = make_session()
    assert session.run("*0x1000") == ["0x44434241"]
    session.readonly = False
    assert session.run("*0x1000=0x1234") == []
    assert (
        "write_bytes",
        {
            "allow_writes": True,
            "ea": 0x1000,
            "data": b"\x34\x12\x00\x00\x00\x00\x00\x00",
        },
    ) in client.calls
    session.run("*")
    assert session.failed and "needs an address" in str(session.last_error)


def test_compare_commands():
    class CompareClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes":
                self.calls.append((op, args))
                return b"ABCD" if args["ea"] == 0x1000 else b"AXCD"
            return super().call(op, **args)

    session, _ = make_session(CompareClient())
    assert session.run("c 0x1000 0x2000 4") == [
        "0x0000000000001001 0x42 != 0x58"
    ]
    assert session.run("c1 0x1000 0x2000 4") == [
        "0x0000000000001001 0x42 != 0x58"
    ]
    session.run("c 0x1000")
    assert session.failed and "two addresses and a length" in str(session.last_error)


def test_text_log_variants():
    session, _ = make_session()
    session.run("T first message")
    session.run("T second message")
    assert session.run("T") == ["1 first message", "2 second message"]
    assert session.run("Tl") == ["2"]
    assert [item["message"] for item in json.loads(session.run("Tj")[0])] == [
        "first message",
        "second message",
    ]
    assert session.run("Tm 2") == ["second message"]
    assert session.run("T*") == ["T first message", "T second message"]
    assert session.run("T- 2") == []
    assert session.run("T") == ["2 second message"]
    assert session.run("T-") == []
    assert session.run("T") == []
    assert session.run("Tl") == ["0"]


def test_session_projects_round_trip(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    session, _ = make_session()
    session.run("f localflag 4 @ 0x3000")
    session.vars["answer"] = 42
    session.config.set("scr.color", 3)
    assert session.run("Ps demo")[0].startswith("-- saved ")
    listing = session.run("P")
    assert any("demo.gdare2-prj" in path for path in listing)
    assert json.loads(session.run("Pj")[0])["vars"]["answer"] == 42

    session.seek_to(0x2000)
    session.config.set("scr.color", 0)
    session.vars.clear()
    assert session.run("Po demo")[0].startswith("-- loaded ")
    assert session.seek == 0x1000
    assert session.config.get_int("scr.color") == 3
    assert session.vars["answer"] == 42
    assert session.flag_store.get("localflag") is not None

    assert session.run("P- demo") == []
    assert session.run("P") == []
    session.run("Po demo")
    assert session.failed and "no such project" in str(session.last_error)


def test_dt_is_an_explicit_error():
    session, _ = make_session()
    session.run("dt")
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "tp/tpv/tpx" in str(session.last_error)
