"""Yank, environment, pointer, compare, text log and session projects."""

from __future__ import annotations

import json
import os

from test_session import FakeClient, make_session

from gdare2 import cmd as cmd_module  # noqa: F401  (loads command modules lazily)
from gdare2.errors import UnsupportedError, UsageError


class DiffClient(FakeClient):
    """Serves different blocks at 0x1000 and 0x2000 so compares produce diffs."""

    def call(self, op, **args):
        if op == "read_bytes":
            self.calls.append((op, args))
            return b"ABCD" if args["ea"] == 0x1000 else b"AXCD"
        return super().call(op, **args)


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


def test_yank_json_and_replay_variants():
    session, _ = make_session()
    session.run("y 4")
    assert json.loads(session.run("yj")[0]) == {"length": 4, "bytes": "41424344"}
    replay = session.run("y*")
    assert replay == ["yx 41424344"]
    fresh, _ = make_session()
    assert fresh.run(replay[0]) == []
    assert fresh.yank == session.yank
    session.run("y-")
    assert json.loads(session.run("yj")[0]) == {"length": 0, "bytes": ""}
    assert session.run("y*") == []


def test_yank_paste_print_variants():
    session, client = make_session()
    session.run("yx 4142")
    session.readonly = False
    assert session.run("yp") == ["4142"]
    assert ("write_bytes", {"allow_writes": True, "ea": 0x1000, "data": b"AB"}) in client.calls
    assert session.run("yq") == []
    assert client.calls[-1] == ("write_bytes", {"allow_writes": True, "ea": 0x1000, "data": b"AB"})


def test_yank_paste_variants_require_writes():
    session, _ = make_session()
    session.run("yx 4142")
    session.run("yp")
    assert session.failed and "read-only" in str(session.last_error)
    session.failed = False
    session.run("yq")
    assert session.failed and "read-only" in str(session.last_error)


def test_yank_string_variants():
    class TextClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes":
                self.calls.append((op, args))
                return b"hello\x00world"[: args["size"]]
            return super().call(op, **args)

    session, _ = make_session(TextClient())
    assert session.run("ys 4") == ["-- yanked 4 byte(s) --"]
    assert session.yank == b"hell"
    assert session.run("ys") == ["-- yanked 5 byte(s) --"]
    assert session.yank == b"hello"
    assert session.run("yz 6") == ["-- yanked 6 byte(s) including the terminator --"]
    assert session.yank == b"hello\x00"
    session.run("yz 0")
    assert session.failed and "positive" in str(session.last_error)


def test_yank_wide_string_variants():
    class WideClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes":
                self.calls.append((op, args))
                return b"h\x00i\x00\x00\x00"[: args["size"]]
            return super().call(op, **args)

    session, _ = make_session(WideClient())
    assert session.run("yw 6") == ["-- yanked 4 byte(s) --"]
    assert session.yank == b"h\x00i\x00"
    session.run("yw 5")
    assert session.yank == b"h\x00i\x00"  # odd trailing byte is dropped


def test_yank_wide_string_is_endian_aware():
    class RawClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes":
                self.calls.append((op, args))
                return b"\x00\xd8\x00h"[: args["size"]]
            return super().call(op, **args)

    session, _ = make_session(RawClient())
    session.info["endian"] = "big"
    # Big-endian decodes 0x00d8 as U+00D8, while little-endian would hit an
    # unpaired surrogate and replace it, so this pins the codec choice.
    assert session.run("yw 4") == ["-- yanked 4 byte(s) --"]
    assert session.yank == b"\x00\xd8\x00h"


def test_yank_clipboard_is_explicitly_unsupported():
    session, _ = make_session()
    session.run("y!")
    assert session.failed
    assert isinstance(session.last_error, UnsupportedError)
    assert "clipboard" in str(session.last_error)


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


def test_compare_word_variants():
    session, _ = make_session(DiffClient())
    assert session.run("c2 0x1000 0x2000 4") == ["0x0000000000001000 0x4241 != 0x5841"]
    assert session.run("c4 0x1000 0x2000 4") == [
        "0x0000000000001000 0x44434241 != 0x44435841"
    ]
    assert session.run("c8 0x1000 0x2000 4") == []  # shorter than one word
    session.info["endian"] = "big"
    assert session.run("c2 0x1000 0x2000 2") == ["0x0000000000001000 0x4142 != 0x4158"]
    session.failed = False
    session.run("c2 0x1000")
    assert session.failed and "two addresses and a length" in str(session.last_error)


def test_compare_json_and_verbose():
    session, _ = make_session(DiffClient())
    payload = json.loads(session.run("cJ 0x1000 0x2000 4")[0])
    assert payload == {
        "same": False,
        "differences": [{"addr": 0x1001, "from": 0x42, "to": 0x58}],
    }
    assert json.loads(session.run("cJ 0x1000 0x1000 4")[0]) == {
        "same": True,
        "differences": [],
    }
    assert session.run("cv 0x1000 0x2000 4") == ["0x0000000000001001 (0x42 != 0x58) B X"]


def test_compare_unsupported_variants():
    session, _ = make_session()
    for token in ("ca", "cd", "cf", "cX", "cV"):
        session.failed = False
        session.run(token)
        assert session.failed, token
        assert isinstance(session.last_error, UnsupportedError), token
        assert session.last_error.code == "NOT_SUPPORTED"


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
