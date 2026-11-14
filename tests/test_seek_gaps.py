"""Seek gaps (V11): sa, sC, sd and the explicit sr/ss rejections."""

from __future__ import annotations

from test_session import FakeClient, make_session

from gdare2.errors import NotFoundError, UnsupportedError, UsageError


def test_sa_aligns_the_seek_down_to_the_block_size():
    session, _ = make_session()
    session.seek = 0x1234
    assert session.run("sa") == []
    assert session.seek == 0x1200
    session.run("s 0x13ff")
    assert session.run("sa") == []
    assert session.seek == 0x1300
    assert session.run("sa 0x12ff") == []
    assert session.seek == 0x1200


def test_sC_seeks_to_the_first_matching_comment():
    class CommentClient(FakeClient):
        def call(self, op, **args):
            if op == "comments":
                self.calls.append((op, args))
                return [
                    {"addr": 0x1000, "kind": "eol", "text": "setup code"},
                    {"addr": 0x2000, "kind": "plate", "text": "LOOP start"},
                ]
            return super().call(op, **args)

    session, client = make_session(CommentClient())
    assert session.run("sC loop") == []
    assert session.seek == 0x2000
    assert client.calls[-1][0] == "comments"
    assert client.calls[-1][1]["include_all"] is False
    session.run("sC SETUP")
    assert session.seek == 0x1000
    session.run("sC missing-text")
    assert session.failed and isinstance(session.last_error, NotFoundError)
    session.failed = False
    session.run("sC")
    assert session.failed and isinstance(session.last_error, UsageError)


def test_sC_honors_the_comments_all_config():
    class CommentClient(FakeClient):
        def call(self, op, **args):
            if op == "comments":
                self.calls.append((op, args))
                return [{"addr": 0x1000, "kind": "eol", "text": "note"}]
            return super().call(op, **args)

    session, client = make_session(CommentClient())
    session.config.set("ghidra.comments.all", "true")
    session.run("sC note")
    assert client.calls[-1][1]["include_all"] is True


def test_sd_shows_the_delta_from_the_image_base():
    session, _ = make_session()
    assert session.run("sd") == ["0x0000000000000000"]
    session.run("s 0x2040")
    assert session.run("sd") == ["0x0000000000001040"]
    session.run("s 0x800")
    assert session.run("sd") == ["-0x800"]
    assert session.run("sd 0x3000") == ["0x0000000000002000"]


def test_sr_and_ss_are_explicit_unsupported():
    session, _ = make_session()
    session.run("sr PC")
    assert session.failed and isinstance(session.last_error, UnsupportedError)
    assert "unknown or unsupported command" not in str(session.last_error)
    assert "@s:" in str(session.last_error)
    session.failed = False
    session.run("ss")
    assert session.failed and isinstance(session.last_error, UnsupportedError)
    assert "unknown or unsupported command" not in str(session.last_error)
