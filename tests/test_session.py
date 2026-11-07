from __future__ import annotations

import json

from gdare2.config import Config
from gdare2.session import Session


class FakeClient:
    def __init__(self) -> None:
        self.calls = []

    def call(self, op, **args):
        self.calls.append((op, args))
        if op == "info":
            return {"program": "demo", "arch": "x86", "bits": 64, "language": "x86:LE:64:default"}
        if op == "disasm":
            return [
                {"addr": args["ea"], "size": 2, "bytes": b"\x90\x90", "text": "NOP"},
                {"addr": args["ea"] + 2, "size": 2, "bytes": b"\xc3\x90", "text": "RET"},
            ]
        if op == "read_bytes":
            return b"ABCD"
        if op == "resolve_name":
            return {"main": 0x2000}.get(args["name"])
        if op == "functions":
            return [{"addr": 0x1000, "name": "main", "size": 10, "end": 0x100A}]
        raise AssertionError(op)


def make_session() -> tuple[Session, FakeClient]:
    client = FakeClient()
    info = {
        "program": "demo",
        "arch": "x86",
        "bits": 64,
        "language": "x86:LE:64:default",
        "image_base": 0x1000,
        "entry": 0x1000,
        "filesize": 4,
    }
    return Session(client, info, Config()), client


def test_seek_and_format():
    session, _ = make_session()
    assert session.run("s 0x2000") == []
    assert session.seek == 0x2000
    assert session.run("s") == ["0x0000000000002000"]


def test_seek_by_symbol():
    session, _ = make_session()
    session.run("s main")
    assert session.seek == 0x2000


def test_pd_and_filter():
    session, _ = make_session()
    lines = session.run("pd 2~RET")
    assert len(lines) == 1
    assert "RET" in lines[0]


def test_px_uses_block_size():
    session, client = make_session()
    lines = session.run("px 4")
    assert "41 42 43 44" in lines[-1]
    assert ("read_bytes", {"allow_writes": False, "ea": 0x1000, "size": 4}) in client.calls


def test_redirect(tmp_path):
    session, _ = make_session()
    target = tmp_path / "out.txt"
    assert session.run(f"pd 2 > {target}") == []
    assert "NOP" in target.read_text()


def test_json_default_for_info():
    session, _ = make_session()
    session.json_default = True
    payload = json.loads("\n".join(session.run("iI")))
    assert payload["program"] == "demo"


def test_temporary_seek_is_restored():
    session, _ = make_session()
    session.run("s 0x1000")
    session.run("pd 1 @ 0x2000")
    assert session.seek == 0x1000
