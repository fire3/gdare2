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
        if op == "read_value":
            return {"addr": args["ea"], "width": args.get("width", 4), "value": 0x44434241}
        if op == "disasm_bytes":
            return [
                {"addr": args["ea"], "size": 2, "bytes": b"\x90\x90", "text": "NOP"},
                {"addr": args["ea"] + 2, "size": 1, "bytes": b"\xc3", "text": "RET"},
            ]
        if op == "resolve_name":
            return {"main": 0x2000}.get(args["name"])
        if op == "functions":
            return [{"addr": 0x1000, "name": "main", "size": 10, "end": 0x100A}]
        if op == "function_callers":
            return [{"addr": 0x3000, "name": "caller", "size": 5, "end": 0x3005}]
        if op == "function_callees":
            return [{"addr": 0x4000, "name": "callee", "size": 5, "end": 0x4005}]
        if op == "function_rename":
            return {"addr": args["ea"], "name": args["name"], "size": 10, "end": 0x100A}
        if op == "function_resize":
            return {
                "addr": args["ea"],
                "name": "main",
                "size": args["end"] - args["ea"] + 1,
                "end": args["end"],
            }
        if op == "function_xrefs":
            return [{"from": 0x1000, "to": 0x4000, "type": "CALL"}]
        if op == "hashes":
            return {"md5": "abc", "sha256": "def", "path": "/demo", "format": "ELF"}
        if op == "block_at":
            return {"name": ".text", "addr": 0x1000, "end": 0x1FFF, "size": 0x1000, "perms": "r-x"}
        if op == "basic_block":
            return {"start": 0x1000, "end": 0x1005, "successors": [0x1010]}
        if op == "instruction_info":
            return {
                "addr": args["ea"],
                "size": 2,
                "bytes": b"\x90\x90",
                "text": "NOP",
                "flow": "FALL_THROUGH",
                "references": [],
            }
        if op == "address_info":
            return {
                "addr": args["ea"],
                "mapped": True,
                "block": {"name": ".text", "addr": 0x1000, "end": 0x1FFF},
                "function": {"name": "main", "addr": 0x1000},
                "instruction": {"text": "NOP"},
            }
        if op == "graph":
            return {
                "addr": 0x1000,
                "name": "main",
                "blocks": [
                    {
                        "addr": 0x1000,
                        "start": 0x1000,
                        "end": 0x1005,
                        "ninstr": 1,
                        "successors": [0x1010],
                        "ops": [
                            {
                                "addr": 0x1000,
                                "size": 2,
                                "bytes": b"\x90\x90",
                                "text": "NOP",
                            }
                        ],
                    },
                    {
                        "addr": 0x1010,
                        "start": 0x1010,
                        "end": 0x1011,
                        "ninstr": 0,
                        "successors": [],
                        "ops": [],
                    },
                ],
                "edges": [{"src": 0x1000, "dst": 0x1010, "type": "jump"}],
            }
        if op == "iter_targets":
            return [
                {"addr": 0x1000, "size": 10, "name": "main"},
                {"addr": 0x2000, "size": 20, "name": "helper"},
            ]
        if op == "batch":
            return [self._batch_item(spec) for spec in args["ops"]]
        if op == "save":
            return {"saved": True}
        if op == "analyze_bytes":
            return {
                "addr": args["ea"],
                "size": 3,
                "bytes": b"\x90\x90\xc3",
                "instruction": {"text": "NOP"},
            }
        if op == "analyze_data":
            return {
                "addr": args["ea"],
                "count": args["count"],
                "word_size": 8,
                "size": args["count"] * 8,
                "type": "qword",
            }
        if op == "decompile":
            return {
                "addr": args["ea"],
                "name": "main",
                "c": "int main(void)\n{\n  return 0;\n}",
                "signature": "int main(void)",
            }
        if op == "function_variables":
            return {
                "addr": args["ea"],
                "name": "main",
                "variable_count": 1,
                "parameter_count": 0,
                "variables": [
                    {
                        "name": "local_8",
                        "type": "int",
                        "storage": "Stack[-0x8]",
                        "kind": "sp",
                        "parameter": False,
                    }
                ],
            }
        raise AssertionError(op)

    def _batch_item(self, spec):
        op = spec["op"]
        args = spec["args"]
        if op == "disasm":
            return {
                "ok": True,
                "result": [
                    {
                        "addr": args["ea"],
                        "size": 2,
                        "bytes": b"\x90\x90",
                        "text": "NOP",
                    }
                ],
            }
        if op == "read_bytes":
            return {"ok": True, "result": b"A" * int(args["size"])}
        return {"ok": False, "error": {"code": "BAD_ARGS", "message": f"no fake {op}"}}


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


def test_pdi_pi_pdl_and_pd_bytes():
    session, _ = make_session()
    assert "NOP" in session.run("pdi 1")[0]
    assert session.run("pi 2") == ["NOP", "RET"]
    assert session.run("pdl 1")[0].endswith("NOP")
    assert len(session.run("pD 3")) == 2


def test_words_and_json_variants():
    session, _ = make_session()
    assert "1145258561" in session.run("pvj4")[0]
    assert session.run("p8j 4")[0].startswith("{")
    assert len(session.run("pxw 4")) == 1


def test_info_hashes_and_calls():
    session, _ = make_session()
    assert "md5" in session.run("it")[0]
    assert "caller" in session.run("afc @ main")[0]
    assert "callee" in session.run("afC @ main")[0]
    assert "CALL" in session.run("afx @ main")[0]


def test_iterator_uses_one_batch_request():
    session, client = make_session()
    lines = session.run("pd 1 @@f")
    assert len(lines) == 2
    assert "0x0000000000001000" in lines[0]
    assert "0x0000000000002000" in lines[1]
    daemon_calls = [op for op, _ in client.calls if op != "resolve_name"]
    assert daemon_calls == ["iter_targets", "batch"]
    assert [item["args"]["ea"] for item in client.calls[-1][1]["ops"]] == [0x1000, 0x2000]


def test_explicit_iterator_skips_target_lookup():
    session, client = make_session()
    session.run("pd 1 @@=0x1000,0x3000")
    daemon_calls = [op for op, _ in client.calls]
    assert daemon_calls == ["batch"]
    assert [item["args"]["ea"] for item in client.calls[-1][1]["ops"]] == [0x1000, 0x3000]


def test_sized_iterator_sets_per_target_blocksize():
    session, client = make_session()
    session.run("px @@@f")
    assert [op for op, _ in client.calls] == ["iter_targets", "batch"]
    operations = client.calls[-1][1]["ops"]
    assert [item["args"]["size"] for item in operations] == [10, 20]


def test_graph_and_address_commands():
    session, _ = make_session()
    assert "main" in session.run("agf")[0]
    assert "0x0000000000001010" in "\n".join(session.run("agf"))
    dot = "\n".join(session.run("agfd"))
    assert dot.startswith('digraph "main"')
    assert '"0x1000" -> "0x1010"' in dot
    assert json.loads("\n".join(session.run("agfj")))["blocks"]
    assert "0x0000000000001000" in session.run("ab @ main")[0]
    assert "FALL_THROUGH" in "\n".join(session.run("ao @ main"))
    assert "func:" in "\n".join(session.run("ai @ main"))


def test_function_helpers():
    session, _ = make_session()
    assert session.run("afln") == ["main"]
    assert session.run("afl+") == ["10"]
    session.json_default = True
    assert json.loads("\n".join(session.run("agf")))["name"] == "main"


def test_function_write_commands():
    session, client = make_session()
    renamed = session.run("s main; afn renamed")[0]
    assert renamed.endswith("renamed")
    resized = session.run("s main; afu 0x1010")[0]
    assert "0x0000000000001010" in resized
    assert [
        op for op, _ in client.calls if op in ("function_rename", "function_resize")
    ] == ["function_rename", "function_resize"]


def test_dot_commands_reach_registry():
    session, client = make_session()
    assert "program: demo" in session.run(".g")
    session.readonly = False
    assert session.run(".gsave") == []
    assert ("save", {"allow_writes": True}) in client.calls


def test_manual_analysis_commands():
    session, client = make_session()
    assert "9090c3 NOP" in session.run("a8 90 90 c3")[0]
    assert "2x8 qword" in session.run("ad 2")[0]
    assert [op for op, _ in client.calls] == ["analyze_bytes", "analyze_data"]


def test_decompile_and_variables():
    session, _ = make_session()
    assert session.run("pdc @ main")[-1] == "}"
    variables = "\n".join(session.run("afv @ main"))
    assert "vars: 1" in variables
    assert "local_8" in variables
    session.json_default = True
    assert json.loads("\n".join(session.run("pdc @ main")))["signature"] == "int main(void)"
