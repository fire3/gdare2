from __future__ import annotations

import json

import pytest

from gdare2 import cmd as cmd_module
from gdare2 import registry
from gdare2.cmd import CommandSpec, register
from gdare2.config import Config
from gdare2.session import Session


class FakeClient:
    def __init__(self) -> None:
        self.calls = []

    def call(self, op, **args):
        self.calls.append((op, args))
        if op == "info":
            return {
                "program": "demo",
                "target": "/bin/fake",
                "arch": "x86",
                "bits": 64,
                "language": "x86:LE:64:default",
                "instance_id": "demo-id",
                "state": "ready",
            }
        if op == "analyze":
            return {"state": "unchanged"}
        if op == "disasm":
            return [
                {
                    "addr": args["ea"],
                    "size": 2,
                    "bytes": b"\x90\x90",
                    "text": "NOP",
                    "mnemonic": "NOP",
                    "symbol": "main",
                },
                {
                    "addr": args["ea"] + 2,
                    "size": 2,
                    "bytes": b"\xc3\x90",
                    "text": "RET",
                    "mnemonic": "RET",
                },
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
        if op == "symbols":
            items = [
                {
                    "addr": 0x1000,
                    "name": "entry",
                    "type": "LABEL",
                    "external": False,
                    "global": True,
                },
                {
                    "addr": 0x2000,
                    "name": "helper",
                    "type": "LABEL",
                    "external": False,
                    "global": True,
                },
            ]
            offset = int(args.get("offset", 0))
            limit = int(args.get("limit", len(items)))
            return items[offset : offset + limit]
        if op == "symbol_create":
            return {
                "addr": args["ea"],
                "name": args["name"],
                "type": "LABEL",
                "external": False,
                "global": True,
            }
        if op == "symbol_rename":
            return {
                "addr": 0x2000,
                "name": args["new_name"],
                "type": "LABEL",
                "external": False,
                "global": True,
            }
        if op == "symbol_delete":
            return {
                "addr": 0x2000,
                "name": args.get("name") or "helper",
                "type": "LABEL",
                "external": False,
                "global": True,
            }
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
        if op == "sections":
            return [
                {"addr": 0x1000, "size": 0x1000, "name": ".text", "perms": "r-x"},
                {"addr": 0x3000, "size": 0x200, "name": ".data", "perms": "rw-"},
            ]
        if op == "block_at":
            return {"name": ".text", "addr": 0x1000, "end": 0x1FFF, "size": 0x1000, "perms": "r-x"}
        if op == "basic_block":
            return {"start": 0x1000, "end": 0x1005, "successors": [0x1010]}
        if op == "function_at":
            return {"addr": 0x1000, "name": "main", "size": 10, "end": 0x100A}
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
        if op == "types":
            if args.get("name"):
                return {
                    "name": args["name"],
                    "path": f"/{args['name']}",
                    "kind": args.get("kind") or "struct",
                    "length": 8,
                    "components": [
                        {"offset": 0, "length": 4, "name": "field_0", "type": "int"}
                    ],
                    "values": [{"name": "ONE", "value": 1}],
                    "base_type": "int",
                }
            return [
                {"name": "demo_struct", "path": "/demo_struct", "kind": "struct", "length": 8},
                {"name": "demo_enum", "path": "/demo_enum", "kind": "enum", "length": 4},
            ]
        if op == "strings":
            return [
                {"addr": 0x1000, "length": 5, "string": "hello", "type": "string"},
                {"addr": 0x2000, "length": 5, "string": "world", "type": "string"},
            ]
        if op == "exports":
            return [
                {"addr": 0x1000, "name": "entry", "type": "FUNCTION"},
            ]
        if op == "type_read":
            return {
                "name": args["name"],
                "path": f"/{args['name']}",
                "kind": "int",
                "length": 4,
                "count": 1,
                "addr": args.get("ea", 0),
                "bytes": b"ABCD",
                "values": [0x44434241],
            }
        if op == "function_signatures":
            return [
                {
                    "addr": 0x1000,
                    "name": "main",
                    "signature": "int main(void)",
                    "calling_convention": "unknown",
                }
            ]
        if op == "function_signature":
            return {
                "addr": args["ea"],
                "name": "main",
                "signature": "int main(void)",
                "calling_convention": "unknown",
                "parameters": [],
            }
        if op == "function_set_signature":
            return {
                "addr": args["ea"],
                "name": "main",
                "signature": args["signature"],
                "calling_convention": "unknown",
                "parameters": [],
            }
        if op == "type_define":
            return {
                "name": "demo_new",
                "path": "/demo_new",
                "kind": "struct",
                "length": 8,
                "declaration": "struct demo_new { int field; };",
            }
        if op == "type_c":
            return {
                "name": "demo_new",
                "kind": "struct",
                "declaration": "struct demo_new { int field; };",
            }
        if op == "type_delete":
            return {"removed": [args["name"]], "count": 1}
        if op == "comments":
            return [{"addr": 0x1000, "kind": "eol", "text": "hello"}]
        if op == "comment_set":
            return {"addr": args["ea"], "kind": args["kind"], "text": args["text"]}
        if op == "comment_delete":
            return {"addr": args["ea"], "kind": args["kind"], "text": ""}
        if op == "write_bytes":
            data = bytes(args["data"])
            return {"addr": args["ea"], "size": len(data), "bytes": data}
        if op == "assemble":
            return {
                "items": [
                    {"addr": args["ea"], "text": args["text"], "bytes": b"\x90\x90", "size": 2}
                ],
                "bytes": b"\x90\x90",
                "size": 2,
            }
        if op == "assemble_write":
            return {
                "items": [
                    {"addr": args["ea"], "text": args["text"], "bytes": b"\x90\x90", "size": 2}
                ],
                "bytes": b"\x90\x90",
                "size": 2,
                "addr": args["ea"],
                "written": {"addr": args["ea"], "size": 2, "bytes": b"\x90\x90"},
            }
        if op == "write_patches":
            return {
                "patches": len(args["patches"]),
                "bytes": sum(len(patch["data"]) for patch in args["patches"]),
            }
        if op == "write_copy":
            return {"addr": args["dst"], "src": args["src"], "size": args["size"]}
        if op in ("undo", "redo"):
            return {"addr": 0x1000, "size": 2, "segments": 1}
        if op == "strings_all":
            return [
                {"offset": 0x10, "length": 5, "string": "hello"},
            ]
        if op == "function_reanalyze":
            return {"addr": args["ea"], "name": "main", "size": 10, "end": 0x100A}
        if op == "variable_refs":
            return [
                {
                    "name": args.get("name") or "local_8",
                    "storage": "Stack[-0x8]",
                    "kind": "stack",
                    "refs": [0x1000, 0x1004],
                }
            ]
        if op == "variable_rename":
            return {
                "old": args["old"],
                "name": args["new"],
                "storage": "Stack[-0x8]",
            }
        if op == "exec_python":
            return {"output": "demo\n"}
        if op == "search_raw":
            return {
                "hits": [0x20, 0x24],
                "meta": {
                    "shown": 2,
                    "offset": 0,
                    "limit": args.get("limit", 4096),
                    "truncated": False,
                    "scope": "raw",
                    "forward": True,
                },
            }
        if op == "search":
            return {
                "hits": [0x1000, 0x1004],
                "meta": {
                    "shown": 2,
                    "offset": args.get("offset", 0),
                    "limit": args.get("limit", 4096),
                    "truncated": False,
                    "scope": args.get("scope", "io.maps"),
                    "forward": args.get("forward", True),
                },
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


def make_session(client=None) -> tuple[Session, FakeClient]:
    client = client or FakeClient()
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
    assert "4142 4344" in lines[-1]
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


def test_json_filter_and_pipe_are_line_oriented():
    session, _ = make_session()
    filtered = session.run("iIj~arch")
    assert filtered == ['  "arch": "x86",']
    piped = session.run("iIj|head -1")
    assert piped == ["{"]


def test_json_default_resolves_separate_command_specs():
    session, _ = make_session()
    session.json_default = True
    output = session.run("f")
    assert output and output[0].lstrip().startswith("[")
    # ``-j`` must not turn ``<cmd>?`` into the JSON variant.
    help_lines = session.run("afl?")
    assert "list functions" in help_lines[0]


def test_backtick_substitution():
    session, _ = make_session()
    session.run("s `? 0x2000`")
    assert session.seek == 0x2000
    assert session.run("s `? 0x1000`; s") == ["0x0000000000001000"]
    session.run("s `? 0x2000`")
    session.run("s `? no-such-symbol`")
    assert session.failed


def test_backtick_substitution_rejects_unterminated():
    session, _ = make_session()
    session.run("s `? 0x2000")
    assert session.failed
    assert "unterminated backtick" in str(session.last_error)


def test_function_iterators_are_equivalent():
    session, _ = make_session()
    assert session.run("pd 1 @@f") == session.run("pd 1 @@F")


def test_print_read_variants():
    session, _ = make_session()
    assert session.run("p8s 4") == ["41 42 43 44"]
    assert session.run("p8d 4") == ["65 66 67 68 "]
    assert session.run("p8, 4") == ["0x41,0x42,0x43,0x44"]
    assert session.run("p8* 4") == ["wx+ 41424344"]
    assert session.run("p8x 4") == ["41424344"]
    assert session.run("p8b") == ["41424344"]
    assert session.run("p8f") == ["41424344"]
    assert json.loads(session.run("pxj 4")[0]) == [65, 66, 67, 68]
    assert session.run("psn") == ["ABCD"]
    assert session.run("psx 4") == ["ABCD"]
    assert session.run("psu 4") == ["ABCD"]
    assert session.run("psw") == ["AC"]
    assert session.run("psp") == ["BCD"]
    assert session.run("psz") == ["ABCD"]
    record = json.loads(session.run("psj")[0])
    assert record == {
        "string": "ABCD",
        "offset": 0x1000,
        "section": ".text",
        "length": 4,
        "type": "ascii",
    }
    assert any("NOP" in line for line in session.run("pdb"))
    assert session.run("pA 2")[0] == "0x0000000000001000 nop 2 NOP"
    assert len(session.run("pC 2")) == 2
    assert "1145258561" in session.run("pxd 8")[0]
    assert "1145258561" in session.run("pxu 8")[0]


def test_pv_variants():
    class ValueClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes":
                self.calls.append((op, args))
                return b"\x04\x03\x02\x01\xff\xff\xff\xff"[: args["size"]]
            return super().call(op, **args)

    session, client = make_session(ValueClient())
    assert session.run("pv4") == ["0x01020304"]
    assert session.run("pv4u") == ["16909060"]
    assert session.run("pv4d") == ["16909060"]
    assert session.run("pvu") == ["18446744069431493380"]
    assert session.run("pvd") == ["-4278058236"]
    assert session.run("pvp") == ["0xffffffff01020304"]
    assert json.loads(session.run("pvj4")[0])[0]["value"] == 0x01020304
    assert client.calls[-1][0] == "read_bytes"


def test_print_family_explicit_unsupported():
    session, _ = make_session()
    session.run("pdk")
    assert session.failed and "no Ghidra equivalent" in str(session.last_error)
    session.failed = False
    session.run("pdr")
    assert session.failed and "not implemented" in str(session.last_error)


def test_all_xrefs_variants():
    class XrefClient(FakeClient):
        def call(self, op, **args):
            if op == "xrefs_all":
                self.calls.append((op, args))
                return [
                    {"from": 0x1000, "to": 0x2000, "type": "UNCONDITIONAL_CALL"},
                    {"from": 0x1004, "to": 0x3000, "type": "DATA"},
                ]
            return super().call(op, **args)

    session, _ = make_session(XrefClient())
    assert session.run("ax*") == [
        "axC 0x0000000000001000 0x0000000000002000",
        "axd 0x0000000000001004 0x0000000000003000",
    ]
    assert session.run("axlq")[1] == "0x0000000000001004 -> 0x0000000000003000  DATA"
    assert session.run("axlc") == ["2"]
    assert '"from": 4096' in session.run("axlj")[0]
    session.run("axj 0x1000")
    assert session.failed
    assert "read-only for xrefs" in str(session.last_error)


def test_export_variants_are_replayable():
    session, _ = make_session()
    flags = session.run("f*")
    assert "f helper 0 @ 0x0000000000002000" in flags
    replay, _ = make_session()
    for line in flags:
        replay.run(line)
    assert replay.flag_store.get("helper").addr == 0x2000
    assert replay.flag_store.get("main").addr == 0x1000

    comments = session.run("C*")
    assert comments == ["CCu base64:aGVsbG8= @ 0x0000000000001000"]
    assert session.run("CC*") == comments
    writable, client = make_session()
    writable.readonly = False
    writable.run(comments[0])
    assert (
        "comment_set",
        {"allow_writes": True, "ea": 0x1000, "text": "hello", "kind": "eol"},
    ) in client.calls

    declarations = session.run("t*")
    assert declarations == ["td 'struct demo_new { int field; };'"]
    writable, client = make_session()
    writable.readonly = False
    writable.run(declarations[0])
    assert (
        "type_define",
        {"allow_writes": True, "decl": "struct demo_new { int field; };"},
    ) in client.calls

    assert session.run("b*") == ["b 0x100"]
    assert session.run("iS*") == [
        "f section..text 4096 @ 0x0000000000001000",
        "f section..data 512 @ 0x0000000000003000",
    ]
    session.run("s 0x2000")
    assert session.run("s*") == ["f undo_0 = 0x0000000000001000"]


def test_comment_base64_payload_roundtrip_and_errors():
    session, client = make_session()
    session.readonly = False
    session.run("CCu base64:aGVsbG8= @ main")
    assert (
        "comment_set",
        {"allow_writes": True, "ea": 0x2000, "text": "hello", "kind": "eol"},
    ) in client.calls
    session.run("Cp base64:cGxhdGU= @ main")
    assert (
        "comment_set",
        {"allow_writes": True, "ea": 0x2000, "text": "plate", "kind": "plate"},
    ) in client.calls
    session.run("CCu base64:!!!")
    assert session.failed
    assert "invalid base64" in str(session.last_error)


def test_file_info_config_and_function_addresses():
    session, _ = make_session()
    assert session.run("i")[0] == "file     /bin/fake"
    assert "arch" in "\n".join(session.run("i"))

    config_keys = session.run("e?")
    assert any(line.startswith("asm.bytes =") for line in config_keys)
    payload = json.loads("\n".join(session.run("ej")))
    assert payload["asm.bytes"] is True

    addresses = session.run("aflq")
    assert addresses == ["0x0000000000001000"]
    assert session.run("aflq main") == ["0x0000000000001000"]
    assert session.run("afl main")[0].endswith("main")

    session.json_default = True
    assert session.run("e")[0].lstrip().startswith("{")
    assert json.loads("\n".join(session.run("i")))["program"] == "demo"


def test_list_daemon_instances(monkeypatch):
    session, _ = make_session()
    monkeypatch.setattr(
        registry,
        "live_instances",
        lambda: [
            {
                "instance_id": "abc123",
                "pid": 42,
                "port": 4567,
                "readonly": False,
                "target": "/bin/fake",
                "health": {"state": "ready"},
            }
        ],
    )
    lines = session.run("L")
    assert lines[0].startswith("instance")
    assert "abc123" in lines[1]
    assert "/bin/fake" in lines[1]


def test_duplicate_command_registration_is_rejected():
    spec = CommandSpec("zz-test", "test", lambda session, statement: [])
    register(spec)
    try:
        with pytest.raises(ValueError, match="duplicate command pattern"):
            register(CommandSpec("zz-test", "test", lambda session, statement: []))
    finally:
        cmd_module._COMMANDS.remove(spec)
    patterns = [item.pattern for item in cmd_module.all_commands()]
    assert len(patterns) == len(set(patterns))


def test_iterator_skips_targets_without_instructions(capsys):
    class SkipClient(FakeClient):
        def call(self, op, **args):
            if op == "iter_targets":
                return [{"addr": 0x1000, "size": 10}, {"addr": 0xDEAD, "size": 1}]
            if op == "batch":
                replies = []
                for operation in args["ops"]:
                    address = operation["args"]["ea"]
                    if address == 0xDEAD:
                        replies.append(
                            {
                                "ok": False,
                                "error": {
                                    "code": "NOT_FOUND",
                                    "message": "no instruction at or after 0xdead",
                                },
                            }
                        )
                    else:
                        replies.append(
                            {
                                "ok": True,
                                "result": [
                                    {
                                        "addr": address,
                                        "size": 2,
                                        "bytes": b"\x90\x90",
                                        "text": "NOP",
                                    }
                                ],
                            }
                        )
                return replies
            return super().call(op, **args)

    session, _ = make_session(SkipClient())
    lines = session.run("pd 1 @@F")
    assert len(lines) == 1
    assert "skipped 1" in capsys.readouterr().err


def test_temporary_seek_is_restored():
    session, _ = make_session()
    session.run("s 0x1000")
    session.run("pd 1 @ 0x2000")
    assert session.seek == 0x1000


def test_pdi_pi_pdl_and_pd_bytes():
    session, _ = make_session()
    pdi = session.run("pdi 1")[0]
    assert "NOP" in pdi
    assert "main" in pdi
    assert "main" not in session.run("pd 1")[0]
    assert session.run("pi 2") == ["NOP", "RET"]
    assert session.run("pdl 1")[0].endswith("NOP")
    assert len(session.run("pD 3")) == 2


def test_pdi_shows_client_flags_as_separate_lines():
    session, _ = make_session()
    session.run("f demoflag = 0x1000")
    lines = session.run("pdi 1")
    assert any(line.endswith("entry:") for line in lines)
    assert any(line.endswith("demoflag:") for line in lines)
    assert any("main" in line and "NOP" in line for line in lines)

    session.run("e asm.flags=false")
    disabled = session.run("pdi 1")
    assert not any(line.endswith("demoflag:") for line in disabled)
    assert not any("main" in line for line in disabled)


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
    session.readonly = False
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
    session.readonly = False
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


def test_types_signatures_and_comments():
    session, _ = make_session()
    assert "demo_struct" in "\n".join(session.run("t"))
    assert "field_0" in "\n".join(session.run("ts demo_struct"))
    assert "ONE" in "\n".join(session.run("te demo_enum"))
    assert "int main(void)" in session.run("tf")[0]
    assert "hello" in session.run("C")[0]
    assert "hello" in "\n".join(session.run("C. @ main"))
    session.readonly = False
    assert "updated" in session.run("CC updated @ main")[0]
    assert "deleted" in session.run("CC- @ main")[0]


def test_type_define_c_output_and_signature_write():
    session, client = make_session()
    session.readonly = False
    defined = session.run("td 'struct demo_new { int field; };'")[0]
    assert "demo_new struct size=8" in defined
    assert ("type_define", {"allow_writes": True, "decl": "struct demo_new { int field; };"}) in client.calls
    assert "struct demo_new" in "\n".join(session.run("tc demo_new"))
    assert "int main(void)" in session.run("tfc")[0]
    session.readonly = False
    assert "void demo(int x)" in session.run("s main; afs void demo(int x)")[0]
    assert "removed demo_new" in session.run("tf- demo_new")[0]
    assert [op for op, _ in client.calls if op.startswith(("type_", "function_set"))] == [
        "type_define",
        "type_c",
        "function_set_signature",
        "type_delete",
    ]


def test_iterator_meta_is_used_for_total_and_truncation(capsys):
    class MetaClient(FakeClient):
        def call_with_meta(self, op, **args):
            value = self.call(op, **args)
            if op == "iter_targets":
                return value, {
                    "total": 5000,
                    "shown": len(value),
                    "limit": 4096,
                    "truncated": True,
                }
            return value, {"total": 5000, "shown": len(value), "errors": 0}

    session, client = make_session(MetaClient())
    session.run("pd 1 @@f")
    assert client.calls[-1][1]["total"] == 5000
    assert "truncated at 4096 of 5000 targets" in capsys.readouterr().err


def test_write_commands_are_gated():
    session, client = make_session()
    assert session.run("wx 9090") == []
    assert session.failed
    assert "read-only" in str(session.last_error)
    assert not [call for call in client.calls if call[0] == "write_bytes"]


def test_wx_and_w_text_write_bytes():
    session, client = make_session()
    session.readonly = False
    assert session.run("wx 90 90") == []
    assert ("write_bytes", {"allow_writes": True, "ea": 0x1000, "data": b"\x90\x90"}) in client.calls
    assert session.run('w "hi"') == []
    assert ("write_bytes", {"allow_writes": True, "ea": 0x1000, "data": b"hi"}) in client.calls


def test_wx_wildcard_nibbles_build_a_mask():
    from gdare2.cmd.write import parse_hexpairs

    data, mask = parse_hexpairs("90?f")
    assert data == b"\x90\x0f"
    assert mask == b"\xff\x0f"


def test_write_cache_flushes_in_one_request():
    session, client = make_session()
    session.readonly = False
    session.config.set("io.cache", "true")
    assert session.run("wx 9090; wx 4142") == []
    assert not [call for call in client.calls if call[0] == "write_bytes"]
    listed = session.run("wc")
    assert "9090" in listed[0]
    assert "4142" in listed[1]
    assert session.run("wc+") == []
    writes = [call for call in client.calls if call[0] == "write_patches"]
    assert len(writes) == 1
    patches = writes[0][1]["patches"]
    assert [patch["ea"] for patch in patches] == [0x1000, 0x1000]
    assert session.write_cache == []


def test_w_saves_and_wq_quits():
    session, client = make_session()
    session.readonly = False
    session.config.set("io.cache", "true")
    assert session.run("wx 90; w") == []
    ops = [op for op, _ in client.calls]
    assert ops[-2:] == ["write_patches", "save"]
    assert session.run("wq") == []
    assert session.quit_requested
    assert [op for op, _ in client.calls].count("save") == 2


def test_undo_redo_and_wd():
    session, client = make_session()
    session.readonly = False
    session.run("wd 16 4")
    assert ("write_copy", {"allow_writes": True, "dst": 0x1010, "src": 0x1000, "size": 4}) in client.calls
    assert session.run("u; U") == []
    assert [op for op, _ in client.calls if op in ("undo", "redo")] == ["undo", "redo"]


def test_gsave_commits_cache_before_saving():
    session, client = make_session()
    session.readonly = False
    session.config.set("io.cache", "true")
    session.run("wx 90; .gsave")
    ops = [op for op, _ in client.calls]
    assert ops[-2:] == ["write_patches", "save"]


def test_search_text_hex_wide_and_value():
    session, client = make_session()
    assert session.run("/x 9090") == [
        "0x0000000000001000",
        "0x0000000000001004",
    ]
    assert client.calls[-1][0] == "search"
    assert client.calls[-1][1]["data"] == b"\x90\x90"
    assert session.run("/ hello") == ["0x0000000000001000", "0x0000000000001004"]
    assert client.calls[-1][1]["data"] == b"hello"
    session.run("/w hi")
    assert client.calls[-1][1]["data"] == "hi".encode("utf-16-le")
    session.run("/v4 0x1234")
    assert client.calls[-1][1]["data"] == b"\x34\x12\x00\x00"


def test_search_json_and_repeat():
    session, client = make_session()
    payload = json.loads("\n".join(session.run("/xj 9090")))
    assert payload["hits"] == [0x1000, 0x1004]
    assert session.seek == 0x1000
    assert session.run("//") == ["0x0000000000001000", "0x0000000000001004"]
    assert client.calls[-1][1]["cursor"] == 0x1001
    assert client.calls[-1][1]["forward"] is True
    session.run("/-")
    assert client.calls[-1][1]["cursor"] == 0x0FFF
    assert client.calls[-1][1]["forward"] is False


def test_search_respects_range_config():
    session, client = make_session()
    session.config.set("search.from", "0x2000")
    session.config.set("search.to", "0x2fff")
    session.run("/x 90")
    args = client.calls[-1][1]
    assert args["from_addr"] == 0x2000
    assert args["to_addr"] == 0x2FFF
    assert args["cursor"] == 0x2000


def test_flag_commands_and_write_back():
    session, client = make_session()
    assert session.config.get_bool("ghidra.flags.write") is False
    assert "entry" in "\n".join(session.run("f"))
    assert session.run("fq") == ["entry", "main", "helper"]
    assert session.run("f? entry") == ["1"]
    assert session.run("f? missing") == ["0"]

    session.run("s 0x3000; f local_flag 4 @ 0x3000")
    assert session.flag_store.get("local_flag") is not None
    assert session.run("s local_flag") == []
    assert session.seek == 0x3000
    assert session.run("f.") == ["0x0000000000003000   4 local_flag"]

    session.readonly = False
    session.config.set("ghidra.flags.write", "true")
    assert session.run("f remote_flag @ 0x4000") == []
    assert ("symbol_create", {"allow_writes": True, "ea": 0x4000, "name": "remote_flag"}) in client.calls
    assert session.run("fr remote_flag renamed_flag") == []
    assert session.run("f- renamed_flag") == []


def test_flag_rename_and_delete_are_local_without_write_back():
    session, client = make_session()
    session.run("f local @ 0x5000")
    assert session.run("fr local renamed") == []
    assert session.flag_store.get("renamed") is not None
    assert session.run("f- renamed") == []
    assert session.flag_store.get("renamed") is None
    assert not [call for call in client.calls if call[0].startswith("symbol_")]


def test_variables_last_output_and_script(tmp_path):
    session, _ = make_session()
    assert session.run("$foo=0x10") == []
    assert session.run("$foo") == ["16"]
    assert session.run("$foo = $foo + 1") == []
    assert session.run("$foo") == ["17"]
    assert any(line.startswith("$foo = 17") for line in session.run("$"))
    assert any(line.startswith("$foo = 17") for line in session.run("$?"))

    session.run("s 0x2000")
    assert session.run("s; _")[-1] == "0x0000000000002000"

    script = tmp_path / "demo.rc"
    script.write_text("s 0x2000\npd 1\n")
    lines = session.run(f"S {script}")
    assert any("NOP" in line for line in lines)


def test_x_hexdump_variants():
    session, _ = make_session()
    assert session.run("x8 4") == ["41424344"]
    assert "4142 4344" in "\n".join(session.run("x 4"))
    assert json.loads("\n".join(session.run("xj 4")))["bytes"] == "41424344"
    assert len(session.run("xw 4")) == 1


def test_exports_architectures_and_typed_reads():
    session, client = make_session()
    exports = session.run("iE")
    assert "entry" in "\n".join(exports)
    assert any("x86" in line for line in session.run("ia"))
    assert json.loads("\n".join(session.run("iaj")))[0]["name"] == "x86-16"

    typed = session.run("tp int @ 0x1000")
    assert "int size=4" in typed[0]
    assert "0x44434241" in "\n".join(typed)
    assert ("type_read", {"allow_writes": False, "name": "int", "ea": 0x1000}) in client.calls

    hex_typed = session.run("tpx int 41424344")
    assert "int size=4" in hex_typed[0]

    session.readonly = False
    assert session.run("t- demo_type") == ["removed demo_type"]


def test_regex_search_and_cmd_hit():
    session, _ = make_session()
    assert session.run("/r hello") == ["0x0000000000001000"]
    assert session.run("//") == []
    assert json.loads("\n".join(session.run("/rj world")))["hits"] == [0x2000]

    session.config.set("cmd.hit", "pi 1")
    lines = session.run("/x 9090")
    assert lines and any("NOP" in line for line in lines)


def test_temporary_blocksize_and_address_file_iterator(tmp_path):
    session, client = make_session()
    session.run("px @!4")
    assert session.blocksize == 0x100
    assert ("read_bytes", {"allow_writes": False, "ea": 0x1000, "size": 4}) in client.calls

    addresses = tmp_path / "addrs.txt"
    addresses.write_text("0x1000\n0x2000\n")
    lines = session.run(f"pd 1 @@.{addresses}")
    assert len(lines) == 2
    ops = [item["args"]["ea"] for item in client.calls[-1][1]["ops"]]
    assert ops == [0x1000, 0x2000]

    session.run("pd 1 @@F")
    assert client.calls[-2][0] == "iter_targets"


def test_dot_sync_analyze_and_help():
    session, client = make_session()
    session.info["state"] = "stale"
    assert session.run(".gsync") == []
    assert session.info["state"] == "ready"
    assert ("info", {"allow_writes": False}) in client.calls
    assert "analysis:" in session.run(".ganalyze")[0]
    assert any(line.startswith(".g") for line in session.run(".ghelp"))


def test_assembler_and_integer_base64_writes():
    session, client = make_session()
    assert session.run("pa nop") == ["9090"]
    assert any("wx 9090" in line for line in session.run("wa* nop"))

    session.readonly = False
    assert any("9090" in line for line in session.run("wa nop"))
    session.run("wi4 0x1234")
    assert ("write_bytes", {"allow_writes": True, "ea": 0x1000, "data": b"\x34\x12\x00\x00"}) in client.calls
    assert session.run("wi4") == ["0x44434241"]
    session.run("wi4+ 1")
    assert client.calls[-1][1]["data"] == b"BBCD"
    session.run("w6d QUI=")
    assert client.calls[-1][1]["data"] == b"AB"
    assert session.run("w6e 4") == ["QUJDRA=="]


def test_whole_file_strings_pattern_and_assembly_search():
    session, client = make_session()
    assert session.run("izz") == ["0x00000010 hello"]
    assert json.loads("\n".join(session.run("izzj")))[0]["offset"] == 0x10

    assert session.run("/p 9090") == ["0x0000000000001000", "0x0000000000001004"]
    assert session.run("/a NOP") == ["0x0000000000001000", "0x0000000000001004"]
    assert [op for op, _ in client.calls if op in ("search", "assemble")][-2:] == [
        "assemble",
        "search",
    ]


def test_raw_search_and_search_iterators():
    session, client = make_session()
    session.config.set("search.in", "raw")
    assert session.run("/x 9090") == ["0x0000000000000020", "0x0000000000000024"]
    assert client.calls[-1][0] == "search_raw"

    lines = session.run("px 1 @@/x 9090")
    assert any("0x0000000000000020" in line for line in lines)
    assert any("0x0000000000000024" in line for line in lines)
    assert client.calls[-1][0] == "batch"
    assert [item["args"]["ea"] for item in client.calls[-1][1]["ops"]] == [0x20, 0x24]

    lines = session.run("pd 1 @@s:0x1000 0x1004 2")
    assert len(lines) == 3
    assert [item["args"]["ea"] for item in client.calls[-1][1]["ops"]] == [
        0x1000,
        0x1002,
        0x1004,
    ]


def test_search_iterator_uses_response_level_meta(capsys):
    class SearchMetaClient(FakeClient):
        def call_with_meta(self, op, **args):
            value = self.call(op, **args)
            if op == "search":
                return value, {
                    "shown": len(value["hits"]),
                    "offset": 0,
                    "limit": 2,
                    "truncated": True,
                    "scope": "io.maps",
                    "forward": True,
                }
            return value, {}

    session, _ = make_session(SearchMetaClient())
    session.run("px 1 @@/x 9090")
    err = capsys.readouterr().err
    assert "iterator truncated" in err


def test_temporary_range_operator():
    session, client = make_session()
    session.run("px @{0x1000 0x1003}")
    assert ("read_bytes", {"allow_writes": False, "ea": 0x1000, "size": 4}) in client.calls
    assert session.tmp_range is None


def test_gexec_and_variable_analysis_commands():
    session, _ = make_session()
    session.readonly = False
    session.allow_exec = True
    assert session.run(".gexec print('demo')") == ["demo"]
    session.allow_exec = False
    assert session.run(".gexec 1+1") == []
    assert "allow-exec" in str(session.last_error)

    assert session.run("s main; afr") == ["0x0000000000002000 main"]
    refs = session.run("afvR local_8")
    assert refs and refs[0].endswith("[stack]")
    assert session.run("afvW local_8") == refs
    assert "local_8 -> new_name" in session.run("an local_8 new_name")[0]


def test_assembler_calls_extend_and_restore_client_timeout():
    class TimeoutClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.timeout = 30.0
            self.seen = []

        def call(self, op, **args):
            if op in ("assemble", "assemble_write"):
                self.seen.append(self.timeout)
            return super().call(op, **args)

    session, client = make_session(TimeoutClient())
    session.config.set("ghidra.assemble.timeout", 180)
    assert session.run("pa NOP") == ["9090"]
    assert client.seen == [180.0]
    assert client.timeout == 30.0


def test_list_offset_slices_daemon_results():
    session, client = make_session()
    session.config.set("list.offset", 1)
    lines = session.run("is")
    assert len(lines) == 1
    assert "helper" in lines[0]
    assert client.calls[-1] == (
        "symbols",
        {"allow_writes": False, "limit": 10000, "offset": 1},
    )
    assert session.run("aflc") == ["1"]


def test_list_truncation_warning_mentions_next_offset(capsys):
    class MetaClient(FakeClient):
        def call_with_meta(self, op, **args):
            if op == "symbols":
                return [{"addr": 0x1000, "name": "entry", "type": "LABEL"}], {
                    "total": 12000,
                    "shown": 1,
                    "offset": 10000,
                    "limit": 1,
                    "truncated": True,
                }
            return super().call(op, **args), {}

    session, _ = make_session(MetaClient())
    session.run("is")
    assert "--list-offset 10001" in capsys.readouterr().err


def test_cmd_batch_false_uses_individual_calls():
    session, client = make_session()
    session.config.set("cmd.batch", False)
    lines = session.run("pd 1 @@=0x1000,0x2000")
    assert len(lines) == 4
    operations = [op for op, _ in client.calls]
    assert "batch" not in operations
    assert operations.count("disasm") == 2


def test_elf_header_dynamic_and_relocation_commands(tmp_path):
    from test_formats_elf import _elf64_dynamic

    target = tmp_path / "sample.elf"
    target.write_bytes(_elf64_dynamic())
    session, _ = make_session()
    session.info["target"] = str(target)

    header = session.run("ih")
    assert any("EntryPoint" in line for line in header)
    assert any("ELF" in line for line in header)
    assert len(json.loads(session.run("ihj")[0])) == 14
    assert any("Machine" in line for line in session.run("iH"))

    assert session.run("il") == ["libc.so.6"]
    assert json.loads(session.run("ilj")[0]) == ["libc.so.6"]

    relocations = session.run("ir")
    assert relocations[0].startswith("vaddr")
    assert any("ADD_64" in line and "0x401234" in line for line in relocations)
    assert any("JUMP_SLOT" in line and "puts" in line for line in relocations)
    rows = json.loads(session.run("irj")[0])
    assert rows[1] == {
        "vaddr": 0x401008,
        "paddr": 0x401008,
        "type": "JUMP_SLOT",
        "ntype": 7,
        "name": "puts",
    }

    session.json_default = True
    assert isinstance(json.loads(session.run("ir")[0]), list)


def test_elf_commands_reject_non_elf_and_missing_target(tmp_path):
    session, _ = make_session()
    session.info["target"] = str(tmp_path / "missing.bin")
    session.run("ih")
    assert session.failed and "ih cannot read" in str(session.last_error)
    session.failed = False
    session.info["target"] = None
    session.run("il")
    assert session.failed and "no target path" in str(session.last_error)


def test_comment_listing_respects_include_all():
    session, client = make_session()
    session.run("C")
    call = [item for item in client.calls if item[0] == "comments"][-1]
    assert call[1]["include_all"] is False
    session.config.set("ghidra.comments.all", True)
    session.run("C")
    call = [item for item in client.calls if item[0] == "comments"][-1]
    assert call[1]["include_all"] is True


def test_type_detail_layout_and_struct_hex_input():
    session, client = make_session()
    lines = session.run("ts demo_struct")
    assert "kind: struct" in lines
    assert "size: 8" in lines
    assert "+0000    4 int field_0" in lines

    session.run("tpx demo_struct 41424344")
    call = [item for item in client.calls if item[0] == "type_read"][-1]
    assert call[1]["data"] == b"ABCD"


def test_literal_commands_and_dollar_substitution():
    session, _ = make_session()
    session.run("'T hello~world")
    assert session.run("Tm") == ["hello~world"]

    session.run("s $(? 0x2000)")
    assert session.seek == 0x2000
    session.run("s `? 0x1000`")
    assert session.seek == 0x1000
