from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest
from test_session import FakeClient, make_session

from gdare2.cmd import info as info_cmd
from gdare2.formats.elf import ELF_MAGIC, read_versions


def test_print_compat_family():
    session, _ = make_session()
    assert session.run("p6e 4") == ["QUJDRA=="]
    assert session.run("p6d QUJDRA==") == ["ABCD"]
    assert "unique (count):" in "\n".join(session.run("p= 4"))
    assert "min:" in session.run("p=d 4")[0]
    assert json.loads(session.run("p=j 4")[0])["unique"] == 4
    assert session.run("pr 4") == ["ABCD"]
    assert "ABCD" in session.run("prx 4")[1]
    assert session.run("ph md5 4") == [hashlib.md5(b"ABCD").hexdigest()]
    assert session.run("ph")[0].startswith("md5")
    assert session.run("pwd")[0]
    assert session.run("pdq 1")[0].endswith("NOP")
    assert json.loads(session.run("pdJ 1")[0])[0]["offset"] == 0x1000
    assert session.run("pd,")[0].startswith("name")
    session.run("p6d !!!")
    assert session.failed and "invalid base64" in str(session.last_error)


def test_pj_parses_json_at_seek():
    class JsonClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes":
                self.calls.append((op, args))
                return b'{"a": 1}'
            return super().call(op, **args)

    session, _ = make_session(JsonClient())
    assert json.loads("\n".join(session.run("pj 16"))) == {"a": 1}
    plain, _ = make_session()
    plain.run("pj 4")
    assert plain.failed and "not JSON" in str(plain.last_error)


def test_pd_comments_table_and_quiet_variants():
    class CommentClient(FakeClient):
        def call(self, op, **args):
            if op == "disasm":
                self.calls.append((op, args))
                return [
                    {
                        "addr": args["ea"],
                        "size": 1,
                        "bytes": b"\x90",
                        "text": "NOP",
                        "comment": "note",
                        "symbol": "main",
                    }
                ]
            return super().call(op, **args)

    session, _ = make_session(CommentClient())
    assert "note" in session.run("pdC 1")[0]
    assert "NOP" in session.run("pdq 1")[0]
    assert "note" in "\n".join(session.run("pd, 1"))


def test_seek_history_blocks_and_flags():
    session, client = make_session()
    assert session.run("s:") == ["0x00001000"]
    assert session.run("s:16") == ["0x0000000000001000"]
    session.run("s 0x2000")
    assert session.run("s=")[0].startswith("0x0000000000001000")
    assert session.run("s==")[0].startswith("0x0000000000001000")
    assert session.run("s=*") == [
        "s 0x0000000000001000",
        "s+ 0x0000000000002000",
    ]

    payload = json.loads(session.run("bj")[0])
    assert payload == {"blocksize": 256, "blocksize_limit": 50 * 1024 * 1024}
    assert session.run("bm") == [hex(50 * 1024 * 1024)]
    assert session.run("bm 4096") == []
    assert json.loads(session.run("bj")[0])["blocksize_limit"] == 4096
    session.run("b 8192")
    assert session.failed and "bm limit" in str(session.last_error)
    session.failed = False
    session.run("bm 50M")
    assert session.failed

    session.run("s main; bf main")
    assert session.blocksize == 10
    session.run("fN main")
    session.failed = False
    assert session.run("fN main") == ["main"]
    assert any("main" in line for line in session.run("fn"))
    assert json.loads(session.run("fnj")[0])[0]["name"]
    assert "4142 4344" in "\n".join(session.run("fx entry"))
    assert client.calls


def test_config_env_and_verbose_commands():
    session, _ = make_session()
    commands = session.run("e*")
    assert "e asm.bytes = True" in commands
    assert json.loads(session.run("e*j")[0])["asm.bytes"] is True
    session.run("e scr.color=3; e-")
    assert session.config.get_int("scr.color") == 0
    session.run("e! asm.bytes")
    assert session.config.get_bool("asm.bytes") is False
    session.run("e! scr.color")
    assert session.failed and "expected a boolean" in str(session.last_error)

    assert session.run("env GDA_COVER=abc") == []
    assert session.run("env GDA_COVER") == ["abc"]
    assert json.loads(session.run("envj")[0])["GDA_COVER"] == "abc"
    assert "GDA_COVER=abc" in session.run("env")

    spaces = session.run("es")
    assert "asm" in spaces
    assert "asm.bytes" in session.run("es asm")
    assert session.run("et asm.bytes") == ["bool"]
    assert "instruction bytes" in session.run("ev asm.bytes")[0]
    rows = json.loads(session.run("evj asm.bytes")[0])
    assert rows[0]["name"] == "asm.bytes"
    session.run("ev missing.")
    assert session.failed


def test_demangle_and_binary_info_families(monkeypatch, tmp_path):
    session, client = make_session()
    assert "c++" in session.run("iD")
    assert session.run("iD c++ _Z3foov")[0] == "demo::demangled()"
    assert client.calls[-1] == (
        "demangle",
        {"allow_writes": False, "text": "_Z3foov", "language": "c++"},
    )
    assert "path" in "\n".join(session.run("iC"))
    assert json.loads(session.run("iCj")[0])["build_id"] == ""
    assert "arch" in "\n".join(session.run("iv"))
    assert json.loads(session.run("ivj")[0])["sections"] == 2

    monkeypatch.setattr(
        info_cmd,
        "read_versions",
        lambda _path: [
            {"index": 0, "version": 0, "name": "*local*", "hidden": False},
            {"index": 1, "version": 2, "name": "GLIBC_2.2.5", "hidden": False},
        ],
    )
    monkeypatch.setattr(
        info_cmd,
        "read_init_fini",
        lambda _path: [{"vaddr": 0x1000, "paddr": 0x1000, "type": "init"}],
    )
    session.info["target"] = str(tmp_path / "sample.elf")
    assert "GLIBC_2.2.5" in "\n".join(session.run("iV"))
    assert json.loads(session.run("iVj")[0])[1]["name"] == "GLIBC_2.2.5"
    assert "type=init" in "\n".join(session.run("iee"))
    assert json.loads(session.run("ieej")[0])[0]["type"] == "init"
    assert "2 entrypoints" in session.run("ies")[0]
    assert json.loads(session.run("iesj")[0])[0]["type"] == "entry"

    target = tmp_path / "sig.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 12)
    session.info["target"] = str(target)
    assert "ELF executable" in session.run("iT")[0]
    assert json.loads(session.run("iTj")[0])[0]["name"] == "ELF executable"


def test_metadata_commands_are_gated_and_round_trip():
    session, _ = make_session()
    for command in ("Ch", "Cs 4", "Cm", "Ct note", "CL a.c:1"):
        session.run(command)
        assert session.failed and "read-only" in str(session.last_error), command
        session.failed = False

    session.readonly = False
    session.run("Ch 4")
    assert session.hidden_ranges == [(0x1000, 0x1003)]
    session.run("Ch-")
    assert session.hidden_ranges == []

    session.run("Cs 4")
    assert session.strings[0x1000]["string"] == "ABCD"
    assert "ABCD" in "\n".join(session.run("Cs"))
    assert session.run("Cs.") == ["ABCD"]
    assert json.loads(session.run("Cs.j")[0])["size"] == 4
    assert session.run("Cs*")[0].startswith("Cs 4 @")
    session.run("Cs-")
    assert 0x1000 not in session.strings

    class MagicClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes" and int(args.get("size", 0)) >= 16:
                self.calls.append((op, args))
                return b"\x7fELF" + b"\x00" * 12
            return super().call(op, **args)

    session, _ = make_session(MagicClient())
    session.readonly = False
    assert session.run("Cm") == ["ELF executable"]
    assert session.run("Cm.") == ["ELF executable"]
    assert json.loads(session.run("Cmj")[0])["name"] == "ELF executable"
    session.run("Cm-")
    assert not session.magic

    session, _ = make_session()
    session.readonly = False
    assert session.run("Cf 4 b")
    session.run("Ct widget")
    assert session.run("Ct")[0].endswith("widget")
    assert session.run("Ct.") == ["widget"]
    assert json.loads(session.run("Ctj")[0])[0]["comment"] == "widget"
    session.run("Ct-")
    assert not session.type_comments

    session.run("CL demo.c:42")
    assert session.run("CL.") == ["demo.c:42"]
    assert "demo.c:42" in "\n".join(session.run("CL"))
    assert json.loads(session.run("CLj")[0])[0]["line"] == "demo.c:42"
    assert session.run("CL*")[0].startswith("CL 'demo.c:42'")
    session.run("CL-")
    assert not session.source_lines


def test_search_variants_and_magic(tmp_path):
    session, client = make_session()
    assert session.run("/i Hello") == ["0x0000000000001000", "0x0000000000001004"]
    assert client.calls[-1][1]["ignore_case"] is True
    assert session.run("/d 101112") == ["0x0000000000001000", "0x0000000000001004"]
    assert client.calls[-1][1]["delta"] is True
    assert session.run("/z 4 8") == ["0x0000000000001000", "0x0000000000002000"]

    target = tmp_path / "magic.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 8)
    session.info["target"] = str(target)
    assert "ELF executable" in session.run("/m")[0]
    assert json.loads(session.run("/mj")[0])["hits"][0]["name"] == "ELF executable"

    crypto = tmp_path / "crypto.bin"
    crypto.write_bytes(b"xx-----BEGIN CERTIFICATE-----yy")
    session.info["target"] = str(crypto)
    assert "certificate" in session.run("/c")[0]

    gadgets = tmp_path / "gadgets.bin"
    gadgets.write_bytes(b"\x90\xc3\xc2\x34\x12")
    session.info["target"] = str(gadgets)
    assert any("ret" in line for line in session.run("/R"))
    assert json.loads(session.run("/Rj")[0])["hits"]


def test_write_memory_and_file_variants(tmp_path):
    session, client = make_session()
    for command in ("wv4 1", "wr 4", "ws hi", "ww hi"):
        session.run(command)
        assert session.failed and "read-only" in str(session.last_error), command
        session.failed = False

    session.readonly = False
    session.run("wv4 1 2 3")
    assert client.calls[-1] == (
        "write_bytes",
        {"allow_writes": True, "ea": 0x1000, "data": b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00"},
    )
    session.run("wv1 0x7f; wv2 0x1234; wv8 0x1122334455667788")
    session.run("wvf 1.5")
    assert client.calls[-1][1]["data"] == struct.pack("<f", 1.5)
    session.run("wvF 1.5")
    assert client.calls[-1][1]["data"] == struct.pack("<d", 1.5)
    session.run("ws hello")
    assert client.calls[-1][1]["data"] == b"\x05hello"
    session.run("ww hi")
    assert client.calls[-1][1]["data"] == "hi".encode("utf-16-le")
    session.run("wr 4")
    assert len(client.calls[-1][1]["data"]) == 4

    out = tmp_path / "out.bin"
    assert session.run(f"wt {out} 4") == []
    assert out.read_bytes() == b"ABCD"
    assert session.run(f"wta {out} 4") == []
    assert out.read_bytes() == b"ABCDABCD"
    other = tmp_path / "other.bin"
    assert session.run(f"wtf {other} 4") == []
    assert other.read_bytes() == b"ABCD"


def test_type_extra_commands(tmp_path):
    session, client = make_session()
    assert session.run("tk")[0].endswith(("=struct", "=enum"))
    assert json.loads(session.run("tkj")[0])[0]["name"]
    assert session.run("tn main") == []
    assert session.run("tn") == ["0x0000000000002000"]
    assert session.run("tn- main") == []
    assert session.run("tn main; tn-*") == []
    assert not session.no_return_marks

    header = tmp_path / "demo.h"
    header.write_text("struct demo_h { int x; };\n")
    session.readonly = False
    assert "demo_new" in session.run(f"to {header}")[0]
    assert client.calls[-1][0] == "type_define"
    assert "struct demo_h" in client.calls[-1][1]["decl"]

    assert session.run("tl int") == []
    assert session.run("tl") == ["0x0000000000001000 int"]
    assert session.run("tl int = 0x2000") == []
    assert json.loads(session.run("tlj")[0])[1]["addr"] == 0x2000
    assert any("tl int = 0x0000000000002000" in line for line in session.run("tl*"))
    assert session.run("tls 0x2000") == ["0x0000000000002000 int"]
    assert session.run("tl- 0x2000") == []
    assert session.run("tl-*") == []
    assert "struct demo_new" in "\n".join(session.run("tx"))

    session.run("to missing.h")
    assert session.failed and "cannot read" in str(session.last_error)


def test_project_and_text_log_subcommands(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    session, _ = make_session()
    assert session.run("Pn note one") == []
    assert session.run("Pn") == ["note one"]
    assert json.loads(session.run("Pnj")[0])["notes"] == "note one"
    session.run("T first; T second")
    assert session.run("TT") == ["1 first", "2 second"]
    session.run("T= ")
    assert session.failed and "http.sync" in str(session.last_error)
    session.failed = False

    monkeypatch.chdir(tmp_path)
    (tmp_path / "entry.txt").write_text("x")
    assert "entry.txt" in session.run("Ts")

    assert session.run("Ps demo")[0].startswith("-- saved ")
    assert "seek" in "\n".join(session.run("Pi demo"))
    script = session.run("Pc demo")
    assert any(line.startswith("s ") for line in script)
    script_path = tmp_path / "session.rc"
    assert "saved script" in session.run(f"PS {script_path}")[0]
    assert "s " in script_path.read_text()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert session.run("Pd demo") == []
    assert session.run("P") == []


def test_project_round_trips_metadata(monkeypatch, tmp_path):
    class MagicClient(FakeClient):
        def call(self, op, **args):
            if op == "read_bytes" and int(args.get("size", 0)) >= 16:
                self.calls.append((op, args))
                return b"\x7fELF" + b"\x00" * 12
            return super().call(op, **args)

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    session, _ = make_session(MagicClient())
    session.readonly = False
    session.run("Ch 4; Cs 4; Cm; Ct typed; CL demo.c:1; tl int; tn main; Pn keep me")
    session.run("Ps snapshot")

    session.hidden_ranges = []
    session.strings = {}
    session.magic = {}
    session.type_comments = {}
    session.source_lines = {}
    session.type_links = {}
    session.no_return_marks = set()
    session.project_notes = ""

    assert session.run("Po snapshot")[0].startswith("-- loaded ")
    assert session.hidden_ranges == [(0x1000, 0x1003)]
    assert session.strings[0x1000]["string"] == "ABCD"
    assert session.magic[0x1000] == "ELF executable"
    assert session.type_comments[0x1000] == "typed"
    assert session.source_lines[0x1000] == "demo.c:1"
    assert session.type_links[0x1000] == "int"
    assert session.no_return_marks == {0x2000}
    assert session.project_notes == "keep me"

    script = "\n".join(session.run("Pc snapshot"))
    for prefix in ("Pn ", "Ch ", "Cs ", "Cm ", "Ct ", "CL ", "tl ", "tn "):
        assert prefix in script, prefix


def test_json_default_maps_new_commands(monkeypatch, tmp_path):
    session, _ = make_session()
    target = tmp_path / "sig.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 8)
    session.info["target"] = str(target)
    session.json_default = True
    assert json.loads("\n".join(session.run("fn")))[0]["name"]
    assert json.loads("\n".join(session.run("b")))["blocksize"] == 256
    assert json.loads("\n".join(session.run("e*")))["asm.bytes"] is True
    assert json.loads("\n".join(session.run("iT")))[0]["name"] == "ELF executable"
    assert json.loads("\n".join(session.run("P")))["seek"] == 0x1000


def test_json_default_does_not_break_mutating_commands():
    session, _ = make_session()
    session.json_default = True
    session.run("b 0x20")
    assert session.blocksize == 0x20
    session.run("T message")
    assert json.loads("\n".join(session.run("T")))[0]["message"] == "message"
    session.readonly = False
    session.run("Ct typed")
    assert session.type_comments[0x1000] == "typed"


def test_elf_version_parser_reads_real_dynamic_symbols():
    target = Path(sys.executable)
    if not target.read_bytes().startswith(ELF_MAGIC):
        pytest.skip("test interpreter is not an ELF binary")
    rows = read_versions(target)
    if not rows:
        pytest.skip("test interpreter has no .gnu.version section")
    assert rows[0]["version"] == 0
    assert any(row["name"].startswith("GLIBC_") for row in rows if row["version"] >= 2)
