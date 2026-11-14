"""rasm2 fallback backend and the assembler command wiring."""

from __future__ import annotations

import json

import pytest
from test_session import FakeClient, make_session

from gdare2 import assembler
from gdare2.errors import RemoteError, UnsupportedError, UsageError


def _script(tmp_path, output: str = "9090", exit_code: int = 0):
    args_file = tmp_path / "args.json"
    path = tmp_path / "rasm2"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"open({str(args_file)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        f"print({output!r})\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path, args_file


def _session(tmp_path, *, arch="x86", bits=64, mode="rasm2", output="9090"):
    session, client = make_session()
    session.info.update({"arch": arch, "bits": bits})
    path, args_file = _script(tmp_path, output)
    session.config.set("asm.assembler", mode)
    session.config.set("asm.rasm2", str(path))
    return session, client, args_file


def test_pa_uses_rasm2_and_maps_x86(tmp_path):
    session, _, args_file = _session(tmp_path)
    assert session.run("pa mov eax, 1") == ["9090"]
    assert json.loads(args_file.read_text()) == ["-a", "x86", "-b", "64", "mov eax, 1"]


def test_rasm2_big_endian_arch_arguments(tmp_path):
    session, _, args_file = _session(tmp_path, arch="armbe", bits=32)
    assert session.run("pa add r0, r1, r2") == ["9090"]
    assert json.loads(args_file.read_text()) == [
        "-a",
        "arm",
        "-b",
        "32",
        "-e",
        "add r0, r1, r2",
    ]


def test_rasm2_maps_canonical_elf_architecture_names(tmp_path):
    session, _, args_file = _session(tmp_path, arch="ARM", bits=32)
    session.info["endian"] = "little"
    assert session.run("pa mov r0, 1") == ["9090"]
    assert json.loads(args_file.read_text()) == ["-a", "arm", "-b", "32", "mov r0, 1"]

    session, _, args_file = _session(tmp_path, arch="ARM", bits=32)
    session.info["endian"] = "big"
    assert session.run("pa mov r0, 1") == ["9090"]
    assert json.loads(args_file.read_text()) == [
        "-a",
        "arm",
        "-b",
        "32",
        "-e",
        "mov r0, 1",
    ]

    session, _, args_file = _session(tmp_path, arch="AARCH64", bits=64)
    session.info["endian"] = "little"
    assert session.run("pa ret") == ["9090"]
    assert json.loads(args_file.read_text()) == ["-a", "arm", "-b", "64", "ret"]


def test_wa_variants_write_and_seek(tmp_path):
    session, client, _ = _session(tmp_path)
    session.readonly = False
    assert session.run("wa nop") == ["0x0000000000001000 9090 nop"]
    assert (
        "write_bytes",
        {"allow_writes": True, "ea": 0x1000, "data": b"\x90\x90"},
    ) in client.calls

    assert session.run("wa* nop") == ["wx 9090 @ 0x0000000000001000"]
    session.run("wa+ nop")
    assert session.seek == 0x1002


def test_search_assembly_uses_the_configured_backend(tmp_path):
    session, client, _ = _session(tmp_path)
    lines = session.run("/a nop")
    assert any("0x0000000000001000" in line for line in lines)
    search_call = [call for call in client.calls if call[0] == "search"][-1]
    assert search_call[1]["data"] == b"\x90\x90"


def test_asm_assembler_config_validation(tmp_path):
    session, _, _ = _session(tmp_path, mode="bogus")
    session.run("pa nop")
    assert session.failed
    assert "ghidra, rasm2 or auto" in str(session.last_error)

    session, _, _ = _session(tmp_path)
    session.info["arch"] = "mystery"
    session.run("pa nop")
    assert session.failed
    assert isinstance(session.last_error, UnsupportedError)
    assert "no architecture mapping" in str(session.last_error)


def test_rasm2_failures_are_explicit(tmp_path):
    session, _, _ = _session(tmp_path, output="not-hex")
    session.run("pa nop")
    assert session.failed
    assert "rasm2 failed" in str(session.last_error)

    session, _, _ = _session(tmp_path, output="9090")
    session.config.set("asm.rasm2", "/nonexistent/rasm2")
    session.run("pa nop")
    assert session.failed
    assert "rasm2 not found" in str(session.last_error)


def test_auto_falls_back_and_warns(tmp_path, capsys):
    class NoAssembler(FakeClient):
        def call(self, op, **args):
            if op in ("assemble", "assemble_write"):
                raise RemoteError("NOT_SUPPORTED", "no SLEIGH assembler")
            return super().call(op, **args)

    session, _, _ = _session(tmp_path, mode="auto")
    session.client = NoAssembler()
    assert session.run("pa nop") == ["9090"]
    assert "fallback to rasm2" in capsys.readouterr().err


def test_auto_propagates_the_original_error_when_rasm2_also_fails(tmp_path):
    class NoAssembler(FakeClient):
        def call(self, op, **args):
            if op in ("assemble", "assemble_write"):
                raise RemoteError("NOT_SUPPORTED", "no SLEIGH assembler")
            return super().call(op, **args)

    session, _, _ = _session(tmp_path, mode="auto", output="bad")
    session.client = NoAssembler()
    session.run("pa nop")
    assert session.failed
    assert "no SLEIGH assembler" in str(session.last_error)


def test_empty_assembly_text_is_rejected(tmp_path):
    session, _, _ = _session(tmp_path)
    with pytest.raises(UsageError, match="assembly text"):
        assembler.rasm2_assemble(session, 0x1000, "  \n ")
