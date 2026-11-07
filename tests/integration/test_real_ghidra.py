from __future__ import annotations

import json
import os
import re
import signal
import time
import subprocess
import sys

import pytest

pytestmark = pytest.mark.real_ghidra


@pytest.fixture()
def env(tmp_path):
    values = os.environ.copy()
    values["GDARE2_DATA_DIR"] = str(tmp_path / "data")
    values.setdefault("GHIDRA_INSTALL_DIR", os.path.expanduser("~/ghidra/current"))
    values["XDG_RUNTIME_DIR"] = str(tmp_path / "run")
    yield values
    runtime = tmp_path / "run" / f"gdare2-{os.getuid()}"
    for state_file in runtime.glob("*.json"):
        try:
            pid = int(json.loads(state_file.read_text())["pid"])
            os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError, KeyError):
            continue
    time.sleep(0.3)


def run(env, *args, timeout=240):
    return subprocess.run(
        [sys.executable, "-m", "gdare2", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


def test_import_disasm_and_reuse(env):
    target = "/bin/ls"
    first = run(env, "-qc", "iI; pd 3; px 16", target)
    assert first.returncode == 0, first.stderr
    assert "x86" in first.stdout
    assert "0x0000000000" in first.stdout
    assert "MOV" in first.stdout.upper() or "XOR" in first.stdout.upper()

    second = run(env, "-qc", "pd 1", target)
    assert second.returncode == 0, second.stderr
    assert "import" not in second.stderr.lower()


def test_filter_redirect_and_json(env, tmp_path):
    target = "/bin/ls"
    out = tmp_path / "pd.txt"
    result = run(env, "-j", "-qc", f"pd 20~+call; pdfj > {out}", target)
    assert result.returncode == 0, result.stderr
    assert out.read_text().strip().startswith("{")


def test_raw_binary_base_and_disassembly(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x90\x90\xc3\xcc")
    result = run(env, "-a", "x86", "-b", "64", "-B", "0x400000", "-qc", "iI; pd 2", str(target))
    assert result.returncode == 0, result.stderr
    assert "0x0000000000400000" in result.stdout
    assert "0x0000000000400000" in result.stdout
    assert "NOP" in result.stdout.upper()


def test_batch_function_iteration(env):
    target = "/bin/ls"
    info = run(env, "-j", "-qc", "iI", target)
    assert info.returncode == 0, info.stderr
    entry = int(json.loads(info.stdout)["entry"])
    function = run(env, "-j", "-qc", f"afij @ 0x{entry:x}", target)
    assert function.returncode == 0, function.stderr
    name = json.loads(function.stdout)["name"]

    result = run(
        env,
        "-qc",
        f"s 0x{entry:x}; pd 1 @@f:^{re.escape(name)}$; pd 1 @@i; pd 1 @@b; pd 1 @@=0x{entry:x}",
        target,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("0x") >= 4
    assert "ERROR:" not in result.stderr


def test_graph_and_address_info(env):
    target = "/bin/ls"
    info = run(env, "-j", "-qc", "iI", target)
    assert info.returncode == 0, info.stderr
    entry = int(json.loads(info.stdout)["entry"])

    ascii_graph = run(env, "-qc", f"s 0x{entry:x}; agf", target)
    assert ascii_graph.returncode == 0, ascii_graph.stderr
    assert "[0x" in ascii_graph.stdout

    json_graph = run(env, "-qc", f"s 0x{entry:x}; agfj", target)
    assert json_graph.returncode == 0, json_graph.stderr
    payload = json.loads(json_graph.stdout)
    assert payload["blocks"]
    assert "edges" in payload

    dot = run(env, "-qc", f"s 0x{entry:x}; agfd", target)
    assert dot.returncode == 0, dot.stderr
    assert dot.stdout.startswith("digraph")

    details = run(env, "-qc", f"s 0x{entry:x}; ab; ao; ai", target)
    assert details.returncode == 0, details.stderr
    assert "flow:" in details.stdout
    assert "mapped: true" in details.stdout


def test_function_writes_are_gated_and_persist(env):
    target = "/bin/ls"
    info = run(env, "-j", "-qc", "iI", target)
    assert info.returncode == 0, info.stderr
    entry = int(json.loads(info.stdout)["entry"])
    instruction = run(env, "-j", "-qc", f"aoj @ 0x{entry:x}", target)
    assert instruction.returncode == 0, instruction.stderr
    end = entry + int(json.loads(instruction.stdout)["size"]) - 1

    denied = run(env, "-qc", f"s 0x{entry:x}; afn should_not_apply", target)
    assert denied.returncode == 1
    assert "read-only" in denied.stderr.lower()

    name = "gdare2_m2_renamed_test"
    written = run(
        env,
        "-w",
        "-qc",
        f"s 0x{entry:x}; afn {name}; afu 0x{end:x}; .gsave; .gclose",
        target,
    )
    assert written.returncode == 0, written.stderr
    time.sleep(0.5)

    verify = run(env, "-qc", f"afi @ {name}", target)
    assert verify.returncode == 0, verify.stderr
    assert name in verify.stdout
    resized = run(env, "-j", "-qc", f"afij @ 0x{entry:x}", target)
    assert resized.returncode == 0, resized.stderr
    assert int(json.loads(resized.stdout)["end"]) == end


def test_manual_analysis_writes_persist(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\xcc" * 16)
    base_args = ("-a", "x86", "-b", "64", "-B", "0x400000")

    denied = run(env, *base_args, "-qc", "a8 9090c3", str(target))
    assert denied.returncode == 1
    assert "read-only" in denied.stderr.lower()

    written = run(
        env,
        *base_args,
        "-w",
        "-qc",
        "s 0x400000; a8 9090c3; pd 2; ad 1; .gsave; .gclose",
        str(target),
    )
    assert written.returncode == 0, written.stderr
    assert "NOP" in written.stdout
    assert "1x8 qword" in written.stdout
    time.sleep(0.5)

    verify = run(env, *base_args, "-qc", "px 5", str(target))
    assert verify.returncode == 0, verify.stderr
    assert "90 90 c3" in verify.stdout


def test_decompile_and_variables(env):
    target = "/bin/ls"
    info = run(env, "-j", "-qc", "iI", target)
    assert info.returncode == 0, info.stderr
    entry = int(json.loads(info.stdout)["entry"])

    source = run(env, "-qc", f"s 0x{entry:x}; pdc", target)
    assert source.returncode == 0, source.stderr
    assert "{" in source.stdout and "}" in source.stdout

    variables = run(env, "-j", "-qc", f"s 0x{entry:x}; afvj", target)
    assert variables.returncode == 0, variables.stderr
    payload = json.loads(variables.stdout)
    assert payload["name"]
    assert payload["variable_count"] == len(payload["variables"])
