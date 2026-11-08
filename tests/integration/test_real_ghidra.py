from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.real_ghidra


@pytest.fixture()
def env(tmp_path):
    values = os.environ.copy()
    values["GDARE2_DATA_DIR"] = str(tmp_path / "data")
    values.setdefault("GHIDRA_INSTALL_DIR", os.path.expanduser("~/ghidra/current"))
    values["XDG_RUNTIME_DIR"] = str(tmp_path / "run")
    values["HOME"] = str(tmp_path / "home")
    values["XDG_CONFIG_HOME"] = str(tmp_path / "config")
    values["XDG_STATE_HOME"] = str(tmp_path / "state")
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


def test_types_and_function_signatures(env):
    target = "/bin/ls"
    types = run(env, "-qc", "t~int", target)
    assert types.returncode == 0, types.stderr
    assert "int" in types.stdout

    structs = run(env, "-j", "-qc", "tsj", target)
    assert structs.returncode == 0, structs.stderr
    assert isinstance(json.loads(structs.stdout), list)

    signatures = run(env, "-qc", "tf~entry", target)
    assert signatures.returncode == 0, signatures.stderr
    assert "entry" in signatures.stdout


def test_type_define_c_output_and_signature_write(env):
    target = "/bin/ls"
    info = run(env, "-j", "-qc", "iI", target)
    assert info.returncode == 0, info.stderr
    entry = int(json.loads(info.stdout)["entry"])
    function = run(env, "-j", "-qc", f"afij @ 0x{entry:x}", target)
    assert function.returncode == 0, function.stderr
    name = json.loads(function.stdout)["name"]

    type_name = "gdare2_m3_struct"
    declaration = f"struct {type_name} {{ int field; char text[8]; }};"
    defined = run(
        env,
        "-w",
        "-qc",
        f"td '{declaration}'; .gsave; .gclose",
        target,
    )
    assert defined.returncode == 0, defined.stderr
    assert type_name in defined.stdout
    time.sleep(0.5)

    c_output = run(env, "-qc", f"tc {type_name}", target)
    assert c_output.returncode == 0, c_output.stderr
    assert "struct" in c_output.stdout
    assert "field" in c_output.stdout

    function_type = "gdare2_m3_fn_type"
    deleted = run(
        env,
        "-w",
        "-qc",
        f"td 'int {function_type}(int value);'; tf- {function_type}; .gsave; .gclose",
        target,
    )
    assert deleted.returncode == 0, deleted.stderr
    assert f"removed {function_type}" in deleted.stdout

    signature = f"int {name}(int value)"
    applied = run(
        env,
        "-w",
        "-qc",
        f"s 0x{entry:x}; afs '{signature}'; .gsave; .gclose",
        target,
    )
    assert applied.returncode == 0, applied.stderr
    time.sleep(0.5)

    verify = run(env, "-j", "-qc", f"afsj @ 0x{entry:x}", target)
    assert verify.returncode == 0, verify.stderr
    payload = json.loads(verify.stdout)
    assert name in payload["signature"]
    assert payload["parameters"][0]["name"] == "value"


def test_comments_are_gated_and_persist(env):
    target = "/bin/ls"
    info = run(env, "-j", "-qc", "iI", target)
    assert info.returncode == 0, info.stderr
    entry = int(json.loads(info.stdout)["entry"])

    denied = run(env, "-qc", f"s 0x{entry:x}; CC should_not_apply", target)
    assert denied.returncode == 1
    assert "read-only" in denied.stderr.lower()

    written = run(
        env,
        "-w",
        "-qc",
        f"s 0x{entry:x}; CC gdare2-comment; Cp gdare2-plate; .gsave; .gclose",
        target,
    )
    assert written.returncode == 0, written.stderr
    time.sleep(0.5)

    comments = run(env, "-qc", f"s 0x{entry:x}; C.", target)
    assert comments.returncode == 0, comments.stderr
    assert "gdare2-comment" in comments.stdout
    assert "gdare2-plate" in comments.stdout


def test_byte_writes_are_gated_and_persist(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\xcc" * 16)
    base_args = ("-a", "x86", "-b", "64", "-B", "0x400000")

    denied = run(env, *base_args, "-qc", "wx 9090", str(target))
    assert denied.returncode == 1
    assert "read-only" in denied.stderr.lower()
    assert "-w" in denied.stderr

    written = run(
        env,
        *base_args,
        "-w",
        "-qc",
        "s 0x400000; wx 9090; .gsave; .gclose",
        str(target),
    )
    assert written.returncode == 0, written.stderr
    time.sleep(0.5)

    verify = run(env, *base_args, "-qc", "px 2", str(target))
    assert verify.returncode == 0, verify.stderr
    assert "90 90" in verify.stdout


def test_write_cache_undo_redo_and_masks(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\xcc" * 16)
    base_args = ("-a", "x86", "-b", "64", "-B", "0x400000")

    cached = run(
        env,
        *base_args,
        "-w",
        "-qc",
        "e io.cache=true; s 0x400000; wx 4142; wc; wc+; px 2; .gclose",
        str(target),
    )
    assert cached.returncode == 0, cached.stderr
    assert "4142" in cached.stdout
    assert "41 42" in cached.stdout
    time.sleep(0.5)

    history = run(
        env,
        *base_args,
        "-w",
        "-qc",
        "s 0x400000; wx 9090; wx 4142; u; px 2; U; px 2; .gclose",
        str(target),
    )
    assert history.returncode == 0, history.stderr
    lines = history.stdout.splitlines()
    hex_lines = [line for line in lines if line.startswith("0x0000000000400000")]
    assert "90 90" in hex_lines[0]
    assert "41 42" in hex_lines[1]

    masked = run(
        env,
        *base_args,
        "-w",
        "-qc",
        "s 0x400000; wx 90?f; px 2; .gclose",
        str(target),
    )
    assert masked.returncode == 0, masked.stderr
    assert "90 4f" in masked.stdout


def test_rc_loading_and_skip(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x90\xc3")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gdare2rc").write_text("e scr.color=7\n", encoding="utf-8")
    config_home = tmp_path / "config"
    config_home.mkdir()
    values = dict(env)
    values["HOME"] = str(home)
    values["XDG_CONFIG_HOME"] = str(config_home)
    base_args = ("-a", "x86", "-b", "64", "-B", "0x400000")

    loaded = run(values, *base_args, "-qc", "e scr.color", str(target))
    assert loaded.returncode == 0, loaded.stderr
    assert loaded.stdout.strip() == "7"

    skipped = run(values, *base_args, "-N", "-qc", "e scr.color", str(target))
    assert skipped.returncode == 0, skipped.stderr
    assert skipped.stdout.strip() == "0"


def test_memory_search_variants_and_history(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(
        b"\xcc\x90\x90\xcc\x90\x90\x11\x22hello\x00" + "hi".encode("utf-16-le")
    )
    base_args = ("-a", "x86", "-b", "64", "-B", "0x400000")

    history = run(
        env,
        *base_args,
        "-qc",
        "s 0x400000; /x 9090; //; /-",
        str(target),
    )
    assert history.returncode == 0, history.stderr
    assert history.stdout.splitlines() == [
        "0x0000000000400001",
        "0x0000000000400004",
        "0x0000000000400004",
        "0x0000000000400001",
    ]

    variants = run(
        env,
        *base_args,
        "-qc",
        "s 0x400000; /xj 9090",
        str(target),
    )
    assert variants.returncode == 0, variants.stderr
    payload = json.loads(variants.stdout)
    assert payload["hits"] == [0x400001, 0x400004]

    found = run(
        env,
        *base_args,
        "-qc",
        "s 0x400000; / hello; s 0x400000; /w hi; s 0x400000; /v2 0x2211",
        str(target),
    )
    assert found.returncode == 0, found.stderr
    lines = found.stdout.splitlines()
    assert "0x0000000000400008" in lines
    assert "0x000000000040000E" in lines or "0x000000000040000e" in lines
    assert "0x0000000000400006" in lines


def _wait_for_health(env, instance, timeout=90):
    runtime = Path(env["XDG_RUNTIME_DIR"]) / f"gdare2-{os.getuid()}"
    state_file = runtime / f"{instance}.json"
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            state = json.loads(state_file.read_text())
            with urllib.request.urlopen(
                f"http://127.0.0.1:{state['port']}/health", timeout=1
            ) as response:
                health = json.loads(response.read())
            if health.get("state") in ("ready", "error"):
                return health, state
        except (OSError, ValueError, KeyError) as exc:
            last_error = exc
        time.sleep(0.2)
    raise AssertionError(f"daemon did not become ready: {last_error}")


def test_readonly_daemon_exposes_state_and_rejects_writes(env):
    target = "/bin/ls"
    first = run(env, "-qc", "iI", target)
    assert first.returncode == 0, first.stderr

    runtime = Path(env["XDG_RUNTIME_DIR"]) / f"gdare2-{os.getuid()}"
    state = json.loads(next(runtime.glob("*.json")).read_text())
    instance = state["instance_id"]

    closed = run(env, "-qc", ".gclose", target)
    assert closed.returncode == 0, closed.stderr

    state_file = runtime / f"{instance}.json"
    deadline = time.monotonic() + 30
    while state_file.exists() and time.monotonic() < deadline:
        time.sleep(0.1)

    daemon = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gdare2d",
            "--foreground",
            "--target",
            target,
            "--readonly",
            "--linger",
            "30",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        health, state = _wait_for_health(env, instance)
        assert health["state"] == "ready", health
        assert state["state"] == "ready"

        info = run(env, "--attach", instance, "-qc", ".g")
        assert info.returncode == 0, info.stderr
        assert f"instance_id: {instance}" in info.stdout
        assert "state: ready" in info.stdout

        denied = run(env, "--attach", instance, "-w", "-qc", "s entry; wx 90")
        assert denied.returncode == 1
        assert "read-only" in denied.stderr
        assert "-w" in denied.stderr
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=20)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=5)
