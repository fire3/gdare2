from __future__ import annotations

import contextlib
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
        except (OSError, ValueError, KeyError):
            continue
        _stop_process(pid)


def _stop_process(pid: int, grace: float = 10.0) -> None:
    """Terminate a daemon and wait for exit so JVMs do not pile up."""
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


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

    segments = run(env, "-a", "x86", "-b", "64", "-B", "0x400000", "-qc", "iSS", str(target))
    assert segments.returncode != 0
    assert "not an ELF file" in segments.stderr


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
    assert "9090" in hex_lines[0]
    assert "4142" in hex_lines[1]

    masked = run(
        env,
        *base_args,
        "-w",
        "-qc",
        "s 0x400000; wx 90?f; px 2; .gclose",
        str(target),
    )
    assert masked.returncode == 0, masked.stderr
    assert "904f" in masked.stdout


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


def test_loader_arguments_are_validated(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x90\x90\xc3\xcc")

    ok = run(
        env,
        "--ephemeral",
        "-a",
        "x86",
        "-b",
        "64",
        "--loader-arg",
        "-loader-fileOffset",
        "0",
        "-qc",
        "iI",
        str(target),
    )
    assert ok.returncode == 0, ok.stderr

    bad_arg = run(
        env,
        "--ephemeral",
        "-a",
        "x86",
        "-b",
        "64",
        "--loader-arg",
        "-loader-nope",
        "1",
        "-qc",
        "iI",
        str(target),
    )
    assert bad_arg.returncode == 2
    assert "unknown loader argument" in bad_arg.stderr

    bad_loader = run(
        env,
        "--ephemeral",
        "-a",
        "x86",
        "-b",
        "64",
        "--loader",
        "NopeLoader",
        "-qc",
        "iI",
        str(target),
    )
    assert bad_loader.returncode == 2
    assert "unknown loader" in bad_loader.stderr


def test_flags_create_rename_delete_and_persist(env):
    target = "/bin/ls"
    first = run(env, "-qc", "iI", target)
    assert first.returncode == 0, first.stderr

    created = run(
        env,
        "-w",
        "-qc",
        "e ghidra.flags.write=true; s entry; f demo_flag 4; .gsave; .gclose",
        target,
    )
    assert created.returncode == 0, created.stderr

    listed = run(env, "-qc", "fq; f? demo_flag", target)
    assert listed.returncode == 0, listed.stderr
    assert "demo_flag" in listed.stdout.splitlines()
    assert listed.stdout.splitlines()[-1] == "1"

    renamed = run(
        env,
        "-w",
        "-qc",
        "e ghidra.flags.write=true; fr demo_flag demo_renamed; .gsave; .gclose",
        target,
    )
    assert renamed.returncode == 0, renamed.stderr

    renamed_list = run(env, "-qc", "f? demo_renamed; f? demo_flag", target)
    assert renamed_list.returncode == 0, renamed_list.stderr
    assert renamed_list.stdout.splitlines() == ["1", "0"]

    deleted = run(
        env,
        "-w",
        "-qc",
        "e ghidra.flags.write=true; f- demo_renamed; .gsave; .gclose",
        target,
    )
    assert deleted.returncode == 0, deleted.stderr

    after_delete = run(env, "-qc", "f? demo_renamed", target)
    assert after_delete.returncode == 0, after_delete.stderr
    assert after_delete.stdout.strip() == "0"


def test_assembly_integer_and_base64_writes(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x90\x90\xc3\xcc")
    args = ["-a", "x86", "-b", "64", "-B", "0x400000"]

    assembled = run(env, *args, "-qc", "pa NOP", str(target))
    assert assembled.returncode == 0, assembled.stderr
    assert assembled.stdout.strip()

    written = run(
        env,
        *args,
        "-w",
        "-qc",
        "s 0x400000; wa NOP; .gsave",
        str(target),
    )
    assert written.returncode == 0, written.stderr

    integer = run(
        env,
        *args,
        "-w",
        "-qc",
        "s 0x400000; wi4 0x12345678; .gsave",
        str(target),
    )
    assert integer.returncode == 0, integer.stderr

    read_back = run(env, *args, "-qc", "wi4 @ 0x400000", str(target))
    assert read_back.returncode == 0, read_back.stderr
    assert read_back.stdout.strip() == "0x12345678"

    base64_write = run(
        env,
        *args,
        "-w",
        "-qc",
        "s 0x400000; w6d QUI=; .gsave",
        str(target),
    )
    assert base64_write.returncode == 0, base64_write.stderr

    dump = run(env, *args, "-qc", "px 2 @ 0x400000", str(target))
    assert dump.returncode == 0, dump.stderr
    assert "4142" in dump.stdout


def test_function_reanalysis_and_variable_commands(env):
    target = "/bin/ls"
    first = run(env, "-qc", "iI", target)
    assert first.returncode == 0, first.stderr

    variables = run(env, "-j", "-qc", "s entry; afvj", target)
    assert variables.returncode == 0, variables.stderr
    payload = json.loads(variables.stdout)
    if not payload.get("variables"):
        pytest.skip("main has no decompiler variables")
    name = payload["variables"][0]["name"]

    reads = run(env, "-qc", f"s entry; afvR {name}", target)
    assert reads.returncode == 0, reads.stderr
    writes = run(env, "-qc", f"s entry; afvW {name}", target)
    assert writes.returncode == 0, writes.stderr

    renamed = run(
        env,
        "-w",
        "-qc",
        f"s entry; an {name} renamed_var; .gsave",
        target,
    )
    assert renamed.returncode == 0, renamed.stderr

    after = run(env, "-j", "-qc", "s entry; afvj", target)
    assert after.returncode == 0, after.stderr
    names = [item["name"] for item in json.loads(after.stdout)["variables"]]
    assert "renamed_var" in names

    reanalyzed = run(env, "-w", "-qc", "s entry; afr; .gsave", target)
    assert reanalyzed.returncode == 0, reanalyzed.stderr
    assert "entry" in reanalyzed.stdout


def test_gexec_requires_client_and_daemon_opt_in(env):
    target = "/bin/ls"
    first = run(env, "-qc", "iI", target)
    assert first.returncode == 0, first.stderr

    client_denied = run(
        env,
        "-w",
        "-qc",
        ".gexec print(program.getName())",
        target,
    )
    assert client_denied.returncode == 1
    assert "--allow-exec" in client_denied.stderr

    daemon_denied = run(
        env,
        "--allow-exec",
        "-w",
        "-qc",
        ".gexec print(program.getName())",
        target,
    )
    assert daemon_denied.returncode == 1
    assert "disabled" in daemon_denied.stderr or "allow-exec" in daemon_denied.stderr

    run(env, "-qc", ".gclose", target)
    runtime = Path(env["XDG_RUNTIME_DIR"]) / f"gdare2-{os.getuid()}"
    deadline = time.monotonic() + 30
    while list(runtime.glob("*.json")) and time.monotonic() < deadline:
        time.sleep(0.1)
    allowed = run(
        env,
        "--allow-exec",
        "-w",
        "-qc",
        ".gexec print(program.getName())",
        target,
    )
    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.strip() == "ls"


def test_izz_pattern_assembly_and_raw_search(env, tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x90HELLO\x00\xc3")
    args = ["-a", "x86", "-b", "64", "-B", "0x400000"]

    first = run(env, *args, "-qc", "iI", str(target))
    assert first.returncode == 0, first.stderr

    izz = run(env, *args, "-qc", "izz~HELLO", str(target))
    assert izz.returncode == 0, izz.stderr
    assert "HELLO" in izz.stdout

    pattern = run(env, *args, "-qc", "/p 48454c4c4f", str(target))
    assert pattern.returncode == 0, pattern.stderr
    assert "0x0000000000400001" in pattern.stdout

    assembled = run(env, *args, "-qc", "/a NOP", str(target))
    assert assembled.returncode == 0, assembled.stderr
    assert "0x0000000000400000" in assembled.stdout

    raw = run(
        env,
        *args,
        "-e",
        "search.in=raw",
        "-qc",
        "/x 48454c4c4f",
        str(target),
    )
    assert raw.returncode == 0, raw.stderr
    assert "0x0000000000000001" in raw.stdout


def test_segments_typed_reads_and_json_filter(env):
    from gdare2.formats.elf import read_segments

    target = "/bin/ls"
    segments = read_segments(target)

    segments_json = run(env, "-j", "-qc", "iSSj", target)
    assert segments_json.returncode == 0, segments_json.stderr
    payload = json.loads(segments_json.stdout)
    assert len(payload) == len(segments)
    assert set(payload[0]) >= {"name", "size", "vsize", "perm", "paddr", "vaddr"}

    segments_text = run(env, "-qc", "iSS", target)
    assert segments_text.returncode == 0, segments_text.stderr
    assert len(segments_text.stdout.splitlines()) == len(segments) + 1

    sections_text = run(env, "-qc", "iS", target)
    assert sections_text.returncode == 0, sections_text.stderr
    assert sections_text.stdout != segments_text.stdout

    info = run(env, "-j", "-qc", "iI", target)
    assert info.returncode == 0, info.stderr
    entry = int(json.loads(info.stdout)["entry"])

    typed = run(
        env,
        "-qc",
        f"s 0x{entry:x}; tp int; tpv int; tpx int f30f1efa",
        target,
    )
    assert typed.returncode == 0, typed.stderr
    assert "ERROR" not in typed.stderr
    assert "size=4" in typed.stdout

    tc_int = run(env, "-qc", "tc int", target)
    assert tc_int.returncode == 0, tc_int.stderr
    assert tc_int.stdout.strip()
    assert "typedef unsigned char" not in tc_int.stdout

    tc_struct = run(env, "-qc", "tc Elf64_Ehdr", target)
    assert tc_struct.returncode == 0, tc_struct.stderr
    assert "struct Elf64_Ehdr" in tc_struct.stdout
    assert "typedef unsigned char" not in tc_struct.stdout

    full = run(env, "-qc", "aflj", target)
    assert full.returncode == 0, full.stderr
    filtered = run(env, "-qc", "aflj~entry", target)
    assert filtered.returncode == 0, filtered.stderr
    assert len(filtered.stdout.splitlines()) < len(full.stdout.splitlines())
    assert '"name": "entry"' in filtered.stdout


def test_meta_commands_and_iterator_skip(env):
    target = "/bin/ls"

    file_info = run(env, "-qc", "i", target)
    assert file_info.returncode == 0, file_info.stderr
    assert "file" in file_info.stdout
    assert target in file_info.stdout

    info_json = run(env, "-j", "-qc", "i", target)
    assert info_json.returncode == 0, info_json.stderr
    assert json.loads(info_json.stdout)["program"]

    functions = run(env, "-qc", "afl", target)
    addresses = run(env, "-qc", "aflq", target)
    assert addresses.returncode == 0, addresses.stderr
    assert len(addresses.stdout.splitlines()) == len(functions.stdout.splitlines())
    assert all(line.startswith("0x") for line in addresses.stdout.splitlines())

    config_json = run(env, "-j", "-qc", "e", target)
    assert config_json.returncode == 0, config_json.stderr
    assert "asm.bytes" in json.loads(config_json.stdout)
    config_keys = run(env, "-qc", "e?", target)
    assert "asm.bytes" in config_keys.stdout

    instances = run(env, "-qc", "L", target)
    assert instances.returncode == 0, instances.stderr
    assert "instance" in instances.stdout
    assert target in instances.stdout

    iteration = run(env, "-qc", "pd 1 @@F", target)
    assert iteration.returncode == 0, iteration.stderr
    assert "no instruction at or after" not in iteration.stderr
    # G17 filters external/thunk entries, so @@F no longer has skips.
    assert "WARN: skipped" not in iteration.stderr

    sections = run(env, "-qc", "px 4 @@S", target)
    assert sections.returncode == 0, sections.stderr
    assert "ERROR" not in sections.stderr

    full_functions = run(env, "-j", "-qc", "afl", target)
    page_functions = run(env, "-j", "--list-offset", "10", "-qc", "afl", target)
    assert page_functions.returncode == 0, page_functions.stderr
    assert json.loads(page_functions.stdout) == json.loads(full_functions.stdout)[10:]

    full_symbols = run(env, "-qc", "is", target)
    page_symbols = run(env, "--list-offset", "20", "-qc", "is", target)
    assert page_symbols.returncode == 0, page_symbols.stderr
    assert page_symbols.stdout.splitlines() == full_symbols.stdout.splitlines()[20:]

    rejected = run(env, "-o", "0", "-qc", "iI", target)
    assert rejected.returncode == 2
    assert "file-offset" in rejected.stderr

    coloured = run(env, "-qc", "e scr.color=1; pd 1 @ entry", target)
    assert "\x1b[" in coloured.stdout
    plain = run(env, "-qc", "e scr.color=0; pd 1 @ entry", target)
    assert "\x1b[" not in plain.stdout
    annotated = run(env, "-qc", "e asm.comments=true; pd 1 @ entry", target)
    assert ";-- entry:" in annotated.stdout
    gutter = run(env, "-qc", "e asm.lines=true; pd 1 @ entry", target)
    assert "│" in gutter.stdout
    no_flags = run(env, "-qc", "e asm.flags=false; pdi 1 @ entry", target)
    assert "entry" not in no_flags.stdout
