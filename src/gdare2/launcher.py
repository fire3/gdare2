"""Spawn and attach to a gdare2 daemon."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from gdare2 import registry
from gdare2.argv import Options
from gdare2.client import check_protocol
from gdare2.errors import ConnectionFailure, RemoteError


def import_options(options: Options) -> dict[str, Any]:
    return {
        "arch": options.arch,
        "bits": options.bits,
        "base": options.base,
        "endian": options.endian,
        "ghidra_language": options.ghidra_language,
        "compiler": options.compiler,
        "loader": options.loader,
        "loader_args": options.loader_args,
        "force_language": options.force_language,
        "force_base": options.force_base,
        "no_analysis": options.no_analysis,
        "analyze": options.analyze,
    }


def attach(options: Options) -> dict[str, Any]:
    if options.attach == "auto":
        state = registry.find_any_live()
        if state is None:
            raise ConnectionFailure("--attach auto needs exactly one live gdare2 instance")
    else:
        state = registry.live_instance(str(options.attach))
        if state is None:
            raise ConnectionFailure(f"no live gdare2 instance {options.attach!r}")
    health = state.get("health", {})
    check_protocol(health)
    return state


def ensure(options: Options) -> dict[str, Any]:
    if options.attach:
        return attach(options)
    if not options.file:
        raise ConnectionFailure("a target file is required unless --attach is used")

    target = str(Path(options.file).expanduser())
    ingest_id = registry.instance_id(target, import_options=import_options(options))
    live = registry.live_instance(ingest_id)
    if live is not None:
        check_protocol(live.get("health", {}))
        return live
    if not options.spawn:
        raise ConnectionFailure(f"no live daemon for target; --no-spawn forbids starting one")

    with registry.spawn_lock(ingest_id):
        live = registry.live_instance(ingest_id)
        if live is not None:
            check_protocol(live.get("health", {}))
            return live
        registry.remove_state(ingest_id)
        _spawn(options, target, ingest_id)
        return _wait_for_ready(options, ingest_id)


def _spawn(options: Options, target: str, ingest_id: str) -> None:
    project_parent = Path(options.project) if options.project else registry.data_dir() / "projects" / ingest_id
    project_parent.mkdir(parents=True, exist_ok=True)
    project_name = options.project_name or registry.project_name(target, ingest_id)
    program = options.program or "/" + Path(target).name

    command = [
        sys.executable,
        "-m",
        "gdare2d",
        "--foreground",
        "--target",
        target,
        "--project",
        str(project_parent),
        "--project-name",
        project_name,
        "--program",
        program,
        "--instance-id",
        ingest_id,
    ]
    if options.no_analysis:
        command.append("--no-analysis")
    if options.arch:
        command += ["-a", options.arch]
    if options.bits:
        command += ["-b", options.bits]
    if options.base:
        command += ["-B", options.base]
    if options.endian:
        command += ["--endian", options.endian]
    if options.ghidra_language:
        command += ["--ghidra-language", options.ghidra_language]
    if options.compiler:
        command += ["--compiler", options.compiler]
    if options.loader:
        command += ["--loader", options.loader]
    for key, value in options.loader_args:
        command += ["--loader-arg", key, value]
    if options.force_language:
        command.append("--force-language")
    if options.force_base:
        command.append("--force-base")
    if options.reimport:
        command.append("--reimport")
    if options.linger is not None:
        command += ["--linger", str(options.linger)]
    if options.idle is not None:
        command += ["--idle", str(options.idle)]
    if options.ephemeral:
        command.append("--ephemeral")
    if options.listen:
        command += ["--listen", options.listen]
    if options.save_on_close is True:
        command.append("--save-on-close")
    elif options.save_on_close is False:
        command.append("--no-save-on-close")

    log = registry.log_path(ingest_id)
    handle = log.open("ab")
    env = os.environ.copy()
    if not env.get("GHIDRA_INSTALL_DIR"):
        candidate = Path.home() / "ghidra" / "current"
        if candidate.exists():
            env["GHIDRA_INSTALL_DIR"] = str(candidate)
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
            cwd=str(Path.cwd()),
        )
    finally:
        handle.close()


def _wait_for_ready(options: Options, ingest_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + (options.startup_timeout or 180.0)
    last_state = "starting"
    last_state_data: dict[str, Any] | None = None
    missing_since: float | None = None
    while time.monotonic() < deadline:
        state = registry.read_state(ingest_id)
        if state is not None:
            missing_since = None
            last_state_data = state
            last_state = str(state.get("state", "starting"))
            if not registry.pid_alive(int(state.get("pid", 0))):
                break
            health = registry.health(int(state.get("port", 0)), str(state.get("host") or ""))
            if health is not None:
                if health.get("state") == "ready":
                    state["health"] = health
                    state["state"] = "ready"
                    check_protocol(health)
                    return state
                if health.get("state") == "error":
                    break
        else:
            # A daemon that dies before writing state removes its entry; do
            # not spin until the full startup timeout.
            missing_since = missing_since or time.monotonic()
            if time.monotonic() - missing_since > 2.0:
                break
        time.sleep(0.1)
    tail = _log_tail(ingest_id)
    final_state = registry.read_state(ingest_id) or last_state_data
    if final_state and final_state.get("error"):
        code = str(final_state.get("error_code") or "CONNECTION")
        message = f"daemon failed to start: {final_state['error']}"
        # User/configuration errors are already actionable; only append the
        # daemon log tail for unexpected failures.
        if code not in {"BAD_ARGS", "NOT_READY", "READONLY", "NOT_FOUND", "NOT_FUNC"}:
            message += tail
        raise RemoteError(code, message)
    detail = f" (state={last_state})" if last_state else ""
    raise ConnectionFailure(f"gdare2 daemon failed to become ready{detail}{tail}")


def _log_tail(ingest_id: str, lines: int = 20) -> str:
    try:
        text = registry.log_path(ingest_id).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    tail = text.splitlines()[-lines:]
    return "\n" + "\n".join(tail) if tail else ""
