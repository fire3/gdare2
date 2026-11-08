"""gdare2 daemon entry point."""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import signal
import sys
import threading
import time
from pathlib import Path

from gdare2 import registry
from gdare2d.executor import Executor
from gdare2d.import_plan import build as build_import_plan
from gdare2d.runtime import GhidraRuntime
from gdare2d.server import GdarHTTPServer, Handler


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="gdare2d")
    result.add_argument("--foreground", action="store_true")
    result.add_argument("--target", required=True)
    result.add_argument("--project")
    result.add_argument("--project-name")
    result.add_argument("--program")
    result.add_argument("--instance-id")
    result.add_argument("--readonly", action="store_true", default=False)
    result.add_argument("--write", dest="readonly", action="store_false")
    result.add_argument("--no-analysis", action="store_true")
    result.add_argument("--analysis-timeout", type=float, default=180.0)
    result.add_argument("--log-level", default="info")
    result.add_argument("--log-file")
    result.add_argument("--linger", type=float, default=3600.0)
    result.add_argument("--idle", type=float)
    result.add_argument("--save-on-close", dest="save_on_close", action="store_true", default=True)
    result.add_argument("--no-save-on-close", dest="save_on_close", action="store_false")
    result.add_argument("--ephemeral", action="store_true")
    result.add_argument("--listen", default="127.0.0.1")
    result.add_argument("--port", type=int, default=0)
    result.add_argument("-a", "--arch")
    result.add_argument("-b", "--bits")
    result.add_argument("-B", "-m", "--base", dest="base")
    result.add_argument("--endian")
    result.add_argument("--ghidra-language")
    result.add_argument("--compiler")
    result.add_argument("--loader")
    result.add_argument("--loader-arg", nargs=2, action="append", default=[])
    result.add_argument("--force-language", action="store_true")
    result.add_argument("--force-base", action="store_true")
    result.add_argument("--reimport", action="store_true")
    result.add_argument("--allow-exec", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )
    target = str(Path(args.target).expanduser().resolve())
    ingest_id = args.instance_id or registry.instance_id(
        target,
        import_options={
            "arch": args.arch,
            "bits": args.bits,
            "base": args.base,
            "endian": args.endian,
            "ghidra_language": args.ghidra_language,
            "compiler": args.compiler,
            "loader": args.loader,
            "loader_args": args.loader_arg,
            "force_language": args.force_language,
            "force_base": args.force_base,
            "no_analysis": args.no_analysis,
        },
    )
    project_dir = args.project or str(registry.data_dir() / "projects" / ingest_id)
    project_name = args.project_name or registry.project_name(target, ingest_id)
    program_path = args.program or "/" + Path(target).name
    try:
        plan = build_import_plan(
            target,
            arch=args.arch,
            bits=args.bits,
            base=args.base,
            endian=args.endian,
            ghidra_language=args.ghidra_language,
            compiler=args.compiler,
            loader=args.loader,
            loader_args=args.loader_arg,
            force_language=args.force_language,
            force_base=args.force_base,
        )
    except Exception as exc:
        print(f"gdare2d: {exc}", file=sys.stderr)
        return 2

    runtime = GhidraRuntime(
        target=target,
        project_dir=project_dir,
        project_name=project_name,
        program_path=program_path,
        plan=plan,
        analyze=not args.no_analysis,
        reanalyze=False,
        reimport=args.reimport,
        readonly=args.readonly,
        save_on_close=args.save_on_close,
        ephemeral=args.ephemeral,
        analysis_timeout=args.analysis_timeout,
        ghidra_install=os.environ.get("GHIDRA_INSTALL_DIR"),
    )
    runtime.instance_id = ingest_id
    runtime.pid = os.getpid()
    executor = Executor(runtime)
    token = secrets.token_urlsafe(32)
    server = GdarHTTPServer((args.listen, args.port), Handler, token=token, runtime=runtime, executor=executor)
    port = int(server.server_address[1])
    runtime.port = port
    state = {
        "instance_id": ingest_id,
        "pid": os.getpid(),
        "port": port,
        "token": token,
        "target": target,
        "host": args.listen,
        "project_dir": project_dir,
        "project_name": project_name,
        "program": program_path,
        "state": "starting",
        "started_at": server.started_at,
        "version": __import__("gdare2").__version__,
        "protocol": 1,
        "readonly": args.readonly,
        "ephemeral": args.ephemeral,
        "log": str(registry.log_path(ingest_id)),
    }
    registry.write_state(state)

    stop_event = threading.Event()

    def request_stop(*_args) -> None:
        stop_event.set()
        state["state"] = "draining"
        registry.write_state(state)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    _start_watchdog(server, args.idle if args.idle is not None else args.linger)
    executor.start()
    threading.Thread(
        target=_stop_on_bootstrap_failure,
        args=(executor, server, runtime, state),
        name="gdare2-bootstrap",
        daemon=True,
    ).start()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        executor.stop()
        if runtime.error:
            # Give a waiting client time to read the error state/code before
            # the registry entry disappears.
            time.sleep(1.5)
        registry.remove_state(ingest_id)
    return 1 if executor.failed else 0


def _start_watchdog(server: GdarHTTPServer, idle_seconds: float) -> None:
    if idle_seconds <= 0:
        return

    def watch() -> None:
        while not server.shutting_down.is_set():
            if server.runtime.state == "ready" and not server.runtime.has_active_sessions() and (
                __import__("time").monotonic() - server.last_activity > idle_seconds
            ):
                server.shutdown()
                return
            __import__("time").sleep(min(5.0, max(0.5, idle_seconds / 4)))

    threading.Thread(target=watch, name="gdare2-idle", daemon=True).start()


def _stop_on_bootstrap_failure(
    executor: Executor,
    server: GdarHTTPServer,
    runtime: GhidraRuntime,
    state: dict,
) -> None:
    executor.ready.wait()
    state["state"] = runtime.state
    if runtime.error:
        state["error"] = runtime.error
        state["error_code"] = runtime.error_code
    registry.write_state(state)
    if executor.failed:
        server.shutdown()


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
