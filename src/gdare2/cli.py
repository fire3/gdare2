"""gdare2 command-line entry point."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from collections.abc import Iterable
from pathlib import Path

from gdare2 import __version__, argv, completion, rc, registry
from gdare2.client import Client
from gdare2.config import Config
from gdare2.errors import GdarError, UsageError
from gdare2.launcher import ensure
from gdare2.r2pipe_server import serve_r2pipe
from gdare2.session import Session


def main(argv_list: list[str] | None = None) -> int:
    client = None
    lease = None
    heartbeat_stop = None
    history_file = None
    try:
        options = argv.parse(sys.argv[1:] if argv_list is None else argv_list)
    except UsageError as exc:
        print(f"gdare2: {exc}", file=sys.stderr)
        return exc.exit_code

    if options.show_help:
        _print_help()
        return 0
    if options.show_version:
        print(f"gdare2 {__version__} (protocol 1)")
        return 0
    if options.list_sessions:
        return _list_sessions()
    if options.kill:
        return _kill(options.kill)
    if options.status:
        return _status(options.status)

    for flag, reason in options.ignored:
        if options.quiet == 0:
            print(f"WARN: {flag} ignored: {reason}", file=sys.stderr)

    try:
        state = ensure(options)
        config = Config()
        _apply_cli_config(config, options, auto_colour=True)
        if config.get_bool("cfg.sandbox"):
            options.readonly = True
        timeout = options.timeout or float(config.get_int("ghidra.timeout"))
        client = Client(state, timeout=timeout)
        lease = client.call(
            "session_open",
            pid=os.getpid(),
            kind="interactive" if sys.stdin.isatty() else "batch",
            tty=sys.stdin.isatty(),
            ttl=90,
        )["lease"]
        heartbeat_stop = _start_heartbeat(client, lease)
        info = client.call("info")
        info["readonly"] = options.readonly
        session = Session(
            client,
            info,
            config,
            readonly=options.readonly,
            allow_exec=options.allow_exec,
        )
        session.json_default = options.json

        _run_rc(session, options)
        _apply_cli_config(config, options)
        client.timeout = options.timeout or float(config.get_int("ghidra.timeout"))
        _analysis_request(session, options)
        if options.seek:
            session.seek_to(session.eval(options.seek))

        if options.quiet == 0:
            print(f"gdare2 {__version__} - {info.get('program')} [{info.get('language')}]")
            print(f"project: {info.get('project_dir')}  pid: {state.get('pid')}")

        commands = _command_lines(options)

        pipe_server = None
        if options.pipe_listen:
            pipe_server = serve_r2pipe(session, _pipe_address(options.pipe_listen))
            if options.quiet == 0:
                print(f"r2pipe listening on {options.pipe_listen}")

        if commands:
            for command in commands:
                _emit(session.run(command))
        elif pipe_server is None and not sys.stdin.isatty():
            for line in sys.stdin:
                line = line.rstrip("\n")
                if line and not line.lstrip().startswith("#"):
                    _emit(session.run(line))
                    if session.quit_requested:
                        break
        elif pipe_server is None:
            history_file = completion.setup_readline(session)
            _repl(session, quiet=options.quiet)

        if pipe_server is not None:
            _wait_r2pipe(pipe_server)

        if options.ephemeral:
            client.shutdown(save=not options.readonly)
            _wait_for_daemon_exit(state)
        return 1 if session.failed else 0
    except GdarError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    finally:
        completion.save_history(history_file)
        if heartbeat_stop is not None:
            heartbeat_stop.set()
        if client is not None and lease is not None:
            with contextlib.suppress(GdarError):
                client.call("session_close", lease=lease)


def _wait_r2pipe(server) -> None:
    """Block until a client sends ``q``/``q!`` or the server is interrupted."""
    try:
        while not server.closed.is_set() and not server.session.quit_requested:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown_and_close()


def _pipe_address(spec: str) -> tuple[str, int]:
    host, _, port_text = spec.rpartition(":")
    return (host or "127.0.0.1"), int(port_text)


def _wait_for_daemon_exit(state: dict, timeout: float = 60.0) -> None:
    """Give an ephemeral daemon time to flush and remove its project."""
    pid = int(state.get("pid") or 0)
    deadline = time.monotonic() + timeout
    while pid and time.monotonic() < deadline:
        if not _process_running(pid):
            return
        time.sleep(0.1)


def _apply_cli_config(config: Config, options: argv.Options, *, auto_colour: bool = False) -> None:
    """Apply command-line configuration after rc evaluation.

    Explicit CLI values win over rc-file values.  ``auto_colour`` is only used
    for the first pass so a TTY default does not override an rc setting.
    """
    if options.assembler is not None:
        config.set("asm.assembler", options.assembler)
    for key, value in options.evals:
        config.set(key, value)
    if options.color is not None:
        config.set("scr.color", options.color)
    elif auto_colour and sys.stdout.isatty() and not options.json and not os.environ.get("NO_COLOR"):
        config.set("scr.color", 1)
    if options.list_offset is not None:
        config.set("list.offset", options.list_offset)


def _process_running(pid: int) -> bool:
    """Treat a zombie child as stopped; the CLI is usually its parent."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return registry.pid_alive(pid)
    _, _, rest = stat.rpartition(")")
    fields = rest.split()
    return bool(fields) and fields[0] not in {"Z", "X", "x"}


def _command_lines(options: argv.Options) -> list[str]:
    commands: list[str] = []
    for script in options.pre_scripts:
        commands.extend(_read_script(script))
    commands.extend(options.commands)
    for script in options.post_scripts:
        commands.extend(_read_script(script))
    return commands


def _analysis_request(session: Session, options: argv.Options) -> None:
    """Honour r2's -A/-AA: analyze now, before running commands/scripts."""
    if options.analyze <= 0:
        return
    if session.config.get_str("ghidra.analysis.wait") == "skip":
        return
    command = "aaa" if options.analyze >= 2 else "aa"
    lines = session.run(command)
    if options.quiet == 0:
        _emit(lines)


def _run_rc(session: Session, options: argv.Options) -> None:
    lines = rc.load(options.skip_rc)
    if not lines:
        return
    failed, last_error = session.failed, session.last_error
    quitting = session.quit_requested
    for line in lines:
        _emit(session.run(line))
    session.failed = failed
    session.last_error = last_error
    session.quit_requested = quitting


def _start_heartbeat(client: Client, lease: str, *, ttl: int = 90) -> threading.Event:
    stop = threading.Event()

    def beat() -> None:
        while not stop.wait(max(10, ttl // 3)):
            try:
                client.call("session_heartbeat", lease=lease, ttl=ttl)
            except GdarError:
                return

    threading.Thread(target=beat, name="gdare2-heartbeat", daemon=True).start()
    return stop


def _repl(session: Session, *, quiet: int) -> None:
    while not session.quit_requested:
        try:
            line = input(f"[{session.format_addr(session.seek)}]> ")
        except EOFError:
            break
        except KeyboardInterrupt:
            print()
            continue
        if not line.strip():
            continue
        _emit(session.run(line))


def _emit(lines: Iterable[str]) -> None:
    for line in lines:
        print(line)
    sys.stdout.flush()


def _read_script(path: str) -> list[str]:
    try:
        return [
            line.strip()
            for line in Path(path).expanduser().read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError as exc:
        raise UsageError(f"cannot read script {path}: {exc}") from exc


def _list_sessions() -> int:
    states = registry.live_instances()
    if not states:
        print("no live gdare2 instances")
        return 0
    print("instance          pid     port   state    readonly  target")
    for state in states:
        health = state.get("health", {})
        print(
            f"{state['instance_id']:<17} {state.get('pid', 0):<7} "
            f"{state.get('port', 0):<6} {health.get('state', '?'):<8} "
            f"{str(bool(state.get('readonly'))):<9} {state.get('target', '')}"
        )
    return 0


def _kill(ingest_id: str) -> int:
    state = registry.live_instance(ingest_id)
    if state is None:
        print(f"gdare2: no live instance {ingest_id!r}", file=sys.stderr)
        return 3
    try:
        Client(state).shutdown(save=False)
    except GdarError as exc:
        print(f"gdare2: {exc}", file=sys.stderr)
        return exc.exit_code
    return 0


def _status(ingest_id: str) -> int:
    state = registry.live_instance(ingest_id)
    if state is None:
        print(f"gdare2: no live instance {ingest_id!r}", file=sys.stderr)
        return 3
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


def _print_help() -> None:
    print(
        """Usage: gdare2 [target] [options] [-c command]...

Core options:
  -a <arch>              raw-binary Ghidra language alias
  -b <bits>              raw-binary bit width (16, 32, 64)
  -B, -m <addr>          raw-binary load address
  -c <command>           run command (repeatable)
  -e <key=value>         set configuration (repeatable)
  -j                     JSON output where available
  -L                     list live daemon instances
  -n                     skip automatic analysis on first import
  -q, -qq                quiet, extra quiet
  -s <addr>              initial seek
  -w                     allow write operations

Daemon options:
  --attach <id|auto>     attach to an existing daemon
  --no-spawn             never start a daemon
  --project <dir>        Ghidra project parent directory
  --project-name <name>  Ghidra project name
  --ghidra-language <id> exact Ghidra language ID
  --compiler <id>        compiler spec ID
  --loader <name>        loader class name
  --loader-arg K V       extra loader argument (repeatable)
  --endian big|little    raw-binary endianness
  --ephemeral            close and delete the project after the command
  --kill <id>            ask a daemon to exit
  --status <id>          print daemon state as JSON

Commands: s, b, pd, pdf, px, p8, pv, ps, iI, iS, is, ii, ie, iz,
          afl, afi, af, aa, axt, axf, sb, sf, sF, so, sn, sp, e, q, ?
Run `<command>?` for per-command help."""
    )


if __name__ == "__main__":
    raise SystemExit(main())
