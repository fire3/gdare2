"""Meta commands: help, config, version, quit."""

from __future__ import annotations

from gdare2 import __version__, registry
from gdare2.cmd import command, help_text, require_write
from gdare2.errors import UsageError
from gdare2.jsonutil import dumps


@command("?", "show command help or evaluate an expression")
def _help(session, statement):
    args = statement.args.strip()
    if not args:
        return help_text()
    value = session.eval(args)
    return [str(value)]


@command("?V", "show gdare2 and daemon versions")
def _version(session, statement):
    health = session.info
    return [f"gdare2 {__version__}", f"ghidra {health.get('ghidra_version', 'unknown')}"]


@command("e", "get or set configuration", aliases=("ej",))
def _config(session, statement):
    args = statement.args.strip()
    if statement.cmd.endswith("j") and not args:
        return [dumps({name: value for name, value in session.config.items()})]
    if not args:
        return [f"{name} = {value}" for name, value in session.config.items()]
    if "=" in args:
        name, _, value = args.partition("=")
        session.config.set(name.strip(), value.strip())
        return []
    return [str(session.config.get(args))]


@command("e?", "list configuration keys", aliases=("e??",))
def _config_keys(session, statement):
    return [f"{name} = {value}" for name, value in session.config.items()]


@command("L", "list live gdare2 daemon instances")
def _list_daemons(session, statement):
    states = registry.live_instances()
    if not states:
        return ["no live gdare2 instances"]
    lines = ["instance          pid     port   state    readonly  target"]
    for state in states:
        health = state.get("health", {})
        lines.append(
            f"{state['instance_id']:<17} {state.get('pid', 0):<7} "
            f"{state.get('port', 0):<6} {health.get('state', '?'):<8} "
            f"{str(bool(state.get('readonly'))):<9} {state.get('target', '')}"
        )
    return lines


@command("q", "quit", aliases=("q!",))
def _quit(session, statement):
    session.quit_requested = True
    return []


@command(".g", "show daemon and program information")
def _dot_g(session, statement):
    keys = (
        "instance_id",
        "state",
        "target",
        "program",
        "project",
        "language",
        "compiler",
        "arch",
        "bits",
        "endian",
        "image_base",
        "entry",
        "function_count",
        "readonly",
    )
    return [f"{key}: {session.info.get(key)}" for key in keys]


@command(".gstatus", "show daemon status as JSON")
def _dot_status(session, statement):
    return [dumps(session.info)]


@command(".gsave", "save the Ghidra program")
def _dot_save(session, statement):
    require_write(session)
    session.commit_write_cache()
    session.call("save")
    return []


@command(".gsync", "refresh daemon information and flags")
def _dot_sync(session, statement):
    payload = session.call("info")
    session.info.update(payload)
    session.invalidate_flags()
    session.setup()
    return []


@command(".ganalyze", "run analysis and report the result")
def _dot_analyze(session, statement):
    force = statement.args.strip().lower() in ("all", "aaa")
    payload = session.call("analyze", force=force)
    return [f"analysis: {payload.get('state')}"]


@command(".gexec", "execute Python inside the daemon")
def _dot_exec(session, statement):
    if not session.allow_exec:
        raise UsageError("re-run with --allow-exec to enable .gexec")
    require_write(session)
    code = statement.args.strip()
    if not code:
        raise UsageError(".gexec needs Python code")
    payload = session.call("exec_python", code=code)
    return str(payload.get("output", "")).rstrip().splitlines()


@command(".ghelp", "list gdare2 extension commands")
def _dot_help(session, statement):
    from gdare2.cmd import all_commands

    return [
        f"{spec.pattern:<10} {spec.summary}"
        for spec in all_commands()
        if spec.pattern.startswith(".")
    ]


@command(".gclose", "close the daemon")
def _dot_close(session, statement):
    session.client.shutdown(save=not session.readonly)
    session.quit_requested = True
    return []
