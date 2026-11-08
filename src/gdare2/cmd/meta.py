"""Meta commands: help, config, version, quit."""

from __future__ import annotations

from gdare2 import __version__
from gdare2.cmd import command, help_text, require_write
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


@command("e", "get or set configuration")
def _config(session, statement):
    args = statement.args.strip()
    if not args:
        return [f"{name} = {value}" for name, value in session.config.items()]
    if "=" in args:
        name, _, value = args.partition("=")
        session.config.set(name.strip(), value.strip())
        return []
    return [str(session.config.get(args))]


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


@command(".gclose", "close the daemon")
def _dot_close(session, statement):
    session.client.shutdown(save=not session.readonly)
    session.quit_requested = True
    return []
