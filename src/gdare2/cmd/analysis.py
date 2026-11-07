"""Analysis and function commands."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.errors import UsageError
from gdare2.jsonutil import dumps


@command("afl", "list functions", aliases=("aflj",))
def _functions(session, statement):
    payload = session.call("functions", limit=10000)
    session.warn_truncated("function list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['addr']))} {int(item['size']):5d} {item['name']}"
        for item in payload
    ]


@command("aflc", "count functions")
def _function_count(session, statement):
    payload = session.call("functions", limit=10000)
    return [str(len(payload))]


@command("afc", "list callers of the current function", aliases=("afcj",))
def _callers(session, statement):
    payload = session.call("function_callers", ea=session.seek)
    session.warn_truncated("caller list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [f"{session.format_addr(int(item['addr']))} {item['name']}" for item in payload]


@command("afC", "list functions called by the current function", aliases=("afCj",))
def _callees(session, statement):
    payload = session.call("function_callees", ea=session.seek)
    session.warn_truncated("callee list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [f"{session.format_addr(int(item['addr']))} {item['name']}" for item in payload]


@command("afi", "show function information at seek", aliases=("afij",))
def _function_info(session, statement):
    payload = session.call("function_at", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"name: {payload['name']}",
        f"addr: {session.format_addr(int(payload['addr']))}",
        f"size: {payload['size']}",
        f"end:  {session.format_addr(int(payload['end']))}",
        f"cc:   {payload.get('calling_convention') or ''}",
    ]


@command("af", "create a function at seek")
def _create_function(session, statement):
    if session.readonly:
        raise UsageError("writing requires -w")
    address = session.resolve(statement.args)
    payload = session.call("create_function", ea=address)
    session.seek_to(int(payload["addr"]))
    return []


@command("aa", "analyse the program if needed", aliases=("aaa",))
def _analyze(session, statement):
    payload = session.call("analyze", force=statement.cmd == "aaa")
    return [f"analysis: {payload.get('state')}"] if not session.config.get_bool("scr.null") else []


@command("afb", "list basic blocks of the current function", aliases=("afbj",))
def _blocks(session, statement):
    payload = session.call("basic_blocks", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"0x{int(block['start']):08x} 0x{int(block['end']):08x} "
        + " ".join(f"0x{int(item):08x}" for item in block.get("successors", []))
        for block in payload
    ]
