"""Analysis and function commands."""

from __future__ import annotations

import fnmatch

from gdare2.cmd import command, require_write
from gdare2.errors import UnsupportedError, UsageError
from gdare2.fmt.graph import format_ascii_graph, format_dot_callgraph, format_dot_graph
from gdare2.jsonutil import dumps


def _match_name(name: str, pattern: str) -> bool:
    if not pattern:
        return True
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(name, pattern)
    return pattern in name


@command("afl", "list functions", aliases=("aflj",))
def _functions(session, statement):
    payload, meta = session.call_with_meta("functions", **session.list_args(10000))
    session.warn_list_meta("function list", meta)
    pattern = statement.args.strip()
    if pattern:
        payload = [item for item in payload if _match_name(str(item["name"]), pattern)]
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['addr']))} {int(item['size']):5d} {item['name']}"
        for item in payload
    ]


@command("aflq", "list function addresses")
def _function_addresses(session, statement):
    payload, meta = session.call_with_meta("functions", **session.list_args(10000))
    session.warn_list_meta("function list", meta)
    pattern = statement.args.strip()
    if pattern:
        payload = [item for item in payload if _match_name(str(item["name"]), pattern)]
    return [session.format_addr(int(item["addr"])) for item in payload]


@command("afln", "list function names")
def _function_names(session, statement):
    payload, meta = session.call_with_meta("functions", **session.list_args(10000))
    session.warn_list_meta("function list", meta)
    return [str(item["name"]) for item in payload]


@command("afl+", "show the total function size")
def _function_size(session, statement):
    payload, meta = session.call_with_meta("functions", **session.list_args(10000))
    session.warn_list_meta("function list", meta)
    return [str(sum(int(item["size"]) for item in payload))]


@command("aflc", "count functions")
def _function_count(session, statement):
    payload, meta = session.call_with_meta("functions", limit=0)
    if meta.get("total") is not None:
        return [str(int(meta["total"]))]
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


@command("afv", "show decompiler variables for the current function", aliases=("afvj",))
def _function_variables(session, statement):
    payload = session.call(
        "function_variables",
        ea=session.seek,
        timeout=session.config.get_int("ghidra.decompile.timeout"),
    )
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    lines = [f"name: {payload['name']}", f"vars: {payload['variable_count']}"]
    for variable in payload.get("variables") or []:
        marker = "param" if variable.get("parameter") else "local"
        lines.append(
            f"var {variable.get('type', '')} {variable.get('name', '')} "
            f"@ {variable.get('storage', '')} "
            f"[{variable.get('kind', 'other')}/{marker}]"
        )
    return lines


@command("af", "create a function at seek", aliases=("aF",))
def _create_function(session, statement):
    require_write(session)
    address = session.resolve(statement.args)
    payload = session.call("create_function", ea=address)
    session.seek_to(int(payload["addr"]))
    return []


@command("afn", "rename the current function")
def _rename_function(session, statement):
    require_write(session)
    name = statement.args.strip()
    if not name:
        raise UsageError("afn needs a function name")
    payload = session.call("function_rename", ea=session.seek, name=name)
    return [f"{session.format_addr(int(payload['addr']))} {payload['name']}"]


@command("afu", "resize the current function through an address")
def _resize_function(session, statement):
    require_write(session)
    end = session.resolve(statement.args)
    payload = session.call("function_resize", ea=session.seek, end=end)
    return [
        f"{session.format_addr(int(payload['addr']))} "
        f"{session.format_addr(int(payload['end']))} {payload['name']}"
    ]


@command("a8", "analyze a hex byte array at seek")
def _analyze_bytes(session, statement):
    require_write(session)
    payload = session.call("analyze_bytes", ea=session.seek, hexpairs=statement.args)
    instruction = payload.get("instruction")
    text = instruction.get("text", "") if instruction else "no instruction"
    return [
        f"{session.format_addr(int(payload['addr']))} {payload['size']} "
        f"{bytes(payload.get('bytes', b'')).hex()} {text}"
    ]


@command("ad", "analyze data words at seek")
def _analyze_data(session, statement):
    require_write(session)
    args = statement.args.strip()
    count = int(args, 0) if args else 1
    payload = session.call("analyze_data", ea=session.seek, count=count)
    return [
        f"{session.format_addr(int(payload['addr']))} {payload['count']}x"
        f"{payload['word_size']} {payload['type']}"
    ]


@command("aa", "analyse the program if needed", aliases=("aaa",))
def _analyze(session, statement):
    payload = session.call("analyze", force=statement.cmd == "aaa")
    return [f"analysis: {payload.get('state')}"] if not session.config.get_bool("scr.null") else []


@command("afr", "reanalyze the current function")
def _reanalyze_function(session, statement):
    require_write(session)
    payload = session.call("function_reanalyze", ea=session.seek)
    return [f"{session.format_addr(int(payload['addr']))} {payload['name']}"]


def _variable_refs(session, statement, kind):
    name = statement.args.strip() or None
    payload = session.call("variable_refs", ea=session.seek, name=name, kind=kind)
    lines = []
    for variable in payload:
        for ref in variable.get("refs", []):
            lines.append(
                f"{session.format_addr(int(ref))} {variable['name']} "
                f"[{variable.get('kind', 'other')}]"
            )
    return lines


@command("afvR", "list variable read references")
def _variable_reads(session, statement):
    return _variable_refs(session, statement, "r")


@command("afvW", "list variable write references")
def _variable_writes(session, statement):
    return _variable_refs(session, statement, "w")


@command("an", "rename a function variable")
def _rename_variable(session, statement):
    require_write(session)
    parts = statement.args.split()
    if len(parts) != 2:
        raise UsageError("an needs an old and a new variable name")
    payload = session.call(
        "variable_rename", ea=session.seek, old=parts[0], new=parts[1]
    )
    return [f"{payload['old']} -> {payload['name']} @ {payload['storage']}"]


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


@command("ab", "show the current basic block", aliases=("abj",))
def _current_block(session, statement):
    payload = session.call("basic_block", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    successors = " ".join(
        session.format_addr(int(item)) for item in payload.get("successors", [])
    )
    return [
        f"{session.format_addr(int(payload['start']))} "
        f"{session.format_addr(int(payload['end']))} {successors}".rstrip()
    ]


@command("ao", "show instruction details", aliases=("aoj",))
def _instruction_info(session, statement):
    payload = session.call("instruction_info", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    lines = [
        f"addr:  {session.format_addr(int(payload['addr']))}",
        f"size:  {payload['size']}",
        f"bytes: {bytes(payload.get('bytes', b'')).hex()}",
        f"text:  {payload.get('text', '')}",
        f"flow:  {payload.get('flow', '')}",
    ]
    for reference in payload.get("references") or []:
        lines.append(
            f"xref:  {session.format_addr(int(reference['from']))} -> "
            f"{session.format_addr(int(reference['to']))} {reference.get('type', '')}"
        )
    return lines


@command("ai", "show address information", aliases=("aij",))
def _address_info(session, statement):
    payload = session.call("address_info", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    lines = [
        f"addr:  {session.format_addr(int(payload['addr']))}",
        f"mapped: {str(bool(payload.get('mapped'))).lower()}",
        f"perms: {payload.get('block', {}).get('perms', '---') if payload.get('block') else '---'}",
    ]
    block = payload.get("block")
    function = payload.get("function")
    instruction = payload.get("instruction")
    if block:
        lines.append(
            f"block: {block.get('name', '')} "
            f"{session.format_addr(int(block['addr']))}-"
            f"{session.format_addr(int(block['end']))}"
        )
    if function:
        lines.append(
            f"func:  {function.get('name', '')} "
            f"{session.format_addr(int(function['addr']))}"
        )
    if instruction:
        lines.append(f"insn:  {instruction.get('text', '')}")
    return lines


@command("agf", "show the function control-flow graph", aliases=("agfj", "agfd"))
def _graph(session, statement):
    payload = session.call("graph", ea=session.seek)
    if statement.cmd == "agfj":
        return [dumps(payload)]
    if statement.cmd == "agfd":
        return format_dot_graph(payload)
    return format_ascii_graph(payload, session.config, int(session.info.get("bits") or 32))


@command("ag", "render the current function graph as DOT")
def _graph_dot(session, statement):
    payload = session.call("graph", ea=session.seek)
    return format_dot_graph(payload)


@command("agC", "show the call graph of the current function", aliases=("agCj", "agCd"))
def _call_graph(session, statement):
    args = statement.args.strip()
    try:
        depth = int(args, 0) if args else 1
    except ValueError:
        raise UsageError("agC needs a numeric depth") from None
    if depth < 0:
        raise UsageError("agC depth must not be negative")
    payload = session.call("call_graph", ea=session.seek, depth=depth)
    if statement.cmd == "agCd":
        return format_dot_callgraph(payload)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    nodes = {int(node["addr"]): node for node in payload.get("nodes") or []}
    lines = []
    for addr in sorted(nodes):
        node = nodes[addr]
        marker = " (external)" if node.get("external") else ""
        lines.append(f"{session.format_addr(addr)} {node['name']}{marker}")
    for edge in payload.get("edges") or []:
        source = nodes.get(int(edge["src"])) or {"name": f"0x{int(edge['src']):x}"}
        target = nodes.get(int(edge["dst"])) or {"name": f"0x{int(edge['dst']):x}"}
        lines.append(f"{source['name']} -> {target['name']}")
    return lines


@command("agd", "render the function graph as DOT (not supported)")
def _graph_dot_unsupported(session, statement):
    raise UnsupportedError("agd is not implemented; use agfd for the DOT function graph")


@command("agj", "render the function graph as JSON (not supported)")
def _graph_json_unsupported(session, statement):
    raise UnsupportedError("agj is not implemented; use agfj for the JSON function graph")


@command("ag*", "render graphs as commands for scripting (not supported)")
def _graph_commands_unsupported(session, statement):
    raise UnsupportedError("ag* is not implemented; use agCj/agCd")


@command("ag-", "delete a graph node (not supported)")
def _graph_delete_unsupported(session, statement):
    raise UnsupportedError("ag- is not implemented; graphs are derived from the function model")


@command("agR", "render the global reference graph (not supported)")
def _graph_refs_unsupported(session, statement):
    raise UnsupportedError("agR is not implemented; no global reference graph")


@command("agX", "export graphs to a file (not supported)")
def _graph_export_unsupported(session, statement):
    raise UnsupportedError("agX is not implemented; use agCd > file.dot to export DOT")
