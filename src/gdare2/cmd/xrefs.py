"""Cross-reference commands."""

from __future__ import annotations

import fnmatch

from gdare2.cmd import command
from gdare2.errors import NotFuncError, UnsupportedError, UsageError
from gdare2.jsonutil import dumps


@command("axt", "list references to an address", aliases=("axtj",))
def _xrefs_to(session, statement):
    target = session.resolve(statement.args, default=session.seek)
    payload = session.call("xrefs_to", ea=target)
    session.warn_truncated("xref list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['from']))} {item.get('type', '')} -> {session.format_addr(int(item['to']))}"
        for item in payload
    ]


@command("axf", "list references from an address", aliases=("axfj",))
def _xrefs_from(session, statement):
    source = session.resolve(statement.args, default=session.seek)
    payload = session.call("xrefs_from", ea=source)
    session.warn_truncated("xref list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['from']))} {item.get('type', '')} -> {session.format_addr(int(item['to']))}"
        for item in payload
    ]


@command("afx", "list references from the current function", aliases=("afxj",))
def _function_xrefs(session, statement):
    payload = session.call("function_xrefs", ea=session.seek)
    session.warn_truncated("function xref list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['from']))} {item.get('type', '')} -> {session.format_addr(int(item['to']))}"
        for item in payload
    ]


def _all_xrefs(session):
    payload = session.call("xrefs_all")
    session.warn_truncated("xref list", len(payload))
    return payload


def _xref_opcode(reference_type: str) -> str:
    upper = reference_type.upper()
    if "CALL" in upper:
        return "axC"
    if "JUMP" in upper or "BRANCH" in upper:
        return "axc"
    return "axd"


@command("ax*", "list all references as r2 commands")
def _all_xref_commands(session, statement):
    return [
        f"{_xref_opcode(str(item.get('type', '')))} "
        f"{session.format_addr(int(item['from']))} "
        f"{session.format_addr(int(item['to']))}"
        for item in _all_xrefs(session)
    ]


@command("axlj", "list all references as JSON")
def _all_xrefs_json(session, statement):
    return [dumps(_all_xrefs(session))]


@command("axlq", "list all references quietly")
def _all_xrefs_quiet(session, statement):
    return [
        f"{session.format_addr(int(item['from']))} -> "
        f"{session.format_addr(int(item['to']))}  {str(item.get('type', '')).upper()}"
        for item in _all_xrefs(session)
    ]


@command("axlc", "count all references")
def _all_xrefs_count(session, statement):
    return [str(len(_all_xrefs(session)))]


@command("axj", "add jump reference (not supported)")
def _add_jump_reference(session, statement):
    raise UnsupportedError(
        "axj writes references in radare2; gdare2 is read-only for xrefs "
        "(use axlj/axlq/axlc/ax* to list)"
    )


def _ref_line(session, item) -> str:
    return (
        f"{session.format_addr(int(item['from']))} {item.get('type', '')} "
        f"-> {session.format_addr(int(item['to']))}"
    )


def _write_ref_error(cmd: str) -> UnsupportedError:
    return UnsupportedError(
        f"{cmd} writes references in radare2; gdare2 is read-only for xrefs "
        "(use axlj/axlq/axlc/ax* to list)"
    )


@command("ax", "list all references (ax <addr> form writes: not supported)", aliases=("axl",))
def _list_xrefs(session, statement):
    if statement.args.strip():
        # r2: "ax addr [at]" adds a code reference pointing at addr.
        raise _write_ref_error("ax")
    payload = _all_xrefs(session)
    session.load_flags()
    names: dict[int, str] = {}
    for flag in session.flag_store.all_values():
        names.setdefault(int(flag.addr), str(flag.name))
    rows = [
        (names.get(int(item["from"]), ""), int(item["from"]), str(item.get("type", "")), int(item["to"]))
        for item in payload
    ]
    width = max((len(name) for name, _, _, _ in rows), default=0)
    lines = []
    for name, src, reference_type, dst in rows:
        line = ""
        if width:
            line += f"{name:>{width}} "
        line += f"{session.format_addr(src)} > {reference_type} > {session.format_addr(dst)}"
        if dst in names:
            line += f" {names[dst]}"
        lines.append(line)
    return lines


@command("ax.", "find references from and to an address")
def _xrefs_around(session, statement):
    target = session.resolve(statement.args, default=session.seek)
    payload = session.call("xrefs_from", ea=target) + session.call("xrefs_to", ea=target)
    session.warn_truncated("xref list", len(payload))
    return [_ref_line(session, item) for item in payload]


@command("axq", "list references in quiet format")
def _xrefs_quiet(session, statement):
    return [
        f"{session.format_addr(int(item['from']))} -> "
        f"{session.format_addr(int(item['to']))}  {str(item.get('type', '')).upper()}"
        for item in _all_xrefs(session)
    ]


@command("axF", "find references to flags matching a glob")
def _flag_xrefs(session, statement):
    pattern = statement.args.strip()
    if not pattern:
        raise UsageError("axF needs a flag glob (e.g. axF sym.*)")
    session.load_flags()
    addresses: list[int] = []
    for flag in session.flag_store.all_values():
        if "*" in pattern or "?" in pattern or "[" in pattern:
            matched = fnmatch.fnmatchcase(str(flag.name), pattern)
        else:
            matched = pattern in str(flag.name)
        if matched and int(flag.addr) not in addresses:
            addresses.append(int(flag.addr))
    seen: set[tuple[int, int, str]] = set()
    lines = []
    for address in addresses:
        for item in session.call("xrefs_to", ea=address):
            key = (int(item["from"]), int(item["to"]), str(item.get("type", "")))
            if key in seen:
                continue
            seen.add(key)
            lines.append(_ref_line(session, item))
    session.warn_truncated("xref list", len(lines))
    return lines


AXG_MAX_DEPTH = 8
AXG_MAX_NODES = 128


def _containing_function(session, ea: int, cache: dict[int, dict | None]) -> dict | None:
    if ea not in cache:
        try:
            cache[ea] = session.call("function_at", ea=ea)
        except NotFuncError:
            cache[ea] = None
    return cache[ea]


def _axg_node(
    session,
    fcn: dict,
    state: dict,
    cache: dict[int, dict | None],
    path: frozenset[int],
    depth: int,
) -> dict:
    """Build one r2-style axgj node: {"type": "fcn", "fcn_addr", "name", "refs"}."""
    addr = int(fcn["addr"])
    node = {
        "type": "fcn",
        "fcn_addr": addr,
        "name": str(fcn.get("name") or ""),
        "refs": [],
    }
    state["count"] += 1
    if addr in path or depth >= AXG_MAX_DEPTH or state["count"] >= AXG_MAX_NODES:
        return node
    for item in session.call("xrefs_to", ea=addr):
        caller = _containing_function(session, int(item["from"]), cache)
        if caller is None:
            continue
        child = _axg_node(
            session, caller, state, cache, path | {addr}, depth + 1
        )
        node["refs"].append({str(int(item["from"])): child})
    return node


@command("axg", "show the xref graph reaching the current function", aliases=("axgj", "axg*"))
def _xref_graph(session, statement):
    target = session.resolve(statement.args, default=session.seek)
    cache: dict[int, dict | None] = {}
    root = _containing_function(session, target, cache)
    if root is None:
        # r2 renders an empty graph when the seek is outside any function.
        return [dumps({})] if statement.cmd == "axgj" else []
    state = {"count": 0}
    tree = _axg_node(session, root, state, cache, frozenset(), 0)
    if statement.cmd == "axgj":
        return [dumps({str(int(root["addr"])): tree})]
    nodes: list[str] = []
    edges: list[str] = []

    def walk(node: dict) -> None:
        name = node["name"]
        addr = session.format_addr(int(node["fcn_addr"]))
        nodes.append(f"'agn {addr} {name}" if name else f"'agn {addr}")
        for entry in node["refs"]:
            ((site, child),) = entry.items()
            edges.append(
                f"'age {session.format_addr(int(child['fcn_addr']))} {addr}"
            )
            walk(child)

    walk(tree)
    if statement.cmd == "axg*":
        return nodes + edges
    lines: list[str] = []

    def render(node: dict, site: int, depth: int) -> None:
        lines.append(
            f"{'  ' * depth}- {session.format_addr(site)} fcn "
            f"{session.format_addr(int(node['fcn_addr']))} {node['name']}"
        )
        for entry in node["refs"]:
            ((child_site, child),) = entry.items()
            render(child, int(child_site), depth + 1)

    render(tree, int(root["addr"]), 0)
    return lines


@command("axv", "list local variable read/write references")
def _variable_xrefs(session, statement):
    ea = session.resolve(statement.args, default=session.seek)
    lines: list[str] = []
    for header, kind in (("afvR", "r"), ("afvW", "w")):
        try:
            payload = session.call("variable_refs", ea=ea, kind=kind)
        except NotFuncError:
            return lines
        if not payload:
            continue
        lines.append(header)
        for variable in payload:
            addrs = " ".join(
                session.format_addr(int(ref)) for ref in variable.get("refs", [])
            )
            lines.append(f"{str(variable['name']):>10}  {addrs}".rstrip())
    return lines


@command("axff", "list references from the current function", aliases=("axffj",))
def _axff(session, statement):
    return _function_xrefs(session, statement)


def _ref_write_stub(session, statement):
    raise _write_ref_error(statement.cmd)


_WRITE_REF_COMMANDS = (
    ("axc", "add generic code reference (not supported)"),
    ("axC", "add code call reference (not supported)"),
    ("axd", "add data reference (not supported)"),
    ("axi", "add indirect code reference (not supported)"),
    ("axm", "copy references to the seek (not supported)"),
    ("axr", "add data-read reference (not supported)"),
    ("axs", "add string reference (not supported)"),
    ("axw", "add data-write reference (not supported)"),
    ("ax-", "clean references at an address (not supported)"),
    ("ax-*", "clean all references (not supported)"),
)
for _pattern, _summary in _WRITE_REF_COMMANDS:
    command(_pattern, _summary)(_ref_write_stub)


@command("axH", "not a radare2 6.x command")
def _axh(session, statement):
    raise UnsupportedError(
        "axH is not a radare2 6.x command (radare2 reports 'Invalid H subcommand, try ax?')"
    )
