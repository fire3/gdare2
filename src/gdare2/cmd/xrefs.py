"""Cross-reference commands."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.errors import UnsupportedError
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
