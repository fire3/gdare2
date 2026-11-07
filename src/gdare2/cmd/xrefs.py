"""Cross-reference commands."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.errors import UsageError
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
