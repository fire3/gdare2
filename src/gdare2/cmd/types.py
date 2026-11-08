"""Data type and function signature commands."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.jsonutil import dumps


@command("t", "list or inspect types", aliases=("tj",))
def _types(session, statement):
    return _type_query(session, statement, None)


@command("ts", "list or inspect structures", aliases=("tsj",))
def _structs(session, statement):
    return _type_query(session, statement, "struct")


@command("tu", "list or inspect unions", aliases=("tuj",))
def _unions(session, statement):
    return _type_query(session, statement, "union")


@command("te", "list or inspect enums", aliases=("tej",))
def _enums(session, statement):
    return _type_query(session, statement, "enum")


@command("tt", "list or inspect typedefs", aliases=("ttj",))
def _typedefs(session, statement):
    return _type_query(session, statement, "typedef")


def _type_query(session, statement, kind):
    name = statement.args.strip() or None
    if name:
        payload = session.call("types", kind=kind, name=name)
        if statement.cmd.endswith("j"):
            return [dumps(payload)]
        return _format_detail(session, payload)
    payload = session.call("types", kind=kind, limit=10000)
    session.warn_truncated("type list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{item['name']:<40} {int(item['length']):6d} {item['kind']}"
        for item in payload
    ]


def _format_detail(session, payload):
    lines = [
        f"name: {payload['name']}",
        f"path: {payload['path']}",
        f"kind: {payload['kind']}",
        f"size: {payload['length']}",
    ]
    if payload.get("base_type"):
        lines.append(f"base: {payload['base_type']}")
    if payload.get("prototype"):
        lines.append(f"proto: {payload['prototype']}")
    for component in payload.get("components") or []:
        lines.append(
            f"+{int(component['offset']):04x} {int(component['length']):4d} "
            f"{component['type']} {component['name']}"
        )
    for value in payload.get("values") or []:
        lines.append(f"{int(value['value']):#x} {value['name']}")
    return lines


@command("tf", "list or inspect function signatures", aliases=("tfj",))
def _signatures(session, statement):
    name = statement.args.strip() or None
    payload = session.call("function_signatures", name=name, limit=10000)
    session.warn_truncated("signature list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['addr']))} {item['signature']}"
        for item in payload
    ]
