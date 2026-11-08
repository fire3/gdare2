"""Data type and function signature commands."""

from __future__ import annotations

from gdare2.cmd import command, require_write
from gdare2.cmd.write import parse_hexpairs
from gdare2.errors import UsageError
from gdare2.escape import unquote_text
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


def _type_request(session, statement) -> tuple[str, int]:
    text = statement.args.strip()
    if not text:
        raise UsageError(f"{statement.cmd} needs a type name")
    address = session.seek
    if statement.tmpseek is None:
        parts = text.rsplit(None, 1)
        if len(parts) == 2:
            try:
                address = session.eval(parts[1])
                text = parts[0]
            except Exception:
                pass
    return text, address


def _format_typed(session, payload, *, with_addr: bool) -> list[str]:
    prefix = ""
    if with_addr and payload.get("addr") is not None:
        prefix = f"{session.format_addr(int(payload['addr']))} "
    lines = [
        f"{prefix}{payload['name']} size={int(payload['length'])} "
        f"count={int(payload['count'])}"
    ]
    values = payload.get("values")
    if values is not None:
        for value in values:
            if isinstance(value, dict):
                name = f" {value['name']}" if value.get("name") else ""
                lines.append(f"  {int(value['value']):#x}{name}")
            else:
                lines.append(f"  {int(value):#x} ({int(value)})")
    else:
        lines.append(f"  {bytes(payload.get('bytes', b'')).hex()}")
    return lines


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


@command("td", "define C types from a declaration")
def _define_type(session, statement):
    require_write(session)
    text = unquote_text(statement.args)
    if not text:
        raise UsageError("td needs a C type declaration")
    payload = session.call("type_define", decl=text)
    return [
        f"{payload['name']} {payload['kind']} size={payload['length']}",
        str(payload.get("declaration", "")).rstrip(),
    ]


@command("tc", "print types in C declaration format", aliases=("tcj",))
def _type_c(session, statement):
    name = statement.args.strip() or None
    payload = session.call("type_c", name=name, limit=10000)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    if isinstance(payload, dict):
        return [str(payload.get("declaration", "")).rstrip()]
    lines = []
    for item in payload:
        lines.append(str(item.get("declaration", "")).rstrip())
    return lines


@command("tfc", "print function signatures in C format", aliases=("tfcj",))
def _signatures_c(session, statement):
    name = statement.args.strip() or None
    payload = session.call("function_signatures", name=name, limit=10000)
    session.warn_truncated("signature list", len(payload))
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [str(item["signature"]) for item in payload]


@command("t-", "delete loaded types by name or glob")
def _delete_type(session, statement):
    require_write(session)
    name = statement.args.strip()
    if not name:
        raise UsageError("t- needs a type name or glob")
    payload = session.call("type_delete", name=name)
    return [f"removed {name}" for name in payload.get("removed", [])]


@command("tp", "print memory using a type", aliases=("tpv",))
def _type_print(session, statement):
    type_name, address = _type_request(session, statement)
    payload = session.call("type_read", name=type_name, ea=address)
    return _format_typed(session, payload, with_addr=statement.cmd == "tpv")


@command("tpx", "format a byte sequence using a type")
def _type_print_hex(session, statement):
    text = statement.args.strip()
    type_name = text
    data = None
    if " " in text:
        head, tail = text.rsplit(None, 1)
        try:
            data, _mask = parse_hexpairs(tail)
            type_name = head
        except UsageError:
            pass
    if data is None:
        raise UsageError("tpx needs a type and hexpairs")
    payload = session.call("type_read", name=type_name, data=data)
    return _format_typed(session, payload, with_addr=False)


@command("tf-", "delete loaded function definition types")
def _delete_signature_type(session, statement):
    require_write(session)
    name = statement.args.strip()
    if not name:
        raise UsageError("tf- needs a function type name or glob")
    payload = session.call("type_delete", name=name, kind="function")
    return [f"removed {name}" for name in payload.get("removed", [])]


@command("afs", "get or set the function signature at seek", aliases=("afsj",))
def _function_signature(session, statement):
    text = unquote_text(statement.args)
    if text:
        require_write(session)
        payload = session.call("function_set_signature", ea=session.seek, signature=text)
    else:
        payload = session.call("function_signature", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(payload['addr']))} {payload['signature']} "
        f"[{payload.get('calling_convention', '')}]"
    ]
