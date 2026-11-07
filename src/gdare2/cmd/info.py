"""Binary and program information commands."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.jsonutil import dumps


def _jsonify(value):
    return [dumps(value)]


@command("iI", "show program information", aliases=("iIj", "ij"))
def _info(session, statement):
    payload = session.call("info")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [
        f"arch     {payload.get('arch')}",
        f"bits     {payload.get('bits')}",
        f"endian   {payload.get('endian')}",
        f"language {payload.get('language')}",
        f"compiler {payload.get('compiler')}",
        f"base     {session.format_addr(int(payload.get('image_base') or 0))}",
        f"entry    {session.format_addr(int(payload.get('entry') or 0))}",
        f"size     {payload.get('filesize')}",
        f"format   {payload.get('format')}",
        f"project  {payload.get('project')}",
        f"program  {payload.get('program')}",
    ]


@command("iS", "list memory blocks", aliases=("iSj",))
def _sections(session, statement):
    payload = session.call("sections")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    lines = ["idx  address      size       perms name"]
    for index, block in enumerate(payload):
        lines.append(
            f"{index:3d}  {session.format_addr(int(block['addr']))}  "
            f"{int(block['size']):08x}   {block.get('perms', '---')}  {block.get('name', '')}"
        )
    return lines


@command("is", "list symbols", aliases=("isj",))
def _symbols(session, statement):
    payload = session.call("symbols", limit=10000)
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item.get('type', ''):8s} {item['name']}" for item in payload]


@command("ii", "list imports", aliases=("iij",))
def _imports(session, statement):
    payload = session.call("imports")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item['name']}" for item in payload]


@command("ie", "list entry points", aliases=("iej",))
def _entries(session, statement):
    payload = session.call("entries")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item.get('name', '')}" for item in payload]


@command("iz", "list strings", aliases=("izj",))
def _strings(session, statement):
    payload = session.call("strings", limit=10000)
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item['string']}" for item in payload]
