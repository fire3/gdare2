"""Binary and program information commands."""

from __future__ import annotations

from gdare2.arch_matrix import ARCH_MATRIX
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


@command("iS", "list memory blocks", aliases=("iSj", "iSS", "iSSj"))
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


@command("iS.", "show the memory block at seek")
def _current_section(session, statement):
    payload = session.call("block_at", ea=session.seek)
    return [
        f"name: {payload['name']}",
        f"addr: {session.format_addr(int(payload['addr']))}",
        f"end:  {session.format_addr(int(payload['end']))}",
        f"size: {payload['size']}",
        f"perm: {payload['perms']}",
    ]


@command("it", "show executable hashes", aliases=("itj",))
def _hashes(session, statement):
    payload = session.call("hashes")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [
        f"md5    {payload.get('md5', '')}",
        f"sha256 {payload.get('sha256', '')}",
        f"path   {payload.get('path', '')}",
        f"format {payload.get('format', '')}",
    ]


@command("iM", "show the main or entry address")
def _main_address(session, statement):
    value = session.lookup_name("main")
    if value is None:
        value = session.lookup_name("_start")
    if value is None:
        value = int(session.info.get("entry") or 0)
    return [session.format_addr(value)]


@command("is", "list symbols", aliases=("isj",))
def _symbols(session, statement):
    payload = session.call("symbols", limit=10000)
    session.warn_truncated("symbol list", len(payload))
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item.get('type', ''):8s} {item['name']}" for item in payload]


@command("iE", "list exports", aliases=("iEj",))
def _exports(session, statement):
    payload = session.call("exports", limit=10000)
    session.warn_truncated("export list", len(payload))
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item.get('type', ''):8s} {item['name']}" for item in payload]


@command("ia", "list architectures", aliases=("iaj",))
def _architectures(session, statement):
    payload = [
        {
            "name": item["name"],
            "arch": item["arch"],
            "bits": item["bits"],
            "endian": item["endian"],
            "language": item["language"],
            "current": item["language"] == session.info.get("language"),
        }
        for item in ARCH_MATRIX
    ]
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [
        f"{item['name']:<12} {item['bits']:>2} {item['endian']:<6} {item['language']}"
        + (" *" if item["current"] else "")
        for item in payload
    ]


@command("ii", "list imports", aliases=("iij",))
def _imports(session, statement):
    payload = session.call("imports")
    session.warn_truncated("import list", len(payload))
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
    session.warn_truncated("string list", len(payload))
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item['string']}" for item in payload]
