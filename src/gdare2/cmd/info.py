"""Binary and program information commands."""

from __future__ import annotations

from gdare2.arch_matrix import ARCH_MATRIX
from gdare2.cmd import command
from gdare2.errors import UnsupportedError
from gdare2.formats.elf import (
    ElfFormatError,
    read_header,
    read_needed,
    read_relocations,
    read_segments,
)
from gdare2.jsonutil import dumps


def _jsonify(value):
    return [dumps(value)]


@command("iI", "show program information", aliases=("iIj", "ij"))
def _info(session, statement):
    payload = session.call("info")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return _info_lines(session, payload)


def _info_lines(session, payload: dict) -> list[str]:
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


@command("i", "show information about the current file")
def _file_info(session, statement):
    payload = session.call("info")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"file     {payload.get('target', '')}", *_info_lines(session, payload)]


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


@command("iSS", "list ELF program headers", aliases=("iSSj",))
def _segments(session, statement):
    target = session.info.get("target")
    if not target:
        raise UnsupportedError("iSS needs the original file; this session has no target path")
    try:
        segments = read_segments(str(target))
    except ElfFormatError as exc:
        raise UnsupportedError(f"iSS: {exc}") from exc
    except OSError as exc:
        raise UnsupportedError(f"iSS cannot read {target}: {exc}") from exc
    if statement.cmd.endswith("j"):
        return _jsonify([segment.as_dict() for segment in segments])
    lines = ["idx  paddr              size       vaddr              vsize      perm name"]
    for segment in segments:
        lines.append(
            f"{segment.index:3d}  {session.format_addr(segment.offset)}  "
            f"{segment.filesz:08x}   {session.format_addr(segment.vaddr)}  "
            f"{segment.memsz:08x}   {segment.perm} {segment.name}"
        )
    return lines


@command("iS*", "list memory blocks as replayable flag commands")
def _sections_commands(session, statement):
    payload = session.call("sections")
    lines = []
    for block in payload:
        name = str(block.get("name") or "")
        name = f"section.{name}" if name else "section.unnamed"
        lines.append(
            f"f {name} {int(block['size'])} @ {session.format_addr(int(block['addr']))}"
        )
    return lines


def _elf_target(session, command: str) -> str:
    target = session.info.get("target")
    if not target:
        raise UnsupportedError(f"{command} needs the original file; this session has no target path")
    return str(target)


@command("ih", "show ELF header fields", aliases=("ihj",))
def _elf_header(session, statement):
    target = _elf_target(session, "ih")
    try:
        fields = read_header(target).fields()
    except ElfFormatError as exc:
        raise UnsupportedError(f"ih: {exc}") from exc
    except OSError as exc:
        raise UnsupportedError(f"ih cannot read {target}: {exc}") from exc
    if statement.cmd.endswith("j"):
        return _jsonify(fields)
    return [
        f"0x{int(item['vaddr']):08x} 0x{int(item['paddr']):08x} "
        f"0x{int(item['value']):08x} {item['name']}"
        for item in fields
    ]


@command("iH", "show a compact ELF header table", aliases=("iHj",))
def _elf_header_compact(session, statement):
    target = _elf_target(session, "iH")
    try:
        fields = read_header(target).fields()
    except ElfFormatError as exc:
        raise UnsupportedError(f"iH: {exc}") from exc
    except OSError as exc:
        raise UnsupportedError(f"iH cannot read {target}: {exc}") from exc
    fields = [field for field in fields if field["name"] != "ELF"]
    if statement.cmd.endswith("j"):
        return _jsonify(fields)
    return [
        f"0x{int(item['vaddr']):08x}  {item['name']:<12} 0x{int(item['value']):x}"
        for item in fields
    ]


@command("il", "list dynamic libraries (DT_NEEDED)", aliases=("ilj",))
def _libraries(session, statement):
    target = _elf_target(session, "il")
    try:
        names = read_needed(target)
    except ElfFormatError as exc:
        raise UnsupportedError(f"il: {exc}") from exc
    except OSError as exc:
        raise UnsupportedError(f"il cannot read {target}: {exc}") from exc
    if statement.cmd.endswith("j"):
        return _jsonify(names)
    return names


@command("ir", "list ELF relocations", aliases=("irj",))
def _relocations(session, statement):
    target = _elf_target(session, "ir")
    try:
        relocations = read_relocations(target)
        segments = read_segments(target)
    except ElfFormatError as exc:
        raise UnsupportedError(f"ir: {exc}") from exc
    except OSError as exc:
        raise UnsupportedError(f"ir cannot read {target}: {exc}") from exc
    rows = []
    for relocation in relocations:
        name = relocation.symbol or (
            f"0x{relocation.addend:x}" if relocation.addend else ""
        )
        rows.append(
            {
                "vaddr": relocation.offset,
                "paddr": _file_offset(segments, relocation.offset),
                "type": relocation.type_name,
                "ntype": relocation.type,
                "name": name,
            }
        )
    if statement.cmd.endswith("j"):
        return _jsonify(rows)
    lines = ["vaddr      paddr      type   ntype name"]
    for row in rows:
        lines.append(
            f"0x{row['vaddr']:08x} 0x{row['paddr']:08x} "
            f"{row['type']:<8} {row['ntype']:<5} {row['name']}"
        )
    return lines


def _file_offset(segments, address: int) -> int:
    for segment in segments:
        if segment.vaddr <= address < segment.vaddr + max(segment.filesz, 1):
            return segment.offset + (address - segment.vaddr)
    return address


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
    payload, meta = session.call_with_meta("symbols", **session.list_args(10000))
    session.warn_list_meta("symbol list", meta)
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item.get('type', ''):8s} {item['name']}" for item in payload]


@command("iE", "list exports", aliases=("iEj",))
def _exports(session, statement):
    payload, meta = session.call_with_meta("exports", **session.list_args(10000))
    session.warn_list_meta("export list", meta)
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
    payload, meta = session.call_with_meta("imports", **session.list_args(10000))
    session.warn_list_meta("import list", meta)
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item['name']}" for item in payload]


@command("ie", "list entry points", aliases=("iej",))
def _entries(session, statement):
    payload = session.call("entries")
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item.get('name', '')}" for item in payload]


@command("izz", "scan the whole file for strings", aliases=("izzj",))
def _strings_all(session, statement):
    payload, meta = session.call_with_meta(
        "strings_all", min_length=4, **session.list_args(10000)
    )
    session.warn_list_meta("string scan", meta)
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"0x{int(item['offset']):08x} {item['string']}" for item in payload]


@command("iz", "list strings", aliases=("izj",))
def _strings(session, statement):
    payload, meta = session.call_with_meta("strings", **session.list_args(10000))
    session.warn_list_meta("string list", meta)
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"{session.format_addr(int(item['addr']))} {item['string']}" for item in payload]
