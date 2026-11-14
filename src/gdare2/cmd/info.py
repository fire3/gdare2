"""Binary and program information commands."""

from __future__ import annotations

from pathlib import Path

from gdare2.arch_matrix import ARCH_MATRIX
from gdare2.cmd import command
from gdare2.errors import UnsupportedError
from gdare2.formats.elf import (
    ElfFormatError,
    read_build_id,
    read_header,
    read_init_fini,
    read_needed,
    read_relocations,
    read_segments,
    read_versions,
)
from gdare2.formats.magic import scan as scan_magic
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


@command("iD", "demangle a symbol or list demangler languages", aliases=("iDj",))
def _demangle(session, statement):
    languages = ("c++", "java", "objc", "swift", "dlang", "msvc", "rust")
    text = statement.args.strip()
    if not text:
        if statement.cmd.endswith("j"):
            return [dumps(list(languages))]
        return list(languages)
    words = text.split(None, 1)
    language = None
    if len(words) == 2 and words[0].lower() in languages:
        language, text = words[0], words[1]
    payload = session.call("demangle", text=text, language=language)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    lines = [str(payload.get("name") or payload.get("text") or text)]
    signature = str(payload.get("signature") or "")
    if signature and signature != lines[0]:
        lines.append(signature)
    return lines


@command("iC", "show executable signature information", aliases=("iCj",))
def _signature_info(session, statement):
    payload = dict(session.call("hashes"))
    target = session.info.get("target")
    build_id = ""
    if target:
        try:
            build_id = read_build_id(str(target))
        except (ElfFormatError, OSError):
            build_id = ""
    payload["build_id"] = build_id
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [
        f"path     {payload.get('path', '')}",
        f"format   {payload.get('format', '')}",
        f"md5      {payload.get('md5', '')}",
        f"sha256   {payload.get('sha256', '')}",
        f"build-id {build_id}",
    ]


@command("iV", "show ELF version symbols", aliases=("iVj",))
def _version_info(session, statement):
    target = _elf_target(session, "iV")
    try:
        rows = read_versions(target)
    except ElfFormatError as exc:
        raise UnsupportedError(f"iV: {exc}") from exc
    except OSError as exc:
        raise UnsupportedError(f"iV cannot read {target}: {exc}") from exc
    if statement.cmd.endswith("j"):
        return _jsonify(rows)
    return [
        f"0x{int(row['index']):08x}: {row['version']} ({row['name']})"
        + (" [hidden]" if row["hidden"] else "")
        for row in rows
    ]


@command("iv", "show detailed binary information", aliases=("ivj",))
def _binary_info(session, statement):
    hashes = session.call("hashes")
    sections = session.call("sections")
    payload = {
        "file": session.info.get("target", ""),
        "format": hashes.get("format") or session.info.get("format", ""),
        "arch": session.info.get("arch", ""),
        "bits": int(session.info.get("bits") or 0),
        "endian": session.info.get("endian", ""),
        "language": session.info.get("language", ""),
        "image_base": int(session.info.get("image_base") or 0),
        "entry": int(session.info.get("entry") or 0),
        "size": int(session.info.get("filesize") or 0),
        "sections": len(sections),
        "md5": hashes.get("md5", ""),
        "sha256": hashes.get("sha256", ""),
    }
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [
        f"file     {payload['file']}",
        f"format   {payload['format']}",
        f"arch     {payload['arch']}",
        f"bits     {payload['bits']}",
        f"endian   {payload['endian']}",
        f"language {payload['language']}",
        f"baddr    {session.format_addr(payload['image_base'])}",
        f"entry    {session.format_addr(payload['entry'])}",
        f"size     {payload['size']}",
        f"sections {payload['sections']}",
        f"md5      {payload['md5']}",
        f"sha256   {payload['sha256']}",
    ]


def _target_bytes(session, command: str) -> bytes:
    target = _elf_target(session, command)
    try:
        return Path(target).read_bytes()
    except OSError as exc:
        raise UnsupportedError(f"{command} cannot read {target}: {exc}") from exc


@command("iT", "show file signature matches", aliases=("iTj",))
def _file_signatures(session, statement):
    payload = scan_magic(_target_bytes(session, "iT"))
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    return [f"0x{int(item['offset']):08x} {item['name']}" for item in payload]


@command("iee", "show constructors and destructors", aliases=("ieej",))
def _constructors(session, statement):
    target = _elf_target(session, "iee")
    try:
        payload = read_init_fini(target)
    except ElfFormatError as exc:
        raise UnsupportedError(f"iee: {exc}") from exc
    except OSError as exc:
        raise UnsupportedError(f"iee cannot read {target}: {exc}") from exc
    if statement.cmd.endswith("j"):
        return _jsonify(payload)
    lines = ["[Constructors]"] if payload else []
    for item in payload:
        lines.append(
            f"vaddr={item['vaddr']:#x} paddr={item['paddr']:#x} type={item['type']}"
        )
    return lines


@command("ies", "show entrypoints and symbols", aliases=("iesj",))
def _entry_symbols(session, statement):
    entries = session.call("entries")
    symbols, meta = session.call_with_meta("symbols", **session.list_args(10000))
    session.warn_list_meta("symbol list", meta)
    rows = [
        {"vaddr": int(item["addr"]), "name": item.get("name", ""), "type": "entry"}
        for item in entries
    ]
    seen = {(row["vaddr"], row["name"]) for row in rows}
    for item in symbols:
        row = {
            "vaddr": int(item["addr"]),
            "name": item.get("name", ""),
            "type": "symbol",
        }
        key = (row["vaddr"], row["name"])
        if key not in seen:
            rows.append(row)
            seen.add(key)
    if statement.cmd.endswith("j"):
        return _jsonify(rows)
    lines = [f"{len(entries)} entrypoints", "[Entrypoints]"]
    for item in entries:
        lines.append(f"vaddr={int(item['addr']):#x} type=program name={item.get('name', '')}")
    if symbols:
        lines.append(f"{len(symbols)} symbols")
    return lines


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
