"""Search commands: text, hexpairs, wide text and immediates."""

from __future__ import annotations

import re
from pathlib import Path

from gdare2 import assembler
from gdare2.cmd import command
from gdare2.cmd.write import parse_hexpairs
from gdare2.errors import UnsupportedError, UsageError
from gdare2.escape import text_bytes
from gdare2.formats import magic
from gdare2.formats.elf import PT_LOAD, ElfFormatError, read_segments
from gdare2.jsonutil import dumps

DEFAULT_LIMIT = 4096


@command("/", "search for a text string", aliases=("/j",))
def _search_text(session, statement):
    return _search(session, statement, text_bytes(statement.args), None)


@command("/x", "search for hexpairs", aliases=("/xj",))
def _search_hex(session, statement):
    data, mask = parse_hexpairs(statement.args)
    return _search(session, statement, data, mask)


@command("/b", "search backward for hexpairs", aliases=("/bj",))
def _search_backward(session, statement):
    data, mask = parse_hexpairs(statement.args)
    return _execute(session, statement, data, mask, cursor=session.seek, forward=False)


@command("/i", "search text ignoring case", aliases=("/ij",))
def _search_ignore_case(session, statement):
    return _search(
        session,
        statement,
        text_bytes(statement.args),
        None,
        ignore_case=True,
    )


@command("/d", "search for a deltified byte sequence", aliases=("/dj",))
def _search_delta(session, statement):
    data, mask = parse_hexpairs(statement.args)
    if mask is not None:
        raise UsageError("/d does not support wildcard masks")
    return _search(session, statement, data, None, delta=True)


@command("/p", "search for a hex pattern", aliases=("/pj",))
def _search_pattern(session, statement):
    data, mask = parse_hexpairs(statement.args)
    return _search(session, statement, data, mask)


@command("/a", "assemble text and search for its bytes", aliases=("/aj",))
def _search_assembly(session, statement):
    if not statement.args.strip():
        raise UsageError("/a needs assembly text")
    payload = assembler.assemble(session, session.seek, statement.args)
    return _search(session, statement, bytes(payload["bytes"]), None)


@command("/F", "search for the contents of a file", aliases=("/Fj",))
def _search_file(session, statement):
    words = statement.args.split()
    if not words:
        raise UsageError("/F needs a file path")
    path = Path(words[0])
    try:
        blob = path.read_bytes()
    except OSError as exc:
        raise UsageError(f"/F cannot read {words[0]}: {exc}") from exc
    if len(words) > 1:
        blob = _file_window(blob, words[1], words[2] if len(words) > 2 else None)
    return _search(session, statement, blob, None)


def _file_window(blob: bytes, offset_text: str, size_text: str | None) -> bytes:
    try:
        offset = int(offset_text, 0)
        size = int(size_text, 0) if size_text is not None else None
    except ValueError:
        raise UsageError("/F offset and size must be numeric") from None
    if offset < 0 or (size is not None and size < 0):
        raise UsageError("/F offset and size must not be negative")
    if size is None:
        return blob[offset:]
    return blob[offset : offset + size]


@command("/w", "search for UTF-16 text", aliases=("/wj",))
def _search_wide(session, statement):
    order = "utf-16-be" if session.info.get("endian") == "big" else "utf-16-le"
    return _search(session, statement, statement.args.encode(order), None)


@command(
    "/v",
    "search for an integer",
    aliases=("/vj", "/v1", "/v1j", "/v2", "/v2j", "/v4", "/v4j", "/v8", "/v8j"),
)
def _search_value(session, statement):
    width = _value_width(statement.cmd)
    text = statement.args.strip()
    if not text:
        raise UsageError(f"{statement.cmd} needs an integer")
    try:
        value = int(text, 0)
    except ValueError:
        raise UsageError(f"invalid integer {text!r}") from None
    try:
        data = value.to_bytes(
            width,
            "big" if session.info.get("endian") == "big" else "little",
            signed=False,
        )
    except OverflowError:
        raise UsageError(f"{text} does not fit in {width} bytes") from None
    return _search(session, statement, data, None)


@command("/r", "search defined strings with a regex", aliases=("/rj",))
def _search_regex(session, statement):
    pattern = statement.args.strip()
    if not pattern:
        raise UsageError("/r needs a regular expression")
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise UsageError(f"invalid regular expression: {exc}") from exc
    payload = session.call("strings", limit=10000)
    hits = [
        int(item["addr"])
        for item in payload
        if regex.search(str(item.get("string", ""))) is not None
    ]
    session.last_search = {
        "kind": "regex",
        "pattern": pattern,
        "hits": hits,
        "last": hits[0] if hits else session.seek,
    }
    if hits:
        session.last_result = hits[0]
        session.seek_to(hits[0])
    if statement.cmd.endswith("j"):
        return [dumps({"hits": hits, "meta": {"shown": len(hits), "total": len(hits), "truncated": False}})]
    return [session.format_addr(hit) for hit in hits]


@command("//", "repeat the last search")
@command("/+", "search forward from the last hit")
def _search_next(session, statement):
    return _repeat(session, statement, forward=True)


@command("/-", "search backward from the last hit")
def _search_previous(session, statement):
    return _repeat(session, statement, forward=False)


def _repeat(session, statement, *, forward: bool):
    state = session.last_search
    if state is None:
        raise UsageError("no previous search to repeat")
    last = state.get("last")
    if last is None:
        raise UsageError("no previous search hit to continue from")
    if state.get("kind") == "regex":
        hits = list(state.get("hits") or [])
        if not hits:
            return []
        index = hits.index(last) if last in hits else -1
        index = index + 1 if forward else index - 1
        if index < 0 or index >= len(hits):
            return []
        hit = hits[index]
        state["last"] = hit
        session.last_result = hit
        session.seek_to(hit)
        if statement.cmd.endswith("j"):
            return [dumps({"hits": [hit]})]
        return [session.format_addr(hit)]
    cursor = last + 1 if forward else max(0, last - 1)
    return _execute(
        session,
        statement,
        state["data"],
        state.get("mask"),
        cursor=cursor,
        forward=forward,
        scope=state.get("scope"),
        ignore_case=bool(state.get("ignore_case")),
        delta=bool(state.get("delta")),
    )


def _search(
    session,
    statement,
    data: bytes,
    mask: bytes | None,
    *,
    ignore_case: bool = False,
    delta: bool = False,
) -> list[str]:
    if not data:
        raise UsageError("search pattern is empty")
    lower = int(session.config.get_int("search.from")) or None
    scope = session.config.get_str("search.in")
    cursor = lower if lower is not None else (0 if scope == "raw" else session.seek)
    return _execute(
        session,
        statement,
        data,
        mask,
        cursor=cursor,
        forward=True,
        ignore_case=ignore_case,
        delta=delta,
    )


def _execute(
    session,
    statement,
    data: bytes,
    mask: bytes | None,
    *,
    cursor: int,
    forward: bool,
    scope: str | None = None,
    ignore_case: bool = False,
    delta: bool = False,
) -> list[str]:
    lower = int(session.config.get_int("search.from")) or None
    upper = int(session.config.get_int("search.to")) or None
    scope = scope or session.config.get_str("search.in")
    op = "search_raw" if scope == "raw" else "search"
    maxhits = int(session.config.get_int("search.maxhits"))
    limit = min(DEFAULT_LIMIT, maxhits) if maxhits > 0 else DEFAULT_LIMIT
    args = {
        "data": data,
        "mask": mask,
        "from_addr": lower,
        "to_addr": upper,
        "cursor": int(cursor),
        "forward": forward,
        "limit": limit,
        "offset": 0,
        "ignore_case": bool(ignore_case),
        "delta": bool(delta),
    }
    if op == "search":
        args["scope"] = scope
    payload, response_meta = session.call_with_meta(op, **args)
    if not isinstance(payload, dict):
        payload = {"hits": payload}
    meta = response_meta or payload.get("meta") or {}
    if meta:
        payload["meta"] = meta
    hits = [int(hit) for hit in payload.get("hits", [])]
    if hits:
        session.last_result = hits[0]
        session.seek_to(hits[0])
    hit_command = session.config.get_str("cmd.hit").strip()
    if hit_command and hits and not getattr(session, "_hit_running", False):
        session._hit_running = True
        try:
            lines: list[str] = []
            for hit in hits:
                lines.extend(session.run(f"{hit_command} @ 0x{hit:x}"))
            return lines
        finally:
            session._hit_running = False
    session.last_search = {
        "data": data,
        "mask": mask,
        "scope": scope,
        "ignore_case": bool(ignore_case),
        "delta": bool(delta),
        "last": hits[0] if hits else int(cursor),
    }
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    meta = payload.get("meta") or {}
    if meta.get("truncated"):
        session.stderr(
            f"WARN: search truncated at {meta.get('limit', DEFAULT_LIMIT)} hits; "
            "narrow search.from/search.to"
        )
    return [session.format_addr(hit) for hit in hits]


def _value_width(cmd: str) -> int:
    base = cmd[:-1] if cmd.endswith("j") else cmd
    if base == "/v":
        return 4
    width = int(base[2:], 10)
    if width not in (1, 2, 4, 8):
        raise UsageError("/v width must be 1, 2, 4 or 8")
    return width


@command("/z", "search strings by length", aliases=("/zj",))
def _search_string_size(session, statement):
    words = statement.args.split()
    if len(words) != 2:
        raise UsageError("/z needs min and max string lengths")
    try:
        minimum, maximum = int(words[0], 0), int(words[1], 0)
    except ValueError:
        raise UsageError("/z needs numeric string lengths") from None
    if minimum < 0 or maximum < minimum:
        raise UsageError("/z needs 0 <= min <= max")
    payload = session.call("strings", limit=10000)
    hits = [
        int(item["addr"])
        for item in payload
        if minimum <= int(item.get("length") or len(str(item.get("string", "")))) <= maximum
    ]
    if hits:
        session.last_result = hits[0]
        session.seek_to(hits[0])
    if statement.cmd.endswith("j"):
        return [dumps({"hits": hits, "meta": {"shown": len(hits), "total": len(hits), "truncated": False}})]
    return [session.format_addr(hit) for hit in hits]


def _target_bytes(session, command: str) -> bytes:
    target = session.info.get("target")
    if not target:
        raise UnsupportedError(f"{command} needs the original file; this session has no target path")
    try:
        return Path(str(target)).read_bytes()
    except OSError as exc:
        raise UnsupportedError(f"{command} cannot read {target}: {exc}") from exc


def _file_offset_to_vaddr(target: str, offset: int) -> int:
    try:
        segments = read_segments(target)
    except (ElfFormatError, OSError):
        return offset
    for segment in segments:
        if segment.type != PT_LOAD:
            continue
        if segment.offset <= offset < segment.offset + max(segment.filesz, 1):
            return segment.vaddr + (offset - segment.offset)
    return offset


@command("/m", "search for known magic signatures", aliases=("/mj",))
def _search_magic(session, statement):
    target = str(session.info.get("target") or "")
    hits = magic.scan(_target_bytes(session, "/m"))
    rows = [
        {"addr": _file_offset_to_vaddr(target, int(item["offset"])), "name": item["name"]}
        for item in hits
    ]
    if statement.cmd.endswith("j"):
        return [dumps({"hits": rows})]
    return [f"{session.format_addr(int(item['addr']))} {item['name']}" for item in rows]


@command("/c", "search for crypto material", aliases=("/cj",))
def _search_crypto(session, statement):
    target = str(session.info.get("target") or "")
    hits = magic.scan(_target_bytes(session, "/c"), crypto=True)
    rows = [
        {"addr": _file_offset_to_vaddr(target, int(item["offset"])), "name": item["name"]}
        for item in hits
    ]
    if statement.cmd.endswith("j"):
        return [dumps({"hits": rows})]
    return [f"{session.format_addr(int(item['addr']))} {item['name']}" for item in rows]


@command("/R", "search for return-oriented gadgets", aliases=("/Rj", "/Rq", "/R/"))
def _search_rop(session, statement):
    pattern = statement.args.strip()
    if pattern:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise UsageError(f"invalid gadget regex: {exc}") from exc
    else:
        regex = None
    target = str(session.info.get("target") or "")
    blob = _target_bytes(session, "/R")
    rows = []
    for offset in range(len(blob) - 1):
        if blob[offset] not in (0xC3, 0xC2):
            continue
        gadget = "ret" if blob[offset] == 0xC3 else f"ret 0x{int.from_bytes(blob[offset + 1:offset + 3], 'little'):x}"
        address = _file_offset_to_vaddr(target, offset)
        if regex is not None and regex.search(gadget) is None:
            continue
        rows.append({"addr": address, "gadget": gadget, "size": 1 if blob[offset] == 0xC3 else 3})
        if len(rows) >= 4096:
            break
    if statement.cmd.endswith("j"):
        return [dumps({"hits": rows})]
    return [f"{session.format_addr(int(item['addr']))} {item['gadget']}" for item in rows]


# Searches r2 offers but gdare2 cannot map onto Ghidra memory search. They stay
# registered so scripts get an explicit rejection instead of an unknown-command
# error (per-command decisions are recorded in docs/TASKS-v3.md V12).


@command("/e", "match a regex over memory bytes (not supported)")
def _search_regex_memory(session, statement):
    raise UnsupportedError("/e regex byte search is not supported; use /r for regex over defined strings")


@command("/E", "search addresses matching an esil expression (not supported)")
def _search_esil(session, statement):
    raise UnsupportedError(
        "/E esil-expression search is not supported; use /x with a .. wildcard mask for partial matching"
    )


@command("/f", "forward search modifier (not supported)")
def _search_forward_modifier(session, statement):
    raise UnsupportedError("/f is a forward-search modifier; searches already run forward by default")


@command(
    "/g",
    "search ROP/COP/JOP gadgets by op string (not supported)",
    aliases=("/gR", "/gC", "/gJ"),
)
def _search_gadget_ops(session, statement):
    raise UnsupportedError("/g gadget search by op string is not supported; use /R for return gadgets")


@command("/h", "find a block matching a digest (not supported)")
def _search_digest(session, statement):
    raise UnsupportedError("/h digest block search is not supported")


@command("/o", "show the offset of n instructions backward (not supported)")
def _search_instruction_offset(session, statement):
    raise UnsupportedError("/o instruction-offset lookup is not supported")


@command("/O", "show the offset of n instructions backward (not supported)")
def _search_instruction_offset_fallback(session, statement):
    raise UnsupportedError("/O mirrors /o; instruction-offset lookup is not supported")


@command("/P", "search similar blocks (not supported)")
def _search_similar_blocks(session, statement):
    raise UnsupportedError("/P similar-block search is not supported")


@command("/s", "find sections by block entropy (not supported)", aliases=("/sj",))
def _search_entropy(session, statement):
    raise UnsupportedError("/s entropy section search is not supported")


@command(
    "/V",
    "search for a value inside a range (not supported)",
    aliases=("/V1", "/V2", "/V4", "/V8"),
)
def _search_value_range(session, statement):
    raise UnsupportedError("/V value-in-range search is not supported")


@command("/!", "inverse search modifier (not supported)")
def _search_inverse(session, statement):
    raise UnsupportedError("/! inverse search is not supported")
