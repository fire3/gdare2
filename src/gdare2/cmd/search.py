"""Search commands: text, hexpairs, wide text and immediates."""

from __future__ import annotations

import re

from gdare2.cmd import command
from gdare2.cmd.write import parse_hexpairs
from gdare2.errors import UsageError
from gdare2.escape import text_bytes
from gdare2.jsonutil import dumps

DEFAULT_LIMIT = 4096


@command("/", "search for a text string", aliases=("/j",))
def _search_text(session, statement):
    return _search(session, statement, text_bytes(statement.args), None)


@command("/x", "search for hexpairs", aliases=("/xj",))
def _search_hex(session, statement):
    data, mask = parse_hexpairs(statement.args)
    return _search(session, statement, data, mask)


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
    )


def _search(session, statement, data: bytes, mask: bytes | None) -> list[str]:
    if not data:
        raise UsageError("search pattern is empty")
    lower = int(session.config.get_int("search.from")) or None
    cursor = lower if lower is not None else session.seek
    return _execute(session, statement, data, mask, cursor=cursor, forward=True)


def _execute(
    session,
    statement,
    data: bytes,
    mask: bytes | None,
    *,
    cursor: int,
    forward: bool,
) -> list[str]:
    lower = int(session.config.get_int("search.from")) or None
    upper = int(session.config.get_int("search.to")) or None
    payload = session.call(
        "search",
        data=data,
        mask=mask,
        from_addr=lower,
        to_addr=upper,
        cursor=int(cursor),
        forward=forward,
        limit=DEFAULT_LIMIT,
        offset=0,
        scope=session.config.get_str("search.in"),
    )
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
