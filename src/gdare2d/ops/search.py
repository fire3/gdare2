"""Memory byte-pattern search."""

from __future__ import annotations

from gdare2.errors import UnsupportedError, UsageError
from gdare2.protocol import OpResult
from gdare2d.context import to_addr as to_address
from gdare2d.dispatch import op
from gdare2d.ops._helpers import iter_items, require_program

MAX_PATTERN = 1024 * 1024
MAX_HITS = 65536


@op("search_raw")
def search_raw(
    ctx,
    data: bytes,
    mask: bytes | None = None,
    from_addr: int | None = None,
    to_addr: int | None = None,
    cursor: int | None = None,
    forward: bool = True,
    limit: int = 4096,
    offset: int = 0,
) -> OpResult:
    program = require_program(ctx)
    raw = bytes(data)
    if not raw:
        raise UsageError("search pattern is empty")
    if len(raw) > MAX_PATTERN:
        raise UsageError(f"search pattern is limited to {MAX_PATTERN} bytes")
    mask_bytes = None if mask is None else bytes(mask)
    if mask_bytes is not None and len(mask_bytes) != len(raw):
        raise UsageError("search mask length does not match pattern length")
    if limit <= 0 or limit > MAX_HITS:
        raise UsageError(f"search limit must be between 1 and {MAX_HITS}")
    if offset < 0:
        raise UsageError("search offset must not be negative")
    path = str(program.getExecutablePath() or "")
    if not path:
        raise UnsupportedError("program has no executable path for raw search")
    from pathlib import Path

    try:
        blob = Path(path).read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc

    lower = max(0, int(from_addr)) if from_addr is not None else 0
    upper = (
        min(len(blob) - len(raw), int(to_addr) - len(raw) + 1)
        if to_addr is not None
        else len(blob) - len(raw)
    )
    if cursor is not None:
        if forward:
            lower = max(lower, int(cursor))
        else:
            upper = min(upper, int(cursor))
    if upper < lower:
        hits = []
    elif forward:
        hits = _scan_raw(blob, raw, mask_bytes, lower, upper, True, offset + limit + 1)
    else:
        hits = _scan_raw(blob, raw, mask_bytes, lower, upper, False, offset + limit + 1)
    page = hits[offset : offset + limit]
    return OpResult(
        {"hits": page},
        {
            "shown": len(page),
            "offset": offset,
            "limit": limit,
            "truncated": len(hits) > offset + limit,
            "scope": "raw",
            "forward": bool(forward),
        },
    )


def _scan_raw(blob, pattern, mask, lower, upper, forward, wanted):
    hits = []
    positions = range(upper, lower - 1, -1) if not forward else range(lower, upper + 1)
    for position in positions:
        if len(hits) >= wanted:
            break
        if mask is None:
            if blob[position : position + len(pattern)] == pattern:
                hits.append(position)
        else:
            if all(
                (blob[position + index] & keep) == (value & keep)
                for index, (value, keep) in enumerate(zip(pattern, mask, strict=True))
            ):
                hits.append(position)
    return hits


@op("search")
def search(
    ctx,
    data: bytes,
    mask: bytes | None = None,
    from_addr: int | None = None,
    to_addr: int | None = None,
    cursor: int | None = None,
    forward: bool = True,
    limit: int = 4096,
    offset: int = 0,
    scope: str = "io.maps",
) -> OpResult:
    program = require_program(ctx)
    raw = bytes(data)
    if not raw:
        raise UsageError("search pattern is empty")
    if len(raw) > MAX_PATTERN:
        raise UsageError(f"search pattern is limited to {MAX_PATTERN} bytes")
    mask_bytes = None if mask is None else bytes(mask)
    if mask_bytes is not None and len(mask_bytes) != len(raw):
        raise UsageError("search mask length does not match pattern length")
    if limit <= 0 or limit > MAX_HITS:
        raise UsageError(f"search limit must be between 1 and {MAX_HITS}")
    if offset < 0:
        raise UsageError("search offset must not be negative")
    if scope not in ("io.maps", "bin.sections"):
        raise UnsupportedError(f"search.in={scope!r} is not supported; use io.maps")

    ranges = _ranges(program, from_addr, to_addr, cursor, bool(forward))
    memory = program.getMemory()
    monitor = ctx.monitor()
    wanted = offset + limit + 1
    hits: list[int] = []
    for lower, upper in ranges:
        position = lower if forward else upper
        bound = upper if forward else lower
        while len(hits) < wanted:
            address = memory.findBytes(
                to_address(program, position),
                to_address(program, bound),
                raw,
                mask_bytes,
                bool(forward),
                monitor,
            )
            if address is None:
                break
            hit = int(address.getOffset())
            hits.append(hit)
            position = hit + 1 if forward else hit - 1
            if position < lower or position > upper:
                break

    page = hits[offset : offset + limit]
    return OpResult(
        {"hits": page},
        {
            "shown": len(page),
            "offset": offset,
            "limit": limit,
            "truncated": len(hits) > offset + limit,
            "scope": scope,
            "forward": bool(forward),
        },
    )


def _ranges(program, from_addr, to_addr, cursor, forward: bool) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for block in iter_items(program.getMemory().getBlocks()):
        lower = int(block.getStart().getOffset())
        upper = int(block.getEnd().getOffset())
        if from_addr is not None:
            lower = max(lower, int(from_addr))
        if to_addr is not None:
            upper = min(upper, int(to_addr))
        if cursor is not None:
            if forward:
                lower = max(lower, int(cursor))
            else:
                upper = min(upper, int(cursor))
        if lower <= upper:
            ranges.append((lower, upper))
    ranges.sort(reverse=not forward)
    return ranges
