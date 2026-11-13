"""Listing and function comment queries."""

from __future__ import annotations

import json

from gdare2.errors import NotFoundError, NotFuncError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import iter_items, require_program

MAX_COMMENTS = 10000
COMMENT_KINDS = ("eol", "pre", "post", "plate", "repeatable")
SIDECAR_SET = "gdare2.comments"
SIDECAR_KEY = "user"


def _sidecar(program) -> set[tuple[int, str]]:
    """Comments gdare2 wrote, stored as a program option (persists on save)."""
    options = program.getOptions(SIDECAR_SET)
    raw = options.getString(SIDECAR_KEY, "[]") or "[]"
    try:
        items = json.loads(str(raw))
    except (TypeError, ValueError):
        return set()
    entries = set()
    for item in items if isinstance(items, list) else []:
        try:
            entries.add((int(item[0]), str(item[1])))
        except (TypeError, ValueError, IndexError):
            continue
    return entries


def _save_sidecar(program, entries: set[tuple[int, str]]) -> None:
    options = program.getOptions(SIDECAR_SET)
    options.setString(SIDECAR_KEY, json.dumps(sorted(entries)))


@op("comments")
def comments(
    ctx,
    ea: int | None = None,
    limit: int = MAX_COMMENTS,
    include_all: bool = False,
) -> list[dict]:
    program = require_program(ctx)
    sidecar = _sidecar(program)
    if limit <= 0 or limit > MAX_COMMENTS:
        raise UsageError(f"comment limit must be between 1 and {MAX_COMMENTS}")
    from ghidra.program.model.listing import CommentType

    listing = program.getListing()
    from ghidra.program.model.address import AddressSet

    address_set = AddressSet()
    for block in iter_items(program.getMemory().getBlocks()):
        address_set.addRange(block.getStart(), block.getEnd())
    result = []
    types = [CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE, CommentType.REPEATABLE]
    for comment_type in types:
        iterator = listing.getCommentAddressIterator(comment_type, address_set, True)
        for address in iter_items(iterator):
            if len(result) >= limit:
                break
            if ea is not None and int(address.getOffset()) != int(ea):
                continue
            text = listing.getComment(comment_type, address)
            if text is None:
                continue
            if not include_all and (int(address.getOffset()), comment_type.name().lower()) not in sidecar:
                continue
            result.append(
                {
                    "addr": int(address.getOffset()),
                    "kind": comment_type.name().lower(),
                    "text": str(text),
                }
            )
    result.sort(key=lambda item: (item["addr"], item["kind"]))
    return result


@op("comment_set", writes=True)
def comment_set(ctx, ea: int, text: str, kind: str = "eol") -> dict:
    program = require_program(ctx)
    comment_type = _comment_type(kind)
    address = to_addr(program, int(ea))
    if kind == "plate":
        function = program.getFunctionManager().getFunctionContaining(address)
        if function is None:
            function = program.getFunctionManager().getFunctionAt(address)
        if function is not None:
            function.setComment(text)
            entry = int(function.getEntryPoint().getOffset())
            entries = _sidecar(program)
            entries.add((entry, "plate"))
            _save_sidecar(program, entries)
            return {
                "addr": entry,
                "kind": "plate",
                "text": str(function.getComment() or ""),
            }
    program.getListing().setComment(address, comment_type, text)
    entries = _sidecar(program)
    entries.add((int(ea), str(kind).lower()))
    _save_sidecar(program, entries)
    current = program.getListing().getComment(comment_type, address)
    return {"addr": int(ea), "kind": kind, "text": str(current or "")}


@op("comment_delete", writes=True)
def comment_delete(ctx, ea: int, kind: str = "eol") -> dict:
    program = require_program(ctx)
    comment_type = _comment_type(kind)
    address = to_addr(program, int(ea))
    if kind == "plate":
        function = program.getFunctionManager().getFunctionContaining(address)
        if function is None:
            function = program.getFunctionManager().getFunctionAt(address)
        if function is None:
            raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
        function.setComment("")
        entry = int(function.getEntryPoint().getOffset())
        entries = _sidecar(program)
        entries.discard((entry, "plate"))
        _save_sidecar(program, entries)
        return {"addr": entry, "kind": "plate", "text": ""}
    listing = program.getListing()
    if listing.getComment(comment_type, address) is None:
        raise NotFoundError(f"no {kind} comment at 0x{int(ea):x}")
    listing.setComment(address, comment_type, "")
    entries = _sidecar(program)
    entries.discard((int(ea), str(kind).lower()))
    _save_sidecar(program, entries)
    return {"addr": int(ea), "kind": kind, "text": ""}


def _comment_type(kind: str):
    normalized = str(kind).lower()
    if normalized not in COMMENT_KINDS:
        raise UsageError(f"unknown comment kind {kind!r}")
    from ghidra.program.model.listing import CommentType

    return {
        "eol": CommentType.EOL,
        "pre": CommentType.PRE,
        "post": CommentType.POST,
        "plate": CommentType.PLATE,
        "repeatable": CommentType.REPEATABLE,
    }[normalized]
