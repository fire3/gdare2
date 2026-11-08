"""One-round-trip batch execution and server-side target enumeration."""

from __future__ import annotations

import re

from gdare2.errors import NotFuncError, UsageError
from gdare2.protocol import OpResult
from gdare2.protocol import error as error_payload
from gdare2d.context import to_addr
from gdare2d.dispatch import as_error, invoke, op
from gdare2d.ops._helpers import require_program

MAX_BATCH = 4096
MAX_TARGETS = 4096


@op("batch")
def batch(ctx, ops: list[dict], total: int | None = None) -> OpResult:
    if not isinstance(ops, list) or not ops:
        raise UsageError("batch needs a non-empty ops list")
    if len(ops) > MAX_BATCH:
        raise UsageError(f"batch accepts at most {MAX_BATCH} ops")
    total = len(ops) if total is None else int(total)
    if total < len(ops):
        raise UsageError("batch total must not be smaller than the op count")

    results = []
    errors = 0
    for spec in ops:
        if not isinstance(spec, dict) or not isinstance(spec.get("op"), str):
            results.append(error_payload("BAD_ARGS", "invalid batch op"))
            errors += 1
            continue
        if spec["op"] in {"batch", "iter_targets"}:
            results.append(error_payload("BAD_ARGS", "batch cannot invoke control ops"))
            errors += 1
            continue
        args = spec.get("args") or {}
        if not isinstance(args, dict):
            results.append(error_payload("BAD_ARGS", "batch op args must be an object"))
            errors += 1
            continue
        try:
            value = invoke(ctx, spec["op"], dict(args), allow_writes=ctx.allow_writes)
            results.append({"ok": True, "result": value})
        except Exception as exc:
            results.append(as_error(exc))
            errors += 1
    return OpResult(
        results,
        {
            "total": total,
            "shown": len(results),
            "errors": errors,
            "truncated": total > len(results),
        },
    )


@op("iter_targets")
def iter_targets(
    ctx,
    kind: str,
    ea: int = 0,
    pattern: str | None = None,
    limit: int = MAX_TARGETS,
) -> OpResult:
    program = require_program(ctx)
    if limit <= 0 or limit > MAX_TARGETS:
        raise UsageError(f"target limit must be between 1 and {MAX_TARGETS}")
    kind = str(kind)
    if kind in ("f", "F", "functions"):
        items, total = _function_targets(program, pattern, limit)
    elif kind in ("i", "instructions"):
        items, total = _instruction_targets(program, int(ea), limit)
    elif kind in ("b", "blocks"):
        items, total = _block_targets(program, int(ea), limit, ctx.monitor())
    elif kind in ("S", "iS", "sections"):
        items, total = _section_targets(program, limit)
    elif kind in ("s", "symbols"):
        items, total = _symbol_targets(program, pattern, limit)
    else:
        raise UsageError(f"unsupported iterator {kind!r}")
    return OpResult(
        items,
        {
            "kind": kind,
            "total": total,
            "shown": len(items),
            "limit": limit,
            "truncated": total > len(items),
        },
    )


def _function_targets(program, pattern: str | None, limit: int) -> tuple[list[dict], int]:
    matcher = _matcher(pattern)

    def convert(function):
        name = str(function.getName())
        if matcher is not None and matcher.search(name) is None:
            return None
        return {
            "addr": int(function.getEntryPoint().getOffset()),
            "size": int(function.getBody().getNumAddresses()),
            "name": name,
        }

    return _scan(program.getFunctionManager().getFunctions(True), limit, convert)


def _instruction_targets(program, ea: int, limit: int) -> tuple[list[dict], int]:
    function = _containing_function(program, ea)

    def convert(instruction):
        return {
            "addr": int(instruction.getAddress().getOffset()),
            "size": int(instruction.getLength()),
        }

    return _scan(program.getListing().getInstructions(function.getBody(), True), limit, convert)


def _block_targets(program, ea: int, limit: int, monitor) -> tuple[list[dict], int]:
    function = _containing_function(program, ea)
    from ghidra.program.model.block import BasicBlockModel

    model = BasicBlockModel(program)

    def convert(block):
        start = int(block.getFirstStartAddress().getOffset())
        end = int(block.getMaxAddress().getOffset())
        return {"addr": start, "end": end, "size": max(0, end - start + 1)}

    result, total = _scan(model.getCodeBlocksContaining(function.getBody(), monitor), limit, convert)
    result.sort(key=lambda item: item["addr"])
    return result, total


def _section_targets(program, limit: int) -> tuple[list[dict], int]:
    def convert(block):
        return {
            "addr": int(block.getStart().getOffset()),
            "size": int(block.getSize()),
            "name": str(block.getName()),
        }

    return _scan(program.getMemory().getBlocks(), limit, convert)


def _symbol_targets(program, pattern: str | None, limit: int) -> tuple[list[dict], int]:
    matcher = _matcher(pattern)

    def convert(symbol):
        if symbol.isExternal():
            return None
        name = str(symbol.getName())
        if matcher is not None and matcher.search(name) is None:
            return None
        address = symbol.getAddress()
        if address is None:
            return None
        return {"addr": int(address.getOffset()), "size": 0, "name": name}

    return _scan(program.getSymbolTable().getAllSymbols(True), limit, convert)


def _scan(source, limit: int, convert) -> tuple[list[dict], int]:
    """Convert targets lazily and count all matches while retaining one page."""
    result = []
    total = 0
    if hasattr(source, "hasNext"):
        while source.hasNext():
            item = convert(source.next())
            if item is None:
                continue
            total += 1
            if len(result) < limit:
                result.append(item)
    else:
        for value in source:
            item = convert(value)
            if item is None:
                continue
            total += 1
            if len(result) < limit:
                result.append(item)
    return result, total


def _containing_function(program, ea: int):
    function = program.getFunctionManager().getFunctionContaining(to_addr(program, ea))
    if function is None:
        raise NotFuncError(f"address 0x{ea:x} is not inside a function")
    return function


def _matcher(pattern: str | None):
    if pattern is None or pattern == "":
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise UsageError(f"invalid iterator pattern: {exc}") from exc
