"""One-round-trip batch execution and server-side target enumeration."""

from __future__ import annotations

import re

from gdare2.errors import NotFuncError, UsageError
from gdare2.protocol import error as error_payload
from gdare2d.context import to_addr
from gdare2d.dispatch import as_error, invoke, op
from gdare2d.ops._helpers import iter_items, require_program

MAX_BATCH = 4096
MAX_TARGETS = 4096


@op("batch")
def batch(ctx, ops: list[dict]) -> list[dict]:
    if not isinstance(ops, list) or not ops:
        raise UsageError("batch needs a non-empty ops list")
    if len(ops) > MAX_BATCH:
        raise UsageError(f"batch accepts at most {MAX_BATCH} ops")

    results = []
    for spec in ops:
        if not isinstance(spec, dict) or not isinstance(spec.get("op"), str):
            results.append(error_payload("BAD_ARGS", "invalid batch op"))
            continue
        if spec["op"] in {"batch", "iter_targets"}:
            results.append(error_payload("BAD_ARGS", "batch cannot invoke control ops"))
            continue
        args = spec.get("args") or {}
        if not isinstance(args, dict):
            results.append(error_payload("BAD_ARGS", "batch op args must be an object"))
            continue
        try:
            value = invoke(ctx, spec["op"], dict(args), allow_writes=ctx.allow_writes)
            results.append({"ok": True, "result": value})
        except Exception as exc:
            results.append(as_error(exc))
    return results


@op("iter_targets")
def iter_targets(
    ctx,
    kind: str,
    ea: int = 0,
    pattern: str | None = None,
    limit: int = MAX_TARGETS,
) -> list[dict]:
    program = require_program(ctx)
    if limit <= 0 or limit > MAX_TARGETS:
        raise UsageError(f"target limit must be between 1 and {MAX_TARGETS}")
    kind = str(kind)
    if kind in ("f", "functions"):
        return _function_targets(program, pattern, limit)
    if kind in ("i", "instructions"):
        return _instruction_targets(program, int(ea), limit)
    if kind in ("b", "blocks"):
        return _block_targets(program, int(ea), limit, ctx.monitor())
    if kind in ("S", "iS", "sections"):
        return _section_targets(program, limit)
    if kind in ("s", "symbols"):
        return _symbol_targets(program, pattern, limit)
    raise UsageError(f"unsupported iterator {kind!r}")


def _function_targets(program, pattern: str | None, limit: int) -> list[dict]:
    matcher = _matcher(pattern)
    result = []
    iterator = program.getFunctionManager().getFunctions(True)
    while iterator.hasNext() and len(result) < limit:
        function = iterator.next()
        name = str(function.getName())
        if matcher is not None and matcher.search(name) is None:
            continue
        result.append(
            {
                "addr": int(function.getEntryPoint().getOffset()),
                "size": int(function.getBody().getNumAddresses()),
                "name": name,
            }
        )
    return result


def _instruction_targets(program, ea: int, limit: int) -> list[dict]:
    function = _containing_function(program, ea)
    result = []
    for instruction in iter_items(program.getListing().getInstructions(function.getBody(), True))[:limit]:
        result.append(
            {
                "addr": int(instruction.getAddress().getOffset()),
                "size": int(instruction.getLength()),
            }
        )
    return result


def _block_targets(program, ea: int, limit: int, monitor) -> list[dict]:
    function = _containing_function(program, ea)
    from ghidra.program.model.block import BasicBlockModel

    model = BasicBlockModel(program)
    result = []
    for block in iter_items(model.getCodeBlocksContaining(function.getBody(), monitor))[:limit]:
        start = int(block.getFirstStartAddress().getOffset())
        end = int(block.getMaxAddress().getOffset())
        result.append({"addr": start, "end": end, "size": max(0, end - start + 1)})
    result.sort(key=lambda item: item["addr"])
    return result


def _section_targets(program, limit: int) -> list[dict]:
    result = []
    for block in program.getMemory().getBlocks():
        if len(result) >= limit:
            break
        result.append(
            {
                "addr": int(block.getStart().getOffset()),
                "size": int(block.getSize()),
                "name": str(block.getName()),
            }
        )
    return result


def _symbol_targets(program, pattern: str | None, limit: int) -> list[dict]:
    matcher = _matcher(pattern)
    result = []
    for symbol in program.getSymbolTable().getAllSymbols(True):
        if len(result) >= limit:
            break
        if symbol.isExternal():
            continue
        name = str(symbol.getName())
        if matcher is not None and matcher.search(name) is None:
            continue
        address = symbol.getAddress()
        if address is None:
            continue
        result.append({"addr": int(address.getOffset()), "size": 0, "name": name})
    return result


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
