"""Program sections, symbols, imports, entries and strings."""

from __future__ import annotations

from pathlib import Path

from gdare2.errors import GdarError, UsageError
from gdare2.protocol import OpResult
from gdare2d.dispatch import op
from gdare2d.ops._helpers import require_program

MAX_ITEMS = 10000


@op("sections")
def sections(ctx) -> list[dict]:
    program = require_program(ctx)
    memory = program.getMemory()
    result = []
    for block in memory.getBlocks():
        result.append(
            {
                "name": str(block.getName()),
                "addr": int(block.getStart().getOffset()),
                "end": int(block.getEnd().getOffset()),
                "size": int(block.getSize()),
                "perms": ("r" if block.isRead() else "-")
                + ("w" if block.isWrite() else "-")
                + ("x" if block.isExecute() else "-"),
                "initialized": bool(block.isInitialized()),
            }
        )
    return result


@op("block_at")
def block_at(ctx, ea: int) -> dict:
    from gdare2.errors import NotFoundError
    from gdare2d.context import to_addr

    program = require_program(ctx)
    block = program.getMemory().getBlock(to_addr(program, int(ea)))
    if block is None:
        raise NotFoundError(f"no memory block containing 0x{int(ea):x}")
    return {
        "name": str(block.getName()),
        "addr": int(block.getStart().getOffset()),
        "end": int(block.getEnd().getOffset()),
        "size": int(block.getSize()),
        "perms": ("r" if block.isRead() else "-")
        + ("w" if block.isWrite() else "-")
        + ("x" if block.isExecute() else "-"),
        "initialized": bool(block.isInitialized()),
    }


@op("address_info")
def address_info(ctx, ea: int) -> dict:
    from gdare2d.context import to_addr
    from gdare2d.ops._helpers import function_dict, instruction_dict

    program = require_program(ctx)
    address = to_addr(program, int(ea))
    memory = program.getMemory()
    block = memory.getBlock(address)
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        function = program.getFunctionManager().getFunctionAt(address)
    listing = program.getListing()
    instruction = listing.getInstructionContaining(address)
    if instruction is None:
        instruction = listing.getInstructionAt(address)
    symbol = program.getSymbolTable().getPrimarySymbol(address)

    payload = {
        "addr": int(address.getOffset()),
        "mapped": block is not None,
        "readable": bool(block is not None and block.isRead()),
        "writable": bool(block is not None and block.isWrite()),
        "executable": bool(block is not None and block.isExecute()),
        "block": None,
        "function": None,
        "symbol": None,
        "instruction": None,
    }
    if block is not None:
        payload["block"] = {
            "name": str(block.getName()),
            "addr": int(block.getStart().getOffset()),
            "end": int(block.getEnd().getOffset()),
            "size": int(block.getSize()),
            "perms": ("r" if block.isRead() else "-")
            + ("w" if block.isWrite() else "-")
            + ("x" if block.isExecute() else "-"),
        }
    if function is not None:
        payload["function"] = function_dict(function)
    if symbol is not None:
        payload["symbol"] = {
            "addr": int(symbol.getAddress().getOffset()),
            "name": str(symbol.getName()),
            "type": str(symbol.getSymbolType()),
        }
    if instruction is not None:
        payload["instruction"] = instruction_dict(instruction)
    return payload


@op("hashes")
def hashes(ctx) -> dict:
    program = require_program(ctx)
    return {
        "md5": str(program.getExecutableMD5() or ""),
        "sha256": str(program.getExecutableSHA256() or ""),
        "path": str(program.getExecutablePath() or ""),
        "format": str(program.getExecutableFormat() or ""),
    }


@op("symbols")
def symbols(ctx, limit: int = MAX_ITEMS, offset: int = 0) -> OpResult:
    program = require_program(ctx)
    _check_limit(limit)
    _check_offset(offset)
    result = []
    total = 0
    for symbol in program.getSymbolTable().getAllSymbols(True):
        address = symbol.getAddress()
        if address is None:
            continue
        total += 1
        if total <= offset or len(result) >= limit:
            continue
        result.append(
            {
                "addr": int(address.getOffset()),
                "name": str(symbol.getName()),
                "type": str(symbol.getSymbolType()),
                "external": bool(symbol.isExternal()),
                "global": bool(symbol.isGlobal()),
            }
        )
    return _paged(result, total, offset, limit)


@op("imports")
def imports(ctx, limit: int = MAX_ITEMS, offset: int = 0) -> OpResult:
    program = require_program(ctx)
    _check_limit(limit)
    _check_offset(offset)
    result = []
    total = 0
    for symbol in program.getSymbolTable().getExternalSymbols():
        total += 1
        if total <= offset or len(result) >= limit:
            continue
        address = symbol.getAddress()
        result.append(
            {
                "addr": int(address.getOffset()) if address is not None else 0,
                "name": str(symbol.getName()),
                "type": str(symbol.getSymbolType()),
            }
        )
    return _paged(result, total, offset, limit)


@op("exports")
def exports(ctx, limit: int = MAX_ITEMS, offset: int = 0) -> OpResult:
    program = require_program(ctx)
    _check_limit(limit)
    _check_offset(offset)
    result = []
    total = 0
    for symbol in program.getSymbolTable().getAllSymbols(True):
        if symbol.isExternal() or not symbol.isGlobal():
            continue
        address = symbol.getAddress()
        if address is None:
            continue
        total += 1
        if total <= offset or len(result) >= limit:
            continue
        result.append(
            {
                "addr": int(address.getOffset()),
                "name": str(symbol.getName()),
                "type": str(symbol.getSymbolType()),
            }
        )
    return _paged(result, total, offset, limit)


@op("entries")
def entries(ctx) -> list[dict]:
    program = require_program(ctx)
    result = []
    for address in program.getSymbolTable().getExternalEntryPointIterator():
        symbol = program.getSymbolTable().getPrimarySymbol(address)
        result.append(
            {
                "addr": int(address.getOffset()),
                "name": str(symbol.getName()) if symbol is not None else "",
            }
        )
    return result


@op("strings_all")
def strings_all(
    ctx,
    min_length: int = 4,
    limit: int = MAX_ITEMS,
    offset: int = 0,
) -> OpResult:
    program = require_program(ctx)
    if min_length < 1 or min_length > 256:
        raise UsageError("string minimum length must be between 1 and 256")
    _check_limit(limit)
    _check_offset(offset)
    path = str(program.getExecutablePath() or "")
    if not path:
        raise UsageError("program has no executable path for a whole-file scan")
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise GdarError(f"cannot read {path}: {exc}") from exc
    result = []
    total = 0
    start = None
    for index, byte in enumerate(data):
        printable = 0x20 <= byte < 0x7F
        if printable and start is None:
            start = index
        elif not printable and start is not None:
            if index - start >= min_length:
                total += 1
                if total > offset and len(result) < limit:
                    result.append(
                        {
                            "offset": start,
                            "length": index - start,
                            "string": data[start:index].decode("latin-1"),
                        }
                    )
            start = None
    if start is not None and len(data) - start >= min_length:
        total += 1
        if total > offset and len(result) < limit:
            result.append(
                {
                    "offset": start,
                    "length": len(data) - start,
                    "string": data[start:].decode("latin-1"),
                }
            )
    return _paged(result, total, offset, limit)


@op("strings")
def strings(ctx, limit: int = MAX_ITEMS, offset: int = 0) -> OpResult:
    program = require_program(ctx)
    _check_limit(limit)
    _check_offset(offset)
    result = []
    total = 0
    iterator = program.getListing().getDefinedData(True)
    while iterator.hasNext():
        data = iterator.next()
        try:
            if not data.hasStringValue():
                continue
            value = data.getValue()
        except Exception:
            continue
        if value is None:
            continue
        text = str(value)
        if len(text) < 2 or text.startswith("??"):
            continue
        total += 1
        if total <= offset or len(result) >= limit:
            continue
        result.append(
            {
                "addr": int(data.getAddress().getOffset()),
                "length": int(data.getLength()),
                "string": text,
                "type": str(data.getDataType().getName()),
            }
        )
    return _paged(result, total, offset, limit)


def _check_limit(limit: int) -> None:
    if limit < 0 or limit > MAX_ITEMS:
        raise UsageError(f"limit must be between 0 and {MAX_ITEMS}")


def _check_offset(offset: int) -> None:
    if offset < 0:
        raise UsageError("offset must not be negative")


def _paged(result: list[dict], total: int, offset: int, limit: int) -> OpResult:
    return OpResult(
        result,
        {
            "total": total,
            "shown": len(result),
            "offset": offset,
            "limit": limit,
            "truncated": offset + len(result) < total,
        },
    )
