"""Program sections, symbols, imports, entries and strings."""

from __future__ import annotations

from gdare2.errors import UsageError
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


@op("symbols")
def symbols(ctx, limit: int = MAX_ITEMS) -> list[dict]:
    program = require_program(ctx)
    _check_limit(limit)
    result = []
    for symbol in program.getSymbolTable().getAllSymbols(True):
        if len(result) >= limit:
            break
        address = symbol.getAddress()
        if address is None:
            continue
        result.append(
            {
                "addr": int(address.getOffset()),
                "name": str(symbol.getName()),
                "type": str(symbol.getSymbolType()),
                "external": bool(symbol.isExternal()),
            }
        )
    return result


@op("imports")
def imports(ctx, limit: int = MAX_ITEMS) -> list[dict]:
    program = require_program(ctx)
    _check_limit(limit)
    result = []
    for symbol in program.getSymbolTable().getExternalSymbols():
        if len(result) >= limit:
            break
        address = symbol.getAddress()
        result.append(
            {
                "addr": int(address.getOffset()) if address is not None else 0,
                "name": str(symbol.getName()),
                "type": str(symbol.getSymbolType()),
            }
        )
    return result


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


@op("strings")
def strings(ctx, limit: int = MAX_ITEMS) -> list[dict]:
    program = require_program(ctx)
    _check_limit(limit)
    result = []
    iterator = program.getListing().getDefinedData(True)
    while iterator.hasNext() and len(result) < limit:
        data = iterator.next()
        try:
            value = data.getValue()
        except Exception:
            continue
        if value is None:
            continue
        text = str(value)
        if not text or text.startswith("??"):
            continue
        result.append(
            {
                "addr": int(data.getAddress().getOffset()),
                "length": int(data.getLength()),
                "string": text,
                "type": str(data.getDataType().getName()),
            }
        )
    return result


def _check_limit(limit: int) -> None:
    if limit < 0 or limit > MAX_ITEMS:
        raise UsageError(f"limit must be between 0 and {MAX_ITEMS}")
