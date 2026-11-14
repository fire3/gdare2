"""Symbol/flag write operations backed by the Ghidra symbol table."""

from __future__ import annotations

from gdare2.errors import GdarError, NotFoundError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import iter_items, require_program


def _symbol_dict(symbol) -> dict:
    address = symbol.getAddress()
    return {
        "addr": int(address.getOffset()) if address is not None else 0,
        "name": str(symbol.getName()),
        "type": str(symbol.getSymbolType()),
        "external": bool(symbol.isExternal()),
        "global": bool(symbol.isGlobal()),
    }


def _primary_symbol(program, address):
    symbol = program.getSymbolTable().getPrimarySymbol(address)
    if symbol is None:
        raise NotFoundError(f"no symbol at 0x{int(address.getOffset()):x}")
    return symbol


def _find_symbol(program, name: str):
    candidates = [
        symbol
        for symbol in iter_items(program.getSymbolTable().getSymbols(name))
        if symbol.getAddress() is not None
    ]
    if not candidates:
        raise NotFoundError(f"symbol {name!r} not found")
    for symbol in candidates:
        if not symbol.isExternal():
            return symbol
    return candidates[0]


@op("symbol_create", writes=True)
def symbol_create(ctx, ea: int, name: str) -> dict:
    program = require_program(ctx)
    clean = name.strip()
    if not clean:
        raise UsageError("flag name must not be empty")
    address = to_addr(program, int(ea))
    from ghidra.program.model.symbol import SourceType

    table = program.getSymbolTable()
    existing = table.getSymbols(clean)
    for symbol in iter_items(existing):
        if symbol.getAddress() == address:
            return _symbol_dict(symbol)
    symbol = table.createLabel(
        address,
        clean,
        program.getGlobalNamespace(),
        SourceType.USER_DEFINED,
    )
    return _symbol_dict(symbol)


@op("symbol_rename", writes=True)
def symbol_rename(ctx, name: str, new_name: str) -> dict:
    program = require_program(ctx)
    new_clean = new_name.strip()
    if not new_clean:
        raise UsageError("new flag name must not be empty")
    symbol = _find_symbol(program, name)
    from ghidra.program.model.symbol import SourceType

    symbol.setName(new_clean, SourceType.USER_DEFINED)
    if str(symbol.getName()) != new_clean:
        raise GdarError(f"could not rename symbol {name!r}")
    return _symbol_dict(symbol)


@op("symbol_delete", writes=True)
def symbol_delete(ctx, name: str | None = None, ea: int | None = None) -> dict:
    program = require_program(ctx)
    if name:
        symbol = _find_symbol(program, name)
    elif ea is not None:
        symbol = _primary_symbol(program, to_addr(program, int(ea)))
    else:
        raise UsageError("symbol_delete needs a name or address")
    payload = _symbol_dict(symbol)
    if not symbol.delete():
        raise GdarError(f"could not delete symbol {payload['name']!r}")
    return payload


@op("demangle")
def demangle(ctx, text: str, language: str | None = None) -> dict:
    """Demangle a symbol using Ghidra's demangler registry."""
    program = require_program(ctx)
    value = text.strip()
    if not value:
        raise UsageError("iD needs a symbol name")
    from ghidra.app.util.demangler import DemanglerUtil

    demangled = DemanglerUtil.demangle(program, value)
    if demangled is None:
        return {"text": value, "name": value, "signature": value, "language": language or ""}
    name = str(
        demangled.getDemangledName()
        or demangled.getName()
        or value
    )
    signature = ""
    get_signature = getattr(demangled, "getSignature", None)
    if get_signature is not None:
        try:
            signature = str(get_signature() or "")
        except Exception:
            signature = ""
    return {
        "text": value,
        "name": name,
        "signature": signature or name,
        "language": language or "",
    }
