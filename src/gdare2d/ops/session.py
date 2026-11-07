"""Session, program summary and name lookup ops."""

from __future__ import annotations

from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import require_program


@op("info")
def info(ctx) -> dict:
    require_program(ctx)
    return dict(ctx.runtime.summary)


@op("resolve_name")
def resolve_name(ctx, name: str) -> int | None:
    program = require_program(ctx)
    symbol_table = program.getSymbolTable()
    for symbol in symbol_table.getSymbols(name):
        if not symbol.isExternal():
            return int(symbol.getAddress().getOffset())
    for function in program.getFunctionManager().getFunctions(True):
        if str(function.getName()) == name:
            return int(function.getEntryPoint().getOffset())
    if name.startswith("FUN_"):
        try:
            return int(name[4:], 16)
        except ValueError:
            pass
    return None


@op("analyze")
def analyze(ctx, force: bool = False) -> dict:
    require_program(ctx)
    return ctx.runtime.analyze(force=bool(force))


@op("save", writes=True)
def save(ctx) -> dict:
    require_program(ctx)
    ctx.runtime.save()
    return {"saved": True}
