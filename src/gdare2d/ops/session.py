"""Session, program summary and name lookup ops."""

from __future__ import annotations

from gdare2d.dispatch import op
from gdare2d.ops._helpers import require_program


@op("info")
def info(ctx) -> dict:
    require_program(ctx)
    payload = dict(ctx.runtime.summary)
    payload.update(
        {
            "instance_id": getattr(ctx.runtime, "instance_id", None),
            "state": ctx.runtime.state,
            "pid": getattr(ctx.runtime, "pid", None),
            "port": getattr(ctx.runtime, "port", None),
            "error": ctx.runtime.error,
        }
    )
    return payload


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


@op("save", writes=True, transaction=False)
def save(ctx) -> dict:
    require_program(ctx)
    ctx.runtime.save()
    return {"saved": True}


@op("session_open")
def session_open(ctx, pid: int = 0, kind: str = "batch", tty: bool = False, ttl: int = 90) -> dict:
    lease = ctx.runtime.session_open(pid=pid, kind=kind, tty=tty, ttl=ttl)
    return {"lease": lease, "ttl": ttl}


@op("session_heartbeat")
def session_heartbeat(ctx, lease: str, ttl: int = 90) -> dict:
    return {"alive": ctx.runtime.session_heartbeat(lease, ttl)}


@op("session_close")
def session_close(ctx, lease: str) -> dict:
    return {"closed": ctx.runtime.session_close(lease)}


@op("session_list")
def session_list(ctx) -> list[dict]:
    return ctx.runtime.session_list()
