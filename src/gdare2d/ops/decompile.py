"""Ghidra decompilation and high-level variable extraction."""

from __future__ import annotations

from gdare2.errors import NotFuncError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import function_dict, iter_items, require_program

MAX_DECOMPILE_SECONDS = 300


@op("decompile")
def decompile(ctx, ea: int, timeout: int = 30) -> dict:
    program = require_program(ctx)
    function = _function_at(program, int(ea))
    timeout = int(timeout)
    if timeout <= 0 or timeout > MAX_DECOMPILE_SECONDS:
        raise UsageError(f"decompile timeout must be between 1 and {MAX_DECOMPILE_SECONDS}")

    results = ctx.runtime.decompile(function, timeout)
    decompiled = results.getDecompiledFunction()
    payload = function_dict(function)
    payload.update(
        {
            "c": str(decompiled.getC() or ""),
            "signature": str(decompiled.getSignature() or ""),
            "timed_out": bool(results.isTimedOut()),
        }
    )
    return payload


@op("function_variables")
def function_variables(ctx, ea: int, timeout: int = 30) -> dict:
    program = require_program(ctx)
    function = _function_at(program, int(ea))
    results = ctx.runtime.decompile(function, int(timeout))
    high_function = results.getHighFunction()
    if high_function is None:
        raise NotFuncError(f"decompiler produced no high function for 0x{int(ea):x}")

    symbols = iter_items(high_function.getLocalSymbolMap().getSymbols())
    variables = [_symbol_dict(symbol) for symbol in symbols]
    variables.sort(key=lambda item: (not item["parameter"], item["storage"], item["name"]))
    payload = function_dict(function)
    payload.update(
        {
            "variables": variables,
            "parameter_count": sum(1 for item in variables if item["parameter"]),
            "variable_count": len(variables),
        }
    )
    return payload


def _symbol_dict(symbol) -> dict:
    storage = symbol.getStorage()
    pc_address = symbol.getPCAddress()
    if storage.isRegisterStorage():
        kind = "reg"
    elif storage.isStackStorage():
        kind = "sp"
    else:
        kind = "other"
    return {
        "name": str(symbol.getName()),
        "type": str(symbol.getDataType().getName()),
        "storage": str(storage.toString()),
        "kind": kind,
        "parameter": bool(symbol.isParameter()),
        "global": bool(symbol.isGlobal()),
        "pc": int(pc_address.getOffset()) if pc_address is not None else None,
    }


def _function_at(program, ea: int):
    address = to_addr(program, ea)
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        raise NotFuncError(f"address 0x{ea:x} is not inside a function")
    return function
