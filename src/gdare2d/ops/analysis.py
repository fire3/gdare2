"""Function and analysis queries."""

from __future__ import annotations

import contextlib

from gdare2.errors import GdarError, NotFoundError, NotFuncError, UsageError
from gdare2.protocol import OpResult
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import function_dict, iter_items, require_program

MAX_FUNCTIONS = 10000


@op("functions")
def functions(ctx, limit: int = MAX_FUNCTIONS, offset: int = 0) -> OpResult:
    program = require_program(ctx)
    if limit < 0 or limit > MAX_FUNCTIONS:
        raise UsageError(f"function limit must be between 0 and {MAX_FUNCTIONS}")
    if offset < 0:
        raise UsageError("function offset must not be negative")
    manager = program.getFunctionManager()
    result = []
    total = 0
    iterator = manager.getFunctions(True)
    while iterator.hasNext():
        function = function_dict(iterator.next())
        total += 1
        if total <= offset or len(result) >= limit:
            continue
        result.append(function)
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


@op("function_callers")
def function_callers(ctx, ea: int) -> list[dict]:
    from gdare2.errors import NotFuncError
    from gdare2d.context import to_addr

    program = require_program(ctx)
    function = program.getFunctionManager().getFunctionContaining(to_addr(program, int(ea)))
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    return [function_dict(caller) for caller in function.getCallingFunctions(ctx.monitor())]


@op("function_callees")
def function_callees(ctx, ea: int) -> list[dict]:
    from gdare2.errors import NotFuncError
    from gdare2d.context import to_addr

    program = require_program(ctx)
    function = program.getFunctionManager().getFunctionContaining(to_addr(program, int(ea)))
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    return [function_dict(callee) for callee in function.getCalledFunctions(ctx.monitor())]


@op("function_xrefs")
def function_xrefs(ctx, ea: int) -> list[dict]:
    from gdare2.errors import NotFuncError
    from gdare2d.context import to_addr

    program = require_program(ctx)
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    manager = program.getReferenceManager()
    listing = program.getListing()
    result = []
    seen = set()
    iterator = listing.getInstructions(function.getBody(), True)
    while iterator.hasNext() and len(result) < MAX_FUNCTIONS * 10:
        instruction = iterator.next()
        references = manager.getReferencesFrom(instruction.getAddress())
        if hasattr(references, "hasNext"):
            values = []
            while references.hasNext():
                values.append(references.next())
        else:
            values = list(references)
        for reference in values:
            key = (int(reference.getFromAddress().getOffset()), int(reference.getToAddress().getOffset()))
            if key in seen:
                continue
            seen.add(key)
            result.append(
                {
                    "from": key[0],
                    "to": key[1],
                    "type": str(reference.getReferenceType()),
                    "primary": bool(reference.isPrimary()),
                }
            )
    return result


@op("function_rename", writes=True)
def function_rename(ctx, ea: int, name: str) -> dict:
    program = require_program(ctx)
    name = name.strip()
    if not name:
        raise UsageError("function name must not be empty")
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    from ghidra.program.model.symbol import SourceType

    function.setName(name, SourceType.USER_DEFINED)
    return function_dict(function)


@op("function_resize", writes=True)
def function_resize(ctx, ea: int, end: int) -> dict:
    program = require_program(ctx)
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")

    start = int(function.getEntryPoint().getOffset())
    end = int(end)
    if end < start:
        raise UsageError("function end must not precede its entry point")
    from ghidra.program.model.address import AddressSet

    body = AddressSet(to_addr(program, start), to_addr(program, end))
    function.setBody(body)
    refreshed = program.getFunctionManager().getFunctionAt(function.getEntryPoint())
    if refreshed is None:
        raise GdarError("function resize removed the function")
    return function_dict(refreshed)


@op("function_reanalyze", writes=True)
def function_reanalyze(ctx, ea: int) -> dict:
    program = require_program(ctx)
    address = to_addr(program, int(ea))
    manager = program.getFunctionManager()
    function = manager.getFunctionContaining(address) or manager.getFunctionAt(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    entry = function.getEntryPoint()
    old_name = str(function.getName())
    preserve_name = not (old_name.startswith("FUN_") or old_name.startswith("thunk_FUN_"))
    if not manager.removeFunction(entry):
        raise GdarError(f"could not remove function at 0x{int(ea):x}")

    from ghidra.app.cmd.function import CreateFunctionCmd

    command = CreateFunctionCmd(entry)
    if not command.applyTo(program, ctx.monitor()):
        raise GdarError(f"could not recreate function at 0x{int(ea):x}: {command.getStatusMsg()}")
    refreshed = manager.getFunctionAt(entry) or manager.getFunctionContaining(entry)
    if refreshed is None:
        raise GdarError(f"function reanalysis produced no function at 0x{int(ea):x}")
    if preserve_name:
        from ghidra.program.model.symbol import SourceType

        with contextlib.suppress(Exception):
            refreshed.setName(old_name, SourceType.USER_DEFINED)
    return function_dict(refreshed)


@op("variable_refs")
def variable_refs(
    ctx,
    ea: int,
    name: str | None = None,
    kind: str = "r",
    limit: int = 10000,
) -> list[dict]:
    program = require_program(ctx)
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    if kind not in ("r", "w"):
        raise UsageError("variable reference kind must be r or w")
    results = ctx.runtime.decompile(function)
    high_function = results.getHighFunction()
    if high_function is None:
        raise NotFuncError(f"decompiler produced no high function for 0x{int(ea):x}")

    output = []
    for symbol in iter_items(high_function.getLocalSymbolMap().getSymbols()):
        symbol_name = str(symbol.getName())
        if name and symbol_name != name:
            continue
        high_variable = symbol.getHighVariable()
        if high_variable is None:
            continue
        refs: set[int] = set()
        for varnode in iter_items(high_variable.getInstances()):
            if kind == "w":
                op = varnode.getDef()
                if op is not None:
                    target = op.getSeqnum().getTarget()
                    if target is not None:
                        refs.add(int(target.getOffset()))
            else:
                for op in iter_items(varnode.getDescendants()):
                    target = op.getSeqnum().getTarget()
                    if target is not None:
                        refs.add(int(target.getOffset()))
        output.append(
            {
                "name": symbol_name,
                "storage": str(symbol.getStorage()),
                "kind": "register" if symbol.getStorage().isRegisterStorage()
                else "stack" if symbol.getStorage().isStackStorage()
                else "other",
                "refs": sorted(refs)[:limit],
            }
        )
    if name and not output:
        raise NotFoundError(f"variable {name!r} not found")
    return output


@op("variable_rename", writes=True)
def variable_rename(ctx, ea: int, old: str, new: str) -> dict:
    program = require_program(ctx)
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    clean = new.strip()
    if not clean:
        raise UsageError("new variable name must not be empty")
    from ghidra.program.model.symbol import SourceType

    for variable in iter_items(function.getAllVariables()):
        if str(variable.getName()) == old:
            variable.setName(clean, SourceType.USER_DEFINED)
            return {
                "old": old,
                "name": str(variable.getName()),
                "storage": str(variable.getVariableStorage()),
            }

    # Decompiler-generated parameters/locals may not be present in
    # Function.getAllVariables(); fall back to the high symbol model.
    results = ctx.runtime.decompile(function)
    high_function = results.getHighFunction()
    if high_function is not None:
        for symbol in iter_items(high_function.getLocalSymbolMap().getSymbols()):
            if str(symbol.getName()) != old:
                continue
            if symbol.isParameter():
                index = symbol.getCategoryIndex()
                if 0 <= index < function.getParameterCount():
                    parameter = function.getParameter(index)
                    parameter.setName(clean, SourceType.USER_DEFINED)
                    return {
                        "old": old,
                        "name": str(parameter.getName()),
                        "storage": str(parameter.getVariableStorage()),
                    }
                from ghidra.program.model.listing import ParameterImpl

                parameter = ParameterImpl(
                    clean,
                    symbol.getDataType(),
                    symbol.getStorage(),
                    program,
                    SourceType.USER_DEFINED,
                )
                function.addParameter(parameter, SourceType.USER_DEFINED)
                return {
                    "old": old,
                    "name": str(parameter.getName()),
                    "storage": str(parameter.getVariableStorage()),
                }
            underlying = symbol.getSymbol()
            if underlying is not None:
                underlying.setName(clean, SourceType.USER_DEFINED)
                return {
                    "old": old,
                    "name": str(underlying.getName()),
                    "storage": str(symbol.getStorage()),
                }
    raise NotFoundError(f"variable {old!r} not found")
