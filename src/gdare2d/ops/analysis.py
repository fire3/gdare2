"""Function and analysis queries."""

from __future__ import annotations

from gdare2.errors import GdarError, NotFuncError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import function_dict, require_program

MAX_FUNCTIONS = 10000


@op("functions")
def functions(ctx, limit: int = MAX_FUNCTIONS) -> list[dict]:
    program = require_program(ctx)
    if limit < 0 or limit > MAX_FUNCTIONS:
        raise UsageError(f"function limit must be between 0 and {MAX_FUNCTIONS}")
    manager = program.getFunctionManager()
    result = []
    iterator = manager.getFunctions(True)
    while iterator.hasNext() and len(result) < limit:
        result.append(function_dict(iterator.next()))
    return result


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
