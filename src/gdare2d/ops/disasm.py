"""Disassembly, function and basic-block ops."""

from __future__ import annotations

from gdare2.errors import GdarError, NotFuncError, NotFoundError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import function_dict, instruction_dict, require_program

MAX_INSTRUCTIONS = 4096


def _first(program, ea: int):
    listing = program.getListing()
    address = to_addr(program, ea)
    instruction = listing.getInstructionAt(address)
    if instruction is None:
        instruction = listing.getInstructionAfter(address)
    return instruction


def _at_or_containing(program, ea: int):
    listing = program.getListing()
    address = to_addr(program, ea)
    return listing.getInstructionContaining(address) or listing.getInstructionAfter(address)


@op("disasm")
def disasm(ctx, ea: int, count: int = 1) -> list[dict]:
    program = require_program(ctx)
    if count < 0:
        return disasm_back(ctx, ea=ea, count=-count)
    if count > MAX_INSTRUCTIONS:
        raise UsageError(f"disasm count is limited to {MAX_INSTRUCTIONS}")
    instruction = _first(program, int(ea))
    if instruction is None:
        raise NotFoundError(f"no instruction at or after 0x{int(ea):x}")
    listing = program.getListing()
    result: list[dict] = []
    while instruction is not None and len(result) < count:
        result.append(instruction_dict(instruction))
        instruction = listing.getInstructionAfter(instruction.getAddress())
    return result


@op("disasm_back")
def disasm_back(ctx, ea: int, count: int = 1) -> list[dict]:
    program = require_program(ctx)
    if count > MAX_INSTRUCTIONS:
        raise UsageError(f"disasm count is limited to {MAX_INSTRUCTIONS}")
    listing = program.getListing()
    address = to_addr(program, int(ea))
    instruction = listing.getInstructionBefore(address)
    result: list[dict] = []
    while instruction is not None and len(result) < count:
        result.append(instruction_dict(instruction))
        instruction = listing.getInstructionBefore(instruction.getAddress())
    result.reverse()
    return result


@op("instruction_after")
def instruction_after(ctx, ea: int) -> dict:
    program = require_program(ctx)
    instruction = program.getListing().getInstructionAfter(to_addr(program, int(ea)))
    if instruction is None:
        raise NotFoundError(f"no instruction after 0x{int(ea):x}")
    return instruction_dict(instruction)


@op("instruction_before")
def instruction_before(ctx, ea: int) -> dict:
    program = require_program(ctx)
    instruction = program.getListing().getInstructionBefore(to_addr(program, int(ea)))
    if instruction is None:
        raise NotFoundError(f"no instruction before 0x{int(ea):x}")
    return instruction_dict(instruction)


@op("pdf")
def pdf(ctx, ea: int) -> dict:
    program = require_program(ctx)
    function = program.getFunctionManager().getFunctionContaining(to_addr(program, int(ea)))
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    listing = program.getListing()
    instructions = []
    iterator = listing.getInstructions(function.getBody(), True)
    while iterator.hasNext() and len(instructions) < MAX_INSTRUCTIONS:
        instructions.append(instruction_dict(iterator.next()))
    payload = function_dict(function)
    payload["instructions"] = instructions
    return payload


@op("function_at")
def function_at(ctx, ea: int) -> dict:
    program = require_program(ctx)
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    return function_dict(function)


@op("create_function", writes=True)
def create_function(ctx, ea: int) -> dict:
    program = require_program(ctx)
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        from ghidra.app.cmd.function import CreateFunctionCmd

        command = CreateFunctionCmd(address)
        if not command.applyTo(program, ctx.monitor()):
            raise GdarError(f"could not create function at 0x{int(ea):x}: {command.getStatusMsg()}")
        function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        raise GdarError(f"function creation did not produce a function at 0x{int(ea):x}")
    return function_dict(function)


@op("basic_block")
def basic_block(ctx, ea: int) -> dict:
    program = require_program(ctx)
    from ghidra.program.model.block import BasicBlockModel

    model = BasicBlockModel(program)
    iterator = model.getCodeBlocksContaining(to_addr(program, int(ea)), ctx.monitor())
    if not iterator.hasNext():
        raise NotFoundError(f"no basic block containing 0x{int(ea):x}")
    block = iterator.next()
    return _block_dict(block, ctx.monitor())


@op("basic_blocks")
def basic_blocks(ctx, ea: int) -> list[dict]:
    program = require_program(ctx)
    function = program.getFunctionManager().getFunctionContaining(to_addr(program, int(ea)))
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    from ghidra.program.model.block import BasicBlockModel

    model = BasicBlockModel(program)
    iterator = model.getCodeBlocksContaining(function.getBody(), ctx.monitor())
    result: list[dict] = []
    while iterator.hasNext():
        result.append(_block_dict(iterator.next(), ctx.monitor()))
    result.sort(key=lambda item: item["start"])
    return result


def _block_dict(block, monitor) -> dict:
    successors = []
    try:
        destinations = block.getDestinations(monitor)
        while destinations.hasNext():
            successors.append(int(destinations.next().getDestinationAddress().getOffset()))
    except Exception:
        pass
    return {
        "start": int(block.getFirstStartAddress().getOffset()),
        "end": int(block.getMaxAddress().getOffset()),
        "successors": successors,
    }
