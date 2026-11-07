"""Control-flow graph queries built on Ghidra basic blocks."""

from __future__ import annotations

from gdare2.errors import NotFuncError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import (
    function_dict,
    instruction_dict,
    iter_items,
    require_program,
)

MAX_GRAPH_BLOCKS = 4096
MAX_GRAPH_INSTRUCTIONS = 20000


@op("graph")
def graph(ctx, ea: int) -> dict:
    program = require_program(ctx)
    function = program.getFunctionManager().getFunctionContaining(to_addr(program, int(ea)))
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")

    from ghidra.program.model.block import BasicBlockModel

    monitor = ctx.monitor()
    model = BasicBlockModel(program)
    listing = program.getListing()
    raw_blocks = iter_items(model.getCodeBlocksContaining(function.getBody(), monitor))[
        :MAX_GRAPH_BLOCKS
    ]
    raw_blocks.sort(key=lambda block: int(block.getFirstStartAddress().getOffset()))

    blocks = []
    edges = []
    instruction_count = 0
    for block in raw_blocks:
        start = int(block.getFirstStartAddress().getOffset())
        end = int(block.getMaxAddress().getOffset())
        successors = _successors(block, monitor)
        instructions = []
        remaining = MAX_GRAPH_INSTRUCTIONS - instruction_count
        for instruction in iter_items(listing.getInstructions(block, True))[:remaining]:
            instructions.append(instruction_dict(instruction))
            instruction_count += 1
        payload = {
            "addr": start,
            "offset": start,
            "start": start,
            "end": end,
            "size": max(0, end - start + 1),
            "ninstr": len(instructions),
            "successors": successors,
            "jump": successors[0] if successors else None,
            "fail": successors[1] if len(successors) > 1 else None,
            "ops": instructions,
        }
        blocks.append(payload)
        for index, destination in enumerate(successors):
            edges.append(
                {
                    "src": start,
                    "dst": int(destination),
                    "type": "jump" if index == 0 else "fail",
                }
            )

    payload = function_dict(function)
    payload.update(
        {
            "blocks": blocks,
            "edges": edges,
            "block_count": len(blocks),
            "instruction_count": instruction_count,
            "truncated": len(raw_blocks) >= MAX_GRAPH_BLOCKS
            or instruction_count >= MAX_GRAPH_INSTRUCTIONS,
        }
    )
    return payload


def _successors(block, monitor) -> list[int]:
    result = []
    seen = set()
    for item in iter_items(block.getDestinations(monitor)):
        destination = int(item.getDestinationAddress().getOffset())
        if destination not in seen:
            seen.add(destination)
            result.append(destination)
    return result
