"""Control-flow and call graph queries built on Ghidra function models."""

from __future__ import annotations

from gdare2.errors import NotFuncError, UsageError
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
MAX_CALL_GRAPH_NODES = 256


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


def _call_node(function) -> dict:
    return {
        "addr": int(function.getEntryPoint().getOffset()),
        "name": str(function.getName()),
        "size": int(function.getBody().getNumAddresses()),
    }


def _call_links(source, source_addr: int, monitor):
    """Yield (neighbour, edge_src, edge_dst) with edges pointing caller -> callee."""
    for callee in iter_items(source.getCalledFunctions(monitor)):
        yield callee, source_addr, int(callee.getEntryPoint().getOffset())
    for caller in iter_items(source.getCallingFunctions(monitor)):
        yield caller, int(caller.getEntryPoint().getOffset()), source_addr


@op("call_graph")
def call_graph(ctx, ea: int, depth: int = 1) -> dict:
    program = require_program(ctx)
    depth = int(depth)
    if depth < 0:
        raise UsageError("call graph depth must not be negative")
    function = program.getFunctionManager().getFunctionContaining(to_addr(program, int(ea)))
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")

    monitor = ctx.monitor()
    root = int(function.getEntryPoint().getOffset())
    nodes: dict[int, dict] = {root: _call_node(function)}
    edges: list[dict] = []
    seen_edges: set[tuple[int, int]] = set()
    truncated = False
    frontier = [(function, root)]

    for _ in range(depth):
        next_frontier = []
        for source, source_addr in frontier:
            for neighbour, edge_src, edge_dst in _call_links(source, source_addr, monitor):
                addr = int(neighbour.getEntryPoint().getOffset())
                external = bool(neighbour.isExternal()) or bool(neighbour.isThunk())
                known = addr in nodes
                if not known and len(nodes) >= MAX_CALL_GRAPH_NODES:
                    truncated = True
                    continue
                if not known:
                    node = _call_node(neighbour)
                    if external:
                        node["external"] = True
                    nodes[addr] = node
                if (edge_src, edge_dst) not in seen_edges:
                    seen_edges.add((edge_src, edge_dst))
                    edges.append({"src": edge_src, "dst": edge_dst})
                if not external and not known:
                    next_frontier.append((neighbour, addr))
            if truncated:
                break
        if truncated or not next_frontier:
            break
        frontier = next_frontier

    edges.sort(key=lambda edge: (edge["src"], edge["dst"]))
    return {
        "root": root,
        "depth": depth,
        "nodes": [nodes[addr] for addr in sorted(nodes)],
        "edges": edges,
        "truncated": truncated,
    }
