"""ASCII and Graphviz rendering for basic-block graphs."""

from __future__ import annotations

from gdare2.config import Config
from gdare2.fmt.disasm import format_instruction
from gdare2.fmt.listing import format_addr


def format_ascii_graph(graph: dict, config: Config, bits: int) -> list[str]:
    lines = [
        f"; {graph.get('name', '')} @ {format_addr(int(graph.get('addr', 0)), bits)}",
    ]
    blocks = graph.get("blocks") or []
    for block in blocks:
        start = int(block.get("start", block.get("addr", 0)))
        end = int(block.get("end", start))
        lines.append("")
        lines.append(
            f"{format_addr(start, bits)} [0x{start:x}-0x{end:x}] "
            f"({int(block.get('ninstr', 0))} insn)"
        )
        for instruction in block.get("ops") or []:
            lines.append("  " + format_instruction(instruction, config, bits))
        successors = [int(item) for item in block.get("successors") or []]
        if not successors:
            lines.append("  `-> exit")
        for index, successor in enumerate(successors):
            marker = "|->" if index == 0 else "`->"
            lines.append(f"  {marker} {format_addr(successor, bits)}")
    if not blocks:
        lines.append("; no basic blocks")
    return lines


def format_dot_graph(graph: dict) -> list[str]:
    name = _dot_escape(
        str(graph.get("name") or graph.get("addr") or "graph"),
        line_end=False,
    )
    lines = [
        f'digraph "{name}" {{',
        "  node [shape=box, fontname=\"monospace\"];",
        "  edge [fontname=\"monospace\"];",
    ]
    for block in graph.get("blocks") or []:
        start = int(block.get("start", block.get("addr", 0)))
        label = [f"0x{start:x}"]
        for instruction in block.get("ops") or []:
            label.append(str(instruction.get("text", "")))
        node_id = f"0x{start:x}"
        lines.append(f'  "{node_id}" [label="{_dot_escape(chr(10).join(label))}"];')
    for edge in graph.get("edges") or []:
        source = f"0x{int(edge['src']):x}"
        target = f"0x{int(edge['dst']):x}"
        edge_type = str(edge.get("type", "jump"))
        style = ", style=dashed" if edge_type == "fail" else ""
        lines.append(f'  "{source}" -> "{target}" [label="{edge_type}"{style}];')
    lines.append("}")
    return lines


def _dot_escape(text: str, *, line_end: bool = True) -> str:
    escaped = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "")
        .replace("\n", "\\l")
    )
    return escaped + ("\\l" if line_end else "")
