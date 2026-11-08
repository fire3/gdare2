"""SLEIGH assembler operations."""

from __future__ import annotations

from gdare2.errors import GdarError, UnsupportedError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import require_program

MAX_ASSEMBLY_LINES = 1024


def _assemble(program, ea: int, text: str) -> list[dict]:
    from ghidra.app.plugin.assembler import Assemblers

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise UsageError("assembly text is empty")
    if len(lines) > MAX_ASSEMBLY_LINES:
        raise UsageError(f"assembly is limited to {MAX_ASSEMBLY_LINES} lines")
    try:
        assembler = Assemblers.getAssembler(program)
    except Exception as exc:
        raise UnsupportedError(f"no SLEIGH assembler for this language: {exc}") from exc

    address = to_addr(program, int(ea))
    result = []
    for line in lines:
        try:
            data = bytes(assembler.assembleLine(address, line))
        except Exception as exc:
            raise GdarError(f"assembly failed for {line!r}: {exc}") from exc
        result.append(
            {
                "addr": int(address.getOffset()),
                "text": line,
                "bytes": data,
                "size": len(data),
            }
        )
        address = address.add(len(data))
    return result


@op("assemble")
def assemble(ctx, ea: int, text: str) -> dict:
    program = require_program(ctx)
    items = _assemble(program, int(ea), text)
    return {
        "items": items,
        "bytes": b"".join(item["bytes"] for item in items),
        "size": sum(item["size"] for item in items),
    }


@op("assemble_write", writes=True)
def assemble_write(ctx, ea: int, text: str) -> dict:
    program = require_program(ctx)
    items = _assemble(program, int(ea), text)
    data = b"".join(item["bytes"] for item in items)
    from gdare2d.ops.write import write_bytes

    payload = write_bytes(ctx, ea=int(ea), data=data)
    return {
        "items": items,
        "bytes": data,
        "size": len(data),
        "addr": int(ea),
        "written": payload,
    }
