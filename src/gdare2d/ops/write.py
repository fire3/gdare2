"""Small analysis-write operations used by the M2 command surface."""

from __future__ import annotations

from gdare2.errors import UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import instruction_dict, require_program

MAX_ANALYZE_BYTES = 1024 * 1024
MAX_DATA_WORDS = 65536


@op("analyze_bytes", writes=True)
def analyze_bytes(ctx, ea: int, hexpairs: str) -> dict:
    program = require_program(ctx)
    data = _parse_hexpairs(hexpairs)
    if len(data) > MAX_ANALYZE_BYTES:
        raise UsageError(f"a8 is limited to {MAX_ANALYZE_BYTES} bytes")

    start = to_addr(program, int(ea))
    end = to_addr(program, int(ea) + len(data) - 1)
    listing = program.getListing()
    listing.clearCodeUnits(start, end, False)
    program.getMemory().setBytes(start, data)

    from ghidra.app.cmd.disassemble import DisassembleCommand

    command = DisassembleCommand(start, None, True)
    command.applyTo(program, ctx.monitor())
    instruction = listing.getInstructionAt(start)
    return {
        "addr": int(start.getOffset()),
        "size": len(data),
        "bytes": data,
        "instruction": instruction_dict(instruction) if instruction is not None else None,
    }


@op("analyze_data", writes=True)
def analyze_data(ctx, ea: int, count: int = 1) -> dict:
    program = require_program(ctx)
    if count <= 0:
        raise UsageError("ad word count must be positive")
    if count > MAX_DATA_WORDS:
        raise UsageError(f"ad is limited to {MAX_DATA_WORDS} words")

    bits = int(program.getLanguage().getLanguageDescription().getSize())
    word_size = max(1, bits // 8)
    total = count * word_size
    start = to_addr(program, int(ea))
    end = to_addr(program, int(ea) + total - 1)
    block = program.getMemory().getBlock(start)
    if block is None or int(end.getOffset()) > int(block.getEnd().getOffset()):
        raise UsageError("data range is not contained in one memory block")

    data_type = _word_data_type(word_size)
    from ghidra.program.model.data import DataUtilities

    listing = program.getListing()
    listing.clearCodeUnits(start, end, False)
    for index in range(count):
        address = to_addr(program, int(ea) + index * word_size)
        DataUtilities.createData(
            program,
            address,
            data_type,
            word_size,
            False,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
        )
    return {
        "addr": int(start.getOffset()),
        "count": count,
        "word_size": word_size,
        "size": total,
        "type": str(data_type.getName()),
    }


def _parse_hexpairs(text: str) -> bytes:
    compact = "".join(text.split()).replace("0x", "").replace("0X", "")
    if not compact:
        raise UsageError("a8 needs hexpairs")
    if len(compact) % 2:
        raise UsageError("a8 needs an even number of hex digits")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise UsageError(f"a8 received invalid hexpairs: {exc}") from exc


def _word_data_type(word_size: int):
    from ghidra.program.model.data import ByteDataType, DWordDataType, QWordDataType, WordDataType

    if word_size >= 8:
        return QWordDataType.dataType
    if word_size >= 4:
        return DWordDataType.dataType
    if word_size >= 2:
        return WordDataType.dataType
    return ByteDataType.dataType
