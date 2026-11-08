"""Small analysis-write operations used by the M2 command surface."""

from __future__ import annotations

from pathlib import Path

from gdare2.errors import GdarError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import instruction_dict, require_program
from gdare2d.ops.memory import read_bytes

MAX_ANALYZE_BYTES = 1024 * 1024
MAX_DATA_WORDS = 65536
MAX_WRITE_BYTES = 1024 * 1024
MAX_PATCHES = 4096


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


@op("write_bytes", writes=True)
def write_bytes(ctx, ea: int, data: bytes, mask: bytes | None = None) -> dict:
    program = require_program(ctx)
    raw = bytes(data)
    if not raw:
        raise UsageError("write needs at least one byte")
    if len(raw) > MAX_WRITE_BYTES:
        raise UsageError(f"single write is limited to {MAX_WRITE_BYTES} bytes")
    mask_bytes = None if mask is None else bytes(mask)
    if mask_bytes is not None and len(mask_bytes) != len(raw):
        raise UsageError("write mask length does not match data length")

    start = to_addr(program, int(ea))
    _require_single_block(program, start, len(raw))
    before = read_bytes(ctx, ea=int(ea), size=len(raw))
    after = raw if mask_bytes is None else _apply_mask(before, raw, mask_bytes)
    _clear_code_units(program, start, len(after))
    program.getMemory().setBytes(start, after)
    ctx.runtime.record_write(int(ea), before, after)
    return {"addr": int(ea), "size": len(after), "bytes": after}


@op("write_patches", writes=True)
def write_patches(ctx, patches: list[dict]) -> dict:
    program = require_program(ctx)
    if not isinstance(patches, list) or not patches:
        raise UsageError("wc+ needs at least one patch")
    if len(patches) > MAX_PATCHES:
        raise UsageError(f"write cache is limited to {MAX_PATCHES} patches")

    memory = program.getMemory()
    segments = []
    total = 0
    for patch in patches:
        if not isinstance(patch, dict):
            raise UsageError("invalid patch entry")
        try:
            ea = int(patch["ea"])
            raw = bytes(patch["data"])
        except (KeyError, TypeError, ValueError) as exc:
            raise UsageError(f"invalid patch entry: {exc}") from exc
        if not raw:
            raise UsageError("patch needs at least one byte")
        if len(raw) > MAX_WRITE_BYTES:
            raise UsageError(f"single patch is limited to {MAX_WRITE_BYTES} bytes")
        mask_value = patch.get("mask")
        mask_bytes = None if mask_value is None else bytes(mask_value)
        if mask_bytes is not None and len(mask_bytes) != len(raw):
            raise UsageError("patch mask length does not match data length")

        start = to_addr(program, ea)
        _require_single_block(program, start, len(raw))
        before = read_bytes(ctx, ea=ea, size=len(raw))
        after = raw if mask_bytes is None else _apply_mask(before, raw, mask_bytes)
        _clear_code_units(program, start, len(after))
        memory.setBytes(start, after)
        if before != after:
            segments.append((ea, before, after))
            total += len(after)

    ctx.runtime.record_writes(segments)
    return {"patches": len(patches), "bytes": total}


@op("write_zero", writes=True)
def write_zero(ctx, ea: int, size: int) -> dict:
    if size < 0:
        raise UsageError("w0 size must not be negative")
    if size > MAX_WRITE_BYTES:
        raise UsageError(f"single write is limited to {MAX_WRITE_BYTES} bytes")
    payload = write_bytes(ctx, ea=int(ea), data=b"\x00" * size)
    return {**payload, "zero": size}


@op("write_file", writes=True)
def write_file(ctx, ea: int, path: str) -> dict:
    source = Path(path).expanduser()
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise GdarError(f"cannot read {path}: {exc}") from exc
    if not data:
        raise UsageError(f"{path} is empty")
    if len(data) > MAX_WRITE_BYTES:
        raise UsageError(f"single write is limited to {MAX_WRITE_BYTES} bytes")
    payload = write_bytes(ctx, ea=int(ea), data=data)
    return {**payload, "file": str(source)}


@op("write_copy", writes=True)
def write_copy(ctx, dst: int, src: int, size: int) -> dict:
    program = require_program(ctx)
    if size <= 0:
        raise UsageError("wd size must be positive")
    if size > MAX_WRITE_BYTES:
        raise UsageError(f"single write is limited to {MAX_WRITE_BYTES} bytes")
    data = read_bytes(ctx, ea=int(src), size=size)
    start = to_addr(program, int(dst))
    _require_single_block(program, start, size)
    before = read_bytes(ctx, ea=int(dst), size=size)
    _clear_code_units(program, start, size)
    program.getMemory().setBytes(start, data)
    ctx.runtime.record_write(int(dst), before, data)
    return {"addr": int(dst), "src": int(src), "size": size}


@op("undo", writes=True)
def undo(ctx) -> dict:
    return ctx.runtime.undo_write()


@op("redo", writes=True)
def redo(ctx) -> dict:
    return ctx.runtime.redo_write()


def _apply_mask(before: bytes, data: bytes, mask: bytes) -> bytes:
    return bytes(
        (old & (~keep & 0xFF)) | (value & keep)
        for old, value, keep in zip(before, data, mask)
    )


def _clear_code_units(program, start, size: int) -> None:
    if size <= 0:
        return
    end = to_addr(program, int(start.getOffset()) + size - 1)
    program.getListing().clearCodeUnits(start, end, False)


def _require_single_block(program, start, size: int) -> None:
    if size <= 0:
        return
    end = to_addr(program, int(start.getOffset()) + size - 1)
    block = program.getMemory().getBlock(start)
    if block is None or int(end.getOffset()) > int(block.getEnd().getOffset()):
        raise UsageError("write range is not contained in one memory block")
