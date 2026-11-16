"""Memory reads."""

from __future__ import annotations

import jpype

from gdare2.errors import GdarError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import require_program

MAX_READ = 1024 * 1024


@op("read_bytes")
def read_bytes(ctx, ea: int, size: int) -> bytes:
    program = require_program(ctx)
    if size < 0:
        raise UsageError("size must not be negative")
    if size > MAX_READ:
        raise UsageError(f"single read is limited to {MAX_READ} bytes")
    address = to_addr(program, int(ea))
    if size == 0:
        return b""
    result = bytearray(b"\xff" * size)
    buffer = jpype.JArray(jpype.JByte)(size)
    try:
        count = program.getMemory().getBytes(address, buffer)
    except Exception:
        # r2 fills unmapped reads with 0xff instead of failing the request;
        # `px 8` past EOF is a common workflow.  Keep the bytes that could be
        # read and pad the rest the same way.
        return bytes(result)
    if count < 0:
        return bytes(result)
    for index in range(min(int(count), size)):
        result[index] = int(buffer[index]) & 0xFF
    return bytes(result)


@op("read_value")
def read_value(ctx, ea: int, width: int = 4) -> dict:
    program = require_program(ctx)
    address = to_addr(program, int(ea))
    memory = program.getMemory()
    mask = (1 << (width * 8)) - 1
    try:
        if width == 1:
            value = int(memory.getByte(address))
        elif width == 2:
            value = int(memory.getShort(address))
        elif width == 4:
            value = int(memory.getInt(address))
        elif width == 8:
            value = int(memory.getLong(address))
        else:
            raw = read_bytes(ctx, ea=int(ea), size=width)
            order = "big" if program.getLanguage().isBigEndian() else "little"
            return {"addr": int(ea), "width": width, "value": int.from_bytes(raw, order)}
    except GdarError:
        raise
    except Exception as exc:
        raise GdarError(f"cannot read value at 0x{int(ea):x}: {exc}") from exc
    return {"addr": int(ea), "width": width, "value": value & mask}
