"""Hexdump rendering."""

from __future__ import annotations

from gdare2.fmt.listing import format_addr


def hexdump(data: bytes, base: int, *, cols: int = 16, header: bool = True, bits: int = 32) -> list[str]:
    cols = max(1, min(cols, 64))
    lines: list[str] = []
    if header:
        heads = " ".join(f"{index:02x}" for index in range(cols))
        lines.append(f"- offset -   {heads}  ASCII")
    for offset in range(0, len(data), cols):
        chunk = data[offset : offset + cols]
        hexpart = " ".join(f"{byte:02x}" for byte in chunk)
        hexpart = f"{hexpart:<{cols * 3 - 1}}"
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{format_addr(base + offset, bits)}  {hexpart}  {ascii_part}")
    return lines
