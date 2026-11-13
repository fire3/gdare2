"""Hexdump rendering, matching radare2's ``px`` layout."""

from __future__ import annotations

from gdare2.fmt.listing import format_addr

PRINTABLE = set(range(0x20, 0x7F))


def hexdump(
    data: bytes,
    base: int,
    *,
    cols: int = 16,
    header: bool = True,
    bits: int = 32,
    pairs: bool = True,
    offset: bool = True,
    ascii: bool = True,
) -> list[str]:
    """Render ``data`` like ``px``: offset, hex groups, then ASCII."""
    cols = max(1, min(cols, 64))
    rows: list[str] = []
    if header and data:
        rows.append(_header(base, cols, pairs, offset, ascii))
    for start in range(0, len(data), cols):
        rows.append(
            _row(base + start, data[start : start + cols], cols, bits, pairs, offset, ascii)
        )
    return rows


def _data_width(cols: int, pairs: bool) -> int:
    if pairs and cols % 2 == 0:
        groups = cols // 2
        return groups * 4 + (groups - 1)
    return cols * 2 + (cols - 1)


def _header(base: int, cols: int, pairs: bool, offset: bool, ascii: bool) -> str:
    # r2 pads "- offset -" to the address width and uses two spaces before the
    # ASCII column; without that the header is one column narrower than rows.
    out = "- offset -  " if offset else ""
    if pairs and cols % 2 == 0:
        groups = [
            f"{(base + index) & 0xFF:02X}{(base + index + 1) & 0xFF:02X}"
            for index in range(0, cols, 2)
        ]
    else:
        groups = [f"{(base + index) & 0xFF:02X}" for index in range(cols)]
    out += " ".join(groups)
    if ascii:
        out += "  " + "".join(f"{(base + index) & 0xF:X}" for index in range(cols))
    return out


def _row(
    base: int,
    chunk: bytes,
    cols: int,
    bits: int,
    pairs: bool,
    offset: bool,
    ascii: bool,
) -> str:
    out = f"{format_addr(base, bits)}  " if offset else ""
    if pairs:
        cells = [chunk[index : index + 2].hex() for index in range(0, len(chunk), 2)]
    else:
        cells = [f"{byte:02x}" for byte in chunk]
    out += " ".join(cells).ljust(_data_width(cols, pairs))
    if ascii:
        text = "".join(chr(byte) if byte in PRINTABLE else "." for byte in chunk)
        out += "  " + text
    return out.rstrip()
