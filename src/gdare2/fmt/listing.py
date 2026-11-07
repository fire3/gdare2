"""Address formatting shared by renderers."""

from __future__ import annotations


def addr_width(bits: int) -> int:
    return max(8, (int(bits or 32) + 3) // 4)


def format_addr(address: int, bits: int = 32) -> str:
    return f"0x{address & ((1 << max(bits, 32)) - 1):0{addr_width(bits)}x}"
