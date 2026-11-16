"""Per-request context passed to Ghidra ops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Context:
    runtime: Any
    readonly: bool
    allow_writes: bool
    session_id: str = "batch"

    @property
    def program(self):
        return self.runtime.program

    @property
    def project(self):
        return self.runtime.project

    def monitor(self):
        return self.runtime._pyghidra.task_monitor()


def to_addr(program, address: int):
    """Map an r2-style address onto Ghidra's address space.

    Ghidra imports PIE/ELF images at a non-zero image base (0x100000 for a
    typical x86-64 PIE), while r2 keeps ``laddr`` at 0.  An address below the
    image base that Ghidra has no block for is therefore interpreted as
    image-base-relative (``0x10`` -> ``0x100010``), so r2 literals such as
    ``wx 9090 @ 0x10`` address the same file bytes.  Addresses Ghidra already
    maps are returned untouched.
    """
    factory = program.getAddressFactory()
    space = factory.getDefaultAddressSpace()
    value = int(address)
    mapped = space.getAddress(value)
    try:
        base = int(program.getImageBase().getOffset())
        memory = program.getMemory()
    except Exception:
        return mapped
    if base > 0 and 0 <= value < base and memory.getBlock(mapped) is None:
        shifted = space.getAddress(value + base)
        if memory.getBlock(shifted) is not None:
            return shifted
    return mapped
