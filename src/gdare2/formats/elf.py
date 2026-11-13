"""Minimal ELF program-header reader used by ``iSS``.

This intentionally reads the **input file**, not Ghidra's ``Program`` model:
``iS`` already exposes Ghidra memory blocks, while ``iSS`` is radare2's view of
the ELF program headers (file offset, virtual address, file/memory size and
permissions).  Keeping the parser file-based means it also works for targets
that Ghidra relocates (PIE) or loads at a forced base.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_GNU_PROPERTY = 0x6474E553

_TYPE_NAMES = {
    PT_NULL: "NULL",
    PT_LOAD: "LOAD",
    PT_DYNAMIC: "DYNAMIC",
    PT_INTERP: "INTERP",
    PT_NOTE: "NOTE",
    PT_SHLIB: "SHLIB",
    PT_PHDR: "PHDR",
    PT_TLS: "TLS",
    PT_GNU_EH_FRAME: "GNU_EH_FRAME",
    PT_GNU_STACK: "GNU_STACK",
    PT_GNU_RELRO: "GNU_RELRO",
    PT_GNU_PROPERTY: "GNU_PROPERTY",
}

_MAX_PHNUM = 4096
_PN_XNUM = 0xFFFF


class ElfFormatError(ValueError):
    """The input is not an ELF file this parser understands."""


@dataclass(frozen=True)
class Segment:
    """One ELF program header."""

    index: int
    type: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int
    align: int
    name: str

    @property
    def perm(self) -> str:
        # radare2 renders segments as "-rwx" (execute in the last position).
        return (
            "-"
            + ("r" if self.flags & 4 else "-")
            + ("w" if self.flags & 2 else "-")
            + ("x" if self.flags & 1 else "-")
        )

    def as_dict(self) -> dict:
        """radare2-compatible JSON shape for ``iSSj``."""
        return {
            "name": self.name,
            "size": self.filesz,
            "vsize": self.memsz,
            "perm": self.perm,
            "paddr": self.offset,
            "vaddr": self.vaddr,
        }


def read_segments(path: str | Path) -> list[Segment]:
    """Return the ELF program headers of *path*.

    Raises :class:`ElfFormatError` when *path* is not a supported ELF file and
    :class:`OSError` when it cannot be read.
    """
    with Path(path).open("rb") as handle:
        ident = handle.read(16)
        if len(ident) < 16 or ident[:4] != ELF_MAGIC:
            raise ElfFormatError("not an ELF file")
        elf_class = ident[4]
        data_encoding = ident[5]
        if elf_class not in (1, 2):
            raise ElfFormatError(f"unsupported ELF class {elf_class}")
        if data_encoding not in (1, 2):
            raise ElfFormatError(f"unsupported ELF data encoding {data_encoding}")
        order = "<" if data_encoding == 1 else ">"
        is_64 = elf_class == 2

        header = handle.read(48 if is_64 else 36)
        if len(header) < (48 if is_64 else 36):
            raise ElfFormatError("truncated ELF header")

        if is_64:
            (phoff,) = struct.unpack_from(f"{order}Q", header, 32 - 16)
            (shoff,) = struct.unpack_from(f"{order}Q", header, 40 - 16)
            (phentsize,) = struct.unpack_from(f"{order}H", header, 54 - 16)
            (phnum,) = struct.unpack_from(f"{order}H", header, 56 - 16)
            (shentsize,) = struct.unpack_from(f"{order}H", header, 58 - 16)
        else:
            (phoff,) = struct.unpack_from(f"{order}I", header, 28 - 16)
            (shoff,) = struct.unpack_from(f"{order}I", header, 32 - 16)
            (phentsize,) = struct.unpack_from(f"{order}H", header, 42 - 16)
            (phnum,) = struct.unpack_from(f"{order}H", header, 44 - 16)
            (shentsize,) = struct.unpack_from(f"{order}H", header, 46 - 16)

        expected_size = 56 if is_64 else 32
        if phentsize < expected_size:
            raise ElfFormatError(f"unexpected program header size {phentsize}")

        if phnum == _PN_XNUM and shoff and shentsize >= 40:
            handle.seek(shoff)
            section = handle.read(shentsize)
            if len(section) < 32:
                raise ElfFormatError("truncated section header for PN_XNUM")
            (phnum,) = struct.unpack_from(f"{order}I", section, 28)
        if phnum > _MAX_PHNUM:
            raise ElfFormatError(f"implausible program header count {phnum}")
        if not phoff or not phnum:
            return []

        handle.seek(phoff)
        table = handle.read(phentsize * phnum)
        if len(table) < phentsize * phnum:
            raise ElfFormatError("truncated program header table")

        load_index = 0
        seen: dict[str, int] = {}
        segments: list[Segment] = []
        for index in range(phnum):
            raw = table[index * phentsize : (index + 1) * phentsize]
            if is_64:
                (
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    _p_paddr,
                    p_filesz,
                    p_memsz,
                    p_align,
                ) = struct.unpack_from(f"{order}IIQQQQQQ", raw, 0)
            else:
                (
                    p_type,
                    p_offset,
                    p_vaddr,
                    _p_paddr,
                    p_filesz,
                    p_memsz,
                    p_flags,
                    p_align,
                ) = struct.unpack_from(f"{order}IIIIIIII", raw, 0)

            base_name = _TYPE_NAMES.get(p_type, "UNKNOWN")
            if p_type == PT_LOAD:
                name = f"LOAD{load_index}"
                load_index += 1
            else:
                count = seen.get(base_name, 0)
                seen[base_name] = count + 1
                name = base_name if count == 0 else f"{base_name}_{count}"

            segments.append(
                Segment(
                    index=index,
                    type=p_type,
                    offset=p_offset,
                    vaddr=p_vaddr,
                    filesz=p_filesz,
                    memsz=p_memsz,
                    flags=p_flags,
                    align=p_align,
                    name=name,
                )
            )
        return segments
