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


# ---------------------------------------------------------------------------
# Header, sections, dynamic table and relocations (iH/ih/il/ir)
# ---------------------------------------------------------------------------

SHT_DYNAMIC = 6
SHT_RELA = 4
SHT_REL = 9
SHN_XINDEX = 0xFFFF

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_JMPREL = 23

_MAX_DYNAMIC = 65536
_MAX_RELOCS = 200000


@dataclass(frozen=True)
class ElfHeader:
    """The fields ``ih`` reports, in file order."""

    elf_class: int
    data_encoding: int
    type: int
    machine: int
    version: int
    entry: int
    phoff: int
    shoff: int
    flags: int
    ehsize: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    shstrndx: int
    order: str

    @property
    def is_64(self) -> bool:
        return self.elf_class == 2

    def fields(self) -> list[dict]:
        ident_format = "q" if self.is_64 else "x"
        pointer_format = "q" if self.is_64 else "x"
        word_format = "w"
        return [
            _field("ELF", 0, 4, self._ident_value(), "x"),
            _field("Type", 16, 2, self.type, word_format),
            _field("Machine", 18, 2, self.machine, word_format),
            _field("Version", 20, 4, self.version, ident_format),
            _field("EntryPoint", 24, 8 if self.is_64 else 4, self.entry, pointer_format),
            _field("PhOff", 32, 8 if self.is_64 else 4, self.phoff, pointer_format),
            _field("ShOff", 40, 8 if self.is_64 else 4, self.shoff, pointer_format),
            _field("Flags", 48 if self.is_64 else 36, 4, self.flags, ident_format),
            _field("EhSize", 52 if self.is_64 else 40, 2, self.ehsize, word_format),
            _field("PhentSize", 54 if self.is_64 else 42, 2, self.phentsize, word_format),
            _field("PhNum", 56 if self.is_64 else 44, 2, self.phnum, word_format),
            _field("ShentSize", 58 if self.is_64 else 46, 2, self.shentsize, word_format),
            _field("ShNum", 60 if self.is_64 else 48, 2, self.shnum, word_format),
            _field("ShrStrndx", 62 if self.is_64 else 50, 2, self.shstrndx, word_format),
        ]

    def _ident_value(self) -> int:
        return int.from_bytes(ELF_MAGIC, "little")


def _field(name: str, offset: int, size: int, value: int, fmt: str) -> dict:
    return {
        "name": name,
        "vaddr": offset,
        "paddr": offset,
        "size": size,
        "value": value,
        "format": fmt,
    }


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int


@dataclass(frozen=True)
class DynamicEntry:
    tag: int
    value: int


@dataclass(frozen=True)
class Relocation:
    offset: int
    info: int
    addend: int
    type: int
    type_name: str
    symbol: str
    is_rela: bool


def read_header(path: str | Path) -> ElfHeader:
    data = _load(path)
    order, is_64, header = _parse_ident(data)
    if is_64:
        (
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from(f"{order}HHIQQQIHHHHHH", header, 16)
    else:
        (
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from(f"{order}HHIIIIIHHHHHH", header, 16)
    return ElfHeader(
        elf_class=data[4],
        data_encoding=data[5],
        type=e_type,
        machine=e_machine,
        version=e_version,
        entry=e_entry,
        phoff=e_phoff,
        shoff=e_shoff,
        flags=e_flags,
        ehsize=e_ehsize,
        phentsize=e_phentsize,
        phnum=e_phnum,
        shentsize=e_shentsize,
        shnum=e_shnum,
        shstrndx=e_shstrndx,
        order=order,
    )


def read_sections(path: str | Path) -> list[Section]:
    data = _load(path)
    header = read_header(path)
    if not header.shoff or not header.shentsize:
        return []
    expected = 64 if header.is_64 else 40
    if header.shentsize < expected:
        raise ElfFormatError(f"unexpected section header size {header.shentsize}")
    count = header.shnum
    if count == 0:
        raw = _slice(data, header.shoff, expected, "section header")
        count = _u(raw, 32 if header.is_64 else 20, header.is_64, header.order)
    if count > _MAX_PHNUM:
        raise ElfFormatError(f"implausible section header count {count}")

    entries = []
    for index in range(count):
        offset = header.shoff + index * header.shentsize
        raw = _slice(data, offset, expected, "section header")
        if header.is_64:
            name, stype, flags, addr, body, size, link, info, align, entsize = (
                struct.unpack_from(f"{header.order}IIQQQQIIQQ", raw, 0)
            )
        else:
            name, stype, flags, addr, body, size, link, info, align, entsize = (
                struct.unpack_from(f"{header.order}IIIIIIIIII", raw, 0)
            )
        entries.append(
            Section(index, "", stype, flags, addr, body, size, link, info, align, entsize)
        )

    names = b""
    if entries:
        str_index = header.shstrndx
        if str_index == SHN_XINDEX:
            str_index = entries[0].link
        if 0 <= str_index < len(entries):
            section = entries[str_index]
            names = _slice(data, section.offset, section.size, "section name table")
    if names:
        named = []
        for section in entries:
            offset = header.shoff + section.index * header.shentsize
            name_offset = _u32(data, offset, header.order)
            named.append(
                Section(
                    section.index,
                    _cstring(names, name_offset),
                    section.type,
                    section.flags,
                    section.addr,
                    section.offset,
                    section.size,
                    section.link,
                    section.info,
                    section.align,
                    section.entsize,
                )
            )
        entries = named
    return entries


def read_dynamic(path: str | Path) -> list[DynamicEntry]:
    data = _load(path)
    header = read_header(path)
    body = None
    for segment in read_segments(path):
        if segment.type == PT_DYNAMIC and segment.filesz:
            body = _slice(data, segment.offset, segment.filesz, "PT_DYNAMIC")
            break
    if body is None:
        for section in read_sections(path):
            if section.type == SHT_DYNAMIC and section.size:
                body = _slice(data, section.offset, section.size, "SHT_DYNAMIC")
                break
    if body is None:
        return []
    entry_size = 16 if header.is_64 else 8
    count = min(len(body) // entry_size, _MAX_DYNAMIC)
    entries = []
    for index in range(count):
        if header.is_64:
            tag, value = struct.unpack_from(f"{header.order}qQ", body, index * entry_size)
        else:
            tag, value = struct.unpack_from(f"{header.order}iI", body, index * entry_size)
        if tag == DT_NULL:
            break
        entries.append(DynamicEntry(int(tag), int(value)))
    return entries


def read_needed(path: str | Path) -> list[str]:
    """Return the shared libraries named by DT_NEEDED."""
    data = _load(path)
    entries = read_dynamic(path)
    values = {entry.tag: entry.value for entry in entries}
    strtab = values.get(DT_STRTAB)
    strsz = values.get(DT_STRSZ, 0)
    if strtab is None or not strsz:
        return []
    table = _vaddr_slice(data, read_segments(path), strtab, strsz, "dynamic string table")
    names = []
    for entry in entries:
        if entry.tag == DT_NEEDED:
            names.append(_cstring(table, entry.value))
    return names


def read_relocations(path: str | Path) -> list[Relocation]:
    data = _load(path)
    header = read_header(path)
    entries = read_dynamic(path)
    values = {}
    for entry in entries:
        values[entry.tag] = entry.value
    segments = read_segments(path)
    machine = read_header(path).machine

    strtab = None
    strsz = values.get(DT_STRSZ, 0)
    if DT_STRTAB in values and strsz:
        strtab = _vaddr_slice(
            data, segments, values[DT_STRTAB], strsz, "dynamic string table"
        )

    symbol_table = None
    symbol_size = 24 if header.is_64 else 16
    if DT_SYMTAB in values and DT_SYMENT in values:
        symbol_size = max(16, min(int(values[DT_SYMENT]), 64))
        symbol_table = _vaddr_slice(
            data, segments, values[DT_SYMTAB], symbol_size * _MAX_RELOCS, "symbol table",
            allow_short=True,
        )

    relocations: list[Relocation] = []
    ranges = [
        (DT_RELA, DT_RELASZ, DT_RELAENT, True),
        (DT_REL, DT_RELSZ, DT_RELENT, False),
        (DT_JMPREL, DT_PLTRELSZ, None, values.get(DT_PLTREL) == DT_RELA),
    ]
    for address_tag, size_tag, entry_tag, is_rela in ranges:
        address = values.get(address_tag)
        size = values.get(size_tag)
        if address is None or not size:
            continue
        entry_size = values.get(entry_tag) if entry_tag is not None else None
        if not entry_size:
            entry_size = (24 if header.is_64 else 12) if is_rela else (
                16 if header.is_64 else 8
            )
        body = _vaddr_slice(
            data, segments, address, size, "relocation table", allow_short=True
        )
        for index in range(min(len(body) // entry_size, _MAX_RELOCS)):
            raw = body[index * entry_size : (index + 1) * entry_size]
            relocations.append(
                _parse_relocation(raw, header, machine, is_rela, strtab, symbol_table, symbol_size)
            )
    return relocations


def _parse_relocation(raw, header, machine, is_rela, strtab, symbol_table, symbol_size):
    order = header.order
    if header.is_64:
        if is_rela:
            offset, info, addend = struct.unpack_from(f"{order}QQq", raw, 0)
        else:
            offset, info = struct.unpack_from(f"{order}QQ", raw, 0)
            addend = 0
        symbol_index = info >> 32
        reloc_type = info & 0xFFFFFFFF
    else:
        if is_rela:
            offset, info, addend = struct.unpack_from(f"{order}IIi", raw, 0)
        else:
            offset, info = struct.unpack_from(f"{order}II", raw, 0)
            addend = 0
        symbol_index = info >> 8
        reloc_type = info & 0xFF
    symbol = ""
    if strtab is not None and symbol_table is not None and symbol_index:
        at = symbol_index * symbol_size
        if at + symbol_size <= len(symbol_table):
            name_offset = _u32(symbol_table, at, header.order)
            symbol = _cstring(strtab, name_offset)
    return Relocation(
        offset=int(offset),
        info=int(info),
        addend=int(addend),
        type=int(reloc_type),
        type_name=relocation_name(machine, int(reloc_type)),
        symbol=symbol,
        is_rela=bool(is_rela),
    )


_X86_64_RELOCS = {
    0: "NONE",
    1: "SET_64",
    2: "PC32",
    3: "GOT32",
    4: "PLT32",
    5: "COPY",
    6: "GLOB_DAT",
    7: "JUMP_SLOT",
    8: "ADD_64",
    9: "GOTPCREL",
    10: "SET_32",
    11: "SET_32S",
    12: "SET_16",
    13: "PC16",
    14: "SET_8",
    15: "PC8",
    16: "DTPMOD64",
    17: "DTPOFF64",
    18: "TPOFF64",
    19: "TLSGD",
    20: "TLSLD",
    21: "DTPOFF32",
    22: "GOTTPOFF",
    23: "TPOFF32",
    24: "PC64",
    25: "GOTOFF64",
    26: "GOTPC32",
    32: "SIZE32",
    33: "SIZE64",
    34: "GOTPCRELX",
    35: "REX_GOTPCRELX",
    36: "GOTPCRELX",
    37: "IRELATIVE",
    38: "RELATIVE64",
    41: "GOTPCRELX",
    42: "REX_GOTPCRELX",
}
_ARM_RELOCS = {
    0: "NONE",
    2: "ABS32",
    3: "ABS16",
    21: "GLOB_DAT",
    22: "JUMP_SLOT",
    23: "RELATIVE",
    24: "GOTOFF32",
    25: "GOT32",
    26: "PLT32",
    27: "COPY",
    28: "GLOB_DAT",
    30: "TLS_DESC",
}
_AARCH64_RELOCS = {
    0: "NONE",
    257: "ABS64",
    258: "ABS32",
    259: "ABS16",
    260: "PREL64",
    261: "PREL32",
    262: "PREL16",
    1024: "COPY",
    1025: "GLOB_DAT",
    1026: "JUMP_SLOT",
    1027: "RELATIVE",
    1028: "TLS_DTPMOD64",
    1029: "TLS_DTPREL64",
    1030: "TLS_TPREL64",
    1031: "TLSDESC",
    1032: "IRELATIVE",
}


def relocation_name(machine: int, reloc_type: int) -> str:
    if machine == 62:
        return _X86_64_RELOCS.get(reloc_type, f"TYPE_{reloc_type}")
    if machine == 40:
        return _ARM_RELOCS.get(reloc_type, f"TYPE_{reloc_type}")
    if machine == 183:
        return _AARCH64_RELOCS.get(reloc_type, f"TYPE_{reloc_type}")
    return f"TYPE_{reloc_type}"


def _load(path: str | Path) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        raise


def _parse_ident(data: bytes) -> tuple[str, bool, bytes]:
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ElfFormatError("not an ELF file")
    elf_class = data[4]
    data_encoding = data[5]
    if elf_class not in (1, 2):
        raise ElfFormatError(f"unsupported ELF class {elf_class}")
    if data_encoding not in (1, 2):
        raise ElfFormatError(f"unsupported ELF data encoding {data_encoding}")
    is_64 = elf_class == 2
    size = 64 if is_64 else 52
    if len(data) < size:
        raise ElfFormatError("truncated ELF header")
    return ("<" if data_encoding == 1 else ">"), is_64, data[:size]


def _slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ElfFormatError(f"truncated {label}")
    return data[offset : offset + size]


def _vaddr_slice(
    data: bytes,
    segments: list[Segment],
    address: int,
    size: int,
    label: str,
    *,
    allow_short: bool = False,
) -> bytes:
    for segment in segments:
        if segment.type != PT_LOAD:
            continue
        if segment.vaddr <= address < segment.vaddr + max(segment.filesz, 1):
            offset = segment.offset + (address - segment.vaddr)
            available = max(0, segment.offset + segment.filesz - offset)
            wanted = min(size, available)
            if wanted < size and not allow_short:
                raise ElfFormatError(f"truncated {label}")
            return _slice(data, offset, wanted, label)
    raise ElfFormatError(f"{label} address 0x{address:x} is not mapped")


def _cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _u(data: bytes, offset: int, is_64: bool, order: str = "<") -> int:
    width = 8 if is_64 else 4
    if offset < 0 or offset + width > len(data):
        raise ElfFormatError("truncated extended count")
    return int.from_bytes(data[offset : offset + width], _byteorder(order))


def _byteorder(order: str) -> str:
    return "big" if order == ">" else "little"


def _u32(data: bytes, offset: int, order: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ElfFormatError("truncated name offset")
    return int.from_bytes(data[offset : offset + 4], _byteorder(order))
