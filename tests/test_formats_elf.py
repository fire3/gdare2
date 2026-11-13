from __future__ import annotations

import struct

import pytest

from gdare2.formats import elf
from gdare2.formats.elf import ElfFormatError, read_segments


def _elf64(segments, little: bool = True) -> bytes:
    order = "<" if little else ">"
    phnum = len(segments)
    ident = b"\x7fELF" + bytes([2, 1 if little else 2, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        f"{order}HHIQQQIHHHHHH",
        2,
        0x3E,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        phnum,
        64,
        0,
        0,
    )
    table = b"".join(
        struct.pack(f"{order}IIQQQQQQ", p_type, flags, offset, vaddr, 0, filesz, memsz, 0x1000)
        for p_type, flags, offset, vaddr, filesz, memsz in segments
    )
    return header + table


def _elf32(segments, little: bool = True) -> bytes:
    order = "<" if little else ">"
    phnum = len(segments)
    ident = b"\x7fELF" + bytes([1, 1 if little else 2, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        f"{order}HHIIIIIHHHHHH",
        2,
        3,
        1,
        0,
        52,
        0,
        0,
        52,
        32,
        phnum,
        40,
        0,
        0,
    )
    table = b"".join(
        struct.pack(f"{order}IIIIIIII", p_type, offset, vaddr, 0, filesz, memsz, flags, 0x1000)
        for p_type, flags, offset, vaddr, filesz, memsz in segments
    )
    return header + table


def test_read_elf64_segments(tmp_path):
    path = tmp_path / "sample.elf"
    path.write_bytes(
        _elf64(
            [
                (1, 5, 0x0, 0x0, 0x100, 0x100),
                (1, 5, 0x1000, 0x1000, 0x10, 0x20),
                (4, 4, 0x200, 0x200, 0x8, 0x8),
                (4, 4, 0x300, 0x300, 0x8, 0x8),
            ]
        )
    )
    segments = read_segments(path)
    assert [segment.name for segment in segments] == ["LOAD0", "LOAD1", "NOTE", "NOTE_1"]
    assert [segment.perm for segment in segments] == ["-r-x", "-r-x", "-r--", "-r--"]
    assert segments[1].offset == 0x1000
    assert segments[1].vaddr == 0x1000
    assert segments[1].filesz == 0x10
    assert segments[1].memsz == 0x20
    assert segments[0].as_dict() == {
        "name": "LOAD0",
        "size": 0x100,
        "vsize": 0x100,
        "perm": "-r-x",
        "paddr": 0x0,
        "vaddr": 0x0,
    }


def test_read_elf32_big_endian(tmp_path):
    path = tmp_path / "sample32be.elf"
    path.write_bytes(
        _elf32(
            [(1, 7, 0x80, 0x4000, 0x20, 0x40), (2, 6, 0x200, 0x5000, 0x10, 0x10)],
            little=False,
        )
    )
    segments = read_segments(path)
    assert [segment.name for segment in segments] == ["LOAD0", "DYNAMIC"]
    assert segments[0].perm == "-rwx"
    assert segments[0].vaddr == 0x4000
    assert segments[1].perm == "-rw-"


def test_empty_program_header_table(tmp_path):
    path = tmp_path / "no-phdr.elf"
    path.write_bytes(_elf64([]))
    assert read_segments(path) == []


def test_rejects_non_elf(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x90\x90\xc3\xcc")
    with pytest.raises(ElfFormatError, match="not an ELF"):
        read_segments(path)


def test_rejects_truncated_program_header_table(tmp_path):
    path = tmp_path / "truncated.elf"
    path.write_bytes(_elf64([(1, 5, 0, 0, 0x10, 0x10)])[:80])
    with pytest.raises(ElfFormatError, match="truncated program header"):
        read_segments(path)


def _align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _elf64_sections(names: list[str]) -> bytes:
    order = "<"
    shstr = bytearray(b"\x00")
    offsets = {}
    for name in names:
        offsets[name] = len(shstr)
        shstr.extend(name.encode())
        shstr.append(0)
    body_offset = 64
    shoff = _align(body_offset + len(shstr))
    count = 1 + len(names)
    table = bytearray(64 * count)
    for index, name in enumerate(names, start=1):
        is_strtab = name == ".shstrtab"
        struct.pack_into(
            f"{order}IIQQQQIIQQ",
            table,
            index * 64,
            offsets[name],
            3 if is_strtab else 1,
            0,
            0,
            body_offset if is_strtab else 0,
            len(shstr) if is_strtab else 0,
            0,
            0,
            1,
            0,
        )
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        f"{order}HHIQQQIHHHHHH",
        2,
        0x3E,
        1,
        0,
        0,
        shoff,
        0,
        64,
        56,
        0,
        64,
        count,
        1,
    )
    return header + bytes(shstr).ljust(shoff - body_offset, b"\x00") + bytes(table)


def test_read_header_and_sections(tmp_path):
    path = tmp_path / "sections.elf"
    path.write_bytes(_elf64_sections([".shstrtab", ".text", ".data"]))
    header = elf.read_header(path)
    assert header.elf_class == 2
    assert header.machine == 0x3E
    assert header.shoff != 0
    assert header.shnum == 4
    assert [item["name"] for item in header.fields()][:3] == ["ELF", "Type", "Machine"]
    sections = elf.read_sections(path)
    assert [section.name for section in sections] == ["", ".shstrtab", ".text", ".data"]


def _elf64_dynamic() -> bytes:
    order = "<"
    load_vaddr = 0x400000
    body_offset = 64 + 2 * 56
    dynstr = b"\x00libc.so.6\x00puts\x00"
    dynstr_offset = body_offset
    dynsym_offset = _align(dynstr_offset + len(dynstr))
    dynsym = bytes(24) + struct.pack(f"{order}IBBHQQ", 11, 0x12, 0, 1, 0x1000, 8)
    rela_offset = _align(dynsym_offset + len(dynsym))
    rela = struct.pack(f"{order}QQq", 0x401000, 8, 0x401234)
    jmprel_offset = _align(rela_offset + len(rela))
    jmprel = struct.pack(f"{order}QQq", 0x401008, (1 << 32) | 7, 0)
    dynamic_offset = _align(jmprel_offset + len(jmprel))
    entries = [
        (elf.DT_NEEDED, 1),
        (elf.DT_STRTAB, load_vaddr + dynstr_offset),
        (elf.DT_STRSZ, len(dynstr)),
        (elf.DT_SYMTAB, load_vaddr + dynsym_offset),
        (elf.DT_SYMENT, 24),
        (elf.DT_RELA, load_vaddr + rela_offset),
        (elf.DT_RELASZ, len(rela)),
        (elf.DT_RELAENT, 24),
        (elf.DT_JMPREL, load_vaddr + jmprel_offset),
        (elf.DT_PLTRELSZ, len(jmprel)),
        (elf.DT_PLTREL, elf.DT_RELA),
        (elf.DT_NULL, 0),
    ]
    dynamic = b"".join(struct.pack(f"{order}qQ", tag, value) for tag, value in entries)
    total = dynamic_offset + len(dynamic)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        f"{order}HHIQQQIHHHHHH",
        2,
        0x3E,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        2,
        64,
        0,
        0,
    )
    segments = struct.pack(
        f"{order}IIQQQQQQ", 1, 5, 0, load_vaddr, load_vaddr, total, total, 0x1000
    ) + struct.pack(
        f"{order}IIQQQQQQ",
        2,
        6,
        dynamic_offset,
        load_vaddr + dynamic_offset,
        load_vaddr + dynamic_offset,
        len(dynamic),
        len(dynamic),
        8,
    )
    body = bytearray(total)
    body[0:64] = header
    body[64 : 64 + len(segments)] = segments
    body[dynstr_offset : dynstr_offset + len(dynstr)] = dynstr
    body[dynsym_offset : dynsym_offset + len(dynsym)] = dynsym
    body[rela_offset : rela_offset + len(rela)] = rela
    body[jmprel_offset : jmprel_offset + len(jmprel)] = jmprel
    body[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    return bytes(body)


def test_read_dynamic_needed_and_relocations(tmp_path):
    path = tmp_path / "dynamic.elf"
    path.write_bytes(_elf64_dynamic())
    assert [entry.tag for entry in elf.read_dynamic(path)][:3] == [
        elf.DT_NEEDED,
        elf.DT_STRTAB,
        elf.DT_STRSZ,
    ]
    assert elf.read_needed(path) == ["libc.so.6"]
    relocations = elf.read_relocations(path)
    assert [(item.offset, item.type_name) for item in relocations] == [
        (0x401000, "ADD_64"),
        (0x401008, "JUMP_SLOT"),
    ]
    assert relocations[0].addend == 0x401234
    assert relocations[1].symbol == "puts"


def test_relocation_names_for_other_machines():
    assert elf.relocation_name(40, 22) == "JUMP_SLOT"
    assert elf.relocation_name(183, 1027) == "RELATIVE"
    assert elf.relocation_name(8, 99) == "TYPE_99"
