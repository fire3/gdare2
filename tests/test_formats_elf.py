from __future__ import annotations

import struct

import pytest

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
