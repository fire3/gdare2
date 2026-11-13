"""Program-header parsing beyond the basic ELF fixtures."""

from __future__ import annotations

import struct

import pytest
from test_formats_elf import _elf64

from gdare2.formats import elf


@pytest.mark.parametrize(
    "p_type,expected",
    [
        (elf.PT_NULL, "NULL"),
        (elf.PT_LOAD, "LOAD0"),
        (elf.PT_DYNAMIC, "DYNAMIC"),
        (elf.PT_INTERP, "INTERP"),
        (elf.PT_NOTE, "NOTE"),
        (elf.PT_PHDR, "PHDR"),
        (elf.PT_TLS, "TLS"),
        (elf.PT_GNU_EH_FRAME, "GNU_EH_FRAME"),
        (elf.PT_GNU_STACK, "GNU_STACK"),
        (elf.PT_GNU_RELRO, "GNU_RELRO"),
        (elf.PT_GNU_PROPERTY, "GNU_PROPERTY"),
        (0x70000000, "UNKNOWN"),
    ],
)
def test_segment_type_names(tmp_path, p_type, expected):
    path = tmp_path / "segment.elf"
    path.write_bytes(_elf64([(p_type, 4, 0x10, 0x20, 0x8, 0x8)]))
    assert elf.read_segments(path)[0].name == expected


@pytest.mark.parametrize(
    "flags,perm",
    [
        (0, "----"),
        (1, "---x"),
        (2, "--w-"),
        (4, "-r--"),
        (5, "-r-x"),
        (7, "-rwx"),
    ],
)
def test_segment_permissions(tmp_path, flags, perm):
    path = tmp_path / "perm.elf"
    path.write_bytes(_elf64([(1, flags, 0, 0, 1, 1)]))
    assert elf.read_segments(path)[0].perm == perm


def test_duplicate_segment_names_get_suffixes(tmp_path):
    path = tmp_path / "dup.elf"
    path.write_bytes(
        _elf64(
            [
                (4, 4, 0x10, 0, 1, 1),
                (4, 4, 0x20, 0, 1, 1),
                (4, 4, 0x30, 0, 1, 1),
            ]
        )
    )
    assert [segment.name for segment in elf.read_segments(path)] == [
        "NOTE",
        "NOTE_1",
        "NOTE_2",
    ]


def test_pn_xnum_reads_the_real_count_from_section_zero(tmp_path):
    base = bytearray(_elf64([(1, 5, 0, 0x400000, 0x10, 0x10)]))
    order = "<"
    # phnum = PN_XNUM, shoff points to section 0 with sh_info = real count.
    struct.pack_into(f"{order}H", base, 56, 0xFFFF)
    shoff = len(base)
    struct.pack_into(f"{order}Q", base, 40, shoff)
    section = bytearray(64)
    struct.pack_into(f"{order}I", section, 28, 1)
    base.extend(section)
    path = tmp_path / "pn-xnum.elf"
    path.write_bytes(bytes(base))
    assert [segment.name for segment in elf.read_segments(path)] == ["LOAD0"]


def test_rejects_bad_class_encoding_and_header_size(tmp_path):
    bad_class = bytearray(_elf64([]))
    bad_class[4] = 9
    path = tmp_path / "class.elf"
    path.write_bytes(bytes(bad_class))
    with pytest.raises(elf.ElfFormatError, match="class"):
        elf.read_segments(path)

    bad_encoding = bytearray(_elf64([]))
    bad_encoding[5] = 9
    path.write_bytes(bytes(bad_encoding))
    with pytest.raises(elf.ElfFormatError, match="encoding"):
        elf.read_segments(path)

    small = bytearray(_elf64([]))
    struct.pack_into("<H", small, 54, 16)
    path.write_bytes(bytes(small))
    with pytest.raises(elf.ElfFormatError, match="program header size"):
        elf.read_segments(path)


def test_rejects_implausible_phnum(tmp_path):
    blob = bytearray(_elf64([(1, 5, 0, 0, 1, 1)]))
    struct.pack_into("<H", blob, 56, 5000)
    path = tmp_path / "huge.elf"
    path.write_bytes(bytes(blob))
    with pytest.raises(elf.ElfFormatError, match="implausible"):
        elf.read_segments(path)
