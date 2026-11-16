from __future__ import annotations

import pytest

from gdare2.errors import UsageError
from gdare2d.import_plan import is_raw_binary, resolve_alias


@pytest.mark.parametrize(
    ("arch", "expected"),
    [
        ("x86", "x86:LE:32:default"),
        ("x86_64", "x86:LE:64:default"),
        ("arm", "ARM:LE:32:v7"),
        ("armbe", "ARM:BE:32:v7"),
        ("aarch64", "AARCH64:LE:64:v8A"),
        ("aarch64be", "AARCH64:BE:64:v8A"),
        ("mips", "MIPS:BE:32:default"),
        ("mips64", "MIPS:BE:64:default"),
        ("mipsle", "MIPS:LE:32:default"),
        ("mips64le", "MIPS:LE:64:default"),
        ("ppc", "PowerPC:BE:32:default"),
        ("ppc64", "PowerPC:BE:64:default"),
        ("ppcle", "PowerPC:LE:32:default"),
        ("ppc64le", "PowerPC:LE:64:default"),
        ("sparc", "sparc:BE:32:default"),
        ("sparc64", "sparc:BE:64:default"),
        ("m68k", "68000:BE:32:default"),
        ("riscv32", "RISCV:LE:32:default"),
        ("riscv64", "RISCV:LE:64:default"),
        ("sh1", "SuperH:BE:32:SH-1"),
        ("sh2", "SuperH:BE:32:SH-2"),
        ("sh2a", "SuperH:BE:32:SH-2A"),
    ],
)
def test_alias_defaults(arch, expected):
    assert resolve_alias(arch) == expected


def test_explicit_16_bit_x86():
    assert resolve_alias("x86", bits="16") == "x86:LE:16:Real Mode"


@pytest.mark.parametrize(
    ("arch", "kwargs"),
    [
        ("x86", {"endian": "big"}),
        ("sparc", {"endian": "little"}),
        ("m68k", {"endian": "little"}),
        ("riscv32", {"endian": "big"}),
        ("arm", {"bits": "16"}),
        ("aarch64", {"bits": "32"}),
        ("sparc", {"bits": "16"}),
        ("sh2a", {"endian": "little"}),
        ("sh2a", {"bits": "64"}),
    ],
)
def test_unsupported_combinations(arch, kwargs):
    with pytest.raises(UsageError):
        resolve_alias(arch, **kwargs)


def test_sh4_is_explicitly_unsupported():
    with pytest.raises(UsageError, match="SH-4"):
        resolve_alias("sh4")


def test_coff_object_is_not_treated_as_a_raw_binary(tmp_path):
    import struct

    # ANON_OBJECT_HEADER_BIGOBJ: Sig1=0, Sig2=0xffff, Version=2, Machine=AMD64.
    bigobj = struct.pack("<HHHH", 0, 0xFFFF, 2, 0x8664) + b"\x00" * 20
    path = tmp_path / "big.obj"
    path.write_bytes(bigobj)
    assert is_raw_binary(path) is False

    # Standard COFF: machine, section count, timestamp, symtab, nsyms,
    # optional-header size, characteristics.
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    path.write_bytes(coff)
    assert is_raw_binary(path) is False


def test_plain_bytes_are_still_raw(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x90\xc3" + b"\x00" * 20)
    assert is_raw_binary(path) is True


def test_describe_format_names_the_container(tmp_path):
    import struct

    from gdare2d.import_plan import describe_format

    elf = tmp_path / "a.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert describe_format(elf) == "ELF"

    pe = tmp_path / "a.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 62)
    assert describe_format(pe) == "PE"

    macho = tmp_path / "a.macho"
    macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
    assert describe_format(macho) == "Mach-O"

    bigobj = tmp_path / "a.obj"
    bigobj.write_bytes(struct.pack("<HHHH", 0, 0xFFFF, 2, 0x8664) + b"\x00" * 20)
    assert describe_format(bigobj) == "COFF"

    blob = tmp_path / "a.bin"
    blob.write_bytes(b"\x90\xc3" + b"\x00" * 20)
    assert describe_format(blob) == "unrecognized format"

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert describe_format(empty) == "empty file"

