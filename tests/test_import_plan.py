from __future__ import annotations

import pytest

from gdare2.errors import UsageError
from gdare2d.import_plan import build, is_raw_binary, resolve_alias


@pytest.mark.parametrize(
    ("arch", "expected"),
    [
        ("x86", "x86:LE:32:default"),
        ("x86_64", "x86:LE:64:default"),
        ("arm", "ARM:LE:32:v7"),
        ("armbe", "ARM:BE:32:v7"),
        ("thumb", "ARM:LE:32:v7"),
        ("armthumb", "ARM:LE:32:v7"),
        ("aarch64", "AARCH64:LE:64:v8A"),
        ("aarch64be", "AARCH64:BE:64:v8A"),
        ("mips", "MIPS:LE:32:default"),
        ("mips64", "MIPS:LE:64:default"),
        ("mipsbe", "MIPS:BE:32:default"),
        ("mips64be", "MIPS:BE:64:default"),
        ("mipsle", "MIPS:LE:32:default"),
        ("mips64le", "MIPS:LE:64:default"),
        ("ppc", "PowerPC:LE:32:default"),
        ("ppc64", "PowerPC:LE:64:default"),
        ("ppcbe", "PowerPC:BE:32:default"),
        ("ppc64be", "PowerPC:BE:64:default"),
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
        ("6502", "6502:LE:16:default"),
        ("8051", "8051:BE:16:default"),
        ("avr", "avr8:LE:16:default"),
        ("msp430", "TI_MSP430:LE:16:default"),
    ],
)
def test_alias_defaults(arch, expected):
    assert resolve_alias(arch) == expected


def test_explicit_16_bit_x86():
    assert resolve_alias("x86", bits="16") == "x86:LE:16:Real Mode"


def test_r2_arm_widths_resolve_to_arm_thumb_and_aarch64():
    assert resolve_alias("arm", bits="16") == "ARM:LE:32:v7"
    assert resolve_alias("arm", bits="32") == "ARM:LE:32:v7"
    assert resolve_alias("arm", bits="64") == "AARCH64:LE:64:v8A"
    assert resolve_alias("armbe", bits="64") == "AARCH64:BE:64:v8A"


@pytest.mark.parametrize(
    ("arch", "bits", "expected"),
    [
        ("6502", "8", "6502:LE:16:default"),
        ("8051", "8", "8051:BE:16:default"),
        ("avr", "8", "avr8:LE:16:default"),
        ("msp430", "16", "TI_MSP430:LE:16:default"),
    ],
)
def test_mcu_aliases_accept_r2_byte_widths(arch, bits, expected):
    assert resolve_alias(arch, bits=bits) == expected


def test_thumb_hint_is_carried_on_the_plan(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x01\x20\x70\x47")
    plan = build(str(path), arch="arm", bits="16")
    assert plan.language == "ARM:LE:32:v7"
    assert plan.thumb is True

    plan = build(str(path), arch="arm", bits="32")
    assert plan.thumb is False


@pytest.mark.parametrize(
    ("arch", "kwargs"),
    [
        ("x86", {"endian": "big"}),
        ("sparc", {"endian": "little"}),
        ("m68k", {"endian": "little"}),
        ("riscv32", {"endian": "big"}),
        ("arm", {"bits": "8"}),
        ("aarch64", {"bits": "32"}),
        ("sparc", {"bits": "16"}),
        ("6502", {"bits": "32"}),
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


@pytest.mark.parametrize("arch", ["s390", "s390x", "systemz"])
def test_s390_is_explicitly_unsupported(arch):
    """Ghidra 12.2 has no S390 processor; say so instead of "unknown alias"."""
    with pytest.raises(UsageError, match="S390"):
        resolve_alias(arch)


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

