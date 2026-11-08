from __future__ import annotations

import pytest

from gdare2.errors import UsageError
from gdare2d.import_plan import resolve_alias


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
    ],
)
def test_unsupported_combinations(arch, kwargs):
    with pytest.raises(UsageError):
        resolve_alias(arch, **kwargs)


def test_sh4_is_explicitly_unsupported():
    with pytest.raises(UsageError, match="SH-4"):
        resolve_alias("sh4")
