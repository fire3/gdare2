"""Raw-binary architecture configurations used by the arch matrix."""

from __future__ import annotations

# Keep this list in sync with gdare2d.import_plan.resolve_alias.
ARCH_MATRIX = (
    {"name": "x86-16", "arch": "x86", "bits": "16", "endian": "little", "language": "x86:LE:16:Real Mode"},
    {"name": "x86-32", "arch": "x86", "bits": "32", "endian": "little", "language": "x86:LE:32:default"},
    {"name": "x86-64", "arch": "x86", "bits": "64", "endian": "little", "language": "x86:LE:64:default"},
    {"name": "arm-le", "arch": "armle", "bits": "32", "endian": "little", "language": "ARM:LE:32:v7"},
    {"name": "arm-be", "arch": "armbe", "bits": "32", "endian": "big", "language": "ARM:BE:32:v7"},
    {"name": "aarch64-le", "arch": "aarch64", "bits": "64", "endian": "little", "language": "AARCH64:LE:64:v8A"},
    {"name": "aarch64-be", "arch": "aarch64be", "bits": "64", "endian": "big", "language": "AARCH64:BE:64:v8A"},
    {"name": "mips-le", "arch": "mipsle", "bits": "32", "endian": "little", "language": "MIPS:LE:32:default"},
    {"name": "mips-be", "arch": "mipsbe", "bits": "32", "endian": "big", "language": "MIPS:BE:32:default"},
    {"name": "mips64-le", "arch": "mips64le", "bits": "64", "endian": "little", "language": "MIPS:LE:64:default"},
    {"name": "mips64-be", "arch": "mips64be", "bits": "64", "endian": "big", "language": "MIPS:BE:64:default"},
    {"name": "ppc-be", "arch": "ppc", "bits": "32", "endian": "big", "language": "PowerPC:BE:32:default"},
    {"name": "ppc-le", "arch": "ppcle", "bits": "32", "endian": "little", "language": "PowerPC:LE:32:default"},
    {"name": "ppc64-be", "arch": "ppc64", "bits": "64", "endian": "big", "language": "PowerPC:BE:64:default"},
    {"name": "ppc64-le", "arch": "ppc64le", "bits": "64", "endian": "little", "language": "PowerPC:LE:64:default"},
    {"name": "riscv32", "arch": "riscv32", "bits": "32", "endian": "little", "language": "RISCV:LE:32:default"},
    {"name": "riscv64", "arch": "riscv64", "bits": "64", "endian": "little", "language": "RISCV:LE:64:default"},
    {"name": "m68k", "arch": "m68k", "bits": "32", "endian": "big", "language": "68000:BE:32:default"},
    {"name": "sparc", "arch": "sparc", "bits": "32", "endian": "big", "language": "sparc:BE:32:default"},
    {"name": "sparc64", "arch": "sparc64", "bits": "64", "endian": "big", "language": "sparc:BE:64:default"},
)

RAW_BYTES = bytes.fromhex("90909090c3")
