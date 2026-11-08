"""Import options and Ghidra language alias resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from gdare2.errors import UsageError


@dataclass
class ImportPlan:
    target: str
    language: str | None = None
    compiler: str | None = None
    loader: str | None = None
    loader_args: list[tuple[str, str]] = field(default_factory=list)
    raw: bool = False
    warnings: list[str] = field(default_factory=list)


def build(
    target: str,
    *,
    arch: str | None = None,
    bits: str | None = None,
    base: str | None = None,
    endian: str | None = None,
    ghidra_language: str | None = None,
    compiler: str | None = None,
    loader: str | None = None,
    loader_args: list[tuple[str, str]] | None = None,
    force_language: bool = False,
    force_base: bool = False,
) -> ImportPlan:
    path = Path(target)
    raw = is_raw_binary(path)
    plan = ImportPlan(target=target, compiler=compiler, loader=loader, raw=raw)
    plan.loader_args = list(loader_args or [])

    if ghidra_language:
        plan.language = ghidra_language
    elif arch and (raw or force_language):
        plan.language = resolve_alias(arch, bits=bits, endian=endian)
    elif arch:
        plan.warnings.append("use --force-language to override a recognized format's language")
    elif raw:
        raise UsageError(
            "raw binaries need a Ghidra language: use -a <arch> [-b 32|64] [--endian big|little] "
            "or --ghidra-language <id>"
        )

    if base:
        if raw:
            plan.loader_args.append(("-loader-baseAddr", hex(int(base, 0))))
        elif force_base:
            raise UsageError("--force-base is not implemented for recognized formats")
        else:
            plan.warnings.append("-B/-m only applies to raw binaries; ignored for this format")
    return plan


def is_raw_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(16)
    except OSError:
        return True
    signatures = (
        b"\x7fELF",
        b"MZ",
        b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\x1f\x8b",
        b"dex\n",
        b"PK\x03\x04",
    )
    return not any(head.startswith(signature) for signature in signatures)


_ALIASES = {
    "x86": "x86",
    "i386": "x86",
    "i486": "x86",
    "i586": "x86",
    "i686": "x86",
    "x86_64": "x86",
    "amd64": "x86",
    "x64": "x86",
    "arm": "ARM",
    "armle": "ARM",
    "armbe": "ARM",
    "arm64": "AARCH64",
    "aarch64": "AARCH64",
    "aarch64be": "AARCH64",
    "mips": "MIPS",
    "mipsle": "MIPS",
    "mipsbe": "MIPS",
    "mips64": "MIPS",
    "mips64le": "MIPS",
    "mips64be": "MIPS",
    "ppc": "PowerPC",
    "powerpc": "PowerPC",
    "ppc64": "PowerPC",
    "ppcle": "PowerPC",
    "ppc64le": "PowerPC",
    "riscv": "RISCV",
    "riscv32": "RISCV",
    "riscv64": "RISCV",
    "m68k": "68000",
    "sparc": "sparc",
    "sparc64": "sparc",
    "sh1": "SuperH",
    "sh2": "SuperH",
    "sh2a": "SuperH",
    "sh4": "SuperH4",
}


def resolve_alias(arch: str, *, bits: str | None = None, endian: str | None = None) -> str:
    text = arch.strip()
    if ":" in text:
        return text
    key = text.lower()
    family = _ALIASES.get(key)
    if family is None:
        raise UsageError(f"unknown architecture alias {arch!r}")

    width = _bits(key, bits)
    big = _is_big(key, endian)
    order = "BE" if big else "LE"

    if family == "x86":
        if big:
            raise UsageError("Ghidra provides no big-endian x86 language")
        _require_width(family, width, (16, 32, 64))
        if width == 16:
            return "x86:LE:16:Real Mode"
        return f"x86:LE:{width}:default"
    if family == "ARM":
        _require_width(family, width, (32,))
        return f"ARM:{order}:{width}:v7"
    if family == "AARCH64":
        _require_width(family, width, (64,))
        return f"AARCH64:{order}:{width}:v8A"
    if family == "MIPS":
        _require_width(family, width, (32, 64))
        return f"MIPS:{order}:{width}:default"
    if family == "PowerPC":
        _require_width(family, width, (32, 64))
        return f"PowerPC:{order}:{width}:default"
    if family == "RISCV":
        if big:
            raise UsageError("Ghidra provides no big-endian RISC-V language")
        _require_width(family, width, (32, 64))
        return f"RISCV:LE:{width}:default"
    if family == "68000":
        if not big:
            raise UsageError("Ghidra provides only big-endian 68000 languages")
        _require_width(family, width, (32,))
        return "68000:BE:32:default"
    if family == "sparc":
        if not big:
            raise UsageError("Ghidra 12.2 provides only big-endian SPARC languages")
        _require_width(family, width, (32, 64))
        return f"sparc:BE:{width}:default"
    if family == "SuperH":
        if not big:
            raise UsageError("Ghidra provides only big-endian SuperH languages")
        _require_width(family, width, (32,))
        variant = {"sh1": "SH-1", "sh2": "SH-2", "sh2a": "SH-2A"}[key]
        return f"SuperH:BE:{width}:{variant}"
    if family == "SuperH4":
        raise UsageError(
            "Ghidra 12.2 has no SH-4 language; use --ghidra-language with a "
            "SuperH:BE:32:SH-* ID"
        )
    raise UsageError(f"unknown architecture alias {arch!r}")


def _bits(key: str, explicit: str | None) -> int:
    if explicit:
        try:
            width = int(explicit, 0)
        except ValueError:
            raise UsageError(f"invalid bit width {explicit!r}") from None
        if width not in (16, 32, 64):
            raise UsageError("bit width must be 16, 32 or 64")
        return width
    if "64" in key:
        return 64
    if "16" in key:
        return 16
    return 32


# radare2's bare architecture names imply these endianness defaults.
_DEFAULT_BIG = frozenset({"MIPS", "PowerPC", "68000", "sparc", "SuperH"})


def _is_big(key: str, endian: str | None) -> bool:
    if endian:
        return endian == "big"
    if key.endswith("be"):
        return True
    if key.endswith("le"):
        return False
    family = _ALIASES.get(key)
    return family in _DEFAULT_BIG


def _require_width(family: str, width: int, allowed: tuple[int, ...]) -> None:
    if width not in allowed:
        choices = ", ".join(str(item) for item in allowed)
        raise UsageError(f"{family} supports bit width {choices}, not {width}")
