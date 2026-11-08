"""Typed r2-style configuration keys used by the client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gdare2.errors import UsageError

BOOL = "bool"
INT = "int"
STR = "str"


@dataclass(frozen=True)
class Key:
    name: str
    default: Any
    kind: str
    description: str = ""
    readonly: bool = False
    minimum: int | None = None


KEYS = (
    Key("scr.color", 0, INT, "ANSI colour mode (0-3)"),
    Key("scr.null", False, BOOL, "discard output"),
    Key("scr.interactive", False, BOOL, "interactive mode"),
    Key("asm.arch", "unknown", STR, "architecture (derived)", readonly=True),
    Key("asm.bits", 0, INT, "bitness (derived)", readonly=True),
    Key("asm.bytes", True, BOOL, "show instruction bytes"),
    Key("asm.lines", False, BOOL, "show instruction boundaries"),
    Key("asm.comments", True, BOOL, "show comments"),
    Key("asm.flags", True, BOOL, "show flags"),
    Key("asm.demangle", True, BOOL, "demangle symbols"),
    Key("hex.cols", 16, INT, "hexdump bytes per line", minimum=1),
    Key("hex.header", True, BOOL, "hexdump column header"),
    Key("io.cache", False, BOOL, "buffer writes until wc+"),
    Key("cmd.hit", "", STR, "command run for each search hit"),
    Key("cmd.batch", True, BOOL, "merge @@ iterations into one RPC"),
    Key("search.in", "io.maps", STR, "search scope"),
    Key("search.from", 0, INT, "search start (0 = auto)"),
    Key("search.to", 0, INT, "search end (0 = auto)"),
    Key("cfg.bigendian", False, BOOL, "big-endian (derived)", readonly=True),
    Key("ghidra.version", "", STR, "Ghidra version (derived)", readonly=True),
    Key("ghidra.language", "", STR, "Ghidra language ID (derived)", readonly=True),
    Key("ghidra.compiler", "", STR, "compiler spec (derived)", readonly=True),
    Key("ghidra.program", "", STR, "program name (derived)", readonly=True),
    Key("ghidra.project", "", STR, "project name (derived)", readonly=True),
    Key("ghidra.timeout", 30, INT, "per-op RPC timeout", minimum=1),
    Key("ghidra.decompile.timeout", 30, INT, "decompiler timeout", minimum=1),
    Key("ghidra.analysis.wait", "wait", STR, "wait | poll | skip"),
    Key("ghidra.flags.write", False, BOOL, "write flags back to Ghidra symbols"),
)

_BY_NAME = {key.name: key for key in KEYS}


class Config:
    def __init__(self) -> None:
        self._values = {key.name: key.default for key in KEYS}
        self.explicit: set[str] = set()

    def get(self, name: str) -> Any:
        key = _BY_NAME.get(name)
        if key is None:
            raise UsageError(f"unknown configuration key {name!r}")
        return self._values[name]

    def get_bool(self, name: str) -> bool:
        return bool(self.get(name))

    def get_int(self, name: str) -> int:
        return int(self.get(name))

    def get_str(self, name: str) -> str:
        return str(self.get(name))

    def set(self, name: str, value: Any) -> None:
        key = _BY_NAME.get(name)
        if key is None:
            raise UsageError(f"unknown configuration key {name!r}")
        if key.readonly:
            raise UsageError(f"e {name} is read-only: it reflects the Ghidra program")
        self._values[name] = _coerce(key, value)
        self.explicit.add(name)

    def reflect(self, name: str, value: Any) -> None:
        key = _BY_NAME.get(name)
        if key is None:
            raise UsageError(f"unknown configuration key {name!r}")
        self._values[name] = _coerce(key, value)

    def items(self) -> list[tuple[str, Any]]:
        return [(key.name, self._values[key.name]) for key in KEYS]


def _coerce(key: Key, value: Any) -> Any:
    if key.kind == BOOL:
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("true", "1", "yes", "on"):
            return True
        if text in ("false", "0", "no", "off", ""):
            return False
        raise UsageError(f"e {key.name}: expected a boolean, not {value!r}")
    if key.kind == INT:
        try:
            number = int(str(value).strip(), 0)
        except ValueError:
            raise UsageError(f"e {key.name}: expected a number, not {value!r}") from None
        if key.minimum is not None and number < key.minimum:
            raise UsageError(f"e {key.name}: must be at least {key.minimum}")
        return number
    return str(value)
