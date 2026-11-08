"""Client-side flag store seeded from Ghidra symbols and functions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Flag:
    name: str
    addr: int
    size: int = 0
    kind: str = "flag"
    local: bool = False


class FlagStore:
    def __init__(self) -> None:
        self._flags: dict[str, Flag] = {}

    def clear(self) -> None:
        self._flags.clear()

    def add(self, flag: Flag) -> Flag:
        self._flags[flag.name] = flag
        return flag

    def remove(self, name: str) -> Flag | None:
        return self._flags.pop(name, None)

    def get(self, name: str) -> Flag | None:
        return self._flags.get(name)

    def rename(self, old: str, new: str) -> Flag | None:
        flag = self._flags.pop(old, None)
        if flag is None:
            return None
        flag.name = new
        self._flags[new] = flag
        return flag

    def values(self) -> list[Flag]:
        return sorted(self._flags.values(), key=lambda flag: (flag.addr, flag.name))

    def at(self, address: int) -> list[Flag]:
        return [flag for flag in self.values() if flag.addr == address]

    def __len__(self) -> int:
        return len(self._flags)
