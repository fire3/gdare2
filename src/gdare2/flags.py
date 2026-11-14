"""Client-side flag store seeded from Ghidra symbols and functions."""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_SPACE = "*"


@dataclass
class Flag:
    name: str
    addr: int
    size: int = 0
    kind: str = "flag"
    local: bool = False
    space: str = DEFAULT_SPACE


class FlagStore:
    def __init__(self) -> None:
        self._flags: dict[str, Flag] = {}
        self._space: str = DEFAULT_SPACE
        # Spaces created by switching before any flag lives in them.
        self._created: set[str] = set()

    @property
    def space(self) -> str:
        return self._space

    def set_space(self, name: str) -> None:
        self._space = name or DEFAULT_SPACE
        self._created.add(self._space)

    def spaces(self) -> list[str]:
        return sorted(
            {flag.space for flag in self._flags.values()}
            | self._created
            | {DEFAULT_SPACE}
        )

    def clear(self) -> None:
        self._flags.clear()
        self._created.clear()
        self._space = DEFAULT_SPACE

    def add(self, flag: Flag) -> Flag:
        if not flag.space:
            flag.space = self._space
        self._flags[flag.name] = flag
        return flag

    def remove(self, name: str) -> Flag | None:
        return self._flags.pop(name, None)

    def get(self, name: str) -> Flag | None:
        # Flag lookup works across spaces; listing is space-scoped.
        return self._flags.get(name)

    def rename(self, old: str, new: str) -> Flag | None:
        flag = self._flags.pop(old, None)
        if flag is None:
            return None
        flag.name = new
        self._flags[new] = flag
        return flag

    def remove_space(self, name: str) -> None:
        """Forget a flag space; only meaningful for one that holds no flags."""
        self._created.discard(name)

    def rename_space(self, old: str, new: str) -> None:
        """Re-assign every flag of space ``old`` to space ``new``."""
        for flag in self._flags.values():
            if flag.space == old:
                flag.space = new
        self._created.discard(old)
        if new:
            self._created.add(new)
        if self._space == old:
            self._space = new

    def values(self) -> list[Flag]:
        return sorted(
            (flag for flag in self._flags.values() if flag.space == self._space),
            key=lambda flag: (flag.addr, flag.name),
        )

    def all_values(self) -> list[Flag]:
        return sorted(self._flags.values(), key=lambda flag: (flag.addr, flag.name))

    def at(self, address: int) -> list[Flag]:
        return [flag for flag in self.values() if flag.addr == address]

    def __len__(self) -> int:
        return len(self._flags)
