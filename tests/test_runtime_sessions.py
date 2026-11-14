from __future__ import annotations

from gdare2d.import_plan import ImportPlan
from gdare2d.runtime import GhidraRuntime


def runtime() -> GhidraRuntime:
    return GhidraRuntime(
        target="/bin/true",
        project_dir="/tmp/unused",
        project_name="unused",
        program_path="/true",
        plan=ImportPlan(target="/bin/true"),
    )


def test_session_lease_round_trip():
    rt = runtime()
    lease = rt.session_open(pid=1, kind="batch", tty=False, ttl=30)
    assert rt.has_active_sessions()
    assert rt.session_list()[0]["lease"] == lease
    assert rt.session_heartbeat(lease, 30)
    assert rt.session_close(lease)
    assert not rt.has_active_sessions()


def test_expired_session_is_purged(monkeypatch):
    rt = runtime()
    lease = rt.session_open(pid=1, kind="batch", tty=False, ttl=10)
    rt.sessions[lease]["expires"] = 0
    assert not rt.has_active_sessions()


class _Address:
    def __init__(self, offset: int) -> None:
        self._offset = offset

    def getOffset(self) -> int:
        return self._offset


class _Symbol:
    def __init__(self, offset: int, external: bool = False) -> None:
        self._address = _Address(offset)
        self._external = external

    def getAddress(self) -> _Address:
        return self._address

    def isExternal(self) -> bool:
        return self._external


class _Block:
    def __init__(self, executable: bool) -> None:
        self._executable = executable

    def isExecute(self) -> bool:
        return self._executable


class _Memory:
    def __init__(self, executable_blocks: set[int]) -> None:
        self._executable_blocks = executable_blocks

    def getBlock(self, address):
        offset = address.getOffset()
        return _Block(offset in self._executable_blocks) if offset in self._executable_blocks else None


class _SymbolTable:
    def __init__(self, symbols: dict[str, list[_Symbol]]) -> None:
        self._symbols = symbols

    def getSymbols(self, name: str):
        return self._symbols.get(name, [])

    def getExternalEntryPointIterator(self):
        return iter(())


class _Program:
    def __init__(self, symbols: dict[str, list[_Symbol]], executable_blocks: set[int]) -> None:
        self._symbol_table = _SymbolTable(symbols)
        self._memory = _Memory(executable_blocks)

    def getSymbolTable(self) -> _SymbolTable:
        return self._symbol_table

    def getMemory(self) -> _Memory:
        return self._memory

    def getMinAddress(self) -> _Address:
        return _Address(0x1000)


def test_entry_point_ignores_non_executable_entry_symbol():
    program = _Program(
        {"entry": [_Symbol(6)], "_start": [_Symbol(0xF3AC)]},
        {0xF3AC},
    )
    assert GhidraRuntime._entry_point(program) == 0xF3AC


def test_entry_point_keeps_executable_entry_symbol():
    program = _Program({"entry": [_Symbol(0x106D30)]}, {0x106D30})
    assert GhidraRuntime._entry_point(program) == 0x106D30
