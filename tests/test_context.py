"""Address translation between r2's zero-based view and Ghidra's image base."""

from __future__ import annotations

from gdare2d.context import to_addr


class _Address:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def getOffset(self) -> int:
        return self._value


class _Space:
    def getAddress(self, value: int) -> _Address:
        return _Address(value)


class _Factory:
    def getDefaultAddressSpace(self) -> _Space:
        return _Space()


class _Memory:
    def __init__(self, blocks: set[int]) -> None:
        self._blocks = blocks

    def getBlock(self, address: _Address):
        return object() if address.getOffset() in self._blocks else None


class _Program:
    def __init__(self, base: int, blocks: set[int]) -> None:
        self._base = base
        self._memory = _Memory(blocks)

    def getAddressFactory(self) -> _Factory:
        return _Factory()

    def getImageBase(self) -> _Address:
        return _Address(self._base)

    def getMemory(self) -> _Memory:
        return self._memory


def test_addresses_inside_the_image_are_unchanged():
    program = _Program(0x100000, {0x100010, 0x101080})
    assert to_addr(program, 0x101080).getOffset() == 0x101080


def test_low_addresses_fall_back_to_image_base_relative():
    """r2 keeps laddr 0 for PIE; 0x10 must address the same file byte."""
    program = _Program(0x100000, {0x100010, 0x101080})
    assert to_addr(program, 0x10).getOffset() == 0x100010


def test_directly_mapped_low_addresses_win():
    program = _Program(0x100000, {0x10, 0x100010})
    assert to_addr(program, 0x10).getOffset() == 0x10


def test_no_translation_without_an_image_base():
    program = _Program(0, {0x10})
    assert to_addr(program, 0x10).getOffset() == 0x10


def test_untranslatable_addresses_are_left_alone():
    program = _Program(0x100000, {0x101080})
    assert to_addr(program, 0x10).getOffset() == 0x10
