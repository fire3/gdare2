from __future__ import annotations

import pytest

from gdare2 import expr
from gdare2.errors import UsageError


class FakeResolver:
    pointer_size = 8

    def __init__(self) -> None:
        self.seek = 0x1000

    def lookup_name(self, name: str) -> int | None:
        return {"main": 0x2000, "obj.ptr": 0x3000}.get(name)

    def get_var(self, name: str) -> int | None:
        return {"": self.seek, "b": 0x100, "e": 0x2000}.get(name)

    def deref(self, address: int, size: int) -> int:
        return address + size


def test_bare_decimal_and_hex():
    resolver = FakeResolver()
    assert expr.evaluate("1000", resolver) == 1000
    assert expr.evaluate("0x1000", resolver) == 0x1000
    assert expr.evaluate("0b1010 + 0o10", resolver) == 18


def test_arithmetic_precedence():
    resolver = FakeResolver()
    assert expr.evaluate("1 + 2 * 3", resolver) == 7
    assert expr.evaluate("(1 + 2) * 3", resolver) == 9


def test_names_and_vars():
    resolver = FakeResolver()
    assert expr.evaluate("main + 0x10", resolver) == 0x2010
    assert expr.evaluate("$$ + $b", resolver) == 0x1100


def test_deref_uses_pointer_size():
    resolver = FakeResolver()
    assert expr.evaluate("[main]", resolver) == 0x2008


def test_unknown_name_is_an_error():
    with pytest.raises(UsageError, match="unknown name"):
        expr.evaluate("nope", FakeResolver())
