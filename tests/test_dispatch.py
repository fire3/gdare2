"""Write gating in the op dispatcher (undo/redo are read-only-safe reverts)."""

from __future__ import annotations

import pytest

from gdare2.errors import ReadOnlyError
from gdare2d import dispatch
from gdare2d.context import Context


def _context(*, readonly: bool = True) -> Context:
    return Context(runtime=object(), readonly=readonly, allow_writes=False)


def test_readonly_ok_op_bypasses_the_write_gate():
    @dispatch.op(
        "unit-readonly-ok", writes=True, readonly_ok=True, transaction=False
    )
    def handler(ctx):
        return "ok"

    assert dispatch.invoke(_context(), "unit-readonly-ok", {}, allow_writes=False) == "ok"


def test_plain_write_op_is_still_gated():
    @dispatch.op("unit-write-gate", writes=True, transaction=False)
    def handler(ctx):
        return "ok"

    with pytest.raises(ReadOnlyError):
        dispatch.invoke(_context(), "unit-write-gate", {}, allow_writes=False)
    assert (
        dispatch.invoke(
            _context(readonly=False), "unit-write-gate", {}, allow_writes=True
        )
        == "ok"
    )
