from __future__ import annotations

from gdare2.protocol import OpResult
from gdare2.session import _batch_meta_warning
from gdare2d.ops import batch as batch_op


class FakeContext:
    allow_writes = False


def test_batch_keeps_per_item_meta(monkeypatch):
    def fake_invoke(ctx, name, args, *, allow_writes):
        if name == "search":
            return OpResult(
                {"hits": [0x1000]},
                {
                    "shown": 1,
                    "offset": 0,
                    "limit": 1,
                    "truncated": True,
                    "scope": "io.maps",
                    "forward": True,
                },
            )
        return {"ok": True}

    monkeypatch.setattr(batch_op, "invoke", fake_invoke)
    result = batch_op.batch(
        FakeContext(),
        [{"op": "search", "args": {}}, {"op": "info", "args": {}}],
    )

    assert result.value[0]["result"] == {"hits": [0x1000]}
    assert result.value[0]["meta"]["truncated"] is True
    assert result.value[0]["meta"]["limit"] == 1
    assert "meta" not in result.value[1]
    assert result.meta == {"total": 2, "shown": 2, "errors": 0, "truncated": False}


def test_batch_item_errors_are_isolated(monkeypatch):
    def fake_invoke(ctx, name, args, *, allow_writes):
        if name == "boom":
            raise ValueError("kaboom")
        return {"ok": True}

    monkeypatch.setattr(batch_op, "invoke", fake_invoke)
    result = batch_op.batch(
        FakeContext(),
        [{"op": "boom", "args": {}}, {"op": "info", "args": {}}],
    )

    assert result.value[0]["ok"] is False
    assert result.value[0]["error"]["code"] == "INTERNAL"
    assert result.value[1]["result"] == {"ok": True}
    assert result.meta["errors"] == 1


def test_batch_meta_warning_summarizes_truncated_items():
    replies = [
        {"ok": True, "result": [], "meta": {"shown": 1, "limit": 1, "offset": 0, "truncated": True}},
        {"ok": True, "result": []},
        {"ok": True, "result": [], "meta": {"shown": 2, "limit": 2, "offset": 4, "truncated": True}},
    ]

    warning = _batch_meta_warning(replies)

    assert warning is not None
    assert warning.startswith("WARN: 2 batched item(s) truncated")
    assert "shown 1 at offset 0 (limit 1)" in warning
    assert "shown 2 at offset 4 (limit 2)" in warning


def test_batch_meta_warning_is_silent_without_truncation():
    assert _batch_meta_warning([{"ok": True, "result": []}]) is None
