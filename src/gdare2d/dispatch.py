"""Op registry, write gating, transaction and error mapping."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from gdare2.errors import GdarError, ReadOnlyError, UnknownOpError, UsageError
from gdare2.protocol import error as error_payload
from gdare2d.context import Context

log = logging.getLogger("gdare2d.dispatch")

Handler = Callable[..., Any]


@dataclass(frozen=True)
class OpSpec:
    name: str
    handler: Handler
    writes: bool = False
    transaction: bool = True


_OPS: dict[str, OpSpec] = {}
_LOADED = False


def op(name: str, *, writes: bool = False, transaction: bool = True):
    def decorate(handler: Handler) -> Handler:
        _OPS[name] = OpSpec(name, handler, writes, transaction)
        return handler

    return decorate


def load_all() -> None:
    global _LOADED
    if _LOADED:
        return
    from gdare2d.ops import (  # noqa: F401
        analysis,
        assemble,
        batch,
        comments,
        decompile,
        disasm,
        graph,
        info,
        memory,
        names,
        search,
        session,
        types,
        write,
        xrefs,
    )

    _LOADED = True


def invoke(ctx: Context, name: str, args: dict[str, Any], *, allow_writes: bool) -> Any:
    load_all()
    spec = _OPS.get(name)
    if spec is None:
        raise UnknownOpError(f"unknown op {name!r}")
    if spec.writes and (ctx.readonly or not allow_writes):
        raise ReadOnlyError(
            "read-only request cannot perform a write op; re-run with -w to allow writes",
            data={"op": name},
        )
    spec_error = _check_args(spec, args)
    if spec_error is not None:
        raise UsageError(spec_error)

    try:
        if spec.writes and spec.transaction:
            import pyghidra

            with pyghidra.transaction(ctx.program, f"gdare2: {name}"):
                return spec.handler(ctx, **args)
        return spec.handler(ctx, **args)
    except GdarError as exc:
        if exc.code == "INTERNAL":
            exc.code = "GHIDRA_ERROR"
        raise
    except Exception as exc:
        log.exception("op %s failed", name)
        raise GdarError(f"{type(exc).__name__}: {exc}", data={"op": name}) from exc


def _check_args(spec: OpSpec, args: dict[str, Any]) -> str | None:
    try:
        signature = inspect.signature(spec.handler)
    except (TypeError, ValueError):
        return None
    accepts_kwargs = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )
    if accepts_kwargs:
        return None
    allowed = {
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    }
    unknown = set(args) - allowed - {"ctx"}
    if unknown:
        return f"op {spec.name!r} does not accept {', '.join(sorted(unknown))}"
    return None


def as_error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, GdarError):
        return error_payload(exc.code, exc.message, exc.data)
    return error_payload("INTERNAL", str(exc))
