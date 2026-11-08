"""Opt-in Python escape hatch."""

from __future__ import annotations

import contextlib
import io

from gdare2.errors import ReadOnlyError
from gdare2d.dispatch import op
from gdare2d.ops._helpers import require_program


@op("exec_python", writes=True)
def exec_python(ctx, code: str) -> dict:
    if not getattr(ctx.runtime, "allow_exec", False):
        raise ReadOnlyError("python execution is disabled; start gdare2d with --allow-exec")
    program = require_program(ctx)
    buffer = io.StringIO()
    namespace = {
        "ctx": ctx,
        "program": program,
        "runtime": ctx.runtime,
    }
    with contextlib.redirect_stdout(buffer):
        exec(code, namespace)
    return {"output": buffer.getvalue()}
