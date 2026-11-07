"""Function and analysis queries."""

from __future__ import annotations

from gdare2.errors import UsageError
from gdare2d.dispatch import op
from gdare2d.ops._helpers import function_dict, require_program

MAX_FUNCTIONS = 10000


@op("functions")
def functions(ctx, limit: int = MAX_FUNCTIONS) -> list[dict]:
    program = require_program(ctx)
    if limit < 0 or limit > MAX_FUNCTIONS:
        raise UsageError(f"function limit must be between 0 and {MAX_FUNCTIONS}")
    manager = program.getFunctionManager()
    result = []
    iterator = manager.getFunctions(True)
    while iterator.hasNext() and len(result) < limit:
        result.append(function_dict(iterator.next()))
    return result
