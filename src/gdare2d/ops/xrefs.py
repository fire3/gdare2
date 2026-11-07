"""Cross-reference queries."""

from __future__ import annotations

from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import require_program

MAX_REFS = 10000


def _reference_dict(reference) -> dict:
    return {
        "from": int(reference.getFromAddress().getOffset()),
        "to": int(reference.getToAddress().getOffset()),
        "type": str(reference.getReferenceType()),
        "primary": bool(reference.isPrimary()),
    }


@op("xrefs_to")
def xrefs_to(ctx, ea: int) -> list[dict]:
    program = require_program(ctx)
    iterator = program.getReferenceManager().getReferencesTo(to_addr(program, int(ea)))
    result = []
    while iterator.hasNext() and len(result) < MAX_REFS:
        result.append(_reference_dict(iterator.next()))
    return result


@op("xrefs_from")
def xrefs_from(ctx, ea: int) -> list[dict]:
    program = require_program(ctx)
    iterator = program.getReferenceManager().getReferencesFrom(to_addr(program, int(ea)))
    result = []
    while iterator.hasNext() and len(result) < MAX_REFS:
        result.append(_reference_dict(iterator.next()))
    return result
