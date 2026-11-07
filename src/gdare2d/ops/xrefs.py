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


def _references(value) -> list:
    if hasattr(value, "hasNext"):
        result = []
        while value.hasNext():
            result.append(value.next())
        return result
    try:
        return list(value)
    except TypeError:
        return [value]


@op("xrefs_to")
def xrefs_to(ctx, ea: int) -> list[dict]:
    program = require_program(ctx)
    references = program.getReferenceManager().getReferencesTo(to_addr(program, int(ea)))
    return [_reference_dict(reference) for reference in _references(references)[:MAX_REFS]]


@op("xrefs_from")
def xrefs_from(ctx, ea: int) -> list[dict]:
    program = require_program(ctx)
    references = program.getReferenceManager().getReferencesFrom(to_addr(program, int(ea)))
    return [_reference_dict(reference) for reference in _references(references)[:MAX_REFS]]
