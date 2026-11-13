"""Cross-reference queries."""

from __future__ import annotations

from gdare2.errors import UsageError
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


@op("xrefs_all")
def xrefs_all(ctx, limit: int = MAX_REFS) -> list[dict]:
    """Enumerate references program-wide in address order."""
    program = require_program(ctx)
    if limit <= 0 or limit > MAX_REFS:
        raise UsageError(f"xref limit must be between 1 and {MAX_REFS}")
    iterator = program.getReferenceManager().getReferenceIterator(program.getMinAddress())
    result = []
    while iterator.hasNext() and len(result) < limit:
        reference = iterator.next()
        if reference.getFromAddress() is None or reference.getToAddress() is None:
            continue
        result.append(_reference_dict(reference))
    return result
