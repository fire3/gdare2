"""Read-only Ghidra data type and function signature queries."""

from __future__ import annotations

from gdare2.errors import NotFoundError, UsageError
from gdare2d.dispatch import op
from gdare2d.ops._helpers import iter_items, require_program

MAX_TYPES = 10000
MAX_COMPONENTS = 10000
MAX_SIGNATURES = 10000


@op("types")
def types(ctx, kind: str | None = None, name: str | None = None, limit: int = MAX_TYPES) -> dict | list[dict]:
    program = require_program(ctx)
    if limit <= 0 or limit > MAX_TYPES:
        raise UsageError(f"type limit must be between 1 and {MAX_TYPES}")
    manager = program.getDataTypeManager()
    if name:
        data_type = manager.getDataType(name)
        if data_type is None:
            raise NotFoundError(f"type {name!r} not found")
        return _type_detail(data_type)

    result = []
    for data_type in iter_items(manager.getAllDataTypes()):
        if len(result) >= limit:
            break
        if kind and _type_kind(data_type) != kind:
            continue
        result.append(_type_dict(data_type))
    result.sort(key=lambda item: (item["kind"], item["name"]))
    return result


@op("function_signatures")
def function_signatures(
    ctx,
    name: str | None = None,
    limit: int = MAX_SIGNATURES,
) -> list[dict]:
    program = require_program(ctx)
    if limit <= 0 or limit > MAX_SIGNATURES:
        raise UsageError(f"signature limit must be between 1 and {MAX_SIGNATURES}")
    result = []
    iterator = program.getFunctionManager().getFunctions(True)
    while iterator.hasNext() and len(result) < limit:
        function = iterator.next()
        function_name = str(function.getName())
        if name and name not in function_name:
            continue
        result.append(
            {
                "addr": int(function.getEntryPoint().getOffset()),
                "name": function_name,
                "signature": str(function.getSignature().getPrototypeString()),
                "calling_convention": str(function.getCallingConventionName() or ""),
            }
        )
    return result


def _type_dict(data_type) -> dict:
    return {
        "name": str(data_type.getName()),
        "path": str(data_type.getPathName()),
        "kind": _type_kind(data_type),
        "length": int(data_type.getLength()),
        "category": str(data_type.getCategoryPath()),
    }


def _type_detail(data_type) -> dict:
    payload = _type_dict(data_type)
    components = _components(data_type)
    if components is not None:
        payload["components"] = components
    enum_values = _enum_values(data_type)
    if enum_values is not None:
        payload["values"] = enum_values
    try:
        base = data_type.getBaseDataType()
    except Exception:
        base = None
    if base is not None:
        payload["base_type"] = str(base.getPathName())
    try:
        payload["prototype"] = str(data_type.getPrototypeString())
    except Exception:
        pass
    return payload


def _components(data_type) -> list[dict] | None:
    if not hasattr(data_type, "getComponents"):
        return None
    from ghidra.program.model.data import Structure, Union

    if not isinstance(data_type, (Structure, Union)):
        return None
    result = []
    for component in iter_items(data_type.getComponents())[:MAX_COMPONENTS]:
        result.append(
            {
                "offset": int(component.getOffset()),
                "length": int(component.getLength()),
                "name": str(component.getFieldName()),
                "type": str(component.getDataType().getName()),
                "comment": str(component.getComment() or ""),
            }
        )
    return result


def _enum_values(data_type) -> list[dict] | None:
    from ghidra.program.model.data import Enum

    if not isinstance(data_type, Enum):
        return None
    names = iter_items(data_type.getNames())
    values = iter_items(data_type.getValues())
    return [
        {"name": str(name), "value": int(value)}
        for name, value in zip(names, values)
    ]


def _type_kind(data_type) -> str:
    from ghidra.program.model.data import (
        Array,
        Enum,
        FunctionDefinition,
        Pointer,
        Structure,
        TypeDef,
        Union,
    )

    if isinstance(data_type, FunctionDefinition):
        return "function"
    if isinstance(data_type, Structure):
        return "struct"
    if isinstance(data_type, Union):
        return "union"
    if isinstance(data_type, Enum):
        return "enum"
    if isinstance(data_type, TypeDef):
        return "typedef"
    if isinstance(data_type, Pointer):
        return "pointer"
    if isinstance(data_type, Array):
        return "array"
    return "other"
