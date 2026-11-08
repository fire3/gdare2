"""Ghidra data type, function signature and type application operations."""

from __future__ import annotations

import contextlib
import fnmatch

from gdare2.errors import GdarError, NotFoundError, NotFuncError, UsageError
from gdare2d.context import to_addr
from gdare2d.dispatch import op
from gdare2d.ops._helpers import iter_items, require_program
from gdare2d.ops.memory import read_bytes

MAX_TYPES = 10000
MAX_COMPONENTS = 10000
MAX_SIGNATURES = 10000
MAX_TYPE_READ = 1024 * 1024


@op("types")
def types(ctx, kind: str | None = None, name: str | None = None, limit: int = MAX_TYPES) -> dict | list[dict]:
    program = require_program(ctx)
    if limit <= 0 or limit > MAX_TYPES:
        raise UsageError(f"type limit must be between 1 and {MAX_TYPES}")
    manager = program.getDataTypeManager()
    if name:
        return _type_detail(_find_type(manager, name))

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


@op("function_signature")
def function_signature(ctx, ea: int) -> dict:
    program = require_program(ctx)
    function = _function_at(program, int(ea))
    return _signature_dict(function)


@op("function_set_signature", writes=True)
def function_set_signature(ctx, ea: int, signature: str) -> dict:
    program = require_program(ctx)
    text = signature.strip()
    if not text:
        raise UsageError("afs needs a function signature")
    function = _function_at(program, int(ea))
    parsed = _parse_signature(program, text)

    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd, FunctionRenameOption
    from ghidra.program.model.symbol import SourceType

    command = ApplyFunctionSignatureCmd(
        function.getEntryPoint(),
        parsed,
        SourceType.USER_DEFINED,
        False,
        FunctionRenameOption.RENAME_IF_DEFAULT,
    )
    if not command.applyTo(program, ctx.monitor()):
        detail = str(command.getStatusMsg() or "invalid signature")
        raise GdarError(f"could not apply function signature: {detail}")
    refreshed = _function_at(program, int(ea))
    return _signature_dict(refreshed)


@op("type_define", writes=True)
def type_define(ctx, decl: str) -> dict:
    program = require_program(ctx)
    text = decl.strip()
    if not text:
        raise UsageError("td needs a C type declaration")
    if not text.endswith(";"):
        text += ";"
    from ghidra.app.util.cparser.C import CParser

    parser = CParser(program.getDataTypeManager(), True, None)
    parser.setParseFileName("gdare2 td")
    try:
        data_type = parser.parse(text)
    except Exception as exc:
        raise UsageError(f"C declaration parse failed: {exc}") from exc
    if data_type is None or not str(data_type.getName()):
        raise UsageError("C declaration did not define a type")
    payload = _type_detail(data_type)
    payload["declaration"] = _c_declaration(ctx, data_type)
    return payload


@op("type_c")
def type_c(
    ctx,
    name: str | None = None,
    kind: str | None = None,
    limit: int = MAX_TYPES,
) -> dict | list[dict]:
    program = require_program(ctx)
    if limit <= 0 or limit > MAX_TYPES:
        raise UsageError(f"type limit must be between 1 and {MAX_TYPES}")
    manager = program.getDataTypeManager()
    if name:
        data_type = _find_type(manager, name)
        return {
            "name": str(data_type.getName()),
            "kind": _type_kind(data_type),
            "declaration": _c_declaration(ctx, data_type),
        }

    result = []
    for data_type in iter_items(manager.getAllDataTypes()):
        if len(result) >= limit:
            break
        if kind and _type_kind(data_type) != kind:
            continue
        result.append(
            {
                "name": str(data_type.getName()),
                "kind": _type_kind(data_type),
                "declaration": _c_declaration(ctx, data_type),
            }
        )
    result.sort(key=lambda item: (item["kind"], item["name"]))
    return result


@op("type_read")
def type_read(
    ctx,
    name: str,
    ea: int = 0,
    data: bytes | None = None,
    count: int = 1,
) -> dict:
    program = require_program(ctx)
    manager = program.getDataTypeManager()
    data_type = _find_type(manager, name)
    length = int(data_type.getLength())
    if length <= 0:
        raise UsageError(f"type {name!r} has no fixed length")
    if count <= 0:
        raise UsageError("type read count must be positive")
    if data is None:
        total = length * count
        if total > MAX_TYPE_READ:
            raise UsageError(f"type read is limited to {MAX_TYPE_READ} bytes")
        raw = read_bytes(ctx, ea=int(ea), size=total)
    else:
        raw = bytes(data)
        count = max(1, len(raw) // length)
    payload = {
        "name": str(data_type.getName()),
        "path": str(data_type.getPathName()),
        "kind": _type_kind(data_type),
        "length": length,
        "count": count,
        "addr": int(ea),
        "bytes": raw,
    }
    values = _typed_values(program, data_type, raw, length)
    if values is not None:
        payload["values"] = values
    return payload


@op("type_delete", writes=True)
def type_delete(ctx, name: str, kind: str | None = None) -> dict:
    program = require_program(ctx)
    pattern = name.strip()
    if not pattern:
        raise UsageError("type deletion needs a name or glob")
    manager = program.getDataTypeManager()
    matches = []
    for data_type in iter_items(manager.getAllDataTypes()):
        if not fnmatch.fnmatchcase(str(data_type.getName()), pattern):
            continue
        if kind and _type_kind(data_type) != kind:
            continue
        matches.append(data_type)
    if not matches:
        raise NotFoundError(f"type {pattern!r} not found")

    removed = []
    for data_type in matches:
        type_name = str(data_type.getName())
        if not manager.remove(data_type):
            raise GdarError(f"could not remove type {type_name!r}")
        removed.append(type_name)
    return {"removed": removed, "count": len(removed)}


def _typed_values(program, data_type, raw: bytes, length: int) -> list | None:
    from ghidra.program.model.data import (
        AbstractIntegerDataType,
        Array,
        Enum,
        Pointer,
        TypeDef,
    )

    base = data_type.getBaseDataType()
    if isinstance(data_type, TypeDef):
        base = data_type.getBaseDataType()
    order = "big" if program.getLanguage().isBigEndian() else "little"
    if isinstance(base, Enum):
        values = []
        for offset in range(0, len(raw) - length + 1, length):
            number = int.from_bytes(raw[offset : offset + length], order, signed=True)
            names = iter_items(base.getNames(number))
            values.append({"value": number, "name": str(names[0]) if names else ""})
        return values
    if isinstance(base, AbstractIntegerDataType):
        signed = bool(base.isSigned())
        return [
            int.from_bytes(raw[offset : offset + length], order, signed=signed)
            for offset in range(0, len(raw) - length + 1, length)
        ]
    if isinstance(base, Pointer):
        pointer_size = base.getLength()
        if pointer_size <= 0:
            return None
        return [
            int.from_bytes(raw[offset : offset + pointer_size], order, signed=False)
            for offset in range(0, len(raw) - pointer_size + 1, pointer_size)
        ]
    if isinstance(base, Array):
        element = base.getDataType()
        element_length = int(element.getLength())
        if element_length == 1 and "char" in str(element.getName()).lower():
            return [raw.decode("latin-1", errors="replace").rstrip("\x00")]
    return None


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
    with contextlib.suppress(Exception):
        payload["prototype"] = str(data_type.getPrototypeString())
    return payload


def _find_type(manager, name: str):
    data_type = manager.getDataType(name)
    if data_type is not None:
        return data_type
    path = "/" + name.lstrip("/")
    data_type = manager.getDataType(path)
    if data_type is not None:
        return data_type

    matches = [
        item
        for item in iter_items(manager.getAllDataTypes())
        if str(item.getName()) == name or str(item.getPathName()) == path
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise UsageError(f"type {name!r} is ambiguous; use its full path")
    raise NotFoundError(f"type {name!r} not found")


def _c_declaration(ctx, data_type) -> str:
    from ghidra.program.model.data import DataTypeWriter
    from java.io import StringWriter

    writer = StringWriter()
    DataTypeWriter(ctx.program.getDataTypeManager(), writer).write([data_type], ctx.monitor())
    return str(writer.toString()).strip()


def _parse_signature(program, text: str):
    from ghidra.app.util.cparser.C import CParserUtils

    try:
        parsed = CParserUtils.parseSignature(None, program, text, False)
    except Exception as exc:
        raise UsageError(f"C signature parse failed: {exc}") from exc
    if parsed is None:
        raise UsageError(f"C signature parse failed for {text!r}")
    return parsed


def _signature_dict(function) -> dict:
    signature = function.getSignature()
    payload = {
        "addr": int(function.getEntryPoint().getOffset()),
        "name": str(function.getName()),
        "signature": str(signature.getPrototypeString()),
        "calling_convention": str(signature.getCallingConventionName() or ""),
    }
    payload["parameters"] = [
        {
            "name": str(parameter.getName()),
            "type": str(parameter.getDataType().getName()),
            "ordinal": int(parameter.getOrdinal()),
        }
        for parameter in iter_items(signature.getArguments())
    ]
    return payload


def _function_at(program, ea: int):
    address = to_addr(program, int(ea))
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is None:
        function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        raise NotFuncError(f"address 0x{int(ea):x} is not inside a function")
    return function


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
        for name, value in zip(names, values, strict=True)
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
