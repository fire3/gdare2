"""Conversion helpers keeping Java objects out of JSON."""

from __future__ import annotations

from gdare2.errors import GdarError


def java_bytes(value) -> bytes:
    if value is None:
        return b""
    return bytes((int(byte) & 0xFF) for byte in value)


def iter_items(value) -> list:
    """Normalize a Ghidra iterator, Java array or Python iterable to a list."""
    if value is None:
        return []
    if hasattr(value, "hasNext"):
        result = []
        while value.hasNext():
            result.append(value.next())
        return result
    try:
        return list(value)
    except TypeError:
        return [value]


def instruction_dict(instruction) -> dict:
    raw = java_bytes(instruction.getBytes())
    flow = instruction.getFlowType()
    try:
        symbol = instruction.getPrimarySymbol()
        symbol_name = str(symbol.getName()) if symbol is not None else ""
    except Exception:
        symbol_name = ""
    comment = ""
    try:
        from ghidra.program.model.listing import CommentType

        comment = str(instruction.getComment(CommentType.EOL) or "")
    except Exception:
        comment = ""
    demangled = ""
    if symbol_name.startswith(("_Z", "__Z")):
        try:
            from ghidra.app.util.demangler import DemanglerUtil

            demangled_object = DemanglerUtil.demangle(instruction.getProgram(), symbol_name)
            if demangled_object is not None:
                demangled = str(
                    demangled_object.getDemangledName() or demangled_object.getName() or ""
                )
        except Exception:
            demangled = ""
    return {
        "addr": int(instruction.getAddress().getOffset()),
        "size": int(instruction.getLength()),
        "bytes": raw,
        "text": str(instruction.toString()),
        "mnemonic": str(instruction.getMnemonicString()),
        "symbol": symbol_name,
        "symbol_demangled": demangled,
        "comment": comment,
        "call": bool(flow.isCall()),
        "jump": bool(flow.isJump()),
        "conditional": bool(flow.isConditional()),
    }


def function_dict(function) -> dict:
    body = function.getBody()
    return {
        "addr": int(function.getEntryPoint().getOffset()),
        "name": str(function.getName()),
        "size": int(body.getNumAddresses()),
        "end": int(body.getMaxAddress().getOffset()),
        "calling_convention": str(function.getCallingConventionName() or ""),
        "namespace": str(function.getParentNamespace().getName()),
        "thunk": bool(function.isThunk()),
    }


def require_program(ctx):
    program = ctx.program
    if program is None:
        raise GdarError("program is not open")
    return program
