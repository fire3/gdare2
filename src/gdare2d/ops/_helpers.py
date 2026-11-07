"""Conversion helpers keeping Java objects out of JSON."""

from __future__ import annotations

from gdare2.errors import GdarError


def java_bytes(value) -> bytes:
    if value is None:
        return b""
    return bytes((int(byte) & 0xFF) for byte in value)


def instruction_dict(instruction) -> dict:
    raw = java_bytes(instruction.getBytes())
    flow = instruction.getFlowType()
    return {
        "addr": int(instruction.getAddress().getOffset()),
        "size": int(instruction.getLength()),
        "bytes": raw,
        "text": str(instruction.toString()),
        "mnemonic": str(instruction.getMnemonicString()),
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
