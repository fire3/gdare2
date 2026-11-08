"""RPC envelope and byte transport encoding."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from gdare2 import PROTOCOL_VERSION

BYTES_KEY = "$gdare2.b64"


@dataclass
class OpResult:
    """An op result that also carries response-level metadata."""

    value: Any
    meta: dict[str, Any] | None = None


def encode_bytes(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {BYTES_KEY: base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        return {key: encode_bytes(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode_bytes(item) for item in value]
    return value


def decode_bytes(value: Any) -> Any:
    if isinstance(value, dict):
        if len(value) == 1 and BYTES_KEY in value and isinstance(value[BYTES_KEY], str):
            try:
                return base64.b64decode(value[BYTES_KEY], validate=True)
            except ValueError as exc:
                raise ValueError("invalid base64 bytes envelope") from exc
        return {key: decode_bytes(item) for key, item in value.items()}
    if isinstance(value, list):
        return [decode_bytes(item) for item in value]
    return value


def request(op: str, args: dict[str, Any] | None = None, *, allow_writes: bool = False) -> dict[str, Any]:
    return {
        "id": f"c-{id(args)}",
        "op": op,
        "args": encode_bytes(args or {}),
        "allow_writes": allow_writes,
    }


def ok(result: Any, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    response: dict[str, Any] = {"ok": True, "result": encode_bytes(result)}
    if meta:
        response["meta"] = meta
    return response


def error(code: str, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if data:
        body["data"] = data
    return {"ok": False, "error": body}


def health_payload(state: str, version: str) -> dict[str, Any]:
    return {
        "ok": True,
        "version": version,
        "gdare2_version": version,
        "state": state,
        "protocol": PROTOCOL_VERSION,
    }
