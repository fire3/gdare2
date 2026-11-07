"""JSON rendering that keeps bytes printable."""

from __future__ import annotations

import json
from typing import Any


def jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def dumps(value: Any, **kwargs: Any) -> str:
    kwargs.setdefault("indent", 2)
    kwargs.setdefault("sort_keys", True)
    return json.dumps(jsonable(value), **kwargs)
