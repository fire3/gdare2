"""Small text-to-bytes helpers shared by write and search commands."""

from __future__ import annotations

import ast


def text_bytes(text: str) -> bytes:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ("'", '"'):
        try:
            value = ast.literal_eval(stripped)
        except (SyntaxError, ValueError):
            pass
        else:
            if isinstance(value, str):
                return value.encode("utf-8")
    return text.encode("utf-8")
