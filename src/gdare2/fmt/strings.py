"""String decoding helpers for the ``ps`` family."""

from __future__ import annotations

from gdare2.errors import UsageError

#: ``ps`` forms implemented here (a trailing ``j`` is stripped by the caller).
PS_FORMS = frozenset({"", "w", "z", "p", "W", "u", "x", "n"})


def decode_string(data: bytes, form: str) -> tuple[str, str]:
    """Decode one ``ps`` form, returning ``(text, type_label)``."""
    if form not in PS_FORMS:
        raise UsageError(f"unsupported ps modifier {form!r}")
    if form in ("", "z"):
        return data.split(b"\x00", 1)[0].decode("utf-8", "replace"), "ascii"
    if form == "n":
        return data.split(b"\n", 1)[0].decode("latin-1"), "ascii"
    if form == "p":
        if not data:
            return "", "ascii"
        length = data[0]
        return data[1 : 1 + length].decode("utf-8", "replace"), "ascii"
    if form == "x":
        return escape_bytes(data), "ascii"
    if form == "u":
        return utf16_escape(data), "utf16"
    if form == "w":
        return decode_wide(data, 2), "utf16"
    return decode_wide(data, 4), "utf32"


def escape_bytes(data: bytes) -> str:
    """r2's ``R_PRINT_STRING_ESC_NL``: printable bytes stay, others escape."""
    out: list[str] = []
    for byte in data:
        if byte == 0x5C:
            out.append("\\\\")
        elif byte == 0x0A:
            out.append("\\n")
        elif byte == 0x0D:
            out.append("\\r")
        elif byte == 0x09:
            out.append("\\t")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def utf16_escape(data: bytes) -> str:
    """``psu``: r2's ``r_str_utf16_encode`` escapes every non-ASCII byte."""
    out: list[str] = []
    for byte in data:
        if byte == 0x5C:
            out.append("\\\\")
        elif byte == 0x22:
            out.append('\\"')
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\u00{byte:02x}")
    return "".join(out)


def decode_wide(data: bytes, unit: int) -> str:
    """r2's wide/wide32 renderer: skip NULs, print the low byte."""
    out: list[str] = []
    index = 0
    length = len(data)
    while index < length:
        if unit == 2:
            if data[index] == 0:
                break
        else:
            start = index
            while start < min(index + unit, length) and data[start] == 0:
                start += 1
            index = start
            if index >= length or data[index] == 0:
                break
        byte = data[index]
        if byte == 0x5C:
            out.append("\\\\")
        elif byte == 0x0A:
            out.append("\n")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
        index += unit if unit == 2 else 1
    return "".join(out)
