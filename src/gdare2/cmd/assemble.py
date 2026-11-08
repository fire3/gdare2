"""Assembler, integer-write and base64-write commands."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

from gdare2.cmd import command, require_write
from gdare2.errors import GdarError, UsageError


def _assembly_text(statement) -> str:
    text = statement.args
    if not text.strip():
        if sys.stdin.isatty():
            raise UsageError(f"{statement.cmd} needs assembly text or piped stdin")
        text = sys.stdin.read()
    if not text.strip():
        raise UsageError(f"{statement.cmd} needs assembly text")
    return text


@command("pa", "assemble text to hexpairs")
def _assemble(session, statement):
    payload = session.call("assemble", ea=session.seek, text=_assembly_text(statement))
    return [bytes(payload["bytes"]).hex()]


@command("wa", "assemble and write at seek")
def _assemble_write(session, statement):
    require_write(session)
    payload = session.call(
        "assemble_write", ea=session.seek, text=_assembly_text(statement)
    )
    return [
        f"{session.format_addr(int(item['addr']))} {bytes(item['bytes']).hex()} {item['text']}"
        for item in payload["items"]
    ]


@command("wa*", "print the wx commands for assembly text")
def _assemble_commands(session, statement):
    payload = session.call("assemble", ea=session.seek, text=_assembly_text(statement))
    return [
        f"wx {bytes(item['bytes']).hex()} @ {session.format_addr(int(item['addr']))}"
        for item in payload["items"]
    ]


@command("wa+", "assemble, write, and seek past the result")
def _assemble_write_plus(session, statement):
    require_write(session)
    payload = session.call(
        "assemble_write", ea=session.seek, text=_assembly_text(statement)
    )
    session.seek_to(int(payload["addr"]) + int(payload["size"]))
    return []


@command("waf", "assemble a file and write at seek", aliases=("waF",))
def _assemble_file(session, statement):
    require_write(session)
    path = statement.args.strip()
    if not path:
        raise UsageError("waf needs a source file")
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise GdarError(f"cannot read {path}: {exc}") from exc
    payload = session.call("assemble_write", ea=session.seek, text=text)
    return [
        f"{session.format_addr(int(item['addr']))} {bytes(item['bytes']).hex()} {item['text']}"
        for item in payload["items"]
    ]


def _width(cmd: str) -> tuple[int, str]:
    suffix = cmd[2:]
    sign = ""
    if suffix.endswith(("+", "-")):
        sign = suffix[-1]
        suffix = suffix[:-1]
    width = int(suffix) if suffix else 4
    if width not in (1, 2, 4, 8):
        raise UsageError("wi width must be 1, 2, 4 or 8")
    return width, sign


@command("wi", "read or write an integer at seek")
def _wi(session, statement):
    width, sign = _width(statement.cmd)
    order = "big" if session.info.get("endian") == "big" else "little"
    current = int(session.call("read_value", ea=session.seek, width=width)["value"])
    operand = statement.args.strip()
    if not sign and not operand:
        return [hex(current)]
    if sign:
        delta = session.eval(operand) if operand else 1
        value = current + delta if sign == "+" else current - delta
    else:
        value = session.eval(operand)
    require_write(session)
    mask = (1 << (width * 8)) - 1
    data = (value & mask).to_bytes(width, order, signed=False)
    session.call("write_bytes", ea=session.seek, data=data)
    return []


@command("w6d", "decode base64 and write at seek", aliases=("w6",))
def _write_base64(session, statement):
    require_write(session)
    text = "".join(statement.args.split())
    if not text:
        raise UsageError("w6d needs base64 text")
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise UsageError(f"invalid base64: {exc}") from exc
    session.call("write_bytes", ea=session.seek, data=data)
    return []


@command("w6e", "encode bytes at seek as base64")
def _encode_base64(session, statement):
    args = statement.args.strip()
    size = int(args, 0) if args else session.blocksize
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    return [base64.b64encode(data).decode("ascii")]


# Register every wi width/sign variant.
def _register_wi_variants() -> None:
    for width in ("", "1", "2", "4", "8"):
        for sign in ("", "+", "-"):
            pattern = f"wi{width}{sign}"
            command(pattern, "read or write an integer at seek")(_wi)


_register_wi_variants()
