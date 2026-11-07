"""Printing commands: disassembly and memory."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.errors import UsageError
from gdare2.fmt.disasm import format_disasm
from gdare2.fmt.memory import hexdump
from gdare2.jsonutil import dumps


def _bits(session) -> int:
    return int(session.info.get("bits") or 32)


@command("pd", "disassemble N instructions", detail="Usage: pd [n] [@ addr]")
def _pd(session, statement):
    count = _number(statement.args, 1)
    if count < 0:
        return _pd_backward(session, -count)
    items = session.call("disasm", ea=session.seek, count=count)
    return format_disasm(items, session.config, _bits(session))


def _pd_backward(session, count: int) -> list[str]:
    items = session.call("disasm_back", ea=session.seek, count=count)
    return format_disasm(items, session.config, _bits(session))


@command("pdf", "disassemble the current function", aliases=("pdfj",))
def _pdf(session, statement):
    payload = session.call("pdf", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    lines = [f"; {payload['name']} ({session.format_addr(int(payload['addr']))})"]
    lines.extend(format_disasm(payload["instructions"], session.config, _bits(session)))
    return lines


@command("px", "hexdump memory", detail="Usage: px [n] [@ addr]")
def _px(session, statement):
    size = _number(statement.args, session.blocksize)
    data = session.call("read_bytes", ea=session.seek, size=size)
    return hexdump(
        bytes(data),
        session.seek,
        cols=session.config.get_int("hex.cols"),
        header=session.config.get_bool("hex.header"),
        bits=_bits(session),
    )


@command("p8", "print N bytes as hex")
def _p8(session, statement):
    size = _number(statement.args, session.blocksize)
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    return [data.hex()]


@command("pv", "print a value little-endian")
def _pv(session, statement):
    width = _number(statement.args, 4)
    payload = session.call("read_value", ea=session.seek, width=width)
    return [hex(int(payload["value"]))]


@command("ps", "print a string")
def _ps(session, statement):
    size = _number(statement.args, session.blocksize)
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    return [data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")]


def _number(text: str, default: int) -> int:
    text = text.strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        raise UsageError(f"expected a number, got {text!r}") from None
