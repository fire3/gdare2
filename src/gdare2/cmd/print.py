"""Printing commands: disassembly and memory."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.errors import UsageError
from gdare2.fmt.disasm import format_disasm
from gdare2.fmt.memory import hexdump
from gdare2.jsonutil import dumps


def _bits(session) -> int:
    return int(session.info.get("bits") or 32)


@command(
    "pd",
    "disassemble N instructions",
    detail="Usage: pd [n] [@ addr]",
    aliases=("pdj", "pdi"),
)
def _pd(session, statement):
    count = _number(statement.args, 1)
    if statement.cmd == "pdj":
        return [dumps(session.call("disasm", ea=session.seek, count=max(count, 0)))]
    if count < 0:
        return _pd_backward(session, -count)
    items = session.call("disasm", ea=session.seek, count=count)
    return format_disasm(items, session.config, _bits(session))


def _pd_backward(session, count: int) -> list[str]:
    items = session.call("disasm_back", ea=session.seek, count=count)
    return format_disasm(items, session.config, _bits(session))


@command("pi", "print instruction text only")
def _pi(session, statement):
    count = _number(statement.args, 1)
    items = session.call("disasm", ea=session.seek, count=max(count, 0))
    return [str(item.get("text", "")) for item in items]


@command("pdl", "print instruction address, size and text")
def _pdl(session, statement):
    count = _number(statement.args, 1)
    items = session.call("disasm", ea=session.seek, count=max(count, 0))
    return [
        f"{session.format_addr(int(item['addr']))} {int(item['size']):2d} {item.get('text', '')}"
        for item in items
    ]


@command("pD", "disassemble N bytes")
def _pd_bytes(session, statement):
    size = _number(statement.args, session.blocksize)
    items = session.call("disasm_bytes", ea=session.seek, size=max(size, 0))
    return format_disasm(items, session.config, _bits(session))


@command("pdf", "disassemble the current function", aliases=("pdfj",))
def _pdf(session, statement):
    payload = session.call("pdf", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    lines = [f"; {payload['name']} ({session.format_addr(int(payload['addr']))})"]
    lines.extend(format_disasm(payload["instructions"], session.config, _bits(session)))
    return lines


@command("pdc", "decompile the current function", aliases=("pdcj",))
def _pdc(session, statement):
    payload = session.call("decompile", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return str(payload.get("c") or "").rstrip().splitlines()


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


@command("pxw", "hexdump 32-bit words")
def _pxw(session, statement):
    return _words(session, statement, 4)


@command("pxq", "hexdump 64-bit words")
def _pxq(session, statement):
    return _words(session, statement, 8)


def _words(session, statement, width: int) -> list[str]:
    size = _number(statement.args, session.blocksize)
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    order = "big" if session.info.get("endian") == "big" else "little"
    lines = []
    for offset in range(0, len(data) - width + 1, width):
        value = int.from_bytes(data[offset : offset + width], order)
        lines.append(f"{session.format_addr(session.seek + offset)} 0x{value:0{width * 2}x}")
    return lines


@command("p8", "print N bytes as hex", aliases=("p8j",))
def _p8(session, statement):
    size = _number(statement.args, session.blocksize)
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    if statement.cmd.endswith("j"):
        return [dumps({"addr": session.seek, "size": len(data), "bytes": data.hex()})]
    return [data.hex()]


@command(
    "pv",
    "print a value",
    aliases=("pvj", "pv1", "pv2", "pv4", "pv8", "pvj1", "pvj2", "pvj4", "pvj8"),
)
def _pv(session, statement):
    suffix = statement.cmd[2:]
    as_json = suffix.startswith("j")
    if as_json:
        suffix = suffix[1:]
    width = int(suffix) if suffix in ("1", "2", "4", "8") else _number(statement.args, 4)
    payload = session.call("read_value", ea=session.seek, width=width)
    if as_json:
        return [dumps(payload)]
    return [hex(int(payload["value"]))]


@command("ps", "print a string")
def _ps(session, statement):
    size = _number(statement.args, session.blocksize)
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    return [data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")]


@command("pc", "print a C byte array")
def _pc(session, statement):
    size = _number(statement.args, session.blocksize)
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    return [", ".join(f"0x{byte:02x}" for byte in data)]


def _number(text: str, default: int) -> int:
    text = text.strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        raise UsageError(f"expected a number, got {text!r}") from None
