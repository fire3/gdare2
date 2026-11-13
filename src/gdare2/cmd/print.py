"""Printing commands: disassembly and memory."""

from __future__ import annotations

from gdare2 import pf as pf_format
from gdare2.cmd import command
from gdare2.errors import GdarError, UsageError
from gdare2.fmt.disasm import format_disasm
from gdare2.fmt.memory import hexdump
from gdare2.jsonutil import dumps


def _bits(session) -> int:
    return int(session.info.get("bits") or 32)


def _range_size(session, size: int) -> int:
    if session.tmp_range is not None:
        start, stop = session.tmp_range
        return max(0, stop - start + 1)
    return size


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
    return format_disasm(
        items,
        session.config,
        _bits(session),
        show_symbol=statement.cmd == "pdi",
    )


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
    payload = session.call(
        "decompile",
        ea=session.seek,
        timeout=session.config.get_int("ghidra.decompile.timeout"),
    )
    if statement.cmd.endswith("j"):
        return [dumps(payload)]
    return str(payload.get("c") or "").rstrip().splitlines()


@command(
    "x",
    "hexdump memory",
    detail="Usage: x [n] [@ addr]; aliases x8/xw/xq/xj",
    aliases=("x8", "xw", "xq", "xj"),
)
def _x(session, statement):
    if statement.cmd in ("xw", "xq"):
        return _words(session, statement, 4 if statement.cmd == "xw" else 8)
    size = _range_size(session, _number(statement.args, session.blocksize))
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    if statement.cmd == "x8":
        return [data.hex()]
    if statement.cmd == "xj":
        return [dumps({"addr": session.seek, "size": len(data), "bytes": data.hex()})]
    return hexdump(
        data,
        session.seek,
        cols=session.config.get_int("hex.cols"),
        header=session.config.get_bool("hex.header"),
        bits=_bits(session),
    )


@command("px", "hexdump memory", detail="Usage: px [n] [@ addr]")
def _px(session, statement):
    size = _range_size(session, _number(statement.args, session.blocksize))
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
    size = _range_size(session, _number(statement.args, session.blocksize))
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    order = "big" if session.info.get("endian") == "big" else "little"
    lines = []
    for offset in range(0, len(data) - width + 1, width):
        value = int.from_bytes(data[offset : offset + width], order)
        lines.append(f"{session.format_addr(session.seek + offset)} 0x{value:0{width * 2}x}")
    return lines


@command("p8", "print N bytes as hex", aliases=("p8j",))
def _p8(session, statement):
    size = _range_size(session, _number(statement.args, session.blocksize))
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
    size = _range_size(session, _number(statement.args, session.blocksize))
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    return [data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")]


@command("pc", "print a C byte array")
def _pc(session, statement):
    size = _range_size(session, _number(statement.args, session.blocksize))
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


PF_DETAIL = """pf <fmt> [name ...]      decode fields from memory
pfj <fmt> [name ...]     decode fields as JSON
pfs <fmt>                bytes consumed by one format
pf.                      list named formats
pf.<name>                apply a named format
pf.<name> <fmt> [name..] define a named format
Formats: b c C w d i I x o q U f F g t p s S z Z n N u, [n] arrays,
. : , ; skips/rewinds, e endian swap, 0 prefix for unions.
B D E G T X r ? are explicitly unsupported."""


@command("pf", "print formatted data", detail=PF_DETAIL, consumes_repeat=True)
def _pf(session, statement):
    return _pf_command(session, statement)


@command("pfj", "print formatted data as JSON", consumes_repeat=True)
def _pf_json(session, statement):
    return _pf_command(session, statement)


@command("pfs", "report the size of a pf format", consumes_repeat=True)
def _pf_size(session, statement):
    return _pf_command(session, statement)


@command("pf.", "list or apply named pf formats", detail=PF_DETAIL, consumes_repeat=True)
def _pf_named(session, statement):
    return _pf_command(session, statement)


def _pf_mode(token: str):
    if token == "pf":
        return "", False, None
    if token == "pfj":
        return "j", False, None
    if token == "pfs":
        return "s", False, None
    if token == "pf.":
        return "", True, None
    if token.startswith("pfj."):
        return "j", True, token[4:] or None
    if token.startswith("pfs."):
        return "s", True, token[4:] or None
    if token.startswith("pf."):
        return "", True, token[3:] or None
    return None, False, None


def _pf_command(session, statement):
    mode, dotted, named = _pf_mode(statement.cmd)
    if mode is None:
        raise UsageError(f"unsupported print modifier {statement.cmd!r} (see pf?)")
    words = statement.args.split()
    repeat = statement.repeat
    if dotted:
        if named is None:
            if not words:
                return _pf_list(session)
            named, words = words[0], words[1:]
        if words:
            return _pf_define(session, named, words)
        definition = session.pf_formats.get(named)
        if definition is None:
            raise UsageError(f"pf: no named format {named!r}")
        text, names = definition
    else:
        if not words:
            raise UsageError("pf needs a format string (see pf?)")
        text, names = words[0], tuple(words[1:])

    fmt = pf_format.parse_format(
        text,
        pointer_size=session.pointer_size,
        names=names,
        repeat=max(repeat, 1),
        union=repeat == 0,
    )
    if mode == "s":
        return [str(pf_format.format_size(fmt, include_repeat=False))]
    return _pf_render(session, fmt, json_mode=mode == "j")


def _pf_define(session, name: str, words: list[str]) -> list[str]:
    if not words:
        raise UsageError(f"pf.{name} needs a format string")
    text, names = words[0], tuple(words[1:])
    pf_format.parse_format(text, pointer_size=session.pointer_size, names=names)
    session.pf_formats[name] = (text, names)
    return []


def _pf_list(session) -> list[str]:
    lines = []
    for name in sorted(session.pf_formats):
        text, names = session.pf_formats[name]
        suffix = (" " + " ".join(names)) if names else ""
        lines.append(f"pf.{name} {text}{suffix}")
    return lines


def _pf_render(session, fmt, *, json_mode: bool) -> list[str]:
    size = pf_format.format_size(fmt)
    count = min(max(size + 64, session.blocksize), 1024 * 1024)
    data = bytes(session.call("read_bytes", ea=session.seek, size=count))
    rendered = pf_format.render(
        data,
        session.seek,
        fmt,
        endian=str(session.info.get("endian") or "little"),
        format_addr=session.format_addr,
        read_string=_pf_read_string(session),
    )
    if json_mode:
        return [dumps(rendered.rows)]
    return rendered.lines


def _pf_read_string(session):
    def read_string(address: int, size: int) -> str | None:
        try:
            raw = bytes(session.call("read_bytes", ea=address, size=size))
        except GdarError:
            return None
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    return read_string
