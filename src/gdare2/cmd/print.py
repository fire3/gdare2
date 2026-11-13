"""Printing commands: disassembly and memory."""

from __future__ import annotations

from itertools import zip_longest

from gdare2 import pf as pf_format
from gdare2.cmd import command
from gdare2.errors import GdarError, UnsupportedError, UsageError
from gdare2.fmt import strings as stringfmt
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
        pairs=session.config.get_bool("hex.pairs"),
        offset=session.config.get_bool("hex.offset"),
        ascii=session.config.get_bool("hex.ascii"),
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
        pairs=session.config.get_bool("hex.pairs"),
        offset=session.config.get_bool("hex.offset"),
        ascii=session.config.get_bool("hex.ascii"),
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
    aliases=(
        "pvj",
        "pv1",
        "pv2",
        "pv4",
        "pv8",
        "pvj1",
        "pvj2",
        "pvj4",
        "pvj8",
        "pvu",
        "pvd",
        "pvp",
        "pvuj",
        "pvdj",
        "pvpj",
        "pv1u",
        "pv2u",
        "pv4u",
        "pv8u",
        "pv1d",
        "pv2d",
        "pv4d",
        "pv8d",
        "pv1uj",
        "pv2uj",
        "pv4uj",
        "pv8uj",
        "pv1dj",
        "pv2dj",
        "pv4dj",
        "pv8dj",
    ),
)
def _pv(session, statement):
    suffix = statement.cmd[2:]
    as_json = "j" in suffix
    suffix = suffix.replace("j", "")
    width = None
    mode = "hex"
    pointer = False
    for char in suffix:
        if char == "p" and not pointer and width is None:
            pointer = True
        elif char in "ud" and mode == "hex":
            mode = char
        elif char in "1248" and width is None:
            width = int(char)
        else:
            raise UsageError(f"unsupported pv modifier {suffix!r}")
    if not suffix:
        width = _number(statement.args, 4)
        amount = 1
    else:
        if width is None:
            width = max(1, _bits(session) // 8)
        amount = _number(statement.args, 1)
    if amount < 0:
        raise UsageError("pv needs a non-negative count")
    data = bytes(session.call("read_bytes", ea=session.seek, size=width * amount))
    order = "big" if session.info.get("endian") == "big" else "little"
    values = [
        int.from_bytes(data[index : index + width], order)
        for index in range(0, len(data) - width + 1, width)
    ]
    if as_json:
        return [
            dumps(
                [
                    {
                        "value": value,
                        "string": "",
                        "address": session.seek + index * width,
                    }
                    for index, value in enumerate(values)
                ]
            )
        ]
    if mode == "u":
        return [str(value) for value in values]
    if mode == "d":
        return [str(_signed_value(value, width)) for value in values]
    return [f"0x{value:0{width * 2}x}" for value in values]


def _signed_value(value: int, width: int) -> int:
    limit = 1 << (width * 8)
    return value - limit if value >= limit >> 1 else value


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


@command("pdb", "disassemble the current basic block")
def _pdb(session, statement):
    block = session.call("basic_block", ea=session.seek)
    start = int(block["start"])
    size = max(1, int(block["end"]) - start + 1)
    items = session.call("disasm_bytes", ea=start, size=size)
    return format_disasm(items, session.config, _bits(session))


@command("pC", "disassemble in columns")
def _pc_columns(session, statement):
    per_column = _number(statement.args, 16)
    if per_column <= 0:
        raise UsageError("pC needs a positive row count")
    items = session.call("disasm", ea=session.seek, count=per_column * 2)
    cells = [
        f"{session.format_addr(int(item['addr']))} {item.get('text', '')}"
        for item in items
    ]
    left = cells[:per_column]
    right = cells[per_column : per_column * 2]
    column_width = max((len(cell) for cell in left), default=0) + 2
    return [
        f"{a:<{column_width}}{b}".rstrip()
        for a, b in zip_longest(left, right, fillvalue="")
    ]


@command("pA", "show address, type, size and disassembly")
def _pa_type(session, statement):
    count = _number(statement.args, 1)
    items = session.call("disasm", ea=session.seek, count=max(count, 0))
    return [
        f"{session.format_addr(int(item['addr']))} "
        f"{str(item.get('mnemonic', '')).lower()} "
        f"{int(item['size'])} {item.get('text', '')}"
        for item in items
    ]


@command("pdk", "disassemble class methods (not supported)")
def _pdk(session, statement):
    raise UnsupportedError("pdk (class methods) has no Ghidra equivalent; use pdf/afb")


@command("pdr", "recursive block disassembly (not supported)")
def _pdr(session, statement):
    raise UnsupportedError("pdr is not implemented; use pdb/pdf and agf")


@command("pxd", "signed integer dump")
def _pxd(session, statement):
    return _decimal_dump(session, statement, signed=True)


@command("pxu", "unsigned integer dump")
def _pxu(session, statement):
    return _decimal_dump(session, statement, signed=False)


def _decimal_dump(session, statement, *, signed: bool):
    size = _range_size(session, _number(statement.args, session.blocksize))
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    order = "big" if session.info.get("endian") == "big" else "little"
    cols = max(4, (session.config.get_int("hex.cols") // 4) * 4)
    lines = []
    for offset in range(0, len(data), cols):
        chunk = data[offset : offset + cols]
        values = [
            int.from_bytes(chunk[index : index + 4], order)
            for index in range(0, len(chunk) - 3, 4)
        ]
        if signed:
            values = [_signed_value(value, 4) for value in values]
        text = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in chunk)
        cells = " ".join(f"{value:>13d}" for value in values)
        lines.append(
            f"{session.format_addr(session.seek + offset)} {cells}  {text}".rstrip()
        )
    return lines


@command("pxj", "hexdump bytes as a JSON array")
def _pxj(session, statement):
    size = _range_size(session, _number(statement.args, session.blocksize))
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    return [dumps(list(data))]


@command("psz", "print a zero-terminated string")
def _psz(session, statement):
    return _string_form(session, statement, "z")


@command("psw", "print a 16-bit wide string")
def _psw(session, statement):
    return _string_form(session, statement, "w")


@command("psp", "print a pascal string")
def _psp(session, statement):
    return _string_form(session, statement, "p")


@command("psu", "print a utf16 string with escapes")
def _psu(session, statement):
    return _string_form(session, statement, "u")


@command("psx", "print a string with escaped bytes")
def _psx(session, statement):
    return _string_form(session, statement, "x")


@command("psn", "print a string until newline")
def _psn(session, statement):
    return _string_form(session, statement, "n")


@command("psj", "print the current string as JSON")
def _psj(session, statement):
    return _string_form(session, statement, "", as_json=True)


def _string_form(session, statement, form, *, as_json=False):
    size = _range_size(session, _number(statement.args, session.blocksize))
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    text, kind = stringfmt.decode_string(data, form)
    if not as_json:
        return [text]
    section = ""
    try:
        block = session.call("block_at", ea=session.seek)
        section = str(block.get("name", ""))
    except GdarError:
        section = ""
    return [
        dumps(
            {
                "string": text,
                "offset": session.seek,
                "section": section,
                "length": len(text),
                "type": kind,
            }
        )
    ]


@command("p8s", "print space-separated hex bytes")
def _p8s(session, statement):
    data = _raw_bytes(session, statement)
    return [" ".join(f"{byte:02x}" for byte in data)]


@command("p8d", "print space-separated decimal bytes")
def _p8d(session, statement):
    data = _raw_bytes(session, statement)
    return [" ".join(str(byte) for byte in data) + (" " if data else "")]


@command("p8x", "print hexpairs split at hex.cols")
def _p8x(session, statement):
    data = _raw_bytes(session, statement)
    cols = max(1, session.config.get_int("hex.cols"))
    return [data[offset : offset + cols].hex() for offset in range(0, len(data), cols)]


@command("p8,", "print comma-separated hex bytes")
def _p8_comma(session, statement):
    data = _raw_bytes(session, statement)
    return [",".join(f"0x{byte:02x}" for byte in data)]


@command("p8*", "print the block as a wx+ command")
def _p8_commands(session, statement):
    data = _raw_bytes(session, statement)
    return [f"wx+ {data.hex()}"]


@command("p8b", "print the current basic block as hexpairs")
def _p8_block(session, statement):
    block = session.call("basic_block", ea=session.seek)
    start = int(block["start"])
    size = max(1, int(block["end"]) - start + 1)
    return [bytes(session.call("read_bytes", ea=start, size=size)).hex()]


@command("p8f", "print the current function as hexpairs")
def _p8_function(session, statement):
    function = session.call("function_at", ea=session.seek)
    start = int(function["addr"])
    size = max(1, int(function["end"]) - start + 1)
    return [bytes(session.call("read_bytes", ea=start, size=size)).hex()]


def _raw_bytes(session, statement) -> bytes:
    size = _range_size(session, _number(statement.args, session.blocksize))
    return bytes(session.call("read_bytes", ea=session.seek, size=size))
