"""radare2-style ``?`` expression and formatting commands.

These are pure client-side commands: they evaluate integer expressions with
:mod:`gdare2.expr` and render the result in the representation r2 prints.
Physical/virtual address conversion uses the ELF program headers of the
original file (the same "raw file view" as ``iSS``), not Ghidra memory blocks.
"""

from __future__ import annotations

import base64
import binascii
import random

from gdare2.cmd import command
from gdare2.errors import UnsupportedError, UsageError

# r2 prints these in `? <expr>`; missing lines are not faked.
_REPRESENTATIONS = (
    "hex",
    "octal",
    "unit",
    "int64",
    "uint64",
    "binary",
    "ternary",
    "decimal",
)

_UNITS = (("", 1024**0), ("K", 1024), ("M", 1024**2), ("G", 1024**3), ("T", 1024**4), ("P", 1024**5))

_ASCII_TABLE = [
    "  x0 x01 x02 x03 x04 x05 x06 x07 x08 x09 x0a x0b x0c x0d x0e x0f",
    "x00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "x10 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "x20   ! \" # $ % & ' ( ) * + , - . /",
    "x30 0 1 2 3 4 5 6 7 8 9 : ; < = > ?",
    "x40 @ A B C D E F G H I J K L M N O",
    "x50 P Q R S T U V W X Y Z [ \\ ] ^ _",
    "x60 ` a b c d e f g h i j k l m n o",
    "x70 p q r s t u v w x y z { | } ~ ..",
    "x80 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "x90 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "xa0 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "xb0 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "xc0 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "xd0 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "xe0 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
    "xf0 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..",
]


def _eval_arg(session, statement) -> int:
    text = statement.args.strip()
    if not text:
        return session.last_result
    return session.eval(text)


def _human_units(value: int) -> str:
    magnitude = float(value)
    for suffix, _size in reversed(_UNITS):
        limit = float(_size)
        if magnitude >= limit and limit > 1:
            text = f"{magnitude / limit:.1f}".rstrip("0").rstrip(".")
            return f"{text}{suffix}"
    return str(int(value))


def _representations(value: int) -> dict[str, str]:
    unsigned = value & 0xFFFFFFFFFFFFFFFF
    signed = unsigned - (1 << 64) if unsigned >= (1 << 63) else unsigned
    return {
        "int64": str(signed),
        "uint64": str(unsigned),
        "hex": f"0x{unsigned:x}",
        "octal": oct(unsigned).replace("0o", "0"),
        "unit": _human_units(unsigned),
        "binary": f"{unsigned:b}b",
        "ternary": _ternary(unsigned),
        "decimal": str(signed),
    }


def _ternary(value: int) -> str:
    if value == 0:
        return "0t0"
    digits = ""
    while value:
        digits = str(value % 3) + digits
        value //= 3
    return f"0t{digits}"


def _map_virtual(session, address: int) -> int:
    from gdare2.cmd.info import _elf_target
    from gdare2.formats.elf import ElfFormatError, read_segments

    target = _elf_target(session, "?p")
    try:
        segments = read_segments(str(target))
    except (ElfFormatError, OSError) as exc:
        raise UnsupportedError(f"?p/?P needs an ELF target: {exc}") from exc
    for segment in segments:
        start = segment.vaddr
        end = start + segment.memsz
        if start <= address < end:
            offset = address - start + segment.offset
            if offset < segment.offset + segment.filesz:
                return offset
    raise UsageError(f"virtual address {address:#x} is not inside a PT_LOAD segment")


def _map_physical(session, offset: int) -> int:
    from gdare2.cmd.info import _elf_target
    from gdare2.formats.elf import ElfFormatError, read_segments

    target = _elf_target(session, "?P")
    try:
        segments = read_segments(str(target))
    except (ElfFormatError, OSError) as exc:
        raise UnsupportedError(f"?p/?P needs an ELF target: {exc}") from exc
    for segment in segments:
        start = segment.offset
        end = start + segment.filesz
        if start <= offset < end:
            return offset - start + segment.vaddr
    raise UsageError(f"physical address {offset:#x} is not inside a PT_LOAD file range")


@command("?", "show command help or evaluate an expression")
def _question(session, statement):
    args = statement.args.strip()
    if not args:
        from gdare2.cmd import help_text

        return help_text()
    # A single decimal line keeps `s \`? expr\`` script substitution working;
    # r2's multi-line representation table is available via ?j.
    value = session.eval(args)
    session.last_result = value
    return [str(value)]


@command("?j", "evaluate an expression and print r2-style JSON")
def _question_json(session, statement):
    args = statement.args.strip()
    if not args:
        raise UsageError("?j needs an expression")
    value = session.eval(args)
    session.last_result = value
    reps = _representations(value)
    payload = {
        "int32": reps["decimal"],
        "uint32": str(value & 0xFFFFFFFF),
        "int64": reps["int64"],
        "uint64": reps["uint64"],
        "hex": f"0x{value & 0xFFFFFFFFFFFFFFFF:08x}",
        "octal": reps["octal"],
        "unit": reps["unit"],
        "binary": f"0b{value & 0xFFFFFFFFFFFFFFFF:b}",
        "ternary": reps["ternary"],
        "decimal": reps["decimal"],
    }
    from gdare2.jsonutil import dumps

    return [dumps(payload)]


@command("?v", "show hex value of a math expression")
def _question_value(session, statement):
    value = _eval_arg(session, statement)
    session.last_result = value
    return [f"0x{value & 0xFFFFFFFFFFFFFFFF:x}"]


@command("?vi", "show decimal value of a math expression")
def _question_decimal(session, statement):
    suffix = statement.cmd[3:]
    value = _eval_arg(session, statement)
    if suffix:
        width = int(suffix) * 8
        mask = (1 << width) - 1
        unsigned = value & mask
        if unsigned >= 1 << (width - 1):
            unsigned -= 1 << width
        return [str(unsigned)]
    return [str(value)]


@command("?vx", "show zero-padded hex value of a math expression")
def _question_padded(session, statement):
    value = _eval_arg(session, statement)
    session.last_result = value
    return [f"0x{value & 0xFFFFFFFFFFFFFFFF:08x}"]


@command("?X", "show hexadecimal value without 0x prefix")
def _question_hex_plain(session, statement):
    value = _eval_arg(session, statement)
    session.last_result = value
    return [f"{value & 0xFFFFFFFFFFFFFFFF:x}"]


@command("?x", "hexpair of a string, or hexpair conversions")
def _question_hexpair(session, statement):
    from gdare2.escape import text_bytes

    cmd = statement.cmd
    args = statement.args.strip()
    if cmd.startswith("?x-"):
        hexpart = args or cmd[3:]
        if not hexpart:
            raise UsageError("?x- needs a hexpair")
        try:
            data = bytes.fromhex(hexpart.replace("0x", ""))
        except ValueError as exc:
            raise UsageError(f"?x- invalid hexpair: {exc}") from exc
        return [data.decode("latin-1")]
    if cmd.startswith("?x+"):
        numtext = args or cmd[3:]
        if not numtext:
            raise UsageError("?x+ needs a number")
        value = session.eval(numtext)
        order = ">" if session.config.get_bool("cfg.bigendian") else "<"
        width = max(1, (value.bit_length() + 7) // 8)
        return [int(value).to_bytes(width, "little" if order == "<" else "big").hex()]
    if not args:
        raise UsageError("?x needs a string or hexpair operand")
    return [text_bytes(args).hex()]


@command("?b", "show binary value of a number")
def _question_binary(session, statement):
    value = _eval_arg(session, statement)
    session.last_result = value
    return [f"{value & 0xFFFFFFFFFFFFFFFF:b}b"]


@command("?o", "show octal value of a number")
def _question_octal(session, statement):
    value = _eval_arg(session, statement)
    session.last_result = value
    return [oct(value & 0xFFFFFFFFFFFFFFFF).replace("0o", "0")]


@command("?u", "show a value in human-readable units")
def _question_units(session, statement):
    value = _eval_arg(session, statement)
    session.last_result = value
    return [_human_units(value & 0xFFFFFFFFFFFFFFFF)]


@command("?l", "return the length of a string")
def _question_length(session, statement):
    return [str(len(statement.args))]


@command("?lq", "return the string length quietly (sets $?)")
def _question_length_quiet(session, statement):
    session.last_result = len(statement.args)
    return []


@command("?e", "echo arguments")
def _question_echo(session, statement):
    text = statement.args.rstrip()
    return [text] if text else [""]


@command("?r", "generate a random number between from and to")
def _question_random(session, statement):
    words = statement.args.split()
    try:
        low = session.eval(words[0]) if words else 0
        high = session.eval(words[1]) if len(words) > 1 else 0xFFFFFFFF
    except UsageError:
        low, high = 0, 0xFFFFFFFF
    if low > high:
        low, high = high, low
    value = random.randint(low, high)
    session.last_result = value
    return [f"0x{value:x}"]


@command("?s", "print a sequence of numbers from to by step")
def _question_sequence(session, statement):
    words = statement.args.split()
    if len(words) < 2:
        raise UsageError("?s needs from and to")
    start = session.eval(words[0])
    stop = session.eval(words[1])
    step = session.eval(words[2]) if len(words) > 2 else 1
    if step <= 0:
        raise UsageError("?s step must be positive")
    if stop < start:
        return [""]
    values = list(range(start, stop + 1, step))
    return [" ".join(str(v) for v in values)]


@command("?q", "compute an expression quietly (sets $?)")
def _question_quiet(session, statement):
    args = statement.args.strip()
    if not args:
        raise UsageError("?q needs an expression")
    value = session.eval(args)
    session.last_result = value
    return [str(value)]


@command("?=", "update $? with the result of an expression")
def _question_set_result(session, statement):
    args = statement.args.strip()
    if not args:
        raise UsageError("?= needs an expression")
    session.last_result = session.eval(args)
    return []


@command("?==", "compare two strings and set $? (0 when equal)")
def _question_strcmp(session, statement):
    words = statement.args.split()
    if len(words) < 2:
        raise UsageError("?== needs two strings")
    session.last_result = 0 if words[0] == words[1] else 1
    return []


@command("?btw", "boolean value of a <= b <= c")
def _question_between(session, statement):
    words = statement.args.split()
    if len(words) < 3:
        raise UsageError("?btw needs three values")
    low, mid, high = (session.eval(word) for word in words[:3])
    value = 1 if low <= mid <= high else 0
    session.last_result = value
    return [str(value)]


def _run_if(session, statement, predicate) -> list[str]:
    command_text = statement.args.strip()
    if not command_text:
        raise UsageError(f"{statement.cmd} needs a command to run")
    if predicate(session.last_result):
        return session.run(command_text)
    return []


@command("?eq", "run a command if $? == 0")
def _question_eq(session, statement):
    return _run_if(session, statement, lambda value: value == 0)


@command("?ne", "run a command if $? != 0")
def _question_ne(session, statement):
    return _run_if(session, statement, lambda value: value != 0)


@command("?le", "run a command if $? < 0")
def _question_le(session, statement):
    return _run_if(session, statement, lambda value: value < 0)


@command("?ge", "run a command if $? > 0")
def _question_ge(session, statement):
    return _run_if(session, statement, lambda value: value > 0)


@command("?b64", "encode a string as base64", aliases=("?b64-",))
def _question_base64(session, statement):
    from gdare2.escape import text_bytes

    args = statement.args
    if statement.cmd == "?b64-":
        try:
            return [base64.b64decode(args.strip()).decode("latin-1")]
        except (binascii.Error, ValueError) as exc:
            raise UsageError(f"?b64- invalid base64: {exc}") from exc
    return [base64.b64encode(text_bytes(args)).decode("ascii")]


@command("?a", "show the ASCII table")
def _question_ascii(session, statement):
    return list(_ASCII_TABLE)


@command("?p", "convert a virtual address to a file offset")
def _question_phys(session, statement):
    args = statement.args.strip()
    if not args:
        raise UsageError("?p needs a virtual address")
    return [f"0x{_map_virtual(session, session.eval(args)):x}"]


@command("?P", "convert a file offset to a virtual address")
def _question_virt(session, statement):
    args = statement.args.strip()
    if not args:
        raise UsageError("?P needs a file offset")
    return [f"0x{_map_physical(session, session.eval(args)):x}"]
