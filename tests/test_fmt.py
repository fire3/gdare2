from __future__ import annotations

from gdare2.config import Config
from gdare2.fmt.disasm import format_disasm, format_instruction
from gdare2.fmt.memory import hexdump


def _item(**overrides):
    item = {
        "addr": 0x1000,
        "size": 2,
        "bytes": b"\x90\x90",
        "text": "NOP",
        "mnemonic": "NOP",
        "symbol": "main",
        "symbol_demangled": "",
        "comment": "",
        "call": False,
        "jump": False,
    }
    item.update(overrides)
    return item


def test_basic_instruction_layout():
    config = Config()
    line = format_instruction(_item(), config, 64)
    assert line.startswith("0x0000000000001000")
    assert "90 90" in line
    assert line.endswith("NOP")
    assert "\x1b[" not in line


def test_json_style_symbol_column():
    config = Config()
    line = format_instruction(_item(), config, 64, show_symbol=True)
    assert "main" in line
    config.set("asm.flags", False)
    assert "main" not in format_instruction(_item(), config, 64, show_symbol=True)


def test_colour_modes():
    config = Config()
    config.set("scr.color", 1)
    line = format_instruction(_item(), config, 64)
    assert "\x1b[" in line
    config.set("scr.color", 0)
    assert "\x1b[" not in format_instruction(_item(), config, 64)


def test_annotations_and_gutter():
    config = Config()
    config.set("asm.comments", True)
    lines = format_disasm([_item(comment="note"), _item(addr=0x1002, symbol="")], config, 64)
    assert lines[0] == ";-- main:"
    assert "; note" in lines[1]

    config.set("asm.lines", True)
    gutter = format_disasm([_item()], config, 64)[-1]
    assert gutter.startswith("│ ")

    config.set("asm.flags", False)
    assert ";-- main:" not in format_disasm([_item()], config, 64)


def test_demangled_symbol_is_used_when_enabled():
    config = Config()
    item = _item(symbol="_Z3foov", symbol_demangled="foo()")
    assert "foo()" in format_instruction(item, config, 64, show_symbol=True)
    config.set("asm.demangle", False)
    assert "foo()" not in format_instruction(item, config, 64, show_symbol=True)


def test_hexdump_options():
    data = bytes(range(20))
    lines = hexdump(data, 0x1000, cols=8, header=True, bits=64)
    assert lines[0].startswith("- offset -")
    assert lines[2].startswith("0x0000000000001008")
    assert "08 09 0a 0b 0c 0d 0e 0f" in lines[2]
    no_header = hexdump(data, 0x1000, cols=8, header=False, bits=64)
    assert len(no_header) == 3
