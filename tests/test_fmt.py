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
    assert "9090" in line
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


def test_flag_lines_are_rendered_before_instructions():
    config = Config()
    lines = format_disasm(
        [_item(symbol="main")],
        config,
        64,
        show_symbol=True,
        flags={0x1000: ["main", "user_flag"]},
    )
    assert lines[0].endswith("user_flag:")
    assert not any(line.endswith("main:") for line in lines)
    assert "main" in lines[-1]

    config.set("asm.flags", False)
    hidden = format_disasm(
        [_item(symbol="main")],
        config,
        64,
        show_symbol=True,
        flags={0x1000: ["user_flag"]},
    )
    assert not any("user_flag" in line for line in hidden)


def test_hexdump_options():
    data = bytes(range(20))
    lines = hexdump(data, 0x1000, cols=8, header=True, bits=64)
    assert lines[0].startswith("- offset -")
    assert lines[2].startswith("0x0000000000001008")
    assert "0809 0a0b 0c0d 0e0f" in lines[2]
    no_header = hexdump(data, 0x1000, cols=8, header=False, bits=64)
    assert len(no_header) == 3
    no_pairs = hexdump(data, 0x1000, cols=8, header=False, pairs=False, bits=64)
    assert "08 09 0a 0b" in no_pairs[1]
    no_offset = hexdump(data, 0x1000, cols=8, header=False, offset=False, bits=64)
    assert no_offset[0].startswith("0001")
    no_ascii = hexdump(data, 0x1000, cols=8, header=False, ascii=False, bits=64)
    assert "." not in no_ascii[0].replace("0x", "")


def test_long_instruction_bytes_are_elided_like_r2():
    config = Config()
    line = format_instruction(_item(bytes=bytes(range(12))), config, 64)
    assert "0001020304050607.." in line
    assert "08090a0b" not in line


def test_byte_block_is_one_column_for_filters():
    from gdare2 import filter as grep

    config = Config()
    lines = format_disasm([_item()], config, 64)
    assert grep.apply_spec(lines, "[1]") == ["9090"]
    assert grep.apply_spec(lines, "[2]") == ["NOP"]


def test_asm_offset_false_hides_the_address_column():
    config = Config()
    config.set("asm.offset", False)
    item = {"addr": 0x1000, "size": 2, "bytes": b"\x90", "text": "NOP"}
    line = format_instruction(item, config, 64)
    assert "0x" not in line
    assert line.strip() == "NOP"


def test_scr_utf8_false_uses_ascii_gutters():
    config = Config()
    config.set("asm.lines", True)
    config.set("scr.utf8", False)
    items = [
        {"addr": 0x1000, "size": 2, "bytes": b"\x90", "text": "NOP"},
        {"addr": 0x1002, "size": 2, "bytes": b"\xc3", "text": "RET", "jump": 0x1000},
    ]
    lines = format_disasm(items, config, 64)
    assert lines[0].startswith("| ")
    assert lines[1].startswith("`-")


def test_bin_demangle_false_keeps_mangled_names():
    config = Config()
    config.set("bin.demangle", False)
    item = {"addr": 0x1000, "size": 2, "bytes": b"\x90", "text": "call", "symbol": "_Z3foo", "symbol_demangled": "foo()"}
    assert format_instruction(item, config, 64, show_symbol=True).count("_Z3foo") >= 1


def test_cfg_sandbox_key_exists():
    config = Config()
    config.set("cfg.sandbox", True)
    assert config.get_bool("cfg.sandbox") is True


def test_unsupported_r2_keys_fail_with_reason():
    import pytest

    from gdare2.errors import UsageError

    config = Config()
    with pytest.raises(UsageError, match="ESIL"):
        config.set("asm.emu", "true")
    with pytest.raises(UsageError, match="anal\\."):
        config.set("anal.autoname", "true")
