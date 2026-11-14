"""Tests for the ``pc`` codegen formatters and their command wiring (V6)."""

from __future__ import annotations

import json

import pytest
from test_session import make_session

from gdare2.errors import UnsupportedError, UsageError
from gdare2.fmt import codegen
from gdare2.parser import parse_statement

ABC = b"ABCD"


# -- pure formatters (no session) ------------------------------------------


def test_binary_is_one_continuous_bit_string():
    assert codegen.format_binary(b"\x01\x02", 0) == ["0b0000000100000010"]
    assert codegen.format_binary(b"\xb6", 0) == ["0b10110110"]


def test_c_char_escapes_every_byte():
    assert codegen.format_c_char(ABC, 0x1000) == [
        'const char buffer[4] = "\\x41\\x42\\x43\\x44";'
    ]
    assert "\\x00\\xff\\x10" in codegen.format_c_char(b"\x00\xff\x10", 0)[0]


def test_c_decimal_uses_decimal_values():
    assert codegen.format_c_decimal(ABC, 0x1000) == [
        "const unsigned char buffer[4] = { 65, 66, 67, 68 };"
    ]


def test_c_include_reuses_pc_values_with_a_declaration_header():
    assert codegen.format_c_include(ABC, 0x1000) == [
        "#include <stdint.h>",
        "const unsigned char buffer[4] = { 0x41, 0x42, 0x43, 0x44 };",
    ]


def test_c_string_appends_the_nul_terminator():
    assert codegen.format_c_string(ABC, 0x1000) == [
        'const char buffer[5] = "\\x41\\x42\\x43\\x44\\x00";'
    ]


def test_fortran_uses_kind_4_to_keep_bytes_in_range():
    assert codegen.format_fortran(b"\xff\x00", 0) == [
        "integer(kind=4), dimension(2) :: buffer = (/ 255, 0 /)"
    ]


def test_go_slice_literal():
    assert codegen.format_go(ABC, 0x1000) == [
        "buf := []byte{0x41, 0x42, 0x43, 0x44}"
    ]


def test_hexpairs_matches_p8_shape():
    assert codegen.format_hexpairs(ABC, 0x1000) == ["41424344"]


def test_json_array_round_trips():
    assert codegen.format_json(ABC, 0x1000) == ["[65, 66, 67, 68]"]
    assert json.loads(codegen.format_json(b"", 0)[0]) == []


def test_rust_swift_and_typescript_arrays():
    assert codegen.format_rust(ABC, 0x1000) == [
        "let buffer: [u8; 4] = [0x41, 0x42, 0x43, 0x44];"
    ]
    assert codegen.format_swift(ABC, 0x1000) == [
        "let buffer: [UInt8] = [0x41, 0x42, 0x43, 0x44]"
    ]
    assert codegen.format_typescript(ABC, 0x1000) == [
        "const buffer: number[] = [0x41, 0x42, 0x43, 0x44];"
    ]


def test_shell_hexpairs_are_prefixed_and_spaced():
    assert codegen.format_shell(ABC, 0x1000) == ["0x41 0x42 0x43 0x44"]


def test_verilog_uses_a_systemverilog_assignment_pattern():
    assert codegen.format_verilog(ABC, 0x1000) == [
        "byte unsigned buffer[0:3] = '{8'h41, 8'h42, 8'h43, 8'h44};"
    ]


def test_wasm_embeds_the_address_as_i32_const():
    assert codegen.format_wasm(ABC, 0x1000) == [
        '(data (i32.const 0x1000) "\\41\\42\\43\\44")'
    ]


def test_formatters_tolerate_empty_data():
    for name in (
        "binary",
        "c_char",
        "c_decimal",
        "c_include",
        "c_string",
        "fortran",
        "go",
        "hexpairs",
        "json",
        "rust",
        "shell",
        "swift",
        "typescript",
        "verilog",
        "wasm",
    ):
        lines = getattr(codegen, f"format_{name}")(b"", 0x1000)
        assert lines and all(isinstance(line, str) for line in lines), name


# -- session wiring ---------------------------------------------------------


def test_pc_family_renders_the_block():
    session, _ = make_session()
    assert session.run("pcb 4") == ["0b01000001010000100100001101000100"]
    assert session.run("pcc 4") == ['const char buffer[4] = "\\x41\\x42\\x43\\x44";']
    assert session.run("pcd 4") == ["const unsigned char buffer[4] = { 65, 66, 67, 68 };"]
    assert session.run("pcF 4") == [
        "integer(kind=4), dimension(4) :: buffer = (/ 65, 66, 67, 68 /)"
    ]
    assert session.run("pcg 4") == ["buf := []byte{0x41, 0x42, 0x43, 0x44}"]
    assert session.run("pci 4") == [
        "#include <stdint.h>",
        "const unsigned char buffer[4] = { 0x41, 0x42, 0x43, 0x44 };",
    ]
    assert session.run("pcJ 4") == ["[65, 66, 67, 68]"]
    assert session.run("pcq 4") == ["41424344"]
    assert session.run("pcr 4") == ["let buffer: [u8; 4] = [0x41, 0x42, 0x43, 0x44];"]
    assert session.run("pcS 4") == ["let buffer: [UInt8] = [0x41, 0x42, 0x43, 0x44]"]
    assert session.run("pct 4") == ["const buffer: number[] = [0x41, 0x42, 0x43, 0x44];"]
    assert session.run("pcu 4") == ["0x41 0x42 0x43 0x44"]
    assert session.run("pcv 4") == [
        "byte unsigned buffer[0:3] = '{8'h41, 8'h42, 8'h43, 8'h44};"
    ]
    assert session.run("pcw 4") == ['(data (i32.const 0x1000) "\\41\\42\\43\\44")']
    assert session.run("pcz 4") == [
        'const char buffer[5] = "\\x41\\x42\\x43\\x44\\x00";'
    ]


def test_pc_length_defaults_to_blocksize_and_reads_at_seek():
    session, client = make_session()
    assert session.run("pcg") == ["buf := []byte{0x41, 0x42, 0x43, 0x44}"]
    assert session.blocksize == 0x100
    assert ("read_bytes", {"allow_writes": False, "ea": 0x1000, "size": 0x100}) in client.calls

    session.run("s 0x2000")
    assert session.run("pcw 4") == ['(data (i32.const 0x2000) "\\41\\42\\43\\44")']
    assert ("read_bytes", {"allow_writes": False, "ea": 0x2000, "size": 4}) in client.calls


def test_pc_length_accepts_expressions_and_rejects_zero():
    session, client = make_session()
    assert session.run("pcg 2+2") == session.run("pcg 4")
    assert ("read_bytes", {"allow_writes": False, "ea": 0x1000, "size": 4}) in client.calls

    session.run("pcg 0")
    assert session.failed
    assert isinstance(session.last_error, UsageError)
    assert "positive" in str(session.last_error)


def test_pc_a_pcl_and_pcE_are_explicitly_unsupported():
    session, _ = make_session()
    for command in ("pcA", "pcl", "pcE"):
        with pytest.raises(UnsupportedError, match="not supported; see TASKS-v3 V6"):
            session.run_statement(parse_statement(command))


def test_plain_pc_keeps_its_shape_and_new_patterns_are_distinct():
    session, _ = make_session()
    assert session.run("pc 4") == ["0x41, 0x42, 0x43, 0x44"]
    from gdare2 import cmd as cmd_module

    patterns = [spec.pattern for spec in cmd_module.all_commands()]
    family = ["pcA", "pcb", "pcc", "pcd", "pcE", "pcF", "pcg", "pci", "pcJ",
              "pcl", "pcq", "pcr", "pcS", "pct", "pcu", "pcv", "pcw", "pcz"]
    assert all(pattern in patterns for pattern in family)
    assert len(set(family)) == len(family)
