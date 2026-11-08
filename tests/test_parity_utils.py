from __future__ import annotations

from gdare2.parity import (
    GOLDEN_SCHEMA,
    ghidra_version,
    golden_mismatch_reason,
    normalize_function_name,
    parse_pdi,
    r2_version,
    sha256_file,
)


def test_normalize_address_derived_names_uses_each_side_base():
    assert normalize_function_name("fcn.00006790", base=0) == "fcn_6790"
    assert normalize_function_name("FUN_00106790", base=0x100000) == "fcn_6790"
    assert normalize_function_name("sub_0000be68", base=0x8000) == "fcn_3e68"


def test_normalize_imports_and_entry_names():
    assert normalize_function_name("sym.imp.getenv") == "getenv"
    assert normalize_function_name("sym.error") == "error"
    assert normalize_function_name("entry0") == "entry"
    assert normalize_function_name("entry.init0") == "_INIT_0"


def test_parse_r2_pdi_skips_flag_only_lines():
    text = "\n".join(
        [
            "0x00006760   rip:",
            "0x00006760                 31ed  xor ebp, ebp",
            "0x00006762               4989d1  mov r9, rdx",
        ]
    )
    records = parse_pdi(text)
    assert [item["addr"] for item in records] == [0x6760, 0x6762]
    assert [item["size"] for item in records] == [2, 3]
    assert [item["bytes"] for item in records] == ["31ed", "4989d1"]


def test_parse_pdi_accepts_gdare2_symbol_column():
    text = "0x0000000000106760  entry                     31 ed                 XOR EBP,EBP"
    records = parse_pdi(text)
    assert len(records) == 1
    assert records[0]["addr"] == 0x106760
    assert records[0]["symbol"] == "entry"
    assert records[0]["bytes"] == "31ed"
    assert records[0]["size"] == 2


def test_parse_backward_disassembly_with_pipes_and_elided_bytes():
    text = "|           0x00006749      4c8b05500b..   mov r8, qword [obj.optarg]"
    records = parse_pdi(text)
    assert len(records) == 1
    assert records[0]["addr"] == 0x6749
    assert records[0]["size"] == 6


def test_golden_mismatch_reason_checks_schema_versions_and_hash():
    meta = {
        "schema": GOLDEN_SCHEMA,
        "r2_version": "radare2 6.2.5",
        "ghidra_version": "12.2",
        "target_sha256": "abc",
    }
    assert (
        golden_mismatch_reason(
            meta, r2_version="radare2 6.2.5", ghidra_version="12.2", target_sha256="abc"
        )
        is None
    )
    assert "schema" in golden_mismatch_reason(
        {**meta, "schema": 0}, r2_version="", ghidra_version="", target_sha256=""
    )
    assert "r2" in golden_mismatch_reason(
        meta, r2_version="radare2 6.3", ghidra_version="12.2", target_sha256="abc"
    )
    assert "ghidra" in golden_mismatch_reason(
        meta, r2_version="radare2 6.2.5", ghidra_version="12.3", target_sha256="abc"
    )
    assert "target-sha256" in golden_mismatch_reason(
        meta, r2_version="radare2 6.2.5", ghidra_version="12.2", target_sha256="def"
    )


def test_sha256_file(tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"gdare2")
    assert sha256_file(target) == sha256_file(target)
    assert len(sha256_file(target)) == 64


def test_tool_version_helpers_tolerate_missing_tools(tmp_path):
    assert ghidra_version(tmp_path) == ""
    assert r2_version(str(tmp_path / "no-such-r2")) == ""
