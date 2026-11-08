from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gdare2.parity import (
    ghidra_version,
    golden_mismatch_reason,
    normalize_function_name,
    parse_pdi,
    r2_version,
    sha256_file,
)

pytestmark = pytest.mark.parity

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = ROOT / "tests" / "golden"
DEFAULT_ARM_TARGET = ROOT.parent / "vulfirm" / "OverFlow" / "R6700v3" / "upnpd"


def _arm_target() -> Path:
    override = os.environ.get("GDARE2_ARM_TARGET")
    return Path(override) if override else DEFAULT_ARM_TARGET


PARITY_CASES = (
    pytest.param({"golden": "ls.json", "target": Path("/bin/ls")}, id="ls"),
    pytest.param({"golden": "upnpd.json", "target": _arm_target()}, id="arm32-upnpd"),
)


def _load_golden(name: str) -> dict:
    return json.loads((GOLDEN_DIR / name).read_text(encoding="utf-8"))


def _gdare2_json(run_gdare2, target, command: str):
    result = run_gdare2("-j", "-qc", command, str(target))
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _gdare2_text(run_gdare2, target, command: str) -> str:
    result = run_gdare2("-qc", command, str(target))
    assert result.returncode == 0, result.stderr
    return result.stdout


def _golden(case) -> dict:
    target = case["target"]
    if not target.is_file():
        pytest.skip(
            f"parity target missing: {target}; check out ../vulfirm or set GDARE2_ARM_TARGET"
        )
    golden = _load_golden(case["golden"])
    reason = golden_mismatch_reason(
        golden["meta"],
        r2_version=r2_version(),
        ghidra_version=ghidra_version(),
        target_sha256=sha256_file(target),
    )
    if reason is not None:
        pytest.skip(reason)
    return golden


def _info(run_gdare2, case, golden) -> dict:
    payload = _gdare2_json(run_gdare2, case["target"], "iI")
    info = payload[0] if isinstance(payload, list) else payload
    assert info["language"] == golden["meta"]["language"]
    return info


@pytest.mark.parametrize("case", PARITY_CASES)
def test_info_fields(run_gdare2, case):
    golden = _golden(case)
    info = _info(run_gdare2, case, golden)
    r2 = golden["r2"]
    assert str(info["arch"]).lower() == str(r2["info"]["arch"]).lower()
    assert int(info["bits"]) == int(r2["info"]["bits"])
    assert info["endian"] == r2["info"]["endian"]
    assert int(info["entry"]) - int(info["image_base"]) == r2["entry"] - r2["base"]


@pytest.mark.parametrize("case", PARITY_CASES)
def test_sections_parity(run_gdare2, case):
    golden = _golden(case)
    info = _info(run_gdare2, case, golden)
    sections = _gdare2_json(run_gdare2, case["target"], "iS")
    r2 = golden["r2"]

    r2_names = {item["name"] for item in r2["sections"] if item["name"]}
    names = {item["name"] for item in sections}
    assert r2_names <= names, sorted(r2_names - names)

    r2_text = next(item for item in r2["sections"] if item["name"] == ".text")
    gd_text = next(item for item in sections if item["name"] == ".text")
    assert int(gd_text["size"]) == r2_text["size"]
    assert int(gd_text["addr"]) - int(info["image_base"]) == r2_text["vaddr"] - r2["base"]


def _at_entry(info: dict, command: str) -> str:
    return f"s 0x{int(info['entry']):x}; {command}"


@pytest.mark.parametrize("case", PARITY_CASES)
def test_function_sets_and_counts(run_gdare2, case):
    golden = _golden(case)
    info = _info(run_gdare2, case, golden)
    functions = _gdare2_json(run_gdare2, case["target"], "afl")
    r2 = golden["r2"]

    r2_imports = {
        normalize_function_name(item["name"], base=r2["base"])
        for item in r2["functions"]
        if item["name"].startswith("sym.imp.")
    }
    names = {
        normalize_function_name(item["name"], base=int(info["image_base"]))
        for item in functions
    }
    assert r2_imports, "golden has no imports to compare"
    assert r2_imports <= names, sorted(r2_imports - names)

    assert len(functions) >= len(r2["functions"])
    assert len(functions) <= 3 * len(r2["functions"])
    entry_offset = int(info["entry"]) - int(info["image_base"])
    assert any(
        int(item["addr"]) - int(info["image_base"]) == entry_offset for item in functions
    )


@pytest.mark.parametrize("case", PARITY_CASES)
def test_entry_bytes_parity(run_gdare2, case):
    golden = _golden(case)
    info = _info(run_gdare2, case, golden)
    payload = _gdare2_json(run_gdare2, case["target"], _at_entry(info, "xj 32"))
    assert bytes.fromhex(payload["bytes"]).hex() == golden["r2"]["bytes"]


@pytest.mark.parametrize("case", PARITY_CASES)
def test_disassembly_structure(run_gdare2, case):
    golden = _golden(case)
    info = _info(run_gdare2, case, golden)
    payload = _gdare2_json(run_gdare2, case["target"], _at_entry(info, "pdj 8"))
    r2 = golden["r2"]
    base = int(info["image_base"])

    assert len(payload) == len(r2["pd"])
    for actual, expected in zip(payload, r2["pd"], strict=True):
        assert int(actual["addr"]) - base == expected["addr"] - r2["base"]
        assert int(actual["size"]) == expected["size"]
        assert str(actual["bytes"]).lower() == expected["bytes"]


@pytest.mark.parametrize("case", PARITY_CASES)
def test_pdi_pdl_and_backward_disassembly(run_gdare2, case):
    golden = _golden(case)
    info = _info(run_gdare2, case, golden)
    r2 = golden["r2"]
    base = int(info["image_base"])
    entry = int(info["entry"]) - base

    pdi = parse_pdi(_gdare2_text(run_gdare2, case["target"], _at_entry(info, "pdi 8")))
    assert len(pdi) == len(r2["pdi"])
    for actual, expected in zip(pdi, r2["pdi"], strict=True):
        assert actual["addr"] - base == expected["addr"] - r2["base"]
        assert actual["size"] == expected["size"]
        assert actual["bytes"] == expected["bytes"]

    pdl_lines = _gdare2_text(run_gdare2, case["target"], _at_entry(info, "pdl 8")).splitlines()
    assert len([line for line in pdl_lines if line.strip()]) == len(r2["pdl_lines"])

    backward = parse_pdi(_gdare2_text(run_gdare2, case["target"], _at_entry(info, "pd -8")))
    assert 0 < len(backward) <= 8
    addresses = [item["addr"] - base for item in backward]
    assert all(left < right for left, right in zip(addresses, addresses[1:], strict=False))
    assert all(address < entry for address in addresses)
