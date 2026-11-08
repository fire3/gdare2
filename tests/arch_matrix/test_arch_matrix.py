from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gdare2.arch_matrix import ARCH_MATRIX
from gdare2d.import_plan import resolve_alias

pytestmark = pytest.mark.arch_matrix
ROOT = Path(__file__).resolve().parents[2]


def test_aliases_match_matrix():
    for entry in ARCH_MATRIX:
        resolved = resolve_alias(entry["arch"], bits=entry["bits"], endian=entry["endian"])
        assert resolved == entry["language"], entry["name"]


def test_raw_import_matrix():
    if importlib.util.find_spec("pyghidra") is None:
        pytest.skip("pyghidra is not installed")
    ghidra = Path(os.environ.get("GHIDRA_INSTALL_DIR", Path.home() / "ghidra" / "current"))
    if not ghidra.is_dir():
        pytest.skip(f"Ghidra install not found: {ghidra}")

    env = os.environ.copy()
    env["GHIDRA_INSTALL_DIR"] = str(ghidra)
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "arch_matrix.py"), "--json"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert len(payload) == len(ARCH_MATRIX)
    assert all(item["ok"] for item in payload), payload
    for item in payload:
        assert item["info_ok"], item
        assert item["pd_ok"], item
        assert item["pd"].strip(), item
        assert "bits" in item and "big_endian" in item
