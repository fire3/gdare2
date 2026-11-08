"""Helpers shared by the r2 golden capture tool and the parity tests.

The parity layer compares structure, not bytes: instruction boundaries and
addresses are meaningful, mnemonic spelling is not.  Everything here is pure
Python so the client package keeps its "no JVM" property.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

GOLDEN_SCHEMA = 1

# r2 spells well-known entry/init functions differently from Ghidra.  Map them
# onto the Ghidra names so a name set comparison is meaningful.
_RENAMED_FUNCTIONS = {
    "entry0": "entry",
    "entry.init0": "_INIT_0",
    "entry.fini0": "_FINI_0",
}

_BYTES_TOKEN = re.compile(r"^[0-9a-fA-F.]+(?: [0-9a-fA-F.]+)*$")


def sha256_file(path: str | Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def r2_version(binary: str | None = None) -> str:
    """Return the first line of ``radare2 -v`` (empty when r2 is absent)."""
    executable = binary or shutil.which("radare2") or "radare2"
    try:
        result = subprocess.run(
            [executable, "-v"], capture_output=True, text=True, timeout=30, check=False
        )
    except OSError:
        return ""
    lines = result.stdout.splitlines()
    return lines[0].strip() if lines else ""


def ghidra_version(install_dir: str | Path | None = None) -> str:
    """Read the Ghidra version without starting a JVM."""
    root = install_dir or os.environ.get("GHIDRA_INSTALL_DIR") or (Path.home() / "ghidra" / "current")
    properties = Path(root) / "Ghidra" / "application.properties"
    try:
        text = properties.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        if line.startswith("application.version="):
            return line.partition("=")[2].strip()
    return ""


def normalize_function_name(name: str, *, base: int = 0) -> str:
    """Normalize r2/Ghidra function names to a comparable spelling.

    ``base`` is the image base of the side the name came from; address-derived
    names (``fcn.00106790`` / ``FUN_00106790``) become base-relative so r2 and
    Ghidra agree even when they choose different load addresses.
    """
    text = str(name).strip()
    if text in _RENAMED_FUNCTIONS:
        return _RENAMED_FUNCTIONS[text]
    for prefix in ("sym.imp.", "imp."):
        if text.startswith(prefix):
            return text[len(prefix) :]
    if text.startswith("sym."):
        return text[4:]
    for prefix in ("thunk_FUN_", "fcn.", "FUN_", "sub_", "func_"):
        if text.startswith(prefix):
            suffix = text[len(prefix) :]
            try:
                value = int(suffix, 16)
            except ValueError:
                return text
            return f"fcn_{value - int(base):x}"
    return text


def parse_pdi(text: str) -> list[dict[str, Any]]:
    """Parse per-instruction lines from ``pdi`` output (r2 and gdare2).

    Lines are split on runs of two or more spaces, which is the gutter both
    tools use between the address, optional symbol, bytes and text columns.
    Flag-only lines (``0x...  rip:``) have no byte column and are skipped.
    """
    records = []
    for line in text.splitlines():
        record = _parse_instruction_line(line)
        if record is not None:
            records.append(record)
    return records


def parse_text_disasm(text: str) -> list[dict[str, Any]]:
    """Parse plain ``pd`` output.  Same gutter format as ``pdi``."""
    return parse_pdi(text)


def _parse_instruction_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip().lstrip("|│").strip()
    parts = [part.strip() for part in re.split(r"\s{2,}", stripped) if part.strip()]
    if len(parts) < 2 or not parts[0].lower().startswith("0x"):
        return None
    try:
        address = int(parts[0], 16)
    except ValueError:
        return None
    rest = parts[1:]
    if len(rest) >= 2 and not _BYTES_TOKEN.match(rest[0]):
        symbol, bytes_text = rest[0], rest[1]
        text_parts = rest[2:]
    elif _BYTES_TOKEN.match(rest[0]):
        symbol, bytes_text = "", rest[0]
        text_parts = rest[1:]
    else:
        return None
    data = bytes_text.replace(" ", "").lower()
    if not data or len(data) % 2 or not _BYTES_TOKEN.match(bytes_text):
        return None
    return {
        "addr": address,
        "bytes": data,
        "size": len(data) // 2,
        "symbol": symbol,
        "text": "  ".join(text_parts),
    }


def normalize_mnemonic(text: str) -> str:
    """Lower-case and drop operands, which Ghidra and r2 spell differently."""
    head = str(text).strip().split(None, 1)
    return head[0].lower() if head else ""


def golden_mismatch_reason(
    meta: dict[str, Any],
    *,
    r2_version: str,
    ghidra_version: str,
    target_sha256: str,
) -> str | None:
    """Return a human-readable reason when a golden file is stale."""
    if meta.get("schema") != GOLDEN_SCHEMA:
        return f"golden schema {meta.get('schema')!r} != {GOLDEN_SCHEMA}; re-run tools/capture_r2_golden.py"
    checks = (
        ("r2", meta.get("r2_version"), r2_version),
        ("ghidra", meta.get("ghidra_version"), ghidra_version),
        ("target-sha256", meta.get("target_sha256"), target_sha256),
    )
    for label, expected, actual in checks:
        if expected and actual and expected != actual:
            return (
                f"golden {label} {expected!r} != current {actual!r}; "
                "re-run tools/capture_r2_golden.py"
            )
    return None
