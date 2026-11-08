#!/usr/bin/env python3
"""Capture structured radare2 golden files for the parity suite.

Golden files are JSON so tests can compare structure instead of raw text.  Each
file records the tool versions, the target hash and the Ghidra language so a
stale golden is detected and regenerated rather than failing mysteriously.

Example:
    GHIDRA_INSTALL_DIR=~/ghidra/current \
        .venv/bin/python tools/capture_r2_golden.py --target /bin/ls \
        --output tests/golden/ls.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gdare2.parity import GOLDEN_SCHEMA, ghidra_version, parse_pdi, sha256_file  # noqa: E402

PD_COUNT = 8
PX_COUNT = 32
PD_BACK_COUNT = 8


def r2_version(binary: str) -> str:
    try:
        result = subprocess.run(
            [binary, "-v"], capture_output=True, text=True, timeout=30, check=False
        )
    except OSError:
        return ""
    first = result.stdout.splitlines()[0] if result.stdout else ""
    return first.strip()


def run_r2(binary: str, target: str, command: str, *, analyze: bool, timeout: int) -> str:
    args = [binary, "-e", "scr.color=0", "-e", "scr.utf8=0", "-q"]
    if analyze:
        args.append("-A")
    args.extend(["-c", command, target])
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        raise SystemExit(f"r2 failed for {command!r}: {result.stderr.strip()}")
    return result.stdout


def r2_json(binary: str, target: str, command: str, *, analyze: bool, timeout: int):
    text = run_r2(binary, target, command, analyze=analyze, timeout=timeout)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise SystemExit(f"r2 returned invalid JSON for {command!r}: {exc}") from exc


def capture(target: str, *, r2: str, timeout: int, gdare2_python: str) -> dict:
    info = r2_json(r2, target, "iIj", analyze=False, timeout=timeout)
    entries = r2_json(r2, target, "iej", analyze=False, timeout=timeout)
    entry = int(entries[0]["vaddr"]) if entries else 0
    base = int(info.get("baddr") or 0)
    seek = f"s 0x{entry:x}"
    sections = r2_json(r2, target, "iSj", analyze=False, timeout=timeout)
    functions = r2_json(r2, target, "aflj", analyze=True, timeout=timeout)
    bytes_payload = r2_json(
        r2, target, f"{seek}; pxj {PX_COUNT}", analyze=False, timeout=timeout
    )
    pd = r2_json(r2, target, f"{seek}; pdj {PD_COUNT}", analyze=True, timeout=timeout)
    pdi_text = run_r2(r2, target, f"{seek}; pdi {PD_COUNT}", analyze=True, timeout=timeout)
    pdl_text = run_r2(r2, target, f"{seek}; pdl {PD_COUNT}", analyze=True, timeout=timeout)
    pd_back_text = run_r2(
        r2, target, f"{seek}; pd -{PD_BACK_COUNT}", analyze=True, timeout=timeout
    )

    gdare2_info = _gdare2_info(target, gdare2_python)

    return {
        "meta": {
            "schema": GOLDEN_SCHEMA,
            "r2_version": r2_version(r2),
            "ghidra_version": gdare2_info.get("ghidra_version") or ghidra_version(),
            "language": gdare2_info.get("language", ""),
            "target": str(target),
            "target_sha256": sha256_file(target),
            "captured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "gdare2_version": gdare2_info.get("version", ""),
        },
        "r2": {
            "info": {
                key: info.get(key)
                for key in ("arch", "bits", "endian", "baddr", "binsz", "bintype")
            },
            "entry": entry,
            "base": base,
            "sections": [
                {
                    "name": str(item.get("name") or ""),
                    "vaddr": int(item.get("vaddr") or 0),
                    "size": int(item.get("size") or 0),
                    "perm": str(item.get("perm") or ""),
                }
                for item in sections
            ],
            "functions": [
                {
                    "addr": int(item.get("addr") or 0),
                    "size": int(item.get("size") or 0),
                    "name": str(item.get("name") or ""),
                }
                for item in functions
            ],
            "bytes": bytes(bytes_payload).hex(),
            "pd": [
                {
                    "addr": int(item.get("addr") or 0),
                    "size": int(item.get("size") or 0),
                    "bytes": str(item.get("bytes") or "").lower(),
                    "disasm": str(item.get("disasm") or ""),
                }
                for item in pd
            ],
            "pdi": parse_pdi(pdi_text),
            "pdl_lines": [line for line in pdl_text.splitlines() if line.strip()],
            "pd_back": parse_pdi(pd_back_text),
        },
    }


def _gdare2_info(target: str, python: str) -> dict:
    """Ask gdare2 for the language and Ghidra version with an ephemeral daemon."""
    with tempfile.TemporaryDirectory(prefix="gdare2-golden-") as temporary:
        env = os.environ.copy()
        env["GDARE2_DATA_DIR"] = str(Path(temporary) / "data")
        env["XDG_RUNTIME_DIR"] = str(Path(temporary) / "run")
        env.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "ghidra" / "current"))
        result = subprocess.run(
            [python, "-m", "gdare2", "--ephemeral", "-j", "-qc", "iI", target],
            capture_output=True,
            text=True,
            env=env,
            timeout=1800,
            check=False,
        )
    if result.returncode != 0:
        raise SystemExit(
            "gdare2 could not open the target; pass a working GHIDRA_INSTALL_DIR:\n"
            + result.stderr.strip()
        )
    payload = json.loads(result.stdout)
    if isinstance(payload, list):
        payload = payload[0]
    from gdare2 import __version__

    payload.setdefault("version", __version__)
    return payload


def default_output(target: str) -> Path:
    name = Path(target).name.replace(".", "-")
    return ROOT / "tests" / "golden" / f"{name}.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", help="golden JSON path (default: tests/golden/<name>.json)")
    parser.add_argument("--r2", default=shutil.which("radare2") or "radare2")
    parser.add_argument("--python", default=sys.executable, help="Python used to run gdare2")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()

    if not Path(args.target).is_file():
        parser.error(f"target not found: {args.target}")
    output = Path(args.output) if args.output else default_output(args.target)
    golden = capture(
        args.target,
        r2=args.r2,
        timeout=args.timeout,
        gdare2_python=args.python,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(golden, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
