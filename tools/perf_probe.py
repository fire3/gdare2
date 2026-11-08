#!/usr/bin/env python3
"""Record a repeatable performance baseline for gdare2.

Measures the cold open (import + auto-analysis) and warm command latency over
a persistent temporary daemon.  The JSON output is committed as
``docs/perf-baseline.json`` and is informative only: it is not a pass/fail test.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gdare2.parity import ghidra_version, r2_version, sha256_file  # noqa: E402

WARM_COMMANDS = {
    "info": "iI",
    "afl": "afl",
    "symbols": "is",
    "pd100": "pd 100",
    "pdc": "pdc",
}


def _run(env: dict, python: str, args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [python, "-m", "gdare2", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


def _measure(env: dict, python: str, command: str, *, timeout: int) -> float:
    started = time.perf_counter()
    result = _run(env, python, ["-qc", command, env["_TARGET"]], timeout)
    elapsed = time.perf_counter() - started
    if result.returncode != 0:
        raise SystemExit(f"command failed: {command}\n{result.stderr.strip()}")
    return elapsed


def probe(target: str, *, python: str, repeat: int, timeout: int) -> dict:
    temporary = Path(tempfile.mkdtemp(prefix="gdare2-perf-"))
    env = os.environ.copy()
    env["GDARE2_DATA_DIR"] = str(temporary / "data")
    env["XDG_RUNTIME_DIR"] = str(temporary / "run")
    env["HOME"] = str(temporary / "home")
    env["XDG_CONFIG_HOME"] = str(temporary / "config")
    env["XDG_STATE_HOME"] = str(temporary / "state")
    env.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "ghidra" / "current"))
    env["_TARGET"] = str(target)
    try:
        cold = _measure(env, python, "iI", timeout=timeout)
        info_result = _run(env, python, ["-j", "-qc", "iI", str(target)], timeout)
        info = json.loads(info_result.stdout)
        if isinstance(info, list):
            info = info[0]
        entry = int(info["entry"])

        warm: dict[str, dict[str, float]] = {}
        for name, command in WARM_COMMANDS.items():
            if name == "pdc":
                command = f"s 0x{entry:x}; pdc"
            samples = [_measure(env, python, command, timeout=timeout) for _ in range(repeat)]
            warm[name] = {
                "min_ms": round(min(samples) * 1000, 2),
                "median_ms": round(statistics.median(samples) * 1000, 2),
                "max_ms": round(max(samples) * 1000, 2),
            }
        return {
            "target": str(target),
            "target_sha256": sha256_file(target),
            "language": info.get("language"),
            "functions": info.get("function_count"),
            "cold_open_ms": round(cold * 1000, 2),
            "warm": warm,
            "samples": repeat,
        }
    finally:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            _run(env, python, ["-qc", ".gclose", str(target)], timeout)
        shutil.rmtree(temporary, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="+")
    parser.add_argument("--output", default=str(ROOT / "docs" / "perf-baseline.json"))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--json", action="store_true", help="print instead of writing")
    args = parser.parse_args()

    payload = {
        "captured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "r2_version": r2_version(),
        "ghidra_version": ghidra_version(),
        "samples_per_command": args.repeat,
        "targets": [],
    }
    for target in args.target:
        if not Path(target).is_file():
            parser.error(f"target not found: {target}")
        record = probe(target, python=args.python, repeat=args.repeat, timeout=args.timeout)
        payload["targets"].append(record)
        print(f"{target}: cold {record['cold_open_ms']} ms", file=sys.stderr)

    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json:
        sys.stdout.write(text)
    else:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"wrote {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
