#!/usr/bin/env python3
"""Import one raw binary per architecture and verify the Ghidra language."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from gdare2.arch_matrix import ARCH_MATRIX, RAW_BYTES
from gdare2d.import_plan import resolve_alias


def validate_aliases() -> list[str]:
    errors = []
    for entry in ARCH_MATRIX:
        try:
            resolved = resolve_alias(entry["arch"], bits=entry["bits"], endian=entry["endian"])
        except Exception as exc:
            errors.append(f"{entry['name']}: alias failed: {exc}")
            continue
        if resolved != entry["language"]:
            errors.append(
                f"{entry['name']}: alias resolved to {resolved}, expected {entry['language']}"
            )
    return errors


def run_matrix(project_dir: Path, project_name: str, *, keep: bool) -> list[dict]:
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "ghidra" / "current"))
    import pyghidra

    if not pyghidra.started():
        pyghidra.start()

    project_dir.mkdir(parents=True, exist_ok=True)
    source = project_dir / "arch-matrix.bin"
    source.write_bytes(RAW_BYTES)
    results: list[dict] = []
    with pyghidra.open_project(project_dir, project_name, create=True) as project:
        for entry in ARCH_MATRIX:
            program_path = f"/{entry['name']}"
            record = {"name": entry["name"], "expected": entry["language"]}
            try:
                data = project.getProjectData()
                existing = data.getFile(program_path)
                if existing is not None:
                    existing.delete()
                loader = (
                    pyghidra.program_loader()
                    .project(project)
                    .source(str(source))
                    .name(program_path)
                    .language(entry["language"])
                )
                with loader.load() as load_results:
                    load_results.save(pyghidra.task_monitor())
                with pyghidra.program_context(project, program_path) as program:
                    actual = str(program.getLanguageID())
                    record.update(
                        {
                            "actual": actual,
                            "ok": actual == entry["language"],
                            "bits": int(program.getLanguage().getLanguageDescription().getSize()),
                            "big_endian": bool(program.getLanguage().isBigEndian()),
                        }
                    )
            except Exception as exc:
                record.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            results.append(record)
    if not keep:
        shutil.rmtree(project_dir, ignore_errors=True)
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", help="project parent directory (default: temporary)")
    parser.add_argument("--project-name", default="arch_matrix")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the temporary project")
    args = parser.parse_args()

    alias_errors = validate_aliases()
    if alias_errors:
        for error in alias_errors:
            print(error, file=sys.stderr)
        return 1

    if args.project:
        project_dir = Path(args.project)
        results = run_matrix(project_dir, args.project_name, keep=True)
    else:
        with tempfile.TemporaryDirectory(prefix="gdare2-arch-") as temporary:
            results = run_matrix(Path(temporary) / "project", args.project_name, keep=args.keep)

    passed = sum(1 for result in results if result.get("ok"))
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        for result in results:
            status = "ok" if result.get("ok") else "FAIL"
            detail = result.get("actual") or result.get("error", "")
            print(f"{status:<4} {result['name']:<12} {detail}")
    print(
        f"{passed}/{len(results)} configurations passed",
        file=sys.stderr if args.json else sys.stdout,
    )
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
