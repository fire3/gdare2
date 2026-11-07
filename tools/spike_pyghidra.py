#!/usr/bin/env python3
"""P0 spike: exercise the PyGhidra APIs gdare2 depends on.

Usage:
    python tools/spike_pyghidra.py /bin/ls [--project DIR] [--no-analyze]

The script opens a persistent project, imports the target, runs auto analysis,
prints basic program facts, and decompiles the entry point or ``main``.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--project", default="/tmp/gdare2-p0")
    parser.add_argument("--project-name", default="p0")
    parser.add_argument("--no-analyze", action="store_true")
    parser.add_argument("--reimport", action="store_true")
    args = parser.parse_args()

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "ghidra" / "current"))
    import pyghidra

    t0 = time.monotonic()
    pyghidra.start()
    print(f"start: {time.monotonic() - t0:.2f}s")

    project_dir = Path(args.project)
    project_dir.mkdir(parents=True, exist_ok=True)
    program_path = "/" + Path(args.target).name

    with pyghidra.open_project(project_dir, args.project_name, create=True) as project:
        existing = _project_file(project, program_path)
        t1 = time.monotonic()
        if existing is None or args.reimport:
            loader = pyghidra.program_loader().project(project).source(args.target).name(program_path)
            with loader.load() as results:
                results.save(pyghidra.task_monitor())
            print(f"import: {time.monotonic() - t1:.2f}s")
        else:
            print("import: reused existing program")

        analysis_log = ""
        with pyghidra.program_context(project, program_path) as program:
            should_analyze = not args.no_analyze and (existing is None or args.reimport)
            if should_analyze:
                t2 = time.monotonic()
                analysis_log = pyghidra.analyze(program)
                program.save("gdare2 P0 analysis", pyghidra.task_monitor())
                print(f"analysis: {time.monotonic() - t2:.2f}s")
            elif existing is not None and not args.no_analyze:
                print("analysis: reused existing program")

            fm = program.getFunctionManager()
            functions = list(fm.getFunctions(True))
            print(f"name: {program.getName()}")
            print(f"language: {program.getLanguageID()}")
            print(f"compiler: {program.getCompilerSpec().getCompilerSpecID()}")
            print(f"image-base: 0x{program.getImageBase().getOffset():x}")
            print(f"functions: {len(functions)}")
            for function in functions[:5]:
                print(f"  {function.getEntryPoint()} {function.getName()}")

            target = _find_main(program, functions)
            if target is not None:
                _decompile(program, target)
            if analysis_log:
                lines = analysis_log.splitlines()
                print(f"analysis-log-lines: {len(lines)}")

        print(f"total: {time.monotonic() - t0:.2f}s")
    return 0


def _project_file(project, path: str):
    try:
        return project.getProjectData().getFile(path)
    except Exception:
        return None


def _find_main(program, functions):
    for function in functions:
        if function.getName() == "main":
            return function
    entries = program.getSymbolTable().getExternalEntryPointIterator()
    for entry in entries:
        function = program.getFunctionManager().getFunctionAt(entry)
        if function is not None:
            return function
    return functions[0] if functions else None


def _decompile(program, function) -> None:
    import pyghidra

    from ghidra.app.decompiler import DecompInterface

    interface = DecompInterface()
    interface.openProgram(program)
    t = time.monotonic()
    results = interface.decompileFunction(function, 30, pyghidra.task_monitor())
    print(f"decompile: {time.monotonic() - t:.2f}s")
    if results.decompileCompleted():
        text = results.getDecompiledFunction().getC()
        print("--- decompile ---")
        print("\n".join(text.splitlines()[:20]))
    else:
        print(f"decompile-error: {results.getErrorMessage()}")
    interface.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
