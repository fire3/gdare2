"""PyGhidra project/program lifecycle, confined to the executor thread."""

from __future__ import annotations

import logging
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from gdare2.errors import DecompileError, GdarError
from gdare2d.import_plan import ImportPlan

log = logging.getLogger("gdare2d.runtime")


class GhidraRuntime:
    def __init__(
        self,
        *,
        target: str,
        project_dir: str,
        project_name: str,
        program_path: str,
        plan: ImportPlan,
        analyze: bool = True,
        reanalyze: bool = False,
        reimport: bool = False,
        readonly: bool = True,
        save_on_close: bool = True,
        ephemeral: bool = False,
        ghidra_install: str | None = None,
    ) -> None:
        self.target = target
        self.project_dir = Path(project_dir)
        self.project_name = project_name
        self.program_path = program_path
        self.plan = plan
        self.analyze_program = analyze
        self.reanalyze = reanalyze
        self.reimport = reimport
        self.readonly = readonly
        self.save_on_close = save_on_close
        self.ephemeral = ephemeral
        self.ghidra_install = ghidra_install
        self.state = "starting"
        self.error: str | None = None
        self.project = None
        self.program = None
        self._consumer = None
        self._decompiler = None
        self._pyghidra = None
        self.summary: dict[str, Any] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self._sessions_lock = threading.Lock()
        self.write_undo: list[dict[str, Any]] = []
        self.write_redo: list[dict[str, Any]] = []

    def open(self) -> None:
        started = time.monotonic()
        try:
            import pyghidra

            self._pyghidra = pyghidra
            self.state = "loading_project"
            if not pyghidra.started():
                kwargs = {"install_dir": Path(self.ghidra_install)} if self.ghidra_install else {}
                pyghidra.start(**kwargs)
            self.project = pyghidra.open_project(self.project_dir, self.project_name, create=True)

            existing = self._find_program()
            if existing is not None and self.reimport:
                existing.delete()
                existing = None
            if existing is None:
                self.state = "importing"
                self._import()
            elif self.reanalyze:
                self.state = "analyzing"
                self._open_program()
                self._run_analysis(force=True)
            else:
                self._open_program()

            if existing is None and self.analyze_program:
                self.state = "analyzing"
                self._run_analysis(force=False)
                if self.plan.raw:
                    self._disassemble_raw_if_needed()
            if self.program is None:
                self._open_program()
            self.summary = self._build_summary()
            self.summary["startup_seconds"] = round(time.monotonic() - started, 3)
            self.state = "ready"
            log.info("program ready in %.2fs: %s", time.monotonic() - started, self.summary)
        except Exception as exc:  # keep the daemon alive so /health can report the failure
            self.state = "error"
            self.error = f"{type(exc).__name__}: {exc}"
            log.exception("failed to open program")
            raise

    def _find_program(self):
        data = self.project.getProjectData()
        return data.getFile(self.program_path)

    def _import(self) -> None:
        loader = (
            self._pyghidra.program_loader()
            .project(self.project)
            .source(self.target)
            .name(self.program_path)
        )
        if self.plan.language:
            loader = loader.language(self.plan.language)
        if self.plan.compiler:
            loader = loader.compiler(self.plan.compiler)
        if self.plan.loader:
            loader = loader.loaders(self.plan.loader)
        for key, value in self.plan.loader_args:
            loader = loader.addLoaderArg(key, value)
        with loader.load() as results:
            results.save(self._pyghidra.task_monitor())
        self._open_program()

    def _open_program(self) -> None:
        if self.program is not None:
            return
        self.program, self._consumer = self._pyghidra.consume_program(
            self.project, self.program_path
        )

    def _run_analysis(self, *, force: bool) -> None:
        from ghidra.program.util.GhidraProgramUtilities import shouldAskToAnalyze

        assert self.program is not None
        if not force and not shouldAskToAnalyze(self.program):
            log.info("program already analyzed")
            return
        started = time.monotonic()
        self._pyghidra.analyze(self.program)
        self.program.save("gdare2 analysis", self._pyghidra.task_monitor())
        log.info("analysis finished in %.2fs", time.monotonic() - started)

    def analyze(self, *, force: bool = False) -> dict[str, Any]:
        assert self.program is not None
        before = self.program.getModificationNumber()
        self._run_analysis(force=force)
        after = self.program.getModificationNumber()
        changed = after != before
        if changed:
            self.program.save("gdare2 analysis", self._pyghidra.task_monitor())
        self.summary = self._build_summary()
        return {"state": "analyzed" if changed else "unchanged", "modification": int(after)}

    def _disassemble_raw_if_needed(self) -> None:
        assert self.program is not None
        listing = self.program.getListing()
        if listing.getInstructionAt(self.program.getMinAddress()) is not None:
            return
        from ghidra.app.cmd.disassemble import DisassembleCommand

        command = DisassembleCommand(self.program.getMinAddress(), None, True)
        with self._pyghidra.transaction(self.program, "gdare2 raw disassembly"):
            command.applyTo(self.program, self._pyghidra.task_monitor())
        self.program.save("gdare2 raw disassembly", self._pyghidra.task_monitor())

    def save(self) -> None:
        assert self.program is not None
        self.program.save("gdare2 save", self._pyghidra.task_monitor())

    def record_write(self, address: int, before: bytes, after: bytes) -> None:
        self.record_writes([(address, before, after)])

    def record_writes(self, segments: list[tuple[int, bytes, bytes]]) -> None:
        writes = [
            {"addr": int(address), "before": bytes(before), "after": bytes(after)}
            for address, before, after in segments
            if before != after
        ]
        if not writes:
            return
        self.write_undo.append({"writes": writes})
        if len(self.write_undo) > 4096:
            self.write_undo.pop(0)
        self.write_redo.clear()

    def undo_write(self) -> dict[str, Any]:
        if not self.write_undo:
            raise GdarError("no byte writes to undo")
        assert self.program is not None
        entry = self.write_undo.pop()
        for item in reversed(entry["writes"]):
            self._write_memory(item["addr"], item["before"])
        self.write_redo.append(entry)
        return self._write_result(entry, "before")

    def redo_write(self) -> dict[str, Any]:
        if not self.write_redo:
            raise GdarError("no byte writes to redo")
        assert self.program is not None
        entry = self.write_redo.pop()
        for item in entry["writes"]:
            self._write_memory(item["addr"], item["after"])
        self.write_undo.append(entry)
        return self._write_result(entry, "after")

    def _write_memory(self, address: int, data: bytes) -> None:
        space = self.program.getAddressFactory().getDefaultAddressSpace()
        start = space.getAddress(int(address))
        end = space.getAddress(int(address) + len(data) - 1)
        self.program.getListing().clearCodeUnits(start, end, False)
        self.program.getMemory().setBytes(start, data)

    @staticmethod
    def _write_result(entry: dict[str, Any], field: str) -> dict[str, Any]:
        writes = entry["writes"]
        return {
            "addr": int(writes[0]["addr"]),
            "size": sum(len(item[field]) for item in writes),
            "segments": len(writes),
        }

    def decompile(self, function, timeout: int = 30):
        assert self.program is not None
        if self._decompiler is None:
            from ghidra.app.decompiler import DecompInterface

            interface = DecompInterface()
            interface.setSimplificationStyle("decompile")
            if not interface.openProgram(self.program):
                interface.dispose()
                raise DecompileError("failed to open program in the Ghidra decompiler")
            self._decompiler = interface
        results = self._decompiler.decompileFunction(
            function,
            max(1, int(timeout)),
            self._pyghidra.task_monitor(),
        )
        if results is None or not results.decompileCompleted():
            message = "decompilation did not complete"
            if results is not None and results.getErrorMessage():
                message = str(results.getErrorMessage())
            raise DecompileError(message)
        return results

    def close(self) -> None:
        self.state = "draining"
        try:
            if self.program is not None:
                if self.save_on_close and not self.readonly:
                    self.program.save("gdare2 close", self._pyghidra.task_monitor())
                if self._decompiler is not None:
                    self._decompiler.dispose()
                    self._decompiler = None
                if self._consumer is not None:
                    self.program.release(self._consumer)
                self.program = None
            if self.project is not None:
                self.project.close()
                self.project = None
        finally:
            self.state = "closed"
            if self.ephemeral:
                shutil.rmtree(self.project_dir, ignore_errors=True)

    def _build_summary(self) -> dict[str, Any]:
        program = self.program
        assert program is not None
        language_id = str(program.getLanguageID())
        parts = language_id.split(":")
        arch = parts[0] if parts else "unknown"
        bits = _language_bits(program, parts)
        endian = "big" if program.getLanguage().isBigEndian() else "little"
        entry = self._entry_point(program)
        target = Path(self.target)
        try:
            filesize = target.stat().st_size
        except OSError:
            filesize = 0
        try:
            ghidra_version = str(__import__("ghidra.framework.Application", fromlist=["Application"]).getApplicationVersion())
        except Exception:
            ghidra_version = "unknown"
        image_base = int(program.getImageBase().getOffset())
        min_addr = int(program.getMinAddress().getOffset())
        if image_base == 0 and min_addr != 0:
            image_base = min_addr
        return {
            "target": str(target),
            "program": program.getName(),
            "project": self.project_name,
            "project_dir": str(self.project_dir),
            "language": language_id,
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "arch": arch,
            "bits": bits,
            "endian": endian,
            "image_base": image_base,
            "min_addr": min_addr,
            "max_addr": int(program.getMaxAddress().getOffset()),
            "entry": entry,
            "function_count": int(program.getFunctionManager().getFunctionCount()),
            "filesize": filesize,
            "format": str(program.getExecutableFormat() or ""),
            "ghidra_version": ghidra_version,
            "readonly": self.readonly,
        }

    def session_open(self, *, pid: int, kind: str, tty: bool, ttl: int) -> str:
        import secrets

        lease = secrets.token_hex(8)
        with self._sessions_lock:
            self._purge_sessions()
            self.sessions[lease] = {
                "lease": lease,
                "pid": int(pid),
                "kind": str(kind),
                "tty": bool(tty),
                "last_seen": time.time(),
                "expires": time.time() + max(10, int(ttl)),
            }
        return lease

    def session_heartbeat(self, lease: str, ttl: int) -> bool:
        with self._sessions_lock:
            self._purge_sessions()
            entry = self.sessions.get(lease)
            if entry is None:
                return False
            entry["last_seen"] = time.time()
            entry["expires"] = time.time() + max(10, int(ttl))
            return True

    def session_close(self, lease: str) -> bool:
        with self._sessions_lock:
            return self.sessions.pop(lease, None) is not None

    def session_list(self) -> list[dict[str, Any]]:
        with self._sessions_lock:
            self._purge_sessions()
            return [dict(entry) for entry in self.sessions.values()]

    def has_active_sessions(self) -> bool:
        with self._sessions_lock:
            self._purge_sessions()
            return bool(self.sessions)

    def _purge_sessions(self) -> None:
        now = time.time()
        for lease in [key for key, entry in self.sessions.items() if entry["expires"] < now]:
            self.sessions.pop(lease, None)

    @staticmethod
    def _entry_point(program) -> int:
        symbol_table = program.getSymbolTable()
        for name in ("entry", "_start"):
            try:
                for symbol in symbol_table.getSymbols(name):
                    address = symbol.getAddress()
                    if address is not None and not symbol.isExternal():
                        return int(address.getOffset())
            except Exception:
                pass
        try:
            memory = program.getMemory()
            iterator = symbol_table.getExternalEntryPointIterator()
            for address in iterator:
                block = memory.getBlock(address)
                if block is not None and block.isExecute():
                    return int(address.getOffset())
        except Exception:
            pass
        try:
            return int(program.getMinAddress().getOffset())
        except Exception:
            return 0


def _language_bits(program, parts: list[str]) -> int:
    if len(parts) > 2:
        try:
            return int(parts[2])
        except ValueError:
            pass
    try:
        return int(program.getLanguage().getLanguageDescription().getSize())
    except Exception:
        return 0
