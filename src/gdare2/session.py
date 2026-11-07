"""Client-side session state and command pipeline."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from gdare2 import cmd, expr, parser, pipe
from gdare2 import filter as grep
from gdare2.client import Client
from gdare2.config import Config
from gdare2.errors import GdarError, RemoteError, UsageError
from gdare2.fmt.listing import format_addr
from gdare2.jsonutil import dumps
from gdare2.parser import Statement

DEFAULT_BLOCKSIZE = 0x100


class Session:
    def __init__(
        self,
        client: Client,
        info: dict[str, Any],
        config: Config,
        *,
        readonly: bool = True,
    ) -> None:
        self.client = client
        self.info = info
        self.config = config
        self.readonly = readonly
        self.pointer_size = max(1, int(info.get("bits", 32)) // 8)
        self.seek = int(info.get("entry") or info.get("image_base") or 0)
        self.blocksize = DEFAULT_BLOCKSIZE
        self.seek_history: list[int] = []
        self.seek_future: list[int] = []
        self.vars: dict[str, int] = {}
        self.last_result = 0
        self.last_output: list[str] = []
        self.json_default = False
        self.failed = False
        self.last_error: GdarError | None = None
        self.quit_requested = False
        self._names: dict[str, int | None] = {}
        self.setup()

    def setup(self) -> None:
        self.config.reflect("asm.arch", self.info.get("arch") or "unknown")
        self.config.reflect("asm.bits", int(self.info.get("bits") or 0))
        self.config.reflect("cfg.bigendian", self.info.get("endian") == "big")
        self.config.reflect("ghidra.version", self.info.get("ghidra_version", ""))
        self.config.reflect("ghidra.language", self.info.get("language", ""))
        self.config.reflect("ghidra.compiler", self.info.get("compiler", ""))
        self.config.reflect("ghidra.program", self.info.get("program", ""))
        self.config.reflect("ghidra.project", self.info.get("project", ""))

    # -- Resolver protocol -------------------------------------------------
    def lookup_name(self, name: str) -> int | None:
        if name in self._names:
            return self._names[name]
        try:
            value = self.client.call("resolve_name", name=name)
        except RemoteError:
            value = None
        result = int(value) if value is not None else None
        self._names[name] = result
        return result

    def get_var(self, name: str) -> int | None:
        if name in self.vars:
            return self.vars[name]
        builtins = {
            "": self.seek,
            "b": self.blocksize,
            "l": self.seek_history[-1] if self.seek_history else self.seek,
            "s": int(self.info.get("filesize") or 0),
            "B": int(self.info.get("image_base") or 0),
            "e": int(self.info.get("entry") or 0),
            "M": self.seek,
            "o": self.seek,
            "?": self.last_result,
        }
        return builtins.get(name)

    def deref(self, address: int, size: int) -> int:
        payload = self.client.call("read_value", ea=address, width=size)
        return int(payload["value"])

    def eval(self, text: str) -> int:
        value = expr.evaluate(text, self)
        self.last_result = value
        return value

    def resolve(self, text: str | None, *, default: int | None = None) -> int:
        if text is None or not text.strip():
            return self.seek if default is None else default
        return self.eval(text.strip())

    # -- execution ---------------------------------------------------------
    def seek_to(self, address: int) -> None:
        if address != self.seek:
            self.seek_history.append(self.seek)
            self.seek_future.clear()
        self.seek = address
        self.last_result = address

    def run(self, line: str, emit: Callable[[list[str]], None] | None = None) -> list[str]:
        output: list[str] = []
        for statement in parser.parse(line):
            try:
                produced = self.run_statement(statement)
            except GdarError as exc:
                self.failed = True
                self.last_error = exc
                self.stderr(f"ERROR: {exc}")
                continue
            output.extend(produced)
            if emit is not None:
                emit(produced)
            if self.quit_requested:
                break
        self.last_output = output
        return output

    def run_statement(self, statement: Statement) -> list[str]:
        if statement.shell:
            return pipe.run_shell(statement.args)
        lines: list[str] = []
        for _ in range(max(statement.repeat, 1)):
            saved = self.seek
            try:
                if statement.tmpseek:
                    self.seek = self.eval(statement.tmpseek)
                lines = self.dispatch(statement)
            finally:
                if statement.tmpseek:
                    self.seek = saved
        return self.postprocess(lines, statement)

    def dispatch(self, statement: Statement) -> list[str]:
        if statement.iterator is not None or statement.iterator_size is not None:
            raise UsageError("@@ iterators are not implemented yet")
        if statement.dot:
            if statement.cmd == "g":
                return self.cmd_info_json(statement)
            raise UsageError(f"unsupported dot command .{statement.cmd}")
        return self.invoke(statement)

    def invoke(self, statement: Statement) -> list[str]:
        spec = cmd.lookup(statement.cmd)
        if spec is None:
            raise cmd.unknown(statement.cmd)
        if statement.help:
            return cmd.help_for(spec)
        statement = self._maybe_json(statement)
        return spec.handler(self, statement)

    def _maybe_json(self, statement: Statement) -> Statement:
        if not self.json_default or statement.cmd.endswith("j"):
            return statement
        mapping = {
            "iI": "iIj",
            "afl": "aflj",
            "afi": "afij",
            "pdf": "pdfj",
            "axt": "axtj",
            "axf": "axfj",
            "iS": "iSj",
            "is": "isj",
            "ii": "iij",
            "ie": "iej",
            "iz": "izj",
        }
        replacement = mapping.get(statement.cmd)
        if replacement is None:
            return statement
        return replace(statement, cmd=replacement)

    def postprocess(self, lines: list[str], statement: Statement) -> list[str]:
        if statement.filter is not None:
            lines = grep.apply_spec(lines, statement.filter)
        if statement.pipe is not None:
            lines = pipe.run_pipe(lines, statement.pipe)
        if statement.redirect is not None:
            pipe.redirect(lines, statement.redirect, append=statement.append)
            return []
        if self.config.get_bool("scr.null"):
            return []
        return lines

    # -- helpers -----------------------------------------------------------
    def format_addr(self, address: int) -> str:
        return format_addr(address, int(self.info.get("bits") or 32))

    def call(self, op: str, **args: Any) -> Any:
        return self.client.call(op, allow_writes=not self.readonly, **args)

    def stderr(self, text: str) -> None:
        import sys

        print(text, file=sys.stderr)

    def cmd_info_json(self, statement: Statement) -> list[str]:
        return [dumps(self.info)]

    def json(self, value: Any) -> list[str]:
        return [dumps(value)]
