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
MAX_BATCH_TARGETS = 4096


class _ProbeStop(Exception):
    """Interrupt a command probe as soon as its first daemon op is known."""


class _BatchSession:
    """A Session-shaped view used while replaying one batched target."""

    def __init__(
        self,
        parent: Session,
        *,
        seek: int | None = None,
        blocksize: int | None = None,
        calls: list[tuple[str, dict[str, Any]]] | None = None,
        responses: list[dict[str, Any]] | None = None,
    ) -> None:
        self._parent = parent
        self.seek = parent.seek if seek is None else seek
        self.blocksize = parent.blocksize if blocksize is None else blocksize
        self._calls = calls if calls is not None else []
        self._responses = responses

    def __getattr__(self, name: str) -> Any:
        return getattr(self._parent, name)

    def get_var(self, name: str) -> int | None:
        builtins = {
            "": self.seek,
            "b": self.blocksize,
            "l": self._parent.seek_history[-1]
            if self._parent.seek_history
            else self.seek,
            "s": int(self._parent.info.get("filesize") or 0),
            "B": int(self._parent.info.get("image_base") or 0),
            "e": int(self._parent.info.get("entry") or 0),
            "M": self.seek,
            "o": self.seek,
            "?": self._parent.last_result,
        }
        if name in self._parent.vars:
            return self._parent.vars[name]
        return builtins.get(name)

    def eval(self, text: str) -> int:
        value = expr.evaluate(text, self)
        self._parent.last_result = value
        return value

    def resolve(self, text: str | None, *, default: int | None = None) -> int:
        if text is None or not text.strip():
            return self.seek if default is None else default
        return self.eval(text.strip())

    def call(self, op: str, **args: Any) -> Any:
        if self._responses is None:
            self._calls.append((op, dict(args)))
            raise _ProbeStop
        if not self._responses:
            raise GdarError(f"batched command made an unexpected extra {op} call")
        item = self._responses.pop(0)
        if not item.get("ok"):
            error = item.get("error") or {}
            raise RemoteError(
                str(error.get("code", "INTERNAL")),
                str(error.get("message", "batched op failed")),
                data=error.get("data"),
            )
        return item.get("result")


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
            return self._dispatch_iterator(statement)
        if statement.dot:
            statement = replace(statement, cmd=f".{statement.cmd}", dot=False)
        return self.invoke(statement)

    def invoke(self, statement: Statement) -> list[str]:
        spec = cmd.lookup(statement.cmd)
        if spec is None:
            raise cmd.unknown(statement.cmd)
        if statement.help:
            return cmd.help_for(spec)
        statement = self._maybe_json(statement)
        return spec.handler(self, statement)

    def _dispatch_iterator(self, statement: Statement) -> list[str]:
        spec = cmd.lookup(statement.cmd)
        if spec is None:
            raise cmd.unknown(statement.cmd)
        if statement.help:
            return cmd.help_for(spec)
        statement = self._maybe_json(statement)

        sized = statement.iterator_size is not None
        iterator_spec = statement.iterator_size if sized else statement.iterator
        kind, pattern = _parse_iterator(iterator_spec or "")
        targets = self._iterator_targets(kind, pattern)
        if not targets:
            return []
        if len(targets) > MAX_BATCH_TARGETS:
            raise UsageError(f"iterator is limited to {MAX_BATCH_TARGETS} targets")

        probe = _BatchSession(self)
        try:
            spec.handler(probe, statement)
        except _ProbeStop:
            pass
        else:
            raise UsageError(f"{statement.cmd!r} cannot be used with @@ iteration")
        if len(probe._calls) != 1:
            raise UsageError(
                f"{statement.cmd!r} makes {len(probe._calls)} daemon calls; "
                "@@ iteration currently requires exactly one"
            )
        op_name, op_args = probe._calls[0]
        if "ea" not in op_args:
            raise UsageError(f"{statement.cmd!r} does not accept an address for @@ iteration")

        operations = []
        for target in targets:
            args = dict(op_args)
            args["ea"] = int(target["addr"])
            target_size = int(target.get("size") or 0)
            if sized and target_size > 0 and not statement.args.strip() and "size" in args:
                args["size"] = target_size
            operations.append({"op": op_name, "args": args})
        replies = self.call("batch", ops=operations)
        if not isinstance(replies, list) or len(replies) != len(targets):
            raise GdarError("daemon returned an invalid batch response")

        lines: list[str] = []
        for target, reply in zip(targets, replies):
            blocksize = self.blocksize
            if sized and int(target.get("size") or 0) > 0:
                blocksize = int(target["size"])
            view = _BatchSession(
                self,
                seek=int(target["addr"]),
                blocksize=blocksize,
                responses=[reply],
            )
            try:
                lines.extend(spec.handler(view, statement))
            except GdarError as exc:
                self.failed = True
                self.last_error = exc
                self.stderr(f"ERROR: {exc}")
        return lines

    def _iterator_targets(self, kind: str, pattern: str | None) -> list[dict[str, Any]]:
        if kind == "=":
            text = pattern or ""
            tokens = [item for item in text.replace(",", " ").split() if item]
            if not tokens:
                raise UsageError("@@= needs at least one address")
            return [{"addr": self.eval(token), "size": 0} for token in tokens]
        return self.call("iter_targets", kind=kind, ea=self.seek, pattern=pattern)

    def _maybe_json(self, statement: Statement) -> Statement:
        if not self.json_default or statement.cmd.endswith("j"):
            return statement
        mapping = {
            "iI": "iIj",
            "it": "itj",
            "pd": "pdj",
            "p8": "p8j",
            "pv": "pvj",
            "afl": "aflj",
            "afc": "afcj",
            "afC": "afCj",
            "afx": "afxj",
            "afi": "afij",
            "afb": "afbj",
            "ab": "abj",
            "ao": "aoj",
            "ai": "aij",
            "agf": "agfj",
            "pdc": "pdcj",
            "afv": "afvj",
            "t": "tj",
            "ts": "tsj",
            "tu": "tuj",
            "te": "tej",
            "tt": "ttj",
            "tf": "tfj",
            "C": "Cj",
            "pdf": "pdfj",
            "axt": "axtj",
            "axf": "axfj",
            "iS": "iSj",
            "iSS": "iSSj",
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

    def warn_truncated(self, label: str, count: int, limit: int = 10000) -> None:
        if count >= limit:
            self.stderr(f"WARN: {label} truncated at {limit} items; narrow the query")

    def cmd_info_json(self, statement: Statement) -> list[str]:
        return [dumps(self.info)]

    def json(self, value: Any) -> list[str]:
        return [dumps(value)]


def _parse_iterator(spec: str) -> tuple[str, str | None]:
    text = spec.strip()
    if not text:
        raise UsageError("iterator needs an operand")
    if text.startswith("="):
        return "=", text.lstrip("=").strip()
    kind, separator, pattern = text.partition(":")
    return kind, pattern if separator else None
