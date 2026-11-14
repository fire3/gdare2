"""Client-side session state and command pipeline."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from gdare2 import cmd, expr, parser, pipe
from gdare2 import filter as grep
from gdare2.client import Client
from gdare2.config import Config
from gdare2.errors import GdarError, RemoteError, UsageError
from gdare2.flags import Flag, FlagStore
from gdare2.fmt.listing import format_addr
from gdare2.jsonutil import dumps
from gdare2.parser import Statement

DEFAULT_BLOCKSIZE = 0x100
MAX_BATCH_TARGETS = 4096
MAX_BACKTICK_DEPTH = 8
_BACKTICK = re.compile(r"`([^`]*)`")
_DOLLAR_SUBST = re.compile(r"\$\(([^()]*)\)")


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
        return self.call_with_meta(op, **args)[0]

    def call_assembler(self, op: str, **args: Any) -> Any:
        return self.call(op, **args)

    def call_with_meta(self, op: str, **args: Any) -> tuple[Any, dict[str, Any]]:
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
        meta = item.get("meta")
        return item.get("result"), meta if isinstance(meta, dict) else {}


class Session:
    def __init__(
        self,
        client: Client,
        info: dict[str, Any],
        config: Config,
        *,
        readonly: bool = True,
        allow_exec: bool = False,
    ) -> None:
        self.client = client
        self.info = info
        self.config = config
        self.readonly = readonly
        self.allow_exec = allow_exec
        self.pointer_size = max(1, int(info.get("bits", 32)) // 8)
        self.seek = int(info.get("entry") or info.get("image_base") or 0)
        self.blocksize = DEFAULT_BLOCKSIZE
        self.max_blocksize = 50 * 1024 * 1024
        self.seek_history: list[int] = []
        self.seek_future: list[int] = []
        self.vars: dict[str, int] = {}
        self.env: dict[str, str] = dict(os.environ)
        self.yank: bytes = b""
        self.text_log: list[tuple[int, str]] = []
        self._log_counter = 0
        self.write_cache: list[dict[str, Any]] = []
        self.last_search: dict[str, Any] | None = None
        self.last_result = 0
        self.last_output: list[str] = []
        self._backtick_depth = 0
        self.json_default = False
        self.failed = False
        self.last_error: GdarError | None = None
        self.quit_requested = False
        self.flag_store = FlagStore()
        self.pf_formats: dict[str, tuple[str, tuple[str, ...]]] = {}
        self.hidden_ranges: list[tuple[int, int]] = []
        self.strings: dict[int, dict[str, Any]] = {}
        self.magic: dict[int, str] = {}
        self.type_comments: dict[int, str] = {}
        self.source_lines: dict[int, str] = {}
        self.type_links: dict[int, str] = {}
        self.no_return_marks: set[int] = set()
        self.project_notes: str = ""
        self.flags_loaded = False
        self.tmp_range: tuple[int, int] | None = None
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
        flag = self.flag_store.get(name)
        if flag is not None:
            return flag.addr
        if name in self._names:
            return self._names[name]
        try:
            value = self.client.call("resolve_name", name=name)
        except RemoteError:
            value = None
        result = int(value) if value is not None else None
        self._names[name] = result
        return result

    def load_flags(self, *, force: bool = False) -> None:
        if self.flags_loaded and not force:
            return
        self.flag_store.clear()
        try:
            symbols = self.call("symbols", limit=10000)
        except GdarError:
            symbols = []
        for item in symbols:
            if not item.get("external"):
                self.flag_store.add(
                    Flag(
                        str(item["name"]),
                        int(item["addr"]),
                        kind=str(item.get("type") or "flag"),
                    )
                )
        try:
            functions = self.call("functions", limit=10000)
        except GdarError:
            functions = []
        for item in functions:
            self.flag_store.add(
                Flag(
                    str(item["name"]),
                    int(item["addr"]),
                    size=int(item.get("size") or 0),
                    kind="fcn",
                )
            )
        self.flags_loaded = True

    def invalidate_flags(self) -> None:
        self.flags_loaded = False
        self.flag_store.clear()

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
        try:
            line = self._expand_backticks(line)
        except GdarError as exc:
            self.failed = True
            self.last_error = exc
            self.stderr(f"ERROR: {exc}")
            return []
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
            self.last_output = produced
            if emit is not None:
                emit(produced)
            if self.quit_requested:
                break
        self.last_output = output
        return output

    def _expand_backticks(self, line: str) -> str:
        """Replace a backtick command with the first line of its output."""
        if "`" not in line and "$(" not in line:
            return line
        if line.count("`") % 2:
            raise UsageError("unterminated backtick substitution")
        if self._backtick_depth >= MAX_BACKTICK_DEPTH:
            raise UsageError("backtick substitution nested too deeply")
        self._backtick_depth += 1
        try:

            def replace_match(match: re.Match[str]) -> str:
                produced = self.run(match.group(1))
                return produced[0].strip() if produced else ""

            line = _DOLLAR_SUBST.sub(replace_match, line)
            return _BACKTICK.sub(replace_match, line)
        finally:
            self._backtick_depth -= 1

    def run_statement(self, statement: Statement) -> list[str]:
        if statement.shell:
            return pipe.run_shell(statement.args)
        lines: list[str] = []
        repeats = max(statement.repeat, 1)
        spec = cmd.lookup(statement.cmd)
        if spec is not None and spec.consumes_repeat:
            repeats = 1
        for _ in range(repeats):
            saved_seek = self.seek
            saved_blocksize = self.blocksize
            saved_range = self.tmp_range
            try:
                if statement.range:
                    start = self.eval(statement.range[0])
                    stop = self.eval(statement.range[1])
                    self.seek = start
                    self.tmp_range = (start, stop)
                elif statement.tmpseek:
                    spec = statement.tmpseek.strip()
                    if spec.startswith("!"):
                        self.blocksize = self.eval(spec[1:].strip())
                    else:
                        self.seek = self.eval(spec)
                lines = self.dispatch(statement)
            finally:
                if statement.range or statement.tmpseek:
                    self.seek = saved_seek
                    self.blocksize = saved_blocksize
                self.tmp_range = saved_range
        return self.postprocess(lines, statement)

    def dispatch(self, statement: Statement) -> list[str]:
        if statement.iterator is not None or statement.iterator_size is not None:
            return self._dispatch_iterator(statement)
        if statement.dot:
            statement = replace(statement, cmd=f".{statement.cmd}", dot=False)
        return self.invoke(statement)

    def invoke(self, statement: Statement) -> list[str]:
        if statement.help:
            spec = cmd.lookup(statement.cmd)
            if spec is None:
                raise cmd.unknown(statement.cmd)
            return cmd.help_for(spec)
        original = cmd.lookup(statement.cmd)
        if original is None:
            raise cmd.unknown(statement.cmd)
        statement = self._maybe_json(statement)
        spec = cmd.lookup(statement.cmd) or original
        return spec.handler(self, statement)

    def _dispatch_iterator(self, statement: Statement) -> list[str]:
        if statement.help:
            spec = cmd.lookup(statement.cmd)
            if spec is None:
                raise cmd.unknown(statement.cmd)
            return cmd.help_for(spec)
        original = cmd.lookup(statement.cmd)
        if original is None:
            raise cmd.unknown(statement.cmd)
        statement = self._maybe_json(statement)
        spec = cmd.lookup(statement.cmd) or original

        sized = statement.iterator_size is not None
        iterator_spec = statement.iterator_size if sized else statement.iterator
        kind, pattern = _parse_iterator(iterator_spec or "")
        targets, target_meta = self._iterator_targets(kind, pattern)
        if not targets:
            return []
        if target_meta.get("truncated"):
            self.stderr(
                f"WARN: iterator truncated at {target_meta.get('limit', MAX_BATCH_TARGETS)} "
                f"of {target_meta.get('total', '?')} targets; narrow the iterator"
            )
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
        if self.config.get_bool("cmd.batch"):
            replies, _meta = self.call_with_meta(
                "batch",
                ops=operations,
                total=int(target_meta.get("total", len(operations))),
            )
        else:
            replies = []
            for operation in operations:
                try:
                    result, operation_meta = self.call_with_meta(
                        operation["op"], **operation["args"]
                    )
                    replies.append({"ok": True, "result": result, "meta": operation_meta})
                except GdarError as exc:
                    replies.append({"ok": False, "error": exc.as_dict()})
        if not isinstance(replies, list) or len(replies) != len(targets):
            raise GdarError("daemon returned an invalid batch response")
        warning = _batch_meta_warning(replies)
        if warning is not None:
            self.stderr(warning)

        lines: list[str] = []
        skipped = 0
        for target, reply in zip(targets, replies, strict=True):
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
                message = str(exc)
                skipped_target = (
                    exc.code == "NOT_FOUND" and "no instruction" in message
                ) or (
                    "Unable to read bytes" in message or "MemoryAccessException" in message
                )
                if skipped_target:
                    # Function/section iterators include PLT thunks and
                    # non-readable blocks; these are expected, not failures.
                    skipped += 1
                    continue
                self.failed = True
                self.last_error = exc
                self.stderr(f"ERROR: {exc}")
        if skipped:
            self.stderr(f"WARN: skipped {skipped} iterator target(s) without readable data")
        return lines

    def _iterator_targets(
        self, kind: str, pattern: str | None
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if kind == "=":
            text = pattern or ""
            tokens = [item for item in text.replace(",", " ").split() if item]
            if not tokens:
                raise UsageError("@@= needs at least one address")
            targets = [
                {"addr": self.eval(token), "size": 0}
                for token in tokens[:MAX_BATCH_TARGETS]
            ]
            return targets, {
                "total": len(tokens),
                "shown": len(targets),
                "truncated": len(tokens) > len(targets),
            }
        if kind.startswith("."):
            path = kind[1:]
            try:
                lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise UsageError(f"cannot read address file {path}: {exc}") from exc
            tokens = [
                line.strip()
                for line in lines
                if line.strip() and not line.strip().startswith("#")
            ]
            targets = [
                {"addr": self.eval(token), "size": 0}
                for token in tokens[:MAX_BATCH_TARGETS]
            ]
            return targets, {
                "total": len(tokens),
                "shown": len(targets),
                "truncated": len(tokens) > len(targets),
            }
        if kind in ("/", "/x", "/p", "/w"):
            from gdare2.cmd.write import parse_hexpairs
            from gdare2.escape import text_bytes

            text = pattern or ""
            if kind in ("/x", "/p"):
                data, mask = parse_hexpairs(text)
            elif kind == "/w":
                order = "utf-16-be" if self.info.get("endian") == "big" else "utf-16-le"
                data, mask = text.encode(order), None
            else:
                data, mask = text_bytes(text), None
            scope = self.config.get_str("search.in")
            if scope == "raw":
                payload, response_meta = self.call_with_meta(
                    "search_raw",
                    data=data,
                    mask=mask,
                    cursor=0,
                    forward=True,
                    limit=MAX_BATCH_TARGETS,
                    offset=0,
                )
            else:
                payload, response_meta = self.call_with_meta(
                    "search",
                    data=data,
                    mask=mask,
                    cursor=0,
                    forward=True,
                    limit=MAX_BATCH_TARGETS,
                    offset=0,
                    scope=scope,
                )
            hits = [{"addr": int(hit), "size": 0} for hit in payload.get("hits", [])]
            meta = response_meta or payload.get("meta") or {}
            return hits, {
                "total": int(meta.get("shown", len(hits))),
                "shown": len(hits),
                "truncated": bool(meta.get("truncated")),
            }
        if kind == "s" and pattern:
            tokens = pattern.split()
            if len(tokens) in (2, 3):
                try:
                    start = self.eval(tokens[0])
                    stop = self.eval(tokens[1])
                    step = self.eval(tokens[2]) if len(tokens) == 3 else 1
                except Exception:
                    pass
                else:
                    if step <= 0:
                        raise UsageError("@@s step must be positive")
                    total = 0 if stop < start else (stop - start) // step + 1
                    targets = [
                        {"addr": address, "size": 0}
                        for address in range(
                            start,
                            min(stop, start + step * (MAX_BATCH_TARGETS - 1)) + 1,
                            step,
                        )
                    ][:MAX_BATCH_TARGETS]
                    return targets, {
                        "total": total,
                        "shown": len(targets),
                        "truncated": total > len(targets),
                    }
        return self.call_with_meta("iter_targets", kind=kind, ea=self.seek, pattern=pattern)

    def _maybe_json(self, statement: Statement) -> Statement:
        if statement.help:
            return statement
        if not self.json_default or statement.cmd.endswith("j"):
            return statement
        if statement.args.strip() and statement.cmd in {
            "b",
            "e",
            "f",
            "T",
            "P",
            "Cs",
            "Cm",
            "Ct",
            "CL",
            "tl",
            "tn",
            "to",
        }:
            return statement
        if statement.cmd.startswith("pf.") and len(statement.cmd) > 3:
            return replace(statement, cmd="pfj" + statement.cmd[2:])
        mapping = {
            "i": "ij",
            "e": "ej",
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
            "tfc": "tfcj",
            "tc": "tcj",
            "afs": "afsj",
            "C": "Cj",
            "pdf": "pdfj",
            "axt": "axtj",
            "axf": "axfj",
            "iS": "iSj",
            "iSS": "iSSj",
            "ih": "ihj",
            "iH": "iHj",
            "il": "ilj",
            "ir": "irj",
            "is": "isj",
            "ii": "iij",
            "iE": "iEj",
            "ia": "iaj",
            "ie": "iej",
            "iz": "izj",
            "izz": "izzj",
            "/": "/j",
            "/x": "/xj",
            "/w": "/wj",
            "/v": "/vj",
            "/v1": "/v1j",
            "/v2": "/v2j",
            "/v4": "/v4j",
            "/v8": "/v8j",
            "x": "xj",
            "f": "fj",
            "pf": "pfj",
            "pj": "pjj",
            "fn": "fnj",
            "b": "bj",
            "p=": "p=j",
            "e*": "e*j",
            "iD": "iDj",
            "iC": "iCj",
            "iV": "iVj",
            "iv": "ivj",
            "iT": "iTj",
            "iee": "ieej",
            "ies": "iesj",
            "Cs": "Csj",
            "Cm": "Cmj",
            "Ct": "Ctj",
            "CL": "CLj",
            "tk": "tkj",
            "tl": "tlj",
            "T": "Tj",
            "P": "Pj",
            "/i": "/ij",
            "/m": "/mj",
            "/d": "/dj",
            "/c": "/cj",
            "/z": "/zj",
            "/R": "/Rj",
        }
        replacement = mapping.get(statement.cmd)
        if replacement is None:
            return statement
        return replace(statement, cmd=replacement)

    def postprocess(self, lines: list[str], statement: Statement) -> list[str]:
        if statement.filter is not None or statement.pipe is not None:
            lines = _split_output_blocks(lines)
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

    def call_with_meta(self, op: str, **args: Any) -> tuple[Any, dict[str, Any]]:
        method = getattr(self.client, "call_with_meta", None)
        if method is not None:
            return method(op, allow_writes=not self.readonly, **args)
        return self.client.call(op, allow_writes=not self.readonly, **args), {}

    def call_assembler(self, op: str, **args: Any) -> Any:
        """Assembler ops may need tens of seconds for the first SLEIGH init."""
        if not hasattr(self.client, "timeout"):
            return self.call(op, **args)
        wanted = float(self.config.get_int("ghidra.assemble.timeout"))
        original = float(self.client.timeout)
        if wanted <= original:
            return self.call(op, **args)
        self.client.timeout = wanted
        try:
            return self.call(op, **args)
        finally:
            self.client.timeout = original

    def commit_write_cache(self) -> None:
        if not self.write_cache:
            return
        patches = list(self.write_cache)
        self.client.call(
            "write_patches",
            allow_writes=not self.readonly,
            patches=patches,
        )
        self.write_cache.clear()

    def log(self, message: str) -> None:
        self._log_counter += 1
        self.text_log.append((self._log_counter, message))

    def stderr(self, text: str) -> None:
        import sys

        print(text, file=sys.stderr)

    def warn_truncated(self, label: str, count: int, limit: int = 10000) -> None:
        if count >= limit:
            self.stderr(f"WARN: {label} truncated at {limit} items; narrow the query")

    def list_args(self, limit: int) -> dict[str, int]:
        """Keyword arguments for a paginated list op (offset only when set)."""
        offset = self.config.get_int("list.offset")
        args = {"limit": limit}
        if offset:
            args["offset"] = offset
        return args

    def warn_list_meta(self, label: str, meta: dict[str, Any] | None) -> None:
        if not meta or not meta.get("truncated"):
            return
        shown = int(meta.get("shown", 0))
        offset = int(meta.get("offset", 0))
        self.stderr(
            f"WARN: {label} truncated at {meta.get('limit')} items "
            f"(total {meta.get('total')}); use --list-offset {offset + shown} to continue"
        )

    def cmd_info_json(self, statement: Statement) -> list[str]:
        return [dumps(self.info)]

    def json(self, value: Any) -> list[str]:
        return [dumps(value)]


def _split_output_blocks(lines: list[str]) -> list[str]:
    """Split multi-line handler output before ``~``/``|`` see it.

    JSON handlers return one string containing newlines.  radare2 filters the
    rendered output line by line, so ``aflj~entry`` must match a single JSON
    line instead of the whole document.
    """
    if not any("\n" in str(line) for line in lines):
        return lines
    output: list[str] = []
    for line in lines:
        text = str(line)
        if "\n" not in text:
            output.append(text)
        else:
            output.extend(text.splitlines())
    return output


def _batch_meta_warning(replies: list[Any]) -> str | None:
    """Summarize per-item truncation metadata returned by a batch request."""
    truncated = []
    for reply in replies:
        if not isinstance(reply, dict):
            continue
        meta = reply.get("meta")
        if isinstance(meta, dict) and meta.get("truncated"):
            truncated.append(meta)
    if not truncated:
        return None
    details = []
    for meta in truncated[:3]:
        shown = meta.get("shown", "?")
        limit = meta.get("limit", "?")
        offset = meta.get("offset", 0)
        details.append(f"shown {shown} at offset {offset} (limit {limit})")
    if len(truncated) > 3:
        details.append(f"and {len(truncated) - 3} more")
    return f"WARN: {len(truncated)} batched item(s) truncated: " + "; ".join(details)


def _parse_iterator(spec: str) -> tuple[str, str | None]:
    text = spec.strip()
    if not text:
        raise UsageError("iterator needs an operand")
    if text.startswith("="):
        return "=", text.lstrip("=").strip()
    if text.startswith("/"):
        kind, separator, pattern = text.partition(" ")
        return kind, pattern.strip() if separator else None
    kind, separator, pattern = text.partition(":")
    return kind, pattern if separator else None
