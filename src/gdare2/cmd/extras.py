"""Yank buffer, environment, pointer, compare, text log and session projects."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from gdare2.cmd import command, require_write
from gdare2.errors import NotFoundError, UnsupportedError, UsageError
from gdare2.flags import DEFAULT_SPACE, Flag
from gdare2.jsonutil import dumps

PROJECT_SUFFIX = ".gdare2-prj"


# -- yank ------------------------------------------------------------------
@command(
    "y",
    "yank bytes, hexpairs, text or a file",
    detail=(
        "yy pastes the clipboard; yx sets hexpairs; yt sets text; yf reads a file;"
        " y- clears it; yj prints the buffer as JSON; y* prints a replayable yx line;"
        " yp pastes and prints hexpairs; yq pastes quietly; ys/yw yank NUL-terminated"
        " narrow/wide (UTF-16) strings; yz keeps the trailing NUL"
    ),
    aliases=(
        "yy",
        "y-",
        "yx",
        "yt",
        "yf",
        "yj",
        "y*",
        "yp",
        "yq",
        "ys",
        "yw",
        "yz",
        "y!",
    ),
)
def _yank(session, statement):
    token = statement.cmd
    argument = statement.args.strip()
    if token == "yy":
        return _paste(session)
    if token == "y-":
        session.yank = b""
        return []
    if token == "yx":
        if not argument:
            raise UsageError("yx needs hexpairs")
        try:
            session.yank = bytes.fromhex(argument.replace(" ", ""))
        except ValueError:
            raise UsageError(f"yx: not a hexpair string: {argument!r}") from None
        return []
    if token == "yt":
        session.yank = argument.encode("utf-8")
        return []
    if token == "yf":
        if not argument:
            raise UsageError("yf needs a file")
        try:
            session.yank = Path(argument).expanduser().read_bytes()
        except OSError as exc:
            raise UsageError(f"cannot read {argument}: {exc}") from exc
        return []
    if token == "yj":
        data = bytes(session.yank)
        return [dumps({"length": len(data), "bytes": data.hex()})]
    if token == "y*":
        data = bytes(session.yank)
        return [f"yx {data.hex()}"] if data else []
    if token == "yp":
        return [_paste_data(session).hex()]
    if token == "yq":
        return _paste(session, echo=False)
    if token == "y!":
        raise UnsupportedError(
            "y! needs an external clipboard integration; use yt/yx/yf to fill the buffer"
        )
    if token == "ys":
        raw = bytes(
            session.call("read_bytes", ea=session.seek, size=_yank_length(session, argument))
        )
        session.yank = raw.split(b"\x00", 1)[0].decode("latin-1").encode("latin-1")
        return [f"-- yanked {len(session.yank)} byte(s) --"]
    if token == "yw":
        raw = bytes(
            session.call("read_bytes", ea=session.seek, size=_yank_length(session, argument))
        )
        codec = "utf-16-be" if session.info.get("endian") == "big" else "utf-16-le"
        raw = raw[: len(raw) - len(raw) % 2]
        session.yank = raw.decode(codec, errors="replace").split("\x00", 1)[0].encode(codec)
        return [f"-- yanked {len(session.yank)} byte(s) --"]
    if token == "yz":
        session.yank = bytes(
            session.call("read_bytes", ea=session.seek, size=_yank_length(session, argument))
        )
        return [f"-- yanked {len(session.yank)} byte(s) including the terminator --"]
    if token != "y":
        raise UsageError(f"unsupported yank command {token!r} (see y?)")
    length = session.eval(argument) if argument else session.blocksize
    if length <= 0:
        raise UsageError("y needs a positive length")
    session.yank = bytes(session.call("read_bytes", ea=session.seek, size=length))
    return [f"-- yanked {len(session.yank)} byte(s) --"]


def _yank_length(session, argument: str) -> int:
    length = session.eval(argument) if argument else session.blocksize
    if length <= 0:
        raise UsageError("yank length must be positive")
    return length


def _paste_data(session) -> bytes:
    if not session.yank:
        raise UsageError("nothing yanked")
    require_write(session)
    data = bytes(session.yank)
    session.call("write_bytes", ea=session.seek, data=data)
    return data


def _paste(session, *, echo: bool = True) -> list[str]:
    data = _paste_data(session)
    if not echo:
        return []
    return [f"-- pasted {len(data)} byte(s) --"]


# -- environment -----------------------------------------------------------
@command("%", "get, set or list environment variables")
def _environment(session, statement):
    token = statement.cmd
    if token == "%j":
        return [dumps(dict(session.env))]
    if token == "%*":
        return [f"%{key}={value}" for key, value in sorted(session.env.items())]
    suffix = token[1:]
    if not suffix:
        return [f"{key}={value}" for key, value in sorted(session.env.items())]
    if "=" in suffix:
        name, _, value = suffix.partition("=")
        session.env[name] = value
        return []
    if suffix in session.env:
        return [session.env[suffix]]
    raise UsageError(f"no environment variable {suffix!r}")


# -- pointer ---------------------------------------------------------------
@command("*", "read or write a pointer")
def _pointer(session, statement):
    body = statement.cmd[1:]
    if not body:
        raise UsageError("* needs an address")
    width = 8 if int(session.info.get("bits") or 32) == 64 else 4
    if "=" in body:
        address_text, _, value_text = body.partition("=")
        target = session.resolve(address_text)
        value = session.eval(value_text)
        require_write(session)
        order = "big" if session.info.get("endian") == "big" else "little"
        mask = (1 << (width * 8)) - 1
        session.call(
            "write_bytes", ea=target, data=(value & mask).to_bytes(width, order)
        )
        return []
    target = session.resolve(body)
    payload = session.call("read_value", ea=target, width=width)
    return [f"0x{int(payload['value']):x}"]


# -- compare ---------------------------------------------------------------
@command("c", "compare two blocks", aliases=("cc", "c1"))
def _compare(session, statement):
    words = statement.args.split()
    if len(words) < 3:
        raise UsageError(f"{statement.cmd} needs two addresses and a length")
    first = session.eval(words[0])
    second = session.eval(words[1])
    length = session.eval(words[2])
    if length <= 0:
        raise UsageError("compare length must be positive")
    left = bytes(session.call("read_bytes", ea=first, size=length))
    right = bytes(session.call("read_bytes", ea=second, size=length))
    width = 16 if int(session.info.get("bits") or 32) == 64 else 8
    lines = []
    for index in range(min(len(left), len(right))):
        if left[index] != right[index]:
            lines.append(
                f"0x{first + index:0{width}x} 0x{left[index]:02x} != 0x{right[index]:02x}"
            )
            if statement.cmd == "c1":
                break
    return lines


def _compare_operands(session, statement) -> tuple[int, int, int]:
    words = statement.args.split()
    if len(words) < 3:
        raise UsageError(f"{statement.cmd} needs two addresses and a length")
    first = session.eval(words[0])
    second = session.eval(words[1])
    length = session.eval(words[2])
    if length <= 0:
        raise UsageError("compare length must be positive")
    return first, second, length


def _compare_words(session, statement, width: int) -> list[str]:
    first, second, length = _compare_operands(session, statement)
    left = bytes(session.call("read_bytes", ea=first, size=length))
    right = bytes(session.call("read_bytes", ea=second, size=length))
    order = "big" if session.info.get("endian") == "big" else "little"
    addr_width = 16 if int(session.info.get("bits") or 32) == 64 else 8
    lines = []
    for offset in range(0, min(len(left), len(right)) - width + 1, width):
        lval = int.from_bytes(left[offset : offset + width], order)
        rval = int.from_bytes(right[offset : offset + width], order)
        if lval != rval:
            lines.append(
                f"0x{first + offset:0{addr_width}x}"
                f" 0x{lval:0{width * 2}x} != 0x{rval:0{width * 2}x}"
            )
    return lines


@command("c2", "compare two blocks 2 bytes at a time")
def _compare_word2(session, statement):
    return _compare_words(session, statement, 2)


@command("c4", "compare two blocks 4 bytes at a time")
def _compare_word4(session, statement):
    return _compare_words(session, statement, 4)


@command("c8", "compare two blocks 8 bytes at a time")
def _compare_word8(session, statement):
    return _compare_words(session, statement, 8)


@command("cJ", "compare two blocks and emit a JSON diff")
def _compare_json(session, statement):
    first, second, length = _compare_operands(session, statement)
    left = bytes(session.call("read_bytes", ea=first, size=length))
    right = bytes(session.call("read_bytes", ea=second, size=length))
    differences = [
        {"addr": first + index, "from": left[index], "to": right[index]}
        for index in range(min(len(left), len(right)))
        if left[index] != right[index]
    ]
    return [dumps({"same": not differences, "differences": differences})]


def _ascii_guess(byte: int) -> str:
    return chr(byte) if 0x20 <= byte < 0x7F else "."


@command("cv", "compare two blocks with an annotated byte diff")
def _compare_verbose(session, statement):
    first, second, length = _compare_operands(session, statement)
    left = bytes(session.call("read_bytes", ea=first, size=length))
    right = bytes(session.call("read_bytes", ea=second, size=length))
    addr_width = 16 if int(session.info.get("bits") or 32) == 64 else 8
    return [
        f"0x{first + index:0{addr_width}x} "
        f"(0x{left[index]:02x} != 0x{right[index]:02x}) "
        f"{_ascii_guess(left[index])} {_ascii_guess(right[index])}"
        for index in range(min(len(left), len(right)))
        if left[index] != right[index]
    ]


@command("ca", "compare decompiler ASTs (unsupported)")
def _compare_ast_unsupported(session, statement):
    raise UnsupportedError(
        "ca compares decompiler ASTs; gdare2 has no AST/type model; use c/cc/cJ for byte diffs"
    )


@command("cd", "compare against an r2 patch directory (unsupported)")
def _compare_dir_unsupported(session, statement):
    raise UnsupportedError("cd applies r2 patch directories; not applicable to a Ghidra session")


@command("cf", "compare against an r2 patch file (unsupported)")
def _compare_file_unsupported(session, statement):
    raise UnsupportedError(
        "cf applies r2 patch files; not applicable to a Ghidra session; use c/cJ for block diffs"
    )


@command("cX", "interactive hexdiff view (unsupported)")
def _compare_hexdiff_unsupported(session, statement):
    raise UnsupportedError("cX needs a terminal hexdiff UI; use c/cv/cJ for textual diffs")


@command("cV", "interactive visual diff view (unsupported)")
def _compare_visual_unsupported(session, statement):
    raise UnsupportedError("cV needs a terminal visual diff UI; use c/cv/cJ for textual diffs")


# -- text log --------------------------------------------------------------
@command(
    "T",
    "append or list text-log messages",
    aliases=("Tl", "Tj", "Tm", "T*", "T-", "Ts", "TT", "T=", "T=&"),
)
def _text_log(session, statement):
    token = statement.cmd
    argument = statement.args.strip()
    if token == "Ts":
        return sorted(path.name for path in Path.cwd().iterdir())
    if token == "TT":
        return [f"{index} {text}" for index, text in session.text_log]
    if token in ("T=", "T=&"):
        raise UsageError(f"{token} requires an r2 remote http.sync server; use T* for local export")
    if token == "T-":
        if argument:
            cutoff = session.eval(argument)
            session.text_log = [item for item in session.text_log if item[0] >= cutoff]
        else:
            session.text_log = []
        return []
    if token == "Tl":
        return [str(session.text_log[-1][0]) if session.text_log else "0"]
    if token == "Tj":
        return [dumps([{"id": index, "message": text} for index, text in session.text_log])]
    if token == "T*":
        return [f"T {text}" for _index, text in session.text_log]
    if token == "Tm":
        words = argument.split()
        start = int(words[0]) if words else 0
        count = int(words[1]) if len(words) > 1 else None
        rows = [text for index, text in session.text_log if index >= start]
        return rows[:count] if count is not None else rows
    if argument:
        if argument.isdigit() and session.text_log:
            start = int(argument)
            return [f"{index} {text}" for index, text in session.text_log if index >= start]
        words = argument.split()
        if len(words) == 2 and all(word.isdigit() for word in words):
            start, count = int(words[0]), int(words[1])
            return [
                f"{index} {text}"
                for index, text in session.text_log
                if index >= start
            ][:count]
        session.log(argument)
        return []
    return [f"{index} {text}" for index, text in session.text_log]


# -- session projects ------------------------------------------------------
def _project_dir() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return state_home / "gdare2" / "projects"


def _project_path(name: str) -> Path:
    candidate = Path(name).expanduser()
    if candidate.parent == Path("."):
        candidate = _project_dir() / candidate.name
    if not candidate.name.endswith(PROJECT_SUFFIX):
        candidate = candidate.with_name(candidate.name + PROJECT_SUFFIX)
    return candidate


def _project_data(session) -> dict:
    config = {
        key: value
        for key, value in session.config.items()
        if key in session.config.explicit
    }
    return {
        "version": 2,
        "seek": session.seek,
        "blocksize": session.blocksize,
        "notes": session.project_notes,
        "config": config,
        "vars": dict(session.vars),
        "env": dict(session.env),
        "flags": [
            {
                "name": flag.name,
                "addr": int(flag.addr),
                "size": int(flag.size),
                "space": flag.space,
            }
            for flag in session.flag_store.all_values()
            if flag.local
        ],
        "hidden_ranges": [list(item) for item in session.hidden_ranges],
        "strings": list(session.strings.values()),
        "magic": {str(key): value for key, value in session.magic.items()},
        "type_comments": {str(key): value for key, value in session.type_comments.items()},
        "source_lines": {str(key): value for key, value in session.source_lines.items()},
        "type_links": {str(key): value for key, value in session.type_links.items()},
        "no_return_marks": sorted(session.no_return_marks),
    }


@command(
    "P",
    "list, save, load or delete session projects",
    aliases=("Ps", "Po", "P-", "Pd", "Pj", "Pc", "Pi", "Pn", "Pnj", "PS"),
)
def _projects(session, statement):
    token = statement.cmd
    name = statement.args.strip()
    if token == "P":
        base = _project_dir()
        if not base.is_dir():
            return []
        return sorted(str(path) for path in base.glob(f"*{PROJECT_SUFFIX}"))
    if token == "Pj":
        return [dumps(_project_data(session))]
    if token == "Pc":
        data = _load_project(name) if name else _project_data(session)
        return _project_script(data)
    if token == "PS":
        if not name:
            raise UsageError("PS needs a script file path")
        path = Path(name).expanduser()
        lines = _project_script(_project_data(session))
        try:
            path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        except OSError as exc:
            raise UsageError(f"cannot write script {path}: {exc}") from exc
        return [f"-- saved script {path} --"]
    if token in ("Pn", "Pnj"):
        if token == "Pnj":
            return [dumps({"notes": session.project_notes})]
        if not name:
            return session.project_notes.splitlines()
        if name == "-":
            raise UsageError("Pn - needs cfg.editor; set notes with Pn <text>")
        session.project_notes = name
        return []
    if token == "Pi":
        data = _load_project(name) if name else _project_data(session)
        return [
            f"project  {_project_path(name) if name else '(current)'}",
            f"seek     {session.format_addr(int(data.get('seek', session.seek)))}",
            f"blocksize {data.get('blocksize', session.blocksize)}",
            f"flags    {len(data.get('flags') or [])}",
            f"notes    {len(str(data.get('notes') or '').splitlines())}",
        ]
    if not name:
        raise UsageError(f"{token} needs a project name")
    path = _project_path(name)
    if token in ("P-", "Pd"):
        if not path.is_file():
            raise NotFoundError(f"no such project: {path}")
        path.unlink()
        return []
    if token == "Po":
        if not path.is_file():
            raise NotFoundError(f"no such project: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise UsageError(f"cannot read project {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise UsageError(f"project {path} is not a gdare2 session snapshot")
        session.seek_to(int(data.get("seek", session.seek)))
        session.blocksize = int(data.get("blocksize", session.blocksize))
        for key, value in (data.get("config") or {}).items():
            try:
                session.config.set(key, value)
            except UsageError:
                continue
        session.vars.update({key: int(value) for key, value in (data.get("vars") or {}).items()})
        session.env.update({key: str(value) for key, value in (data.get("env") or {}).items()})
        session.project_notes = str(data.get("notes") or "")
        # Load daemon flags first so a later load_flags() cannot wipe the
        # project's local flags; the snapshot flags are layered on top.
        session.load_flags()
        for item in data.get("flags") or []:
            session.flag_store.add(
                Flag(
                    item["name"],
                    int(item["addr"]),
                    size=int(item.get("size", 0)),
                    local=True,
                    space=str(item.get("space") or DEFAULT_SPACE),
                )
            )
        session.hidden_ranges = [
            (int(item[0]), int(item[1])) for item in data.get("hidden_ranges") or []
        ]
        session.strings = {
            int(item["addr"]): item for item in data.get("strings") or []
        }
        session.magic = {int(key): str(value) for key, value in (data.get("magic") or {}).items()}
        session.type_comments = {
            int(key): str(value) for key, value in (data.get("type_comments") or {}).items()
        }
        session.source_lines = {
            int(key): str(value) for key, value in (data.get("source_lines") or {}).items()
        }
        session.type_links = {
            int(key): str(value) for key, value in (data.get("type_links") or {}).items()
        }
        session.no_return_marks = {
            int(value) for value in data.get("no_return_marks") or []
        }
        return [f"-- loaded {path} --"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_project_data(session), indent=2), encoding="utf-8")
    return [f"-- saved {path} --"]


def _load_project(name: str) -> dict:
    path = _project_path(name)
    if not path.is_file():
        raise NotFoundError(f"no such project: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read project {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"project {path} is not a gdare2 session snapshot")
    return data


def _project_script(data: dict) -> list[str]:
    lines = [f"s {int(data.get('seek', 0)):#x}", f"b {int(data.get('blocksize', 0)):#x}"]
    notes = str(data.get("notes") or "")
    if notes:
        lines.append(f"Pn {shlex.quote(notes)}")
    for key, value in sorted((data.get("config") or {}).items()):
        lines.append(f"e {key} = {value}")
    for key, value in sorted((data.get("vars") or {}).items()):
        lines.append(f"${key}={value}")
    for key, value in sorted((data.get("env") or {}).items()):
        lines.append(f"env {key}={value}")
    for item in data.get("flags") or []:
        lines.append(
            f"f {item['name']} {int(item.get('size', 0))} @ {int(item['addr']):#x}"
        )
    for start, stop in data.get("hidden_ranges") or []:
        lines.append(f"Ch {int(stop) - int(start) + 1} @ {int(start):#x}")
    for item in data.get("strings") or []:
        lines.append(f"Cs {int(item['size'])} @ {int(item['addr']):#x}")
    for address in sorted((data.get("magic") or {}), key=int):
        lines.append(f"Cm @ {int(address):#x}")
    for address, comment in sorted(
        (data.get("type_comments") or {}).items(), key=lambda item: int(item[0])
    ):
        lines.append(f"Ct {shlex.quote(str(comment))} @ {int(address):#x}")
    for address, line in sorted(
        (data.get("source_lines") or {}).items(), key=lambda item: int(item[0])
    ):
        lines.append(f"CL {shlex.quote(str(line))} @ {int(address):#x}")
    for address, name in sorted(
        (data.get("type_links") or {}).items(), key=lambda item: int(item[0])
    ):
        lines.append(f"tl {shlex.quote(str(name))} = {int(address):#x}")
    for address in data.get("no_return_marks") or []:
        lines.append(f"tn {int(address):#x}")
    return lines


@command("dt", "typed read (radare2 dt is a debug trace)")
def _typed_read_alias(session, statement):
    raise UsageError(
        "dt is radare2's trace command; use tp/tpv/tpx for typed reads"
    )
