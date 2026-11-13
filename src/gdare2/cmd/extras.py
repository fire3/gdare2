"""Yank buffer, environment, pointer, compare, text log and session projects."""

from __future__ import annotations

import json
import os
from pathlib import Path

from gdare2.cmd import command, require_write
from gdare2.errors import NotFoundError, UsageError
from gdare2.flags import Flag
from gdare2.jsonutil import dumps

PROJECT_SUFFIX = ".gdare2-prj"


# -- yank ------------------------------------------------------------------
@command("y", "yank bytes, hexpairs, text or a file", detail="yy pastes the clipboard")
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
    if token != "y":
        raise UsageError(f"unsupported yank command {token!r} (see y?)")
    length = session.eval(argument) if argument else session.blocksize
    if length <= 0:
        raise UsageError("y needs a positive length")
    session.yank = bytes(session.call("read_bytes", ea=session.seek, size=length))
    return [f"-- yanked {len(session.yank)} byte(s) --"]


def _paste(session) -> list[str]:
    if not session.yank:
        raise UsageError("nothing yanked")
    require_write(session)
    session.call("write_bytes", ea=session.seek, data=session.yank)
    return [f"-- pasted {len(session.yank)} byte(s) --"]


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


# -- text log --------------------------------------------------------------
@command("T", "append or list text-log messages", aliases=("Tl", "Tj", "Tm", "T*", "T-"))
def _text_log(session, statement):
    token = statement.cmd
    argument = statement.args.strip()
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
        start = int(argument) if argument else 0
        return [text for index, text in session.text_log if index >= start]
    if argument:
        if argument.isdigit() and session.text_log:
            start = int(argument)
            return [f"{index} {text}" for index, text in session.text_log if index >= start]
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
        if not getattr(session.config, "explicit", None) or key in session.config.explicit
    }
    return {
        "version": 1,
        "seek": session.seek,
        "blocksize": session.blocksize,
        "config": config,
        "vars": dict(session.vars),
        "env": dict(session.env),
        "flags": [
            {"name": flag.name, "addr": int(flag.addr), "size": int(flag.size)}
            for flag in session.flag_store.values()
            if flag.local
        ],
    }


@command("P", "list, save, load or delete session projects", aliases=("Ps", "Po", "P-", "Pj"))
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
    if not name:
        raise UsageError(f"{token} needs a project name")
    path = _project_path(name)
    if token == "P-":
        if not path.is_file():
            raise NotFoundError(f"no such project: {path}")
        path.unlink()
        return []
    if token == "Po":
        if not path.is_file():
            raise NotFoundError(f"no such project: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        session.seek_to(int(data.get("seek", session.seek)))
        session.blocksize = int(data.get("blocksize", session.blocksize))
        for key, value in (data.get("config") or {}).items():
            try:
                session.config.set(key, value)
            except UsageError:
                continue
        session.vars.update({key: int(value) for key, value in (data.get("vars") or {}).items()})
        session.env.update({key: str(value) for key, value in (data.get("env") or {}).items()})
        for item in data.get("flags") or []:
            session.flag_store.add(
                Flag(item["name"], int(item["addr"]), size=int(item.get("size", 0)), local=True)
            )
        return [f"-- loaded {path} --"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_project_data(session), indent=2), encoding="utf-8")
    return [f"-- saved {path} --"]


@command("dt", "typed read (radare2 dt is a debug trace)")
def _typed_read_alias(session, statement):
    raise UsageError(
        "dt is radare2's trace command; use tp/tpv/tpx for typed reads"
    )
