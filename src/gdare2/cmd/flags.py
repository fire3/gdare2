"""Flag commands backed by the client FlagStore and optional Ghidra symbols."""

from __future__ import annotations

import shlex

from gdare2.cmd import command, require_write
from gdare2.errors import NotFoundError, UsageError
from gdare2.flags import Flag
from gdare2.fmt.memory import hexdump
from gdare2.jsonutil import dumps


def _can_write_back(session) -> bool:
    return not session.readonly and session.config.get_bool("ghidra.flags.write")


def _add(session, name: str, address: int, size: int = 0) -> Flag:
    if _can_write_back(session):
        payload = session.call("symbol_create", ea=int(address), name=name)
        return session.flag_store.add(
            Flag(
                str(payload["name"]),
                int(payload["addr"]),
                size=size,
                kind="flag",
            )
        )
    return session.flag_store.add(
        Flag(
            name,
            int(address),
            size=size,
            kind="flag",
            local=True,
            space=session.flag_store.space,
        )
    )

@command("f", "list flags or create one", detail="Usage: f [name [size]] [@ addr] | f name = addr")
def _flags(session, statement):
    session.load_flags()
    text = statement.args.strip()
    if not text:
        return _list(session, statement)
    if "=" in text:
        name, _, value = text.partition("=")
        name = name.strip()
        if not name:
            raise UsageError("f needs a flag name")
        _add(session, name, session.eval(value.strip()))
        return []
    try:
        parts = shlex.split(text)
    except ValueError as exc:
        raise UsageError(f"f cannot parse arguments: {exc}") from None
    if not parts:
        raise UsageError("f needs a flag name")
    name = parts[0]
    size = 0
    address = session.seek
    if len(parts) >= 2:
        try:
            value = int(parts[1], 0)
        except ValueError:
            raise UsageError(f"f expects a numeric size or address, got {parts[1]!r}") from None
        if len(parts) >= 3:
            size = value
            address = session.eval(parts[2])
        else:
            size = value
    _add(session, name, address, size)
    return []


@command("f*", "list flags as replayable commands")
def _flags_commands(session, statement):
    session.load_flags()
    return [
        f"f {flag.name} {int(flag.size)} @ {session.format_addr(int(flag.addr))}"
        for flag in session.flag_store.values()
    ]


@command("fj", "list flags as JSON")
def _flags_json(session, statement):
    session.load_flags()
    return [dumps(_entries(session))]


@command("fq", "list flag names")
def _flags_quiet(session, statement):
    session.load_flags()
    return [flag.name for flag in session.flag_store.values()]


@command("f?", "check whether a flag exists")
def _flags_exists(session, statement):
    session.load_flags()
    name = statement.args.strip()
    if not name:
        raise UsageError("f? needs a flag name")
    return ["1" if session.flag_store.get(name) is not None else "0"]


@command("f-", "delete a flag by name or at seek")
def _flags_delete(session, statement):
    session.load_flags()
    name = statement.args.strip()
    if not name and statement.tmpseek is not None:
        matches = session.flag_store.at(session.seek)
        if not matches:
            raise NotFoundError(f"no flag at {session.format_addr(session.seek)}")
        name = matches[0].name
    if not name:
        raise UsageError("f- needs a flag name or @ addr")
    if _can_write_back(session):
        require_write(session)
        session.call("symbol_delete", name=name)
    if session.flag_store.remove(name) is None and not _can_write_back(session):
        raise NotFoundError(f"flag {name!r} not found")
    return []


@command("fr", "rename a flag")
def _flags_rename(session, statement):
    session.load_flags()
    parts = statement.args.split()
    if len(parts) != 2:
        raise UsageError("fr needs an old and a new flag name")
    old, new = parts
    if _can_write_back(session):
        require_write(session)
        session.call("symbol_rename", name=old, new_name=new)
    if session.flag_store.rename(old, new) is None and not _can_write_back(session):
        raise NotFoundError(f"flag {old!r} not found")
    return []


@command("f.", "list session-local flags")
def _flags_local(session, statement):
    session.load_flags()
    return [
        _format(session, flag)
        for flag in session.flag_store.values()
        if flag.local
    ]


@command("fn", "list flags with their real names", aliases=("fnj",))
def _flag_names(session, statement):
    session.load_flags()
    pattern = statement.args.strip()
    flags = [
        flag
        for flag in session.flag_store.values()
        if not pattern or pattern in flag.name
    ]
    if statement.cmd.endswith("j"):
        return [
            dumps(
                [
                    {
                        "name": flag.name,
                        "realname": flag.name,
                        "size": int(flag.size),
                        "offset": int(flag.addr),
                    }
                    for flag in flags
                ]
            )
        ]
    return [_format(session, flag) for flag in flags]


@command("fN", "show the real flag name at seek")
def _flag_realname(session, statement):
    session.load_flags()
    name = statement.args.strip()
    if name:
        flag = session.flag_store.get(name)
        if flag is None:
            raise NotFoundError(f"flag {name!r} not found")
        return [flag.name]
    matches = session.flag_store.at(session.seek)
    if not matches:
        raise NotFoundError(f"no flag at {session.format_addr(session.seek)}")
    return [matches[0].name]


@command("fx", "hexdump the bytes covered by a flag")
def _flag_hexdump(session, statement):
    session.load_flags()
    name = statement.args.strip()
    if name:
        flag = session.flag_store.get(name)
        if flag is None:
            address = session.eval(name)
            matches = session.flag_store.at(address)
            flag = matches[0] if matches else None
        if flag is None:
            raise NotFoundError(f"fx: no flag {name!r}")
    else:
        matches = session.flag_store.at(session.seek)
        flag = matches[0] if matches else None
    address = int(flag.addr) if flag is not None else session.seek
    size = int(flag.size) if flag is not None and int(flag.size) > 0 else 64
    data = bytes(session.call("read_bytes", ea=address, size=size))
    return hexdump(
        data,
        address,
        cols=session.config.get_int("hex.cols"),
        header=session.config.get_bool("hex.header"),
        bits=int(session.info.get("bits") or 32),
        pairs=session.config.get_bool("hex.pairs"),
        offset=session.config.get_bool("hex.offset"),
        ascii=session.config.get_bool("hex.ascii"),
    )


def _list(session, statement) -> list[str]:
    return [_format(session, flag) for flag in session.flag_store.values()]


def _format(session, flag: Flag) -> str:
    return (
        f"{session.format_addr(flag.addr)} {int(flag.size):3d} "
        f"{flag.name}"
    )


def _entries(session) -> list[dict]:
    return [
        {
            "name": flag.name,
            "addr": int(flag.addr),
            "size": int(flag.size),
            "kind": flag.kind,
            "local": bool(flag.local),
        }
        for flag in session.flag_store.values()
    ]
