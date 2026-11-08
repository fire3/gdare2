"""Flag commands backed by the client FlagStore and optional Ghidra symbols."""

from __future__ import annotations

from gdare2.cmd import command, require_write
from gdare2.errors import NotFoundError, UsageError
from gdare2.flags import Flag
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
        Flag(name, int(address), size=size, kind="flag", local=True)
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
    parts = text.split()
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
