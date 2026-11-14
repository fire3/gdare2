"""Flag commands backed by the client FlagStore and optional Ghidra symbols."""

from __future__ import annotations

import shlex

from gdare2.cmd import command, require_write
from gdare2.errors import NotFoundError, UnsupportedError, UsageError
from gdare2.flags import DEFAULT_SPACE, Flag
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


# -- V9: range and resolution helpers ----------------------------------------


def _range_bounds(session, statement, usage: str) -> tuple[int, int]:
    words = statement.args.split()
    if len(words) != 2:
        raise UsageError(usage)
    start = session.eval(words[0])
    stop = session.eval(words[1])
    if start > stop:
        start, stop = stop, start
    return start, stop


def _flag_command(session, flag: Flag) -> str:
    return (
        f"f {flag.name} {int(flag.size)} @ {session.format_addr(int(flag.addr))}"
    )


@command(
    "fc",
    "list or count flags in an address range",
    detail="Usage: fc [from to]  - with two addresses list one 'f' command per flag,\nwithout arguments print the number of flags in the current space",
)
def _flags_count(session, statement):
    session.load_flags()
    if not statement.args.strip():
        return [str(len(session.flag_store.values()))]
    start, stop = _range_bounds(session, statement, "fc needs a from and a to address")
    return [
        _flag_command(session, flag)
        for flag in session.flag_store.all_values()
        if start <= int(flag.addr) <= stop
    ]


@command("fo", "list flags overlapping an address range")
def _flags_overlap(session, statement):
    session.load_flags()
    start, stop = _range_bounds(session, statement, "fo needs a from and a to address")
    lines = []
    for flag in session.flag_store.all_values():
        address = int(flag.addr)
        size = int(flag.size)
        end = address + (size if size > 0 else 1)
        if end <= start or address > stop:
            continue
        lines.append(_flag_command(session, flag))
    return lines


@command("fd", "resolve a flag name to its address")
def _flag_address(session, statement):
    session.load_flags()
    name = statement.args.strip()
    if name:
        flag = session.flag_store.get(name)
        if flag is None:
            raise NotFoundError(f"fd: no flag {name!r}")
    else:
        matches = session.flag_store.at(session.seek)
        if not matches:
            raise NotFoundError(f"fd: no flag at {session.format_addr(session.seek)}")
        flag = matches[0]
    return [session.format_addr(int(flag.addr))]


# -- V9: explicit not-supported variants --------------------------------------


@command("fb", "set the base address for new flags (not supported)")
def _flag_base_unsupported(session, statement):
    raise UnsupportedError(
        "fb (base address for relative flag moves) has no Ghidra mapping; use f name @ addr"
    )


@command("fe", "create enumerated flags (not supported)")
def _flag_enum_unsupported(session, statement):
    raise UnsupportedError(
        "fe (enumerated flag creation) has no Ghidra mapping; create flags with f in a loop"
    )


@command("ff", "distance in bytes to the next flag (not supported)")
def _flag_distance_unsupported(session, statement):
    raise UnsupportedError(
        "ff (distance to the next flag) has no Ghidra mapping; compare flag addresses with f"
    )


@command("fg", "bring core jobs to the foreground (not supported)")
def _flag_jobs_unsupported(session, statement):
    raise UnsupportedError(
        "fg (foreground core tasks) is an interactive r2 job feature; gdare2 runs synchronously"
    )


@command("fi", "show flags in the current block or range (not supported)")
def _flag_block_unsupported(session, statement):
    raise UnsupportedError("fi (flags in block or range) is covered by fc and fo")


@command("fC", "set a comment for a flag (not supported)")
def _flag_comment_unsupported(session, statement):
    raise UnsupportedError(
        "fC (per-flag comments) has no Ghidra mapping; use CC for address comments"
    )


@command("fO", "flag as ordinals (not supported)")
def _flag_ordinals_unsupported(session, statement):
    raise UnsupportedError("fO (flag ordinals) has no Ghidra mapping")


@command("fR", "relocate flags matching a mask (not supported)")
def _flag_relocate_unsupported(session, statement):
    raise UnsupportedError("fR (flag relocation by mask) has no Ghidra mapping")


@command("fV", "visual flag marks (not supported)")
def _flag_marks_unsupported(session, statement):
    raise UnsupportedError("fV (visual flag marks) has no Ghidra mapping")


# -- V10: flag spaces ---------------------------------------------------------


def _space_line(current: str, space: str) -> str:
    marker = "*" if space == current else " "
    return f"{marker} {space}"


@command(
    "fs",
    "list or select flag spaces",
    detail="Usage: fs [space]  - without an argument list the known spaces and mark\nthe selected one; with an argument switch to it, creating it implicitly",
)
def _flag_spaces(session, statement):
    session.load_flags()
    name = statement.args.strip()
    if name:
        session.flag_store.set_space(name)
        return []
    current = session.flag_store.space
    return [_space_line(current, space) for space in session.flag_store.spaces()]


@command("fsj", "list flag spaces as JSON")
def _flag_spaces_json(session, statement):
    session.load_flags()
    store = session.flag_store
    return [dumps({"current": store.space, "spaces": store.spaces()})]


@command(
    "fs*",
    "list flag spaces as replayable commands",
    detail="Emits one 'fs <space>' line per space with the selected space last,\nso replaying the output restores the selection",
)
def _flag_spaces_commands(session, statement):
    session.load_flags()
    store = session.flag_store
    current = store.space
    ordered = [space for space in store.spaces() if space != current]
    ordered.append(current)
    return [f"fs {space}" for space in ordered]


@command("fsq", "list flag space names")
def _flag_spaces_quiet(session, statement):
    session.load_flags()
    return list(session.flag_store.spaces())


@command(
    "fs-",
    "delete an empty flag space",
    detail="Usage: fs- [space]  - defaults to the selected space; spaces that still\nhold flags are rejected so deletion stays explicit",
)
def _flag_space_delete(session, statement):
    session.load_flags()
    name = statement.args.strip() or session.flag_store.space
    if name == DEFAULT_SPACE:
        raise UsageError("fs- cannot delete the default flag space '*'")
    if name not in session.flag_store.spaces():
        raise NotFoundError(f"fs-: no such flag space {name!r}")
    if any(flag.space == name for flag in session.flag_store.all_values()):
        raise UsageError(
            f"fs-: flag space {name!r} still holds flags; delete or move them first"
        )
    session.flag_store.remove_space(name)
    if session.flag_store.space == name:
        session.flag_store.set_space(DEFAULT_SPACE)
    return []


@command(
    "fsr",
    "rename a flag space",
    detail="Usage: fsr [old] new  - with one argument rename the selected space;\nflags in the old space move to the new one",
)
def _flag_space_rename(session, statement):
    session.load_flags()
    parts = statement.args.split()
    if len(parts) == 1:
        old, new = session.flag_store.space, parts[0]
    elif len(parts) == 2:
        old, new = parts
    else:
        raise UsageError("fsr needs an old and a new space name")
    if old not in session.flag_store.spaces():
        raise NotFoundError(f"fsr: no such flag space {old!r}")
    session.flag_store.rename_space(old, new)
    return []
