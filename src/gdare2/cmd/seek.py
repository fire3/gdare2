"""Seek and block-size commands."""

from __future__ import annotations

from gdare2.cmd import command
from gdare2.errors import NotFoundError, UsageError
from gdare2.jsonutil import dumps


@command("s", "seek to an address or symbol")
def _seek(session, statement):
    args = statement.args.strip()
    if not args:
        return [session.format_addr(session.seek)]
    session.seek_to(session.eval(args))
    return []


@command("s+", "seek forward or through seek history")
def _seek_forward(session, statement):
    args = statement.args.strip()
    if args:
        session.seek_to(session.seek + session.eval(args))
    elif session.seek_future:
        session.seek_history.append(session.seek)
        session.seek = session.seek_future.pop()
    return []


@command("s-", "seek backward or through seek history")
def _seek_backward(session, statement):
    args = statement.args.strip()
    if args:
        session.seek_to(session.seek - session.eval(args))
    elif session.seek_history:
        session.seek_future.append(session.seek)
        session.seek = session.seek_history.pop()
    return []


@command("s++", "seek forward one block")
def _seek_block_forward(session, statement):
    session.seek_to(session.seek + session.blocksize)
    return []


@command("s--", "seek backward one block")
def _seek_block_backward(session, statement):
    session.seek_to(session.seek - session.blocksize)
    return []


@command("s*", "list seek history as replayable undo flags")
def _seek_commands(session, statement):
    history = session.seek_history
    return [
        f"f undo_{index} = {session.format_addr(address)}"
        for index, address in enumerate(reversed(history))
    ]


@command("s.", "seek relative to the current address")
def _seek_relative(session, statement):
    session.seek_to(session.seek + session.eval(statement.args))
    return []


@command("s:", "print the current address with zero padding")
def _seek_padded(session, statement):
    text = statement.cmd[2:] or statement.args.strip()
    digits = session.eval(text) if text else 8
    if digits <= 0:
        raise UsageError("s: padding must be positive")
    return [f"0x{session.seek:0{int(digits)}x}"]


@command(
    "s=",
    "show the seek history",
    aliases=("s==", "s=*", "s=j", "s=!"),
)
def _seek_history(session, statement):
    past = list(session.seek_history)
    future = list(reversed(session.seek_future))
    chain = [*past, session.seek, *future] if past or future else [session.seek]
    if statement.cmd == "s=*":
        return [
            f"{'s+' if index >= len(past) else 's'} {session.format_addr(address)}"
            for index, address in enumerate(chain)
        ]
    return [" > ".join(session.format_addr(address) for address in chain)]


@command("b*", "show the block size as a replayable command")
def _blocksize_command(session, statement):
    return [f"b {session.blocksize:#x}"]


@command("bj", "show block settings as JSON")
def _blocksize_json(session, statement):
    return [dumps({"blocksize": session.blocksize, "blocksize_limit": session.max_blocksize})]


@command("bf", "set the block size from a flag")
def _blocksize_flag(session, statement):
    text = statement.args.strip()
    if not text:
        raise UsageError("bf needs a flag name or address")
    session.load_flags()
    flag = session.flag_store.get(text)
    if flag is None:
        try:
            address = session.eval(text)
        except Exception:
            address = None
        if address is not None:
            matches = session.flag_store.at(address)
            flag = matches[0] if matches else None
    if flag is None:
        raise NotFoundError(f"bf: no flag {text!r}")
    size = int(flag.size) if int(flag.size) > 0 else 1
    if size > session.max_blocksize:
        raise UsageError(f"bf: flag size {size} exceeds blocksize limit")
    session.blocksize = size
    return []


@command("bm", "get or set the maximum block size")
def _blocksize_limit(session, statement):
    text = statement.args.strip()
    if not text:
        return [hex(session.max_blocksize)]
    value = session.eval(text)
    if value <= 0:
        raise UsageError("bm maximum block size must be positive")
    session.max_blocksize = value
    if session.blocksize > value:
        session.blocksize = value
    return []


@command("sb", "seek to the containing basic block")
def _seek_block(session, statement):
    address = session.resolve(statement.args)
    payload = session.call("basic_block", ea=address)
    session.seek_to(int(payload["start"]))
    return []


@command("sf", "seek to the containing function")
def _seek_function(session, statement):
    address = session.resolve(statement.args)
    payload = session.call("function_at", ea=address)
    session.seek_to(int(payload["addr"]))
    return []


@command("sF", "seek to the end of the containing function")
def _seek_function_end(session, statement):
    address = session.resolve(statement.args)
    payload = session.call("function_at", ea=address)
    session.seek_to(int(payload["end"]))
    return []


@command("so", "seek to the next instruction")
def _seek_next_instruction(session, statement):
    count = int(statement.args.strip() or "1", 0)
    address = session.seek
    for _ in range(count):
        payload = session.call("instruction_after", ea=address)
        address = int(payload["addr"])
    session.seek_to(address)
    return []


@command("sn", "seek to the next non-call instruction")
def _seek_next_noncall(session, statement):
    count = int(statement.args.strip() or "1", 0)
    address = session.seek
    while count > 0:
        payload = session.call("instruction_after", ea=address)
        address = int(payload["addr"])
        if not payload.get("call"):
            count -= 1
    session.seek_to(address)
    return []


@command("sp", "seek to the previous instruction")
def _seek_previous(session, statement):
    count = int(statement.args.strip() or "1", 0)
    address = session.seek
    for _ in range(count):
        payload = session.call("instruction_before", ea=address)
        address = int(payload["addr"])
    session.seek_to(address)
    return []


@command("b", "get or set the block size")
def _blocksize(session, statement):
    args = statement.args.strip()
    if not args:
        return [str(session.blocksize)]
    value = session.eval(args)
    if value < 0:
        raise UsageError("block size must not be negative")
    if value > session.max_blocksize:
        raise UsageError(f"block size exceeds bm limit {session.max_blocksize}")
    session.blocksize = value
    return []
