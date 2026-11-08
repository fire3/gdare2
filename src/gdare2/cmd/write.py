"""Byte-write commands, the io.cache buffer and undo/redo."""

from __future__ import annotations

import sys
from pathlib import Path

from gdare2.cmd import command, require_write
from gdare2.errors import GdarError, UsageError
from gdare2.escape import text_bytes

MAX_TEXT_BYTES = 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024


@command("w", "save the program, or write a string at seek")
def _write(session, statement):
    require_write(session)
    text = statement.args
    if text:
        _write_data(session, session.seek, text_bytes(text))
        return []
    _commit_cache(session)
    session.call("save")
    return []


@command("wq", "commit the cache, save and quit")
def _write_quit(session, statement):
    require_write(session)
    _commit_cache(session)
    session.call("save")
    session.quit_requested = True
    return []


@command("wx", "write hexpairs at seek")
def _write_hex(session, statement):
    require_write(session)
    data, mask = parse_hexpairs(statement.args)
    _write_data(session, session.seek, data, mask)
    return []


@command("w0", "write zero bytes at seek")
def _write_zero(session, statement):
    require_write(session)
    args = statement.args.strip()
    size = int(args, 0) if args else session.blocksize
    if size < 0:
        raise UsageError("w0 size must not be negative")
    if size > MAX_TEXT_BYTES:
        raise UsageError(f"single write is limited to {MAX_TEXT_BYTES} bytes")
    _write_data(session, session.seek, b"\x00" * size)
    return []


@command("wf", "write a file (or stdin with -) at seek")
def _write_file(session, statement):
    require_write(session)
    path = statement.args.strip()
    if not path:
        raise UsageError("wf needs a file name or -")
    if path == "-":
        data = sys.stdin.buffer.read()
    else:
        try:
            data = Path(path).expanduser().read_bytes()
        except OSError as exc:
            raise GdarError(f"cannot read {path}: {exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise UsageError(f"single write is limited to {MAX_FILE_BYTES} bytes")
    _write_data(session, session.seek, data)
    return []


@command("wd", "duplicate bytes at seek+offset")
def _write_duplicate(session, statement):
    require_write(session)
    args = statement.args.split()
    offset = int(args[0], 0) if args else 0
    size = int(args[1], 0) if len(args) > 1 else session.blocksize
    if size <= 0:
        raise UsageError("wd size must be positive")
    source = session.seek
    destination = session.seek + offset
    if session.config.get_bool("io.cache"):
        payload = session.call("read_bytes", ea=source, size=size)
        _cache_patch(session, destination, bytes(payload))
    else:
        session.call("write_copy", dst=destination, src=source, size=size)
    return []


@command("wc", "show the pending write cache")
def _write_cache(session, statement):
    return [
        f"{session.format_addr(int(patch['ea']))} {len(patch['data'])} "
        f"{bytes(patch['data']).hex()}"
        for patch in session.write_cache
    ]


@command("wc+", "commit the pending write cache")
def _write_cache_commit(session, statement):
    require_write(session)
    _commit_cache(session)
    return []


@command("wc-", "discard the pending write cache")
def _write_cache_clear(session, statement):
    session.write_cache.clear()
    return []


@command("u", "undo the last byte write")
def _undo(session, statement):
    require_write(session)
    _commit_cache(session)
    session.call("undo")
    return []


@command("U", "redo the last undone byte write")
def _redo(session, statement):
    require_write(session)
    _commit_cache(session)
    session.call("redo")
    return []


def _write_data(session, address: int, data: bytes, mask: bytes | None = None) -> None:
    if not data:
        raise UsageError("write needs at least one byte")
    if len(data) > MAX_TEXT_BYTES:
        raise UsageError(f"single write is limited to {MAX_TEXT_BYTES} bytes")
    if session.config.get_bool("io.cache"):
        _cache_patch(session, address, data, mask)
        return
    args = {"ea": int(address), "data": data}
    if mask is not None:
        args["mask"] = mask
    session.call("write_bytes", **args)


def _cache_patch(session, address: int, data: bytes, mask: bytes | None = None) -> None:
    require_write(session)
    patch = {"ea": int(address), "data": bytes(data)}
    if mask is not None:
        patch["mask"] = bytes(mask)
    session.write_cache.append(patch)


def _commit_cache(session) -> None:
    session.commit_write_cache()


def parse_hexpairs(text: str) -> tuple[bytes, bytes | None]:
    compact = "".join(text.split())
    if compact[:2].lower() == "0x":
        compact = compact[2:]
    if not compact:
        raise UsageError("wx needs hexpairs")
    if len(compact) % 2:
        raise UsageError("wx needs an even number of hex digits")
    data = bytearray()
    mask = bytearray()
    wildcard = False
    for index in range(0, len(compact), 2):
        high, low = compact[index], compact[index + 1]
        value = 0
        keep = 0
        if high in ".?":
            wildcard = True
        elif high in "0123456789abcdefABCDEF":
            value |= int(high, 16) << 4
            keep |= 0xF0
        else:
            raise UsageError(f"wx received invalid hex digit {high!r}")
        if low in ".?":
            wildcard = True
        elif low in "0123456789abcdefABCDEF":
            value |= int(low, 16)
            keep |= 0x0F
        else:
            raise UsageError(f"wx received invalid hex digit {low!r}")
        data.append(value)
        mask.append(keep)
    return bytes(data), bytes(mask) if wildcard else None
