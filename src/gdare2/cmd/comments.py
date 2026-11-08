"""Comment management commands."""

from __future__ import annotations

from gdare2.cmd import command, require_write
from gdare2.errors import NotFoundError, UsageError
from gdare2.jsonutil import dumps


@command("C", "list comments", aliases=("Cj",))
def _comments(session, statement):
    payload = session.call("comments", limit=10000)
    session.warn_truncated("comment list", len(payload))
    if statement.cmd == "Cj":
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['addr']))} {item['kind']:<10} {item['text']}"
        for item in payload
    ]


@command("C.", "show comments at seek")
def _comments_at_seek(session, statement):
    payload = session.call("comments", ea=session.seek, limit=10000)
    if not payload:
        raise NotFoundError(f"no comment at {session.format_addr(session.seek)}")
    return [
        f"{session.format_addr(int(item['addr']))} {item['kind']:<10} {item['text']}"
        for item in payload
    ]


@command("CC", "set an end-of-line comment")
def _set_comment(session, statement):
    text = statement.args.strip()
    if not text:
        return _comments(session, statement)
    require_write(session)
    payload = session.call("comment_set", ea=session.seek, text=text, kind="eol")
    return [f"{session.format_addr(int(payload['addr']))} {payload['kind']} {payload['text']}"]


@command("CC-", "delete an end-of-line comment")
def _delete_comment(session, statement):
    require_write(session)
    payload = session.call("comment_delete", ea=session.seek, kind="eol")
    return [f"{session.format_addr(int(payload['addr']))} {payload['kind']} deleted"]


@command("CC.", "show the end-of-line comment at seek")
def _comment_at_seek(session, statement):
    payload = session.call("comments", ea=session.seek, limit=10000)
    matches = [item for item in payload if item["kind"] == "eol"]
    if not matches:
        raise NotFoundError(f"no EOL comment at {session.format_addr(session.seek)}")
    return [f"{session.format_addr(int(item['addr']))} {item['text']}" for item in matches]


@command("Cd", "set a data comment")
def _data_comment(session, statement):
    return _set_kind(session, statement, "eol")


@command("Cb", "set a basic-block/pre comment")
def _block_comment(session, statement):
    return _set_kind(session, statement, "pre")


@command("Cp", "set a function/plate comment")
def _plate_comment(session, statement):
    return _set_kind(session, statement, "plate")


@command("Cr", "set a repeatable comment")
def _repeatable_comment(session, statement):
    return _set_kind(session, statement, "repeatable")


def _set_kind(session, statement, kind):
    require_write(session)
    text = statement.args.strip()
    if not text:
        raise UsageError(f"{kind} comment text is required")
    payload = session.call("comment_set", ea=session.seek, text=text, kind=kind)
    return [f"{session.format_addr(int(payload['addr']))} {payload['kind']} {payload['text']}"]
