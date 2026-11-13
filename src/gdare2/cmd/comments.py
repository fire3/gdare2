"""Comment management commands."""

from __future__ import annotations

import base64
import binascii

from gdare2.cmd import command, require_write
from gdare2.errors import NotFoundError, UsageError
from gdare2.escape import unquote_text
from gdare2.jsonutil import dumps

_KIND_COMMANDS = {
    "eol": "CCu",
    "pre": "Cb",
    "plate": "Cp",
    "repeatable": "Cr",
}


def _comment_text(text: str) -> str:
    """Decode ``base64:`` payloads so ``C*`` output can round-trip."""
    text = unquote_text(text)
    if text.startswith("base64:"):
        payload = text[len("base64:") :].strip()
        try:
            return base64.b64decode(payload, validate=True).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            raise UsageError("invalid base64 comment payload") from None
    return text


def _comment_lines(session, items) -> list[str]:
    lines = []
    for item in items:
        opcode = _KIND_COMMANDS.get(str(item["kind"]), "CCu")
        encoded = base64.b64encode(str(item["text"]).encode("utf-8")).decode("ascii")
        lines.append(
            f"{opcode} base64:{encoded} @ {session.format_addr(int(item['addr']))}"
        )
    return lines


def _comment_query(session, **kwargs) -> list[dict]:
    return session.call(
        "comments",
        include_all=session.config.get_bool("ghidra.comments.all"),
        **kwargs,
    )


@command("C", "list comments", aliases=("Cj",))
def _comments(session, statement):
    payload = _comment_query(session, limit=10000)
    session.warn_truncated("comment list", len(payload))
    if statement.cmd == "Cj":
        return [dumps(payload)]
    return [
        f"{session.format_addr(int(item['addr']))} {item['kind']:<10} {item['text']}"
        for item in payload
    ]


@command("C.", "show comments at seek")
def _comments_at_seek(session, statement):
    payload = _comment_query(session, ea=session.seek, limit=10000)
    if not payload:
        raise NotFoundError(f"no comment at {session.format_addr(session.seek)}")
    return [
        f"{session.format_addr(int(item['addr']))} {item['kind']:<10} {item['text']}"
        for item in payload
    ]


@command("CC", "set an end-of-line comment")
def _set_comment(session, statement):
    text = _comment_text(statement.args)
    if not text:
        return _comments(session, statement)
    require_write(session)
    payload = session.call("comment_set", ea=session.seek, text=text, kind="eol")
    return [f"{session.format_addr(int(payload['addr']))} {payload['kind']} {payload['text']}"]


@command("CCu", "set an end-of-line comment from text or base64")
def _set_unique_comment(session, statement):
    text = _comment_text(statement.args)
    if not text:
        raise UsageError("CCu needs comment text or base64:<data>")
    require_write(session)
    payload = session.call("comment_set", ea=session.seek, text=text, kind="eol")
    return [f"{session.format_addr(int(payload['addr']))} {payload['kind']} {payload['text']}"]


@command("C*", "list comments as replayable commands", aliases=("CC*", "C*."))
def _comments_commands(session, statement):
    if statement.cmd == "C*.":
        payload = _comment_query(session, ea=session.seek, limit=10000)
    else:
        payload = _comment_query(session, limit=10000)
        session.warn_truncated("comment list", len(payload))
    return _comment_lines(session, payload)


@command("CC-", "delete an end-of-line comment")
def _delete_comment(session, statement):
    require_write(session)
    payload = session.call("comment_delete", ea=session.seek, kind="eol")
    return [f"{session.format_addr(int(payload['addr']))} {payload['kind']} deleted"]


@command("CC.", "show the end-of-line comment at seek")
def _comment_at_seek(session, statement):
    payload = _comment_query(session, ea=session.seek, limit=10000)
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
    text = _comment_text(statement.args)
    if not text:
        raise UsageError(f"{kind} comment text is required")
    payload = session.call("comment_set", ea=session.seek, text=text, kind=kind)
    return [f"{session.format_addr(int(payload['addr']))} {payload['kind']} {payload['text']}"]
