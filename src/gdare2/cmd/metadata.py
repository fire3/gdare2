"""Additional ``C`` metadata commands: hidden data, strings, magic and types."""

from __future__ import annotations

from dataclasses import replace

from gdare2.cmd import command, require_write
from gdare2.cmd.print import _pf_command
from gdare2.errors import NotFoundError, UsageError
from gdare2.escape import unquote_text
from gdare2.formats.magic import scan as scan_magic
from gdare2.jsonutil import dumps


@command("Ch", "hide the item at seek", aliases=("Ch-",))
def _hidden(session, statement):
    require_write(session)
    if statement.cmd == "Ch-":
        session.hidden_ranges = [
            (start, stop)
            for start, stop in session.hidden_ranges
            if not (start <= session.seek <= stop)
        ]
        return []
    text = statement.args.strip()
    size = session.eval(text) if text else session.blocksize
    if size <= 0:
        raise UsageError("Ch size must be positive")
    session.hidden_ranges.append((session.seek, session.seek + size - 1))
    return []


@command("Cs", "manage string metadata", aliases=("Cs-", "Cs.", "Cs*", "Cs.j", "Csj"))
def _strings(session, statement):
    token = statement.cmd
    text = statement.args.strip()
    if token in ("Cs", "Csj") and not text:
        rows = sorted(session.strings.items())
        if token == "Csj":
            return [dumps([item for _addr, item in rows])]
        return [
            f"{session.format_addr(int(item['addr']))} {int(item['size']):4d} {item['string']}"
            for _addr, item in rows
        ]
    if token == "Cs-":
        require_write(session)
        if session.strings.pop(session.seek, None) is None:
            raise NotFoundError(f"no string metadata at {session.format_addr(session.seek)}")
        return []
    if token in ("Cs.", "Cs.j"):
        item = session.strings.get(session.seek)
        if item is None:
            raise NotFoundError(f"no string metadata at {session.format_addr(session.seek)}")
        if token == "Cs.j":
            return [dumps(item)]
        return [str(item["string"])]
    if token == "Cs*":
        return [
            f"Cs {int(item['size'])} @ {session.format_addr(int(item['addr']))}"
            for _addr, item in sorted(session.strings.items())
        ]
    require_write(session)
    size = session.eval(text) if text else 0
    if size < 0:
        raise UsageError("Cs size must not be negative")
    if size:
        data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    else:
        data = bytes(session.call("read_bytes", ea=session.seek, size=session.blocksize))
        data = data.split(b"\x00", 1)[0]
        size = len(data)
    if not data:
        raise UsageError("Cs needs bytes at the current address")
    decoded = data.decode("latin-1", errors="replace")
    session.strings[session.seek] = {
        "addr": session.seek,
        "size": int(size),
        "string": decoded,
        "type": "ascii",
    }
    return []


@command("Cm", "parse magic signatures at seek", aliases=("Cm-", "Cm.", "Cmj"))
def _magic(session, statement):
    token = statement.cmd
    if token == "Cm-":
        require_write(session)
        if session.magic.pop(session.seek, None) is None:
            raise NotFoundError(f"no magic metadata at {session.format_addr(session.seek)}")
        return []
    if token in ("Cm.", "Cmj"):
        value = session.magic.get(session.seek)
        if value is None:
            raise NotFoundError(f"no magic metadata at {session.format_addr(session.seek)}")
        return [dumps({"addr": session.seek, "name": value})] if token == "Cmj" else [value]
    require_write(session)
    size = session.blocksize
    data = bytes(session.call("read_bytes", ea=session.seek, size=size))
    hits = scan_magic(data, limit=1)
    if not hits:
        raise NotFoundError(f"Cm: no known magic at {session.format_addr(session.seek)}")
    session.magic[session.seek] = str(hits[0]["name"])
    return [str(hits[0]["name"])]


@command("Cf", "format memory using a pf format", aliases=("Cf-",))
def _formatted_memory(session, statement):
    if statement.cmd == "Cf-":
        return []
    text = unquote_text(statement.args)
    words = text.split()
    if not words:
        raise UsageError("Cf needs a size and a pf format")
    if len(words) > 1:
        try:
            int(words[0], 0)
        except ValueError:
            pass
        else:
            words = words[1:]
    if not words:
        raise UsageError("Cf needs a pf format")
    return _pf_command(session, replace(statement, cmd="pf", args=" ".join(words)))


@command("Ct", "manage variable type comments", aliases=("Ct.", "Ct-", "Ctj"))
def _type_comments(session, statement):
    token = statement.cmd
    text = unquote_text(statement.args).strip()
    if token == "Ct":
        if text:
            require_write(session)
            session.type_comments[session.seek] = text
            return []
        return [
            f"{session.format_addr(address)} {comment}"
            for address, comment in sorted(session.type_comments.items())
        ]
    if token == "Ctj":
        return [
            dumps(
                [
                    {"addr": address, "comment": comment}
                    for address, comment in sorted(session.type_comments.items())
                ]
            )
        ]
    if token == "Ct-":
        require_write(session)
        if session.type_comments.pop(session.seek, None) is None:
            raise NotFoundError(f"no type comment at {session.format_addr(session.seek)}")
        return []
    comment = session.type_comments.get(session.seek)
    if comment is None:
        raise NotFoundError(f"no type comment at {session.format_addr(session.seek)}")
    return [comment]


@command("CL", "manage source-line metadata", aliases=("CL.", "CL-", "CLj", "CL*"))
def _source_lines(session, statement):
    token = statement.cmd
    text = unquote_text(statement.args).strip()
    if token == "CL":
        if text:
            require_write(session)
            session.source_lines[session.seek] = text
            return []
        return [
            f"{session.format_addr(address)} {line}"
            for address, line in sorted(session.source_lines.items())
        ]
    if token == "CLj":
        return [
            dumps(
                [
                    {"addr": address, "line": line}
                    for address, line in sorted(session.source_lines.items())
                ]
            )
        ]
    if token == "CL*":
        return [
            f"CL {line!r} @ {session.format_addr(address)}"
            for address, line in sorted(session.source_lines.items())
        ]
    if token == "CL-":
        require_write(session)
        if session.source_lines.pop(session.seek, None) is None:
            raise NotFoundError(f"no source line at {session.format_addr(session.seek)}")
        return []
    line = session.source_lines.get(session.seek)
    if line is None:
        raise NotFoundError(f"no source line at {session.format_addr(session.seek)}")
    return [line]
