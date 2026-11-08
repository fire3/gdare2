"""radare2-flavoured command parsing.

Modifiers are peeled from the statement in the same order as radare2:
``;`` then ``@`` then ``~`` then ``|`` then ``>``.  Quotes are respected while
looking for top-level operators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from gdare2.errors import UsageError


@dataclass
class Statement:
    cmd: str = ""
    args: str = ""
    tmpseek: str | None = None
    range: tuple[str, str] | None = None
    filter: str | None = None
    pipe: str | None = None
    redirect: str | None = None
    append: bool = False
    repeat: int = 1
    help: bool = False
    dot: bool = False
    shell: bool = False
    iterator: str | None = None
    iterator_size: str | None = None


def _scan(text: str, char: str, *, from_right: bool = True) -> int:
    """Find ``char`` outside quotes.  ``>`` also skips ``>>``-style runs."""
    quote: str | None = None
    escaped = False
    indices = range(len(text) - 1, -1, -1) if from_right else range(len(text))
    for index in indices:
        current = text[index]
        if escaped:
            escaped = False
            continue
        if current == "\\":
            escaped = True
            continue
        if quote is not None:
            if current == quote:
                quote = None
            continue
        if current in ("'", '"'):
            quote = current
            continue
        if current == char:
            return index
    return -1


def split_statements(line: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char == ";":
            parts.append(line[start:index])
            start = index + 1
    parts.append(line[start:])
    return [part for part in parts if part.strip()]


def parse(line: str) -> list[Statement]:
    return [parse_statement(part) for part in split_statements(line)]


def parse_statement(text: str) -> Statement:
    statement = Statement()
    text = text.strip()

    # 1. redirection (rightmost top-level >, with >> treated as append)
    index = _scan(text, ">")
    if index >= 0:
        append = index > 0 and text[index - 1] == ">"
        start = index - 1 if append else index
        statement.redirect = text[index + 1 :].strip()
        statement.append = append
        if not statement.redirect:
            raise UsageError("redirection needs a file")
        text = text[:start].rstrip()

    # 2. pipe
    index = _scan(text, "|")
    if index >= 0 and not (index > 0 and text[index - 1] == "|") and not (
        index + 1 < len(text) and text[index + 1] == "|"
    ):
        statement.pipe = text[index + 1 :].strip()
        if not statement.pipe:
            raise UsageError("empty pipe command")
        text = text[:index].rstrip()

    # 3. grep
    index = _scan(text, "~")
    if index >= 0:
        statement.filter = text[index + 1 :]
        text = text[:index].rstrip()

    # 4. temporary seek / iterator
    index = _scan(text, "@")
    if index >= 0:
        start = index
        while start > 0 and text[start - 1] == "@":
            start -= 1
        count = index - start + 1
        spec = text[index + 1 :].strip()
        if count >= 3:
            statement.iterator_size = spec
        elif count == 2:
            statement.iterator = spec
        elif spec.startswith("{") and spec.endswith("}"):
            inner = spec[1:-1].strip()
            parts = inner.split()
            if len(parts) != 2:
                raise UsageError("@{from to} needs exactly two addresses")
            statement.range = (parts[0], parts[1])
        else:
            statement.tmpseek = spec
        text = text[:start].rstrip()
        if count >= 2 and not spec:
            raise UsageError("@ iteration needs an operand")
        if count == 1 and not spec:
            raise UsageError("@ seek needs an operand")

    # 5. dot / shell / repeat
    if text.startswith("."):
        statement.dot = True
        text = text[1:].lstrip()
    elif text.startswith("!"):
        statement.shell = True
        statement.args = text[1:].lstrip()
        return statement

    if re.fullmatch(r"0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+", text):
        statement.cmd = "s"
        statement.args = text
        return statement

    match = re.match(r"(\d+)(.*)", text, re.DOTALL)
    if match and match.group(2).strip() and not match.group(2).strip()[0].isdigit():
        statement.repeat = int(match.group(1))
        text = match.group(2).lstrip()

    if not text:
        return statement

    parts = text.split(None, 1)
    cmd = parts[0]
    statement.args = parts[1] if len(parts) > 1 else ""
    if cmd.endswith("?") and cmd not in ("?", "??", "???", "f?", "$?"):
        statement.help = True
        cmd = cmd[:-1]
    elif cmd == "??":
        statement.cmd = "?"
        statement.args = "?"
        return statement
    statement.cmd = cmd
    return statement
