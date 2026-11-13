"""A practical subset of radare2's ``~`` grep language."""

from __future__ import annotations

import json
import re

from gdare2.errors import UsageError

Format = tuple[str, int | None]


def apply_spec(lines: list[str], spec: str) -> list[str]:
    return parse(spec).apply(lines)


class Filter:
    def __init__(self, spec: str) -> None:
        self.spec = spec
        self.words: list[str] = []
        self.ignore_case = False
        self.negate = False
        self.require_all = False
        self.anchor_start = False
        self.anchor_end = False
        self.count = False
        self.sort: str | None = None
        self.sort_column: int | None = None
        self.columns: tuple[tuple[int, int | None], ...] | None = None
        self.lines: tuple[int, int | None] | None = None
        self.json_pretty = False
        self._parse(spec)

    def _parse(self, spec: str) -> None:
        text = spec

        if text == "?ea":
            raise UsageError("~?ea seven-segment output is not supported")
        if text.startswith("<"):
            raise UsageError("~<> XML output is not supported")
        if text.startswith("{"):
            rest = text[1:]
            if rest.startswith(":"):
                raise UsageError("~{: JSON path selection is not supported")
            closing = rest.find("}")
            if closing >= 0:
                self.json_pretty = True
                text = rest[:closing] + rest[closing + 1 :]
            else:
                text = rest

        while text:
            if text.startswith("$!!"):
                self.sort, text = "reverse", text[3:]
            elif text.startswith("$!"):
                self.sort, text = "desc", text[2:]
            elif text.startswith("$:"):
                self.sort = "asc"
                rest = text[2:]
                match = re.match(r"(-?\d+)(!{0,2})", rest)
                if match:
                    self.sort_column = int(match.group(1))
                    if match.group(2) == "!":
                        self.sort = "desc"
                    elif match.group(2) == "!!":
                        self.sort = "reverse"
                    text = rest[match.end() :]
                else:
                    text = rest
            elif text.startswith("$"):
                self.sort, text = "asc", text[1:]
            elif text.startswith("&"):
                self.require_all, text = True, text[1:]
            elif text.startswith("+"):
                self.ignore_case, text = True, text[1:]
            elif text.startswith("!"):
                self.negate, text = True, text[1:]
            elif text.startswith("^"):
                self.anchor_start, text = True, text[1:]
            elif text.startswith("?"):
                self.count, text = True, text[1:]
            else:
                break

        if text.endswith("]") and "[" in text:
            start = text.rindex("[")
            self.columns = _parse_columns(text[start + 1 : -1])
            text = text[:start]

        if text.endswith("$"):
            self.anchor_end = True
            text = text[:-1]

        if text.startswith(":"):
            self.lines = _parse_lines(text[1:])
            text = ""
        elif ":" in text:
            head, _, tail = text.rpartition(":")
            if _is_line_range(tail):
                self.lines, text = _parse_lines(tail), head
            elif tail in (")", "))", "}", ">", "{"):
                raise UsageError(f"~:{tail} format conversion is not supported")

        if text:
            self.words = text.split() if self.require_all else text.split(",")

    def matches(self, line: str) -> bool:
        if not self.words:
            return True
        haystack = line.lower() if self.ignore_case else line
        needles = [word.lower() if self.ignore_case else word for word in self.words]
        checks = []
        for needle in needles:
            try:
                pattern = re.compile(needle)
            except re.error:
                pattern = re.compile(re.escape(needle))
            found = pattern.search(haystack) is not None
            if self.anchor_start:
                found = found and (haystack.startswith(needle) or bool(pattern.match(haystack)))
            if self.anchor_end:
                found = found and (haystack.endswith(needle) or bool(pattern.search(haystack + "$")))
            checks.append(found)
        result = all(checks) if self.require_all else any(checks)
        return not result if self.negate else result

    def apply(self, lines: list[str]) -> list[str]:
        selected = lines
        if self.words or self.negate:
            selected = [line for line in selected if self.matches(line)]
        if self.json_pretty:
            selected = _pretty_json(selected)
        if self.sort is not None:
            selected = _sorted_lines(selected, self.sort, self.sort_column)
        if self.lines is not None:
            selected = _slice_lines(selected, self.lines)
        if self.columns is not None:
            selected = [_pick_columns(line, self.columns) for line in selected]
        if self.count:
            return [str(len(selected))]
        return selected


def parse(spec: str) -> Filter:
    return Filter(spec)


def _pretty_json(lines: list[str]) -> list[str]:
    text = "\n".join(lines)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        raise UsageError("~{} needs JSON input") from None
    return json.dumps(value, indent=2).splitlines()


def _sorted_lines(lines: list[str], mode: str, column: int | None) -> list[str]:
    if mode == "reverse":
        return list(reversed(lines))
    if column is None:
        return sorted(lines, reverse=mode == "desc")
    return sorted(lines, key=lambda line: _column_key(line, column), reverse=mode == "desc")


def _column_key(line: str, column: int):
    fields = line.split()
    if not fields:
        return (1, "")
    index = column if column >= 0 else len(fields) + column
    if not 0 <= index < len(fields):
        return (1, "")
    token = fields[index]
    try:
        return (0, int(token, 0))
    except ValueError:
        return (1, token)


def _is_line_range(text: str) -> bool:
    return bool(re.fullmatch(r"-?\d*(?:[-:]-?\d*)?", text))


def _parse_lines(text: str) -> tuple[int, int | None]:
    if text == "":
        return (0, None)
    if not _is_line_range(text):
        raise UsageError(f"~:{text} format conversion is not supported")
    if ":" in text:
        first, _, last = text.partition(":")
        return (int(first or 0), int(last) if last else None)
    if "-" in text[1:]:
        first, _, last = text.partition("-")
        return (int(first or 0), int(last) if last else None)
    value = int(text)
    if value < 0:
        return (value, None) if value == -1 else (value, value + 1)
    return (value, value + 1)


def _slice_lines(lines: list[str], bounds: tuple[int, int | None]) -> list[str]:
    first, last = bounds
    if last is None:
        return lines[first:]
    return lines[first:last]


def _parse_columns(inner: str) -> tuple[tuple[int, int | None], ...]:
    if not inner:
        raise UsageError("empty column selector")
    selections: list[tuple[int, int | None]] = []
    for token in inner.split(","):
        token = token.strip()
        if not token:
            raise UsageError(f"bad column selector {inner!r}")
        if re.fullmatch(r"-?\d+", token):
            index = int(token)
            selections.append((index, index))
            continue
        match = re.fullmatch(r"(-?\d*)-(-?\d*)", token)
        if match is None or (not match.group(1) and not match.group(2)):
            raise UsageError(f"bad column selector {token!r}")
        first = int(match.group(1)) if match.group(1) else 0
        last = int(match.group(2)) if match.group(2) else None
        selections.append((first, last))
    return tuple(selections)


def _pick_columns(line: str, columns: tuple[tuple[int, int | None], ...]) -> str:
    fields = line.split()
    count = len(fields)
    picked: list[str] = []
    for first, last in columns:
        start = first if first >= 0 else count + first
        if last is None:
            stop = count
        elif last >= 0:
            stop = last + 1
        else:
            stop = count + last + 1
        if start < 0:
            start = 0
        picked.extend(fields[start:stop])
    return " ".join(picked)
