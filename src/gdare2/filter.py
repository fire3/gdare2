"""A practical subset of radare2's ``~`` grep language."""

from __future__ import annotations

import re

from gdare2.errors import UsageError


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
        self.columns: tuple[int, int | None] | None = None
        self.lines: tuple[int, int | None] | None = None
        self._parse(spec)

    def _parse(self, spec: str) -> None:
        text = spec
        while text:
            if text.startswith("$!!"):
                self.sort, text = "reverse", text[3:]
            elif text.startswith("$!"):
                self.sort, text = "desc", text[2:]
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
            inner = text[start + 1 : -1]
            self.columns = _parse_columns(inner)
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
        if self.columns is not None:
            selected = [_pick_columns(line, self.columns) for line in selected]
        if self.lines is not None:
            selected = _slice_lines(selected, self.lines)
        if self.sort == "asc":
            selected = sorted(selected)
        elif self.sort == "desc":
            selected = sorted(selected, reverse=True)
        elif self.sort == "reverse":
            selected = list(reversed(selected))
        if self.count:
            return [str(len(selected))]
        return selected


def parse(spec: str) -> Filter:
    return Filter(spec)


def _is_line_range(text: str) -> bool:
    return bool(re.fullmatch(r"-?\d*(?:[-:]-?\d*)?", text))


def _parse_lines(text: str) -> tuple[int, int | None]:
    if text == "":
        return (0, None)
    if "-" in text:
        first, _, last = text.partition("-")
        return (int(first or 0), int(last) if last else None)
    value = int(text)
    if value >= 0:
        return (value, value + 1)
    return (value, None)


def _slice_lines(lines: list[str], bounds: tuple[int, int | None]) -> list[str]:
    first, last = bounds
    if last is None:
        return lines[first:] if first >= 0 else lines[first:]
    if first < 0 or last < 0:
        return lines[first:last]
    return lines[first:last]


def _parse_columns(inner: str) -> tuple[int, int | None]:
    if not inner:
        raise UsageError("empty column selector")
    if "," in inner:
        raise UsageError("multi-column selectors are not implemented yet")
    if "-" in inner:
        first, _, last = inner.partition("-")
        return (int(first), int(last) if last else None)
    return (int(inner), None)


def _pick_columns(line: str, columns: tuple[int, int | None]) -> str:
    fields = line.split()
    first, last = columns
    if last is None:
        return fields[first] if 0 <= first < len(fields) else ""
    return " ".join(fields[first:last])
