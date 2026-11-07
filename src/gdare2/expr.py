"""radare2-style integer expressions.

Bare digits are decimal; ``0x``, ``0b`` and ``0o`` select other bases.  Names
and ``$`` variables are resolved through a small :class:`Resolver` protocol so
the same code serves ``s``, ``@`` and ``?``.
"""

from __future__ import annotations

import re
from typing import Protocol

from gdare2.errors import UsageError


class Resolver(Protocol):
    pointer_size: int

    def lookup_name(self, name: str) -> int | None: ...

    def get_var(self, name: str) -> int | None: ...

    def deref(self, addr: int, size: int) -> int: ...


_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|[0-9]+")
_NAME = re.compile(r"[A-Za-z_.][A-Za-z0-9_.$:]*")
_VAR = re.compile(r"\$[A-Za-z0-9_?.]*")

_OPS = (
    "<<",
    ">>",
    "<=",
    ">=",
    "==",
    "!=",
    "&&",
    "||",
    "+",
    "-",
    "*",
    "/",
    "%",
    "&",
    "|",
    "^",
    "~",
    "!",
    "<",
    ">",
    "(",
    ")",
    "[",
    "]",
)


def _tokenize(text: str) -> list[tuple[str, object, int]]:
    tokens: list[tuple[str, object, int]] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "$":
            if text.startswith("$$", index):
                tokens.append(("var", "", index))
                index += 2
                continue
            match = _VAR.match(text, index)
            if match is None:
                raise UsageError(f"bad expression: dangling '$' at {index}")
            tokens.append(("var", match.group()[1:], index))
            index = match.end()
            continue
        match = _NUMBER.match(text, index)
        if match is not None:
            raw = match.group()
            if raw[:2].lower() == "0x":
                value = int(raw, 16)
            elif raw[:2].lower() == "0b":
                value = int(raw, 2)
            elif raw[:2].lower() == "0o":
                value = int(raw, 8)
            else:
                value = int(raw, 10)
            tokens.append(("num", value, index))
            index = match.end()
            continue
        match = _NAME.match(text, index)
        if match is not None:
            tokens.append(("name", match.group(), index))
            index = match.end()
            continue
        for op in _OPS:
            if text.startswith(op, index):
                tokens.append(("op", op, index))
                index += len(op)
                break
        else:
            raise UsageError(f"bad expression {text!r}: unexpected {char!r}")
    return tokens


class _Evaluator:
    _BINARY = {
        "||": 1,
        "&&": 2,
        "|": 3,
        "^": 4,
        "&": 5,
        "==": 6,
        "!=": 6,
        "<": 7,
        "<=": 7,
        ">": 7,
        ">=": 7,
        "<<": 8,
        ">>": 8,
        "+": 9,
        "-": 9,
        "*": 10,
        "/": 10,
        "%": 10,
    }

    def __init__(self, tokens, resolver: Resolver, text: str) -> None:
        self.tokens = tokens
        self.resolver = resolver
        self.text = text
        self.index = 0

    def parse(self) -> int:
        value = self.binary(1)
        if self.index != len(self.tokens):
            raise UsageError(f"bad expression {self.text!r}: trailing input")
        return value

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self):
        token = self.peek()
        if token is None:
            raise UsageError(f"bad expression {self.text!r}: unexpected end")
        self.index += 1
        return token

    def expect(self, op: str) -> None:
        token = self.take()
        if token[0] != "op" or token[1] != op:
            raise UsageError(f"bad expression {self.text!r}: expected {op!r}")

    def binary(self, min_prec: int) -> int:
        lhs = self.unary()
        while True:
            token = self.peek()
            if token is None or token[0] != "op":
                break
            op = str(token[1])
            prec = self._BINARY.get(op)
            if prec is None or prec < min_prec:
                break
            self.take()
            rhs = self.binary(prec + 1)
            lhs = self.apply(op, lhs, rhs)
        return lhs

    def unary(self) -> int:
        token = self.peek()
        if token is not None and token[0] == "op" and token[1] in ("+", "-", "~", "!"):
            self.take()
            value = self.unary()
            if token[1] == "-":
                return -value
            if token[1] == "~":
                return ~value
            if token[1] == "!":
                return 1 if value == 0 else 0
            return value
        return self.primary()

    def primary(self) -> int:
        token = self.take()
        kind, value, _ = token
        if kind in ("num", "var", "name"):
            if kind == "num":
                return int(value)
            if kind == "var":
                result = self.resolver.get_var(str(value))
                if result is None:
                    raise UsageError(f"unknown variable ${value}")
                return result
            result = self.resolver.lookup_name(str(value))
            if result is None:
                raise UsageError(f"unknown name {value!r}")
            return result
        if kind == "op" and value == "(":
            result = self.binary(1)
            self.expect(")")
            return result
        if kind == "op" and value == "[":
            address = self.binary(1)
            self.expect("]")
            return self.resolver.deref(address, self.resolver.pointer_size)
        raise UsageError(f"bad expression {self.text!r}: unexpected {value!r}")

    @staticmethod
    def apply(op: str, lhs: int, rhs: int) -> int:
        if op == "+":
            return lhs + rhs
        if op == "-":
            return lhs - rhs
        if op == "*":
            return lhs * rhs
        if op == "/":
            if rhs == 0:
                raise UsageError("division by zero")
            return int(lhs / rhs)
        if op == "%":
            if rhs == 0:
                raise UsageError("modulo by zero")
            return lhs - rhs * int(lhs / rhs)
        if op == "&":
            return lhs & rhs
        if op == "|":
            return lhs | rhs
        if op == "^":
            return lhs ^ rhs
        if op == "<<":
            return lhs << rhs
        if op == ">>":
            return lhs >> rhs
        if op == "==":
            return int(lhs == rhs)
        if op == "!=":
            return int(lhs != rhs)
        if op == "<":
            return int(lhs < rhs)
        if op == "<=":
            return int(lhs <= rhs)
        if op == ">":
            return int(lhs > rhs)
        if op == ">=":
            return int(lhs >= rhs)
        if op == "&&":
            return int(bool(lhs) and bool(rhs))
        if op == "||":
            return int(bool(lhs) or bool(rhs))
        raise UsageError(f"unsupported operator {op!r}")


def evaluate(text: str, resolver: Resolver) -> int:
    stripped = text.strip()
    if not stripped:
        raise UsageError("empty expression")
    return _Evaluator(_tokenize(stripped), resolver, stripped).parse()


def is_number_literal(text: str) -> bool:
    return bool(_NUMBER.fullmatch(text.strip()))
