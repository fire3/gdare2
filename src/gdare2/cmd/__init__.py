"""Command registry for the client."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from gdare2.errors import ReadOnlyError, UnsupportedError

if TYPE_CHECKING:
    from gdare2.parser import Statement
    from gdare2.session import Session

Handler = Callable[["Session", "Statement"], list[str]]


@dataclass
class CommandSpec:
    pattern: str
    summary: str
    handler: Handler
    detail: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)
    consumes_repeat: bool = False


_COMMANDS: list[CommandSpec] = []
_LOADED = False


def register(spec: CommandSpec) -> CommandSpec:
    for existing in _COMMANDS:
        if existing.pattern == spec.pattern:
            raise ValueError(f"duplicate command pattern {spec.pattern!r}")
    _COMMANDS.append(spec)
    return spec


def command(
    pattern: str,
    summary: str,
    detail: str = "",
    aliases: tuple[str, ...] = (),
    consumes_repeat: bool = False,
):
    """Decorator form of :func:`register`."""

    def decorate(handler: Handler) -> Handler:
        register(
            CommandSpec(pattern, summary, handler, detail, aliases, consumes_repeat)
        )
        return handler

    return decorate


def load_all() -> None:
    global _LOADED
    if _LOADED:
        return
    from gdare2.cmd import (  # noqa: F401
        analysis,
        assemble,
        comments,
        flags,
        info,
        meta,
        misc,
        search,
        seek,
        types,
        write,
        xrefs,
    )
    from gdare2.cmd import (  # noqa: F401
        print as print_cmd,
    )

    _LOADED = True


def all_commands() -> list[CommandSpec]:
    load_all()
    return sorted(_COMMANDS, key=lambda spec: (-len(spec.pattern), spec.pattern))


_PREFIX_BASES = (("pfj.", "pfj"), ("pfs.", "pfs"), ("pf.", "pf"))


def lookup(cmd: str) -> CommandSpec | None:
    load_all()
    for spec in all_commands():
        if cmd == spec.pattern or cmd in spec.aliases:
            return spec
    if cmd.startswith("$"):
        for spec in all_commands():
            if spec.pattern == "$":
                return spec
    for prefix, base in _PREFIX_BASES:
        if cmd.startswith(prefix) and len(cmd) > len(prefix):
            for spec in all_commands():
                if spec.pattern == base:
                    return spec
    return None


def help_text() -> list[str]:
    lines = ["Usage: gdare2 [target] [options] [-c command]...", "", "Commands:"]
    for spec in all_commands():
        lines.append(f"  {spec.pattern:<10} {spec.summary}")
    return lines


def help_for(spec: CommandSpec) -> list[str]:
    return [f"{spec.pattern}: {spec.summary}", *(spec.detail.splitlines() if spec.detail else [])]


def unknown(cmd: str) -> UnsupportedError:
    return UnsupportedError(f"unknown or unsupported command {cmd!r}")


def require_write(session) -> None:
    """Reject writes in a read-only client before the daemon round-trip."""
    if session.readonly:
        raise ReadOnlyError("read-only session: re-run with -w to allow writes")
