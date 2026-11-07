"""Command registry for the client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from gdare2.errors import UnsupportedError

if TYPE_CHECKING:
    from gdare2.session import Session
    from gdare2.parser import Statement

Handler = Callable[["Session", "Statement"], list[str]]


@dataclass
class CommandSpec:
    pattern: str
    summary: str
    handler: Handler
    detail: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)


_COMMANDS: list[CommandSpec] = []
_LOADED = False


def register(spec: CommandSpec) -> CommandSpec:
    _COMMANDS.append(spec)
    return spec


def command(
    pattern: str,
    summary: str,
    detail: str = "",
    aliases: tuple[str, ...] = (),
):
    """Decorator form of :func:`register`."""

    def decorate(handler: Handler) -> Handler:
        _COMMANDS.append(CommandSpec(pattern, summary, handler, detail, aliases))
        return handler

    return decorate


def load_all() -> None:
    global _LOADED
    if _LOADED:
        return
    from gdare2.cmd import analysis, info, meta, print as print_cmd, seek, xrefs  # noqa: F401

    _LOADED = True


def all_commands() -> list[CommandSpec]:
    load_all()
    return sorted(_COMMANDS, key=lambda spec: (-len(spec.pattern), spec.pattern))


def lookup(cmd: str) -> CommandSpec | None:
    load_all()
    for spec in all_commands():
        if cmd == spec.pattern or cmd in spec.aliases:
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
