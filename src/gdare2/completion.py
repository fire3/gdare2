"""Readline history path and tab completion candidates."""

from __future__ import annotations

import os
from pathlib import Path

from gdare2 import cmd
from gdare2.config import KEYS


def history_path() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return state_home / "gdare2" / "history"


def complete_line(line: str, text: str) -> list[str]:
    stripped = line.lstrip()
    if stripped.startswith("e ") or stripped == "e":
        return sorted(key.name for key in KEYS if key.name.startswith(text))
    names: set[str] = set()
    for spec in cmd.all_commands():
        names.add(spec.pattern)
        names.update(spec.aliases)
    return sorted(name for name in names if name.startswith(text))


def make_completer():
    import readline

    def complete(text: str, state: int):
        matches = complete_line(readline.get_line_buffer(), text)
        if state < len(matches):
            return matches[state]
        return None

    return complete


def setup_readline():
    try:
        import readline
    except ImportError:
        return None
    path = history_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        readline.read_history_file(path)
    except OSError:
        pass
    readline.set_history_length(2000)
    readline.set_completer_delims(" \t\n")
    readline.set_completer(make_completer())
    readline.parse_and_bind("tab: complete")
    return path


def save_history(path: Path | None) -> None:
    if path is None:
        return
    try:
        import readline

        readline.write_history_file(path)
    except (ImportError, OSError):
        pass
