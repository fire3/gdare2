"""``|`` pipes, ``>`` redirection and ``!`` shell escapes."""

from __future__ import annotations

import subprocess
from pathlib import Path

from gdare2.errors import CommandError, UsageError


def run_pipe(lines: list[str], command: str) -> list[str]:
    if not command.strip():
        raise UsageError("empty pipe command")
    try:
        completed = subprocess.run(
            command,
            shell=True,
            input="\n".join(lines) + ("\n" if lines else ""),
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise CommandError(f"pipe failed: {exc}") from exc
    if completed.returncode != 0 and completed.stderr:
        raise CommandError(completed.stderr.rstrip())
    return completed.stdout.splitlines()


def run_shell(command: str) -> list[str]:
    try:
        completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    except OSError as exc:
        raise CommandError(f"shell command failed: {exc}") from exc
    if completed.returncode != 0 and completed.stderr:
        raise CommandError(completed.stderr.rstrip())
    return completed.stdout.splitlines()


def redirect(lines: list[str], target: str, *, append: bool = False) -> None:
    path = Path(target).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a" if append else "w", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line)
                handle.write("\n")
    except OSError as exc:
        raise CommandError(f"cannot write {target}: {exc}") from exc
