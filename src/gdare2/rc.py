"""rc-file discovery and loading for the client."""

from __future__ import annotations

import os
from pathlib import Path

#: Explicit rc file override.  ``-NN`` still disables every rc file.
ENV_OVERRIDE = "GDARE2_RCFILE"


def rc_paths(skip: int = 0, cwd: Path | None = None) -> list[Path]:
    """Return rc paths in load order (system, user, project root -> cwd)."""
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        if skip >= 2:
            return []
        path = Path(override).expanduser()
        return [path] if path.is_file() else []

    paths: list[Path] = []
    if skip < 2:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        system = config_home / "gdare2" / "rc"
        if system.is_file():
            paths.append(system)
        rc_dir = config_home / "gdare2" / "rc.d"
        if rc_dir.is_dir():
            paths.extend(
                sorted(
                    entry
                    for entry in rc_dir.iterdir()
                    if entry.is_file() and not entry.name.startswith(".")
                )
            )
    if skip < 1:
        user = Path.home() / ".gdare2rc"
        if user.is_file():
            paths.append(user)
        seen = {user}
        for path in _project_rc_paths(cwd):
            if path not in seen:
                paths.append(path)
                seen.add(path)
    return paths


def _project_rc_paths(cwd: Path | None) -> list[Path]:
    """``.gdare2rc`` files from the filesystem root down to the cwd."""
    try:
        start = (cwd or Path.cwd()).resolve()
    except OSError:
        return []
    found: list[Path] = []
    for directory in reversed([start, *start.parents]):
        candidate = directory / ".gdare2rc"
        if candidate.is_file():
            found.append(candidate)
    return found


def load(skip: int = 0) -> list[str]:
    lines: list[str] = []
    for path in rc_paths(skip):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lines.append(stripped)
    return lines
