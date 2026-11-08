"""rc-file discovery and loading for the client."""

from __future__ import annotations

import os
from pathlib import Path


def rc_paths(skip: int = 0) -> list[Path]:
    """Return rc paths in load order (system first, user last)."""
    paths: list[Path] = []
    if skip < 2:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        paths.append(config_home / "gdare2" / "rc")
    if skip < 1:
        paths.append(Path.home() / ".gdare2rc")
    return [path for path in paths if path.is_file()]


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
