"""Version and availability reporting for ``gdare2 -V``.

The client must never import PyGhidra or start a JVM, so every check in this
module is based on distribution metadata, files, and short subprocesses.
That keeps ``gdare2 -V`` useful even on a machine where Ghidra or Java is not
installed yet.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as dist_version
from pathlib import Path

from gdare2 import PROTOCOL_VERSION, __version__

LABEL_WIDTH = 12
JAVA_VERSION_RE = re.compile(r'version\s+"([^"]+)"')
JAVA_MAJOR_RE = re.compile(r"^(?:1\.)?(\d+)")


@dataclass(frozen=True)
class GhidraInfo:
    """Result of locating a Ghidra installation without starting it."""

    root: Path
    version: str = ""
    release: str = ""
    java_min: int = 0
    error: str = ""

    @property
    def available(self) -> bool:
        return not self.error


def ghidra_info(
    environ: Mapping[str, str] | None = None,
    home: str | Path | None = None,
) -> GhidraInfo:
    """Resolve Ghidra exactly like the daemon launcher does.

    ``GHIDRA_INSTALL_DIR`` wins; otherwise ``~/ghidra/current`` is used.
    Only ``Ghidra/application.properties`` is read, so no JVM is involved.
    """
    env = os.environ if environ is None else environ
    configured = env.get("GHIDRA_INSTALL_DIR")
    if configured:
        root = Path(configured).expanduser()
        missing = f"GHIDRA_INSTALL_DIR does not point to a Ghidra install ({root})"
    else:
        root = Path.home() if home is None else Path(home).expanduser()
        root = root / "ghidra" / "current"
        missing = "GHIDRA_INSTALL_DIR is not set and ~/ghidra/current does not exist"

    properties = root / "Ghidra" / "application.properties"
    try:
        text = properties.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return GhidraInfo(root=root, error=missing)

    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip()

    version = fields.get("application.version", "")
    if not version:
        return GhidraInfo(root=root, error=f"application.version is missing from {properties}")

    try:
        java_min = int(fields.get("application.java.min", "") or 0)
    except ValueError:
        java_min = 0
    return GhidraInfo(
        root=root,
        version=version,
        release=fields.get("application.release.name", ""),
        java_min=java_min,
    )


def java_executable(environ: Mapping[str, str] | None = None) -> Path | None:
    """Find Java the way PyGhidra does: PATH first, then ``JAVA_HOME``."""
    env = os.environ if environ is None else environ
    found = shutil.which("java")
    if found:
        return Path(found)

    java_home = env.get("JAVA_HOME")
    if not java_home:
        return None
    names = ("java.exe", "java") if os.name == "nt" else ("java",)
    for name in names:
        candidate = Path(java_home).expanduser() / "bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def java_version(executable: str | Path) -> str:
    """Return the version reported by ``java -version``, or an empty string."""
    try:
        result = subprocess.run(
            [str(executable), "-version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    output = (result.stderr or "") + "\n" + (result.stdout or "")
    match = JAVA_VERSION_RE.search(output)
    if match:
        return match.group(1)
    for line in output.splitlines():
        if line.strip():
            return line.strip()
    return ""


def java_major(version: str) -> int:
    match = JAVA_MAJOR_RE.match(version)
    return int(match.group(1)) if match else 0


def version_lines(
    environ: Mapping[str, str] | None = None,
    home: str | Path | None = None,
) -> list[str]:
    """Build the aligned, idare2-style report printed by ``gdare2 -V``."""
    info = ghidra_info(environ, home)
    return [
        _line("gdare2", f"{__version__} (protocol {PROTOCOL_VERSION})"),
        _line("pyghidra", _pyghidra_version()),
        _line("ghidra", _ghidra_version(info)),
        _line("java", _java_version(info, environ)),
        _line("python", platform.python_version()),
    ]


def _line(label: str, value: str) -> str:
    return f"{label:<{LABEL_WIDTH}}{value}"


def _pyghidra_version() -> str:
    try:
        return dist_version("pyghidra")
    except PackageNotFoundError:
        return "unavailable (not installed)"


def _ghidra_version(info: GhidraInfo) -> str:
    if not info.available:
        return f"unavailable ({info.error})"
    detail = info.version
    if info.release:
        detail += f" {info.release}"
    return f"{detail} ({info.root})"


def _java_version(info: GhidraInfo, environ: Mapping[str, str] | None) -> str:
    executable = java_executable(environ)
    if executable is None:
        requirement = ""
        if info.available and info.java_min:
            requirement = f"; Ghidra {info.version} needs Java {info.java_min}+"
        return f"unavailable (no java in PATH or JAVA_HOME{requirement})"

    version = java_version(executable)
    if not version:
        return f"unavailable ({executable} did not report a version)"

    major = java_major(version)
    if info.available and info.java_min and major and major < info.java_min:
        return f"{version} (too old; Ghidra {info.version} needs Java {info.java_min}+) at {executable}"
    return f"{version} ({executable})"
