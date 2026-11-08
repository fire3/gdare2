"""Daemon discovery, state files and spawn serialization."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None


def runtime_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    path = Path(base) / f"gdare2-{os.getuid()}"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.chmod(0o700)
    return path


def data_dir() -> Path:
    # Ghidra's ProjectLocator rejects path elements that start with '.', so the
    # default project root cannot live under ~/.local/share.
    override = os.environ.get("GDARE2_DATA_DIR")
    path = Path(override) if override else Path.home() / "gdare2-data"
    path.mkdir(parents=True, exist_ok=True)
    return path


# Only options that change the imported Program identity belong in the
# instance id. Runtime actions (analysis, reimport, ephemeral, read-only)
# must not split otherwise identical instances.
FINGERPRINT_KEYS = (
    "arch",
    "bits",
    "base",
    "endian",
    "ghidra_language",
    "compiler",
    "loader",
    "loader_args",
    "force_language",
    "force_base",
    "no_analysis",
)


def import_fingerprint(import_options: dict[str, Any] | None = None) -> str:
    """Return the canonical import-options fingerprint used for instance ids."""
    options = import_options or {}
    normalized: dict[str, Any] = {}
    for key in FINGERPRINT_KEYS:
        value = options.get(key)
        if key == "loader_args" and value:
            value = [list(item) for item in value]
        normalized[key] = value
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def instance_id(
    target: str,
    *,
    import_options: dict[str, Any] | None = None,
) -> str:
    resolved = str(Path(target).expanduser().resolve())
    try:
        stat = os.stat(resolved)
        identity = f"{resolved}:{stat.st_size}:{stat.st_mtime_ns}"
    except OSError:
        identity = resolved
    fingerprint = import_fingerprint(import_options)
    return hashlib.sha256(f"{identity}:{fingerprint}".encode()).hexdigest()[:16]


def project_name(target: str, ingest_id: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(target).name) or "program"
    return f"{stem}-{ingest_id[:8]}"


def state_path(ingest_id: str) -> Path:
    return runtime_dir() / f"{ingest_id}.json"


def log_path(ingest_id: str) -> Path:
    return runtime_dir() / f"{ingest_id}.log"


def write_state(state: dict[str, Any]) -> Path:
    path = state_path(str(state["instance_id"]))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    with contextlib.suppress(OSError):
        temporary.chmod(0o600)
    temporary.replace(path)
    return path


def read_state(ingest_id: str) -> dict[str, Any] | None:
    path = state_path(ingest_id)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def remove_state(ingest_id: str) -> None:
    with contextlib.suppress(OSError):
        state_path(ingest_id).unlink()


def iter_states() -> Iterator[dict[str, Any]]:
    for path in sorted(runtime_dir().glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and "instance_id" in data:
            yield data


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def http_host(host: str | None) -> str:
    """Return a host suitable for a loopback/local HTTP URL."""
    value = (host or "").strip()
    if not value or value in {"0.0.0.0", "*"}:
        return "127.0.0.1"
    if value == "::":
        return "[::1]"
    if ":" in value and not value.startswith("["):
        return f"[{value}]"
    return value


def health(port: int, host: str | None = None, timeout: float = 0.4) -> dict[str, Any] | None:
    url = f"http://{http_host(host)}:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return data if isinstance(data, dict) else None


def live_instance(ingest_id: str) -> dict[str, Any] | None:
    state = read_state(ingest_id)
    if state is None:
        return None
    if not pid_alive(int(state.get("pid", 0))):
        remove_state(ingest_id)
        return None
    health_data = health(int(state.get("port", 0)), str(state.get("host") or ""))
    if health_data is None:
        return None
    state["health"] = health_data
    if health_data.get("state"):
        state["state"] = health_data["state"]
    return state


def find_any_live() -> dict[str, Any] | None:
    found: list[dict[str, Any]] = []
    for state in list(iter_states()):
        live = live_instance(str(state["instance_id"]))
        if live is not None:
            found.append(live)
    return found[0] if len(found) == 1 else None


@contextlib.contextmanager
def spawn_lock(ingest_id: str) -> Iterator[None]:
    path = runtime_dir() / f"{ingest_id}.lock"
    handle = path.open("a+")
    try:
        with contextlib.suppress(OSError):
            path.chmod(0o600)
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
