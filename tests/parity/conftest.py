from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def gdare2_env(tmp_path_factory):
    root = tmp_path_factory.mktemp("gdare2-parity")
    env = os.environ.copy()
    env["GDARE2_DATA_DIR"] = str(root / "data")
    env["XDG_RUNTIME_DIR"] = str(root / "run")
    env["HOME"] = str(root / "home")
    env["XDG_CONFIG_HOME"] = str(root / "config")
    env["XDG_STATE_HOME"] = str(root / "state")
    env.setdefault("GHIDRA_INSTALL_DIR", os.path.expanduser("~/ghidra/current"))
    yield env
    runtime = root / "run" / f"gdare2-{os.getuid()}"
    for state_file in runtime.glob("*.json"):
        try:
            pid = int(json.loads(state_file.read_text())["pid"])
        except (OSError, ValueError, KeyError):
            continue
        _stop_process(pid)


@pytest.fixture(scope="session")
def run_gdare2(gdare2_env):
    def run(*args: str, timeout: int = 1800) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "gdare2", *args],
            capture_output=True,
            text=True,
            env=gdare2_env,
            timeout=timeout,
        )

    return run


def _stop_process(pid: int, grace: float = 10.0) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)
