from __future__ import annotations

from gdare2d.import_plan import ImportPlan
from gdare2d.runtime import GhidraRuntime


def runtime() -> GhidraRuntime:
    return GhidraRuntime(
        target="/bin/true",
        project_dir="/tmp/unused",
        project_name="unused",
        program_path="/true",
        plan=ImportPlan(target="/bin/true"),
    )


def test_session_lease_round_trip():
    rt = runtime()
    lease = rt.session_open(pid=1, kind="batch", tty=False, ttl=30)
    assert rt.has_active_sessions()
    assert rt.session_list()[0]["lease"] == lease
    assert rt.session_heartbeat(lease, 30)
    assert rt.session_close(lease)
    assert not rt.has_active_sessions()


def test_expired_session_is_purged(monkeypatch):
    rt = runtime()
    lease = rt.session_open(pid=1, kind="batch", tty=False, ttl=10)
    rt.sessions[lease]["expires"] = 0
    assert not rt.has_active_sessions()
