from __future__ import annotations

from gdare2 import argv, cli


class FakeSession:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def run(self, line: str):
        self.commands.append(line)
        return []


def test_analysis_request_runs_aa_once():
    session = FakeSession()
    options = argv.parse(["-q", "-A", "/bin/ls"])
    cli._analysis_request(session, options)
    assert session.commands == ["aa"]


def test_analysis_request_runs_aaa_for_double_a():
    session = FakeSession()
    options = argv.parse(["-q", "-AA", "/bin/ls"])
    cli._analysis_request(session, options)
    assert session.commands == ["aaa"]


def test_analysis_request_is_a_noop_without_a():
    session = FakeSession()
    cli._analysis_request(session, argv.parse(["/bin/ls"]))
    assert session.commands == []
