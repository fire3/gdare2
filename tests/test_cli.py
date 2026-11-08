from __future__ import annotations

from gdare2 import argv, cli


class FakeConfig:
    @staticmethod
    def get_str(name):
        return "wait"


class FakeSession:
    config = FakeConfig()

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


def test_analysis_wait_skip_disables_auto_analysis():
    class SkipConfig:
        @staticmethod
        def get_str(name):
            return "skip"

    session = FakeSession()
    session.config = SkipConfig()
    options = argv.parse(["-q", "-A", "/bin/ls"])
    cli._analysis_request(session, options)
    assert session.commands == []
