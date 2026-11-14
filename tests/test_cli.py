from __future__ import annotations

from gdare2 import argv, cli
from gdare2.config import Config


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


def test_cli_config_applies_assembler_and_explicit_evals():
    config = Config()
    options = argv.parse(
        [
            "--assembler",
            "rasm2",
            "-e",
            "asm.assembler=auto",
            "-e",
            "asm.bytes=false",
            "/bin/ls",
        ]
    )
    cli._apply_cli_config(config, options)
    assert config.get_str("asm.assembler") == "auto"
    assert config.get_bool("asm.bytes") is False


def test_cli_config_leaves_assembler_default_without_option():
    config = Config()
    cli._apply_cli_config(config, argv.parse(["/bin/ls"]))
    assert config.get_str("asm.assembler") == "ghidra"
