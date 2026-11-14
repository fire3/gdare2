from __future__ import annotations

import pytest

from gdare2 import argv
from gdare2.errors import UsageError


def test_clustered_short_flags_and_commands():
    options = argv.parse(["-qc", "pd 5", "-e", "asm.bytes=false", "/bin/ls"])
    assert options.quiet == 1
    assert options.commands == ["pd 5"]
    assert options.evals == [("asm.bytes", "false")]
    assert options.file == "/bin/ls"


def test_attached_short_value():
    options = argv.parse(["-s0x1000", "-b64", "/bin/ls"])
    assert options.seek == "0x1000"
    assert options.bits == "64"


def test_doubled_flags():
    options = argv.parse(["-qq", "-AA", "/bin/ls"])
    assert options.quiet == 2
    assert options.analyze == 2


def test_long_daemon_options():
    options = argv.parse(
        [
            "--attach",
            "auto",
            "--no-spawn",
            "--loader-arg",
            "-baseAddr",
            "0x400000",
            "--endian",
            "big",
            "/tmp/blob",
        ]
    )
    assert options.attach == "auto"
    assert options.spawn is False
    assert options.loader_args == [("-baseAddr", "0x400000")]
    assert options.endian == "big"


def test_rejected_debugger_flag():
    with pytest.raises(UsageError, match="debugger"):
        argv.parse(["-d", "/bin/ls"])


def test_ignored_flag_is_recorded():
    options = argv.parse(["-T", "/bin/ls"])
    assert options.ignored and options.ignored[0][0] == "-T"


def test_only_one_target():
    with pytest.raises(UsageError):
        argv.parse(["/bin/ls", "/bin/true"])


def test_ignored_value_flag_consumes_its_argument():
    options = argv.parse(["-k", "linux", "/bin/ls"])
    assert options.file == "/bin/ls"
    assert options.ignored == [("-k", argv.IGNORED["k"])]


def test_assembler_option_accepts_all_backends():
    assert argv.parse(["--assembler", "rasm2", "/bin/ls"]).assembler == "rasm2"
    assert argv.parse(["--assembler=auto", "/bin/ls"]).assembler == "auto"
    assert argv.parse(["/bin/ls"]).assembler is None
    with pytest.raises(UsageError, match="ghidra, rasm2 or auto"):
        argv.parse(["--assembler", "keystone", "/bin/ls"])


def test_allow_exec_is_accepted():
    options = argv.parse(["--allow-exec", "/bin/ls"])
    assert options.allow_exec is True


def test_wait_is_accepted():
    options = argv.parse(["--wait", "/bin/ls"])
    assert options.wait is True


def test_ignored_value_flag_accepts_a_glued_argument():
    options = argv.parse(["-klinux", "/bin/ls"])
    assert options.file == "/bin/ls"


def test_daemon_readonly_is_accepted():
    options = argv.parse(["--daemon-readonly", "/bin/ls"])
    assert options.daemon_readonly is True


def test_list_offset_and_file_offset_rejection():
    options = argv.parse(["--list-offset", "5", "/bin/ls"])
    assert options.list_offset == 5
    with pytest.raises(UsageError, match="file-offset"):
        argv.parse(["-o", "0", "/bin/ls"])
    with pytest.raises(UsageError, match="negative"):
        argv.parse(["--list-offset", "-1", "/bin/ls"])
