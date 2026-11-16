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
            "/tmp/blob",
        ]
    )
    assert options.attach == "auto"
    assert options.spawn is False
    assert options.loader_args == [("-baseAddr", "0x400000")]


def test_endian_uses_r2_config_keys():
    assert argv.parse(["-e", "arch.endian=big", "/tmp/blob"]).endian == "big"
    assert argv.parse(["-e", "arch.endian=little", "/tmp/blob"]).endian == "little"
    assert argv.parse(["-e", "cfg.bigendian=true", "/tmp/blob"]).endian == "big"
    assert argv.parse(["-e", "cfg.bigendian=false", "/tmp/blob"]).endian == "little"
    assert argv.parse(["/tmp/blob"]).endian is None
    with pytest.raises(UsageError, match="arch.endian"):
        argv.parse(["-e", "arch.endian=middle", "/tmp/blob"])


def test_no_gdare2_alias_for_r2_config_options():
    for option in (
        "--endian",
        "--color",
        "--assembler",
        "--list-offset",
        "--json",
        "--sessions",
    ):
        with pytest.raises(UsageError, match="not an r2 option"):
            argv.parse([option, "x", "/tmp/blob"])


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


def test_list_offset_uses_r2_config_and_file_offset_is_rejected():
    options = argv.parse(["-e", "list.offset=5", "/bin/ls"])
    assert ("list.offset", "5") in options.evals
    with pytest.raises(UsageError, match="file-offset"):
        argv.parse(["-o", "0", "/bin/ls"])
