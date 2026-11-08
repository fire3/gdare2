from __future__ import annotations

import io
from contextlib import redirect_stderr

import pytest

from gdare2 import cli
from gdare2.errors import (
    EXIT_CODES,
    CommandError,
    ConnectionFailure,
    DecompileError,
    GdarError,
    NotFoundError,
    NotFuncError,
    NotReadyError,
    ReadOnlyError,
    RemoteError,
    TimeoutFailure,
    UnknownOpError,
    UnsupportedError,
    UsageError,
)

ERROR_CLASSES = (
    UsageError,
    CommandError,
    UnsupportedError,
    UnknownOpError,
    ReadOnlyError,
    NotFoundError,
    NotFuncError,
    NotReadyError,
    DecompileError,
    ConnectionFailure,
    TimeoutFailure,
)


@pytest.mark.parametrize("error_class", ERROR_CLASSES)
def test_error_codes_have_matching_exit_codes(error_class):
    error = error_class("boom")
    assert EXIT_CODES[error.code] == error.exit_code
    assert isinstance(error, GdarError)


def test_documented_exit_code_contract():
    assert EXIT_CODES["BAD_ARGS"] == 2
    assert EXIT_CODES["NOT_READY"] == 3
    assert EXIT_CODES["TIMEOUT"] == 4


@pytest.mark.parametrize(
    ("code", "exit_code"),
    [("BAD_ARGS", 2), ("NOT_READY", 3), ("ANALYZING", 3), ("TIMEOUT", 4), ("MYSTERY", 1)],
)
def test_remote_error_maps_exit_codes(code, exit_code):
    error = RemoteError(code, "remote failure")
    assert error.code == code
    assert error.exit_code == exit_code


def test_cli_unknown_option_exits_with_bad_args(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    err = io.StringIO()
    with redirect_stderr(err):
        status = cli.main(["--no-such-option"])
    assert status == 2
    assert "unknown option" in err.getvalue()


def test_cli_status_for_missing_instance_exits_not_ready(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    err = io.StringIO()
    with redirect_stderr(err):
        status = cli.main(["--status", "does-not-exist"])
    assert status == 3
    assert "no live instance" in err.getvalue()
