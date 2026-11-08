"""Error types shared by the client and the RPC envelope."""

from __future__ import annotations

from typing import Any


class GdarError(Exception):
    """Base class for errors that have a stable code and exit status."""

    code = "INTERNAL"
    exit_code = 1

    def __init__(self, message: str, *, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.data = data or {}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "data": self.data}


class UsageError(GdarError):
    code = "BAD_ARGS"
    exit_code = 2


class CommandError(GdarError):
    code = "INTERNAL"
    exit_code = 1


class UnsupportedError(GdarError):
    code = "NOT_SUPPORTED"
    exit_code = 1


class UnknownOpError(GdarError):
    code = "UNKNOWN_OP"
    exit_code = 1


class ReadOnlyError(GdarError):
    code = "READONLY"
    exit_code = 1


class NotFoundError(GdarError):
    code = "NOT_FOUND"
    exit_code = 1


class NotFuncError(GdarError):
    code = "NOT_FUNC"
    exit_code = 1


class NotReadyError(GdarError):
    code = "NOT_READY"
    exit_code = 3


class DecompileError(GdarError):
    code = "NO_DECOMPILER"
    exit_code = 1


class RemoteError(GdarError):
    """An error returned by the daemon."""

    def __init__(self, code: str, message: str, *, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, data=data)
        self.code = code
        self.exit_code = EXIT_CODES.get(code, 1)


class ConnectionFailure(GdarError):
    code = "CONNECTION"
    exit_code = 3


class TimeoutFailure(GdarError):
    code = "TIMEOUT"
    exit_code = 4


EXIT_CODES: dict[str, int] = {
    "BAD_ARGS": 2,
    "BAD_ADDRESS": 1,
    "NOT_FOUND": 1,
    "NOT_FUNC": 1,
    "NO_DECOMPILER": 1,
    "READONLY": 1,
    "GHIDRA_ERROR": 1,
    "NOT_READY": 3,
    "ANALYZING": 3,
    "TIMEOUT": 4,
    "LOCKED": 3,
    "UNKNOWN_OP": 1,
    "NOT_SUPPORTED": 1,
    "INTERNAL": 1,
}
