"""Per-request context passed to Ghidra ops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Context:
    runtime: Any
    readonly: bool
    allow_writes: bool
    session_id: str = "batch"

    @property
    def program(self):
        return self.runtime.program

    @property
    def project(self):
        return self.runtime.project

    def monitor(self):
        return self.runtime._pyghidra.task_monitor()


def to_addr(program, address: int):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(address))
