"""Assembler backends: Ghidra SLEIGH and an optional rasm2 fallback."""

from __future__ import annotations

import re
import shutil
import subprocess

from gdare2.errors import GdarError, UnsupportedError, UsageError

MAX_LINES = 1024
RASM2_TIMEOUT = 15

#: gdare2 architecture -> (rasm2 -a name, big endian)
_RASM2_ARCH = {
    "x86": ("x86", False),
    "armle": ("arm", False),
    "armbe": ("arm", True),
    "aarch64": ("arm", False),
    "aarch64be": ("arm", True),
    "mipsle": ("mips", False),
    "mipsbe": ("mips", True),
    "mips64le": ("mips", False),
    "mips64be": ("mips", True),
    "ppcle": ("ppc", False),
    "ppc": ("ppc", True),
    "ppc64": ("ppc", True),
    "ppc64le": ("ppc", False),
    "riscv32": ("riscv", False),
    "riscv64": ("riscv", False),
    "sparc": ("sparc", True),
    "sparc64": ("sparc", True),
    "m68k": ("m68k", True),
    "sh2": ("sh", True),
    "sh2a": ("sh", True),
}

_HEXPAIRS = re.compile(r"^[0-9a-fA-F]+$")


def assemble(session, ea: int, text: str) -> dict:
    """Assemble *text* using the configured backend."""
    mode = session.config.get_str("asm.assembler")
    if mode == "ghidra":
        return session.call_assembler("assemble", ea=int(ea), text=text)
    if mode == "rasm2":
        return rasm2_assemble(session, int(ea), text)
    if mode == "auto":
        try:
            return session.call_assembler("assemble", ea=int(ea), text=text)
        except GdarError as original:
            binary = session.config.get_str("asm.rasm2")
            if shutil.which(binary) is None:
                raise original
            try:
                payload = rasm2_assemble(session, int(ea), text)
            except GdarError:
                raise original from None
            session.stderr("WARN: assembler fallback to rasm2")
            return payload
    raise UsageError("e asm.assembler must be ghidra, rasm2 or auto")


def assemble_write(session, ea: int, text: str) -> dict:
    """Assemble and write, using one daemon call for the whole SLEIGH path."""
    mode = session.config.get_str("asm.assembler")
    if mode == "ghidra":
        return session.call_assembler("assemble_write", ea=int(ea), text=text)
    if mode == "auto":
        try:
            return session.call_assembler("assemble_write", ea=int(ea), text=text)
        except GdarError as original:
            binary = session.config.get_str("asm.rasm2")
            if shutil.which(binary) is None:
                raise original
            try:
                payload = rasm2_assemble(session, int(ea), text)
            except GdarError:
                raise original from None
            session.stderr("WARN: assembler fallback to rasm2")
    else:
        payload = assemble(session, int(ea), text)
    session.call("write_bytes", ea=int(ea), data=bytes(payload["bytes"]))
    payload["addr"] = int(ea)
    return payload


def rasm2_assemble(session, ea: int, text: str) -> dict:
    binary = session.config.get_str("asm.rasm2")
    arch = str(session.info.get("arch") or "")
    mapping = _RASM2_ARCH.get(arch)
    if mapping is None:
        raise UnsupportedError(f"rasm2 has no architecture mapping for {arch!r}")
    rasm_arch, big_endian = mapping
    bits = int(session.info.get("bits") or 32)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise UsageError("assembly text is empty")
    if len(lines) > MAX_LINES:
        raise UsageError(f"assembly is limited to {MAX_LINES} lines")

    address = int(ea)
    items = []
    for line in lines:
        command = [binary, "-a", rasm_arch, "-b", str(bits)]
        if big_endian:
            command.append("-e")
        command.append(line)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=RASM2_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            raise UnsupportedError(f"rasm2 not found: {binary}") from None
        except subprocess.TimeoutExpired:
            raise GdarError(f"rasm2 timed out after {RASM2_TIMEOUT}s") from None
        hexpairs = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        if result.returncode != 0 or not hexpairs or len(hexpairs) % 2 or not _HEXPAIRS.match(hexpairs):
            detail = (result.stderr or result.stdout or "no output").strip().splitlines()
            raise GdarError(
                f"rasm2 failed for {line!r}: {detail[-1] if detail else 'no output'}"
            )
        data = bytes.fromhex(hexpairs)
        items.append(
            {"addr": address, "text": line, "bytes": data, "size": len(data)}
        )
        address += len(data)
    return {
        "items": items,
        "bytes": b"".join(item["bytes"] for item in items),
        "size": sum(item["size"] for item in items),
        "assembler": "rasm2",
    }
