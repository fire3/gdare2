"""Code generators for the ``pc`` output-format family (TASKS-v3 V6).

Every formatter is a pure function ``format_<lang>(data: bytes, address: int)``
returning the output lines, so they are unit-testable without a session.  The
shapes follow radare2's ``pc`` family where a stable shape exists; divergences
are noted per function.  Generated arrays are named ``buffer`` (``buf`` for Go),
matching radare2's default.

Shapes chosen for this client:

``pcb``  one continuous ``0b``-prefixed bit string, MSB first per byte
``pcc``  ``const char buffer[N] = "\\xNN...";`` with every byte escaped
``pcd``  ``const unsigned char buffer[N] = { <decimal> };``
``pcF``  Fortran 90 array of ``integer(kind=4)`` (Fortran has no unsigned type,
         so ``kind=4`` keeps byte values 0-255 in range)
``pcg``  ``buf := []byte{0xNN, ...}``
``pci``  ``#include <stdint.h>`` line plus a ``const unsigned char`` declaration
         reusing ``pc``'s value shape
``pcJ``  compact JSON array of byte values on one line
``pcq``  hexpairs only, one line (same shape as ``p8``)
``pcr``  ``let buffer: [u8; N] = [0xNN, ...];``
``pcS``  ``let buffer: [UInt8] = [0xNN, ...]``
``pct``  ``const buffer: number[] = [0xNN, ...];``
``pcu``  ``0x``-prefixed hexpairs, space separated (shell friendly)
``pcv``  SystemVerilog unpacked byte array with an ``'{...}`` assignment pattern
``pcw``  WAT data segment: ``(data (i32.const 0xADDR) "\\NN...")`` (``address``
         becomes the segment offset)
``pcz``  ``pcc`` plus an explicit trailing ``\\x00`` byte (length is N+1)
"""

from __future__ import annotations

import json

#: Name used for generated arrays, matching radare2's default.
BUFFER_NAME = "buffer"


def _escaped_c(data: bytes) -> str:
    """Render every byte as a ``\\xNN`` escape.

    Printable bytes are escaped too: C greedily absorbs hex digits after
    ``\\x`` (``"\\x41B"`` is a single 0x1B byte), so literal text next to an
    escape would silently change the data.
    """
    return "".join(f"\\x{byte:02x}" for byte in data)


def _hex_values(data: bytes) -> str:
    return ", ".join(f"0x{byte:02x}" for byte in data)


def _decimal_values(data: bytes) -> str:
    return ", ".join(str(byte) for byte in data)


def format_binary(data: bytes, address: int) -> list[str]:
    """``pcb``: one continuous ``0b``-prefixed bit string, MSB first per byte."""
    bits = "".join(f"{byte:08b}" for byte in data)
    return ["0b" + bits]


def format_c_char(data: bytes, address: int) -> list[str]:
    """``pcc``: C char array rendered as a string literal with ``\\xNN`` escapes."""
    return [f'const char {BUFFER_NAME}[{len(data)}] = "{_escaped_c(data)}";']


def format_c_decimal(data: bytes, address: int) -> list[str]:
    """``pcd``: C byte array with decimal initializers."""
    return [
        f"const unsigned char {BUFFER_NAME}[{len(data)}] = "
        + "{ " + _decimal_values(data) + " };"
    ]


def format_c_include(data: bytes, address: int) -> list[str]:
    """``pci``: ``#include``-style C byte array reusing ``pc``'s value shape."""
    return [
        "#include <stdint.h>",
        f"const unsigned char {BUFFER_NAME}[{len(data)}] = "
        + "{ " + _hex_values(data) + " };",
    ]


def format_c_string(data: bytes, address: int) -> list[str]:
    """``pcz``: C string with an explicit trailing NUL byte."""
    return [f'const char {BUFFER_NAME}[{len(data) + 1}] = "{_escaped_c(data)}\\x00";']


def format_fortran(data: bytes, address: int) -> list[str]:
    """``pcF``: Fortran 90 array; ``integer(kind=4)`` keeps 0-255 in range."""
    return [
        f"integer(kind=4), dimension({len(data)}) :: {BUFFER_NAME}"
        + " = (/ " + _decimal_values(data) + " /)"
    ]


def format_go(data: bytes, address: int) -> list[str]:
    """``pcg``: Go slice literal assigned to ``buf``."""
    return ["buf := []byte{" + _hex_values(data) + "}"]


def format_hexpairs(data: bytes, address: int) -> list[str]:
    """``pcq``: quiet hexpairs on one line, like ``p8``."""
    return [data.hex()]


def format_json(data: bytes, address: int) -> list[str]:
    """``pcJ``: compact JSON array of byte values."""
    return [json.dumps(list(data))]


def format_rust(data: bytes, address: int) -> list[str]:
    """``pcr``: Rust ``u8`` array."""
    return [f"let {BUFFER_NAME}: [u8; {len(data)}] = " + "[" + _hex_values(data) + "];"]


def format_shell(data: bytes, address: int) -> list[str]:
    """``pcu``: ``0x``-prefixed hexpairs, space separated."""
    return [" ".join(f"0x{byte:02x}" for byte in data)]


def format_swift(data: bytes, address: int) -> list[str]:
    """``pcS``: Swift ``UInt8`` array."""
    return [f"let {BUFFER_NAME}: [UInt8] = " + "[" + _hex_values(data) + "]"]


def format_typescript(data: bytes, address: int) -> list[str]:
    """``pct``: TypeScript ``number[]`` array."""
    return [f"const {BUFFER_NAME}: number[] = " + "[" + _hex_values(data) + "];"]


def format_verilog(data: bytes, address: int) -> list[str]:
    """``pcv``: SystemVerilog unpacked byte array with an assignment pattern."""
    last = max(len(data) - 1, 0)
    values = ", ".join(f"8'h{byte:02x}" for byte in data)
    return [f"byte unsigned {BUFFER_NAME}[0:{last}] = " + "'{" + values + "};"]


def format_wasm(data: bytes, address: int) -> list[str]:
    """``pcw``: WAT data segment; ``address`` becomes the ``i32.const`` offset."""
    payload = "".join(f"\\{byte:02x}" for byte in data)
    return [f'(data (i32.const 0x{address:x}) "{payload}")']
