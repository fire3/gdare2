"""r2-shaped instruction rendering."""

from __future__ import annotations

from gdare2.config import Config
from gdare2.fmt.listing import format_addr


def format_instruction(item: dict, config: Config, bits: int) -> str:
    address = format_addr(int(item["addr"]), bits)
    raw = item.get("bytes", b"")
    hexbytes = " ".join(f"{byte:02x}" for byte in raw)
    text = str(item.get("text", ""))
    if config.get_bool("asm.bytes"):
        return f"{address}  {hexbytes:<20}  {text}"
    return f"{address}  {text}"


def format_disasm(items: list[dict], config: Config, bits: int) -> list[str]:
    return [format_instruction(item, config, bits) for item in items]
