"""r2-shaped instruction rendering."""

from __future__ import annotations

from gdare2.config import Config
from gdare2.fmt.listing import format_addr


def format_instruction(
    item: dict,
    config: Config,
    bits: int,
    *,
    show_symbol: bool = False,
) -> str:
    address = format_addr(int(item["addr"]), bits)
    raw = item.get("bytes", b"")
    hexbytes = " ".join(f"{byte:02x}" for byte in raw)
    text = str(item.get("text", ""))
    symbol = str(item.get("symbol") or "")
    if show_symbol:
        if config.get_bool("asm.bytes"):
            return f"{address}  {symbol:<24}  {hexbytes:<20}  {text}".rstrip()
        return f"{address}  {symbol:<24}  {text}".rstrip()
    if config.get_bool("asm.bytes"):
        return f"{address}  {hexbytes:<20}  {text}"
    return f"{address}  {text}"


def format_disasm(
    items: list[dict],
    config: Config,
    bits: int,
    *,
    show_symbol: bool = False,
) -> list[str]:
    return [
        format_instruction(item, config, bits, show_symbol=show_symbol)
        for item in items
    ]
