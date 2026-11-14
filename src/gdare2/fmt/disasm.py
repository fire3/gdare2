"""r2-shaped instruction rendering with optional colour and annotations."""

from __future__ import annotations

from gdare2.config import Config
from gdare2.fmt.listing import format_addr

ANSI_RESET = "\x1b[0m"
_COLORS = {
    "addr": "38;5;75",
    "bytes": "38;5;245",
    "mnemonic": "38;5;178",
    "comment": "38;5;34",
    "label": "38;5;34",
    "gutter": "38;5;240",
}


def _paint(text: str, kind: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\x1b[{_COLORS[kind]}m{text}{ANSI_RESET}"


def display_symbol(item: dict, config: Config) -> str:
    if not config.get_bool("asm.flags"):
        return ""
    symbol = str(item.get("symbol") or "")
    if symbol and config.get_bool("asm.demangle"):
        symbol = str(item.get("symbol_demangled") or symbol)
    return symbol


def format_instruction(
    item: dict,
    config: Config,
    bits: int,
    *,
    show_symbol: bool = False,
) -> str:
    colour = config.get_int("scr.color") > 0
    address = _paint(format_addr(int(item["addr"]), bits), "addr", colour)
    raw = item.get("bytes", b"")
    # r2 renders the byte block as one contiguous hexpair token and elides
    # instructions longer than eight bytes, which keeps ``~[1]`` on the whole
    # byte column instead of the first byte.
    hexbytes = "".join(f"{byte:02x}" for byte in raw[:8])
    if len(raw) > 8:
        hexbytes += ".."
    text = str(item.get("text", ""))
    symbol = display_symbol(item, config) if show_symbol else ""
    comment = str(item.get("comment") or "") if config.get_bool("asm.comments") else ""

    mnemonic, separator, operands = text.partition(" ")
    rendered_text = _paint(mnemonic, "mnemonic", colour)
    if separator:
        rendered_text += f" {operands}"
    if comment:
        rendered_text += " " + _paint(f"; {comment}", "comment", colour)

    show_bytes = config.get_bool("asm.bytes")
    if show_symbol:
        if show_bytes:
            return (
                f"{address}  {symbol:<24}  "
                f"{_paint(f'{hexbytes:<20}', 'bytes', colour)}  {rendered_text}"
            ).rstrip()
        return f"{address}  {symbol:<24}  {rendered_text}".rstrip()
    if show_bytes:
        return f"{address}  {_paint(f'{hexbytes:<20}', 'bytes', colour)}  {rendered_text}"
    return f"{address}  {rendered_text}"


def format_disasm(
    items: list[dict],
    config: Config,
    bits: int,
    *,
    show_symbol: bool = False,
    flags: dict[int, list[str]] | None = None,
) -> list[str]:
    colour = config.get_int("scr.color") > 0
    annotations = config.get_bool("asm.comments")
    show_flags = config.get_bool("asm.flags")
    lines: list[str] = []
    previous_symbol = ""
    for item in items:
        symbol = display_symbol(item, config)
        address = int(item["addr"])
        if show_flags and flags:
            symbols = {symbol, str(item.get("symbol_demangled") or "")}
            for name in flags.get(address, ()):
                if name not in symbols:
                    lines.append(
                        _paint(f"{format_addr(address, bits)}  {name}:", "label", colour)
                    )
        if annotations and symbol and symbol != previous_symbol:
            lines.append(_paint(f";-- {symbol}:", "label", colour))
        rendered = format_instruction(item, config, bits, show_symbol=show_symbol)
        if config.get_bool("asm.lines"):
            gutter = "└─" if item.get("jump") else "│ "
            rendered = _paint(gutter, "gutter", colour) + " " + rendered
        lines.append(rendered)
        previous_symbol = symbol
    return lines
