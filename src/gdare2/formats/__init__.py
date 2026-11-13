"""Parsers for the original input file formats."""

from gdare2.formats.elf import ElfFormatError, Segment, read_segments

__all__ = ["ElfFormatError", "Segment", "read_segments"]
