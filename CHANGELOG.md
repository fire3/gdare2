# Changelog

All notable changes to gdare2 are documented here.  The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

v2 compatibility batches A–C (G1–G18) and the first batch-D item (G19).

### Added

- PyPI-ready packaging: PEP 639 license metadata, a required
  `pyghidra>=3.2.0` runtime dependency, a `dev` dependency group, self-hosted
  README badges, packaging regression tests, and TestPyPI/PyPI Trusted
  Publishing workflows.
- `pip install gdare2` is now the documented installation path.
- `--assembler=ghidra|rasm2|auto` now configures `asm.assembler`; explicit
  values override rc files, and `-e asm.assembler=...` wins on the same
  command line.
- `pdi` emits r2-style `address  flag:` lines for client-side flags without
  duplicating the current instruction symbol.
- `iSS` reads ELF program headers from the input file; `ih`/`iH`/`il`/`ir`
  expose the ELF header, `DT_NEEDED` libraries and relocations.
- Replayable command variants: `f*`, `C*`/`CC*`/`C*.`, `CCu base64:`,
  `t*`, `s*`, `b*`, `iS*` and `ax*`/`axlj`/`axlq`/`axlc`.
- `pf`/`pfj`/`pfs`/`pf.<name>` formatting with scalars, arrays, offset
  controls, unions and named formats.
- `~` filter v2: multi-column/negative/range selectors, column sorting and
  `~{}` JSON pretty-printing.
- `p` family read commands: `pdb`, `pC`, `pA`, `pxd`/`pxu`/`pxj`, the `ps`
  variants, `p8` projections and `pvu`/`pvd`/`pvp`.
- Tab completion for flags/functions and `$` variables; rc hierarchy with
  `rc.d/*`, project ancestor files and `GDARE2_RCFILE`.
- Backtick command substitution and `px` layout aligned with r2
  (`hex.pairs`/`hex.offset`/`hex.ascii`).
- GitHub Actions CI, configuration/format test suites and a PyPI publish
  workflow.

### Changed

- The README is now English-only. The `docs/` tree is maintained locally and
  excluded from Git and release artifacts.
- `pd`/`pdi` render instruction bytes as contiguous hexpairs (r2 shape);
  instructions longer than eight bytes are elided with `..`.
- `@@f`/`@@F` skip external, thunk and non-executable function entries.
- `pd -j` JSON and `-j` command resolution follow the r2 line-oriented
  filter model.

### Fixed

- Entry-point detection prefers an executable `_start` and ignores
  non-executable DWARF symbols named `entry` (seen in the Tenda `httpd`
  firmware sample).
- `tp`/`tpv` no longer crash on built-in integer types; `tc <name>` only emits
  the requested declaration.
- JSON output participates in `~`/`|` line by line.
- `~` filters keep backslash escapes such as `~\.text`.
- Pagination via `--list-offset`/`e list.offset`, with explicit metadata.

## [0.1.0] - 2026-11-07

Initial import: two-process daemon/client architecture, read-only core,
analysis, disassembly, decompilation, types, writes, search, flags, scripts,
parity golden files and the 22-configuration architecture matrix.
