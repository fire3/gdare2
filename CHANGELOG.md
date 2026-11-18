# Changelog

All notable changes to gdare2 are documented here.  The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- r2's raw-import spellings now resolve on Ghidra: `-a arm -b 64` selects
  AArch64, `-a arm -b 16` (or `-a thumb`) selects Thumb via the ARM `TMode`
  context register, and `6502`/`8051`/`avr`/`msp430` map to Ghidra's MCU
  languages. `-b 8` is accepted for the byte-wide processors even though
  Ghidra models their address space as 16-bit. Previously these failed before
  the daemon could start (`ARM supports bit width 32` / `unknown architecture
  alias`), so retest's MCU and AArch64 raw targets could not be opened at all.

### Changed

- The default `--startup-timeout` is 600s (was 180s). A cold import is JVM
  start + Ghidra load + auto-analysis, and a multi-MB firmware image needs
  minutes: a packed 7.9MB ELF measured 150–270s. The 3-minute default used to
  give up in the middle of the analysis, so the client returned `exit 3` with
  no output while the daemon went on to finish the work. While it waits, and
  unless `-q` is given, the client now prints
  `gdare2: waiting for <target> (<state>, Ns)` on stderr every 20s instead of
  looking hung.

### Fixed

- `pd N` on a raw blob keeps decoding after a `ret`/`rts`/`blr`, like r2,
  instead of stopping at the end of the analysed flow. The bytes the listing
  did not cover are decoded with `PseudoDisassembler`, so the program is not
  mutated. This made MCU/AArch64/PPC/MIPS raw disassembly stop after one or
  two instructions.
- `-a s390`/`s390x`/`systemz` now reports that Ghidra 12.2 ships no S390
  language instead of `unknown architecture alias` (the daemon still cannot
  analyse the target; this is a backend gap, not an r2 spelling problem).
- A bare `-a mips`/`-a ppc` now decodes little-endian, matching r2's
  `cfg.bigendian=false` default; `-e arch.endian=big` and the `*be` aliases
  still select big-endian. Previously little-endian raw MIPS/PPC blobs could
  not be disassembled at all ("no instruction at or after 0x0").
- Files that Ghidra has no loader for (COFF bigobj, sBPF ELF, a fuzzed PE or
  Mach-O) now fail with one actionable line —
  `no Ghidra loader supports this file (COFF); force a raw import with
  --loader BinaryLoader --ghidra-language <id>` — instead of a raw
  `ghidra.app.util.opinion.LoadException: No load spec found`. radare2 opens
  some of these with its own bin plugins; that is backend coverage, documented
  in `docs/DIVERGENCES.md` 3.6. A `--loader`/`--ghidra-language` given by the
  user is still reported verbatim, so a typo is not hidden behind the new text.
- Daemon startup errors raised by gdare2 itself are no longer prefixed with
  their Python class name (`UsageError:`/`UnsupportedError:`); the client shows
  the message r2 users need to read.
- The daemon no longer writes a `BrokenPipeError` traceback to its log when a
  client hangs up mid-request (a watchdog killing `gdare2`, for example). The
  connection is logged at debug level instead.

## [0.1.1] - 2026-11-16

### Fixed

- `ii` now prints r2's import table from the ELF dynamic symbol table: the
  same `nth/vaddr/bind/type/lib/name` header and rule, with GLOBAL/WEAK
  binding, FUNC/NOTYPE type and the PLT stub as vaddr when one exists. It used
  to print two columns with the ordinal rendered as an address, which also
  broke `ii | wc -l` and `ii~?`.
- COFF object files (including bigobj) are recognised as a file format, so
  they are handed to Ghidra's loaders instead of being mistaken for a raw
  binary and rejected with "raw binaries need a Ghidra language".
- `u`/`U` (undo/redo) now work in a read-only session: they only replay the
  daemon's tracked write history, so the undo of a patch written by an earlier
  `-w` session succeeds instead of failing with "read-only session". The undo
  record now stores the translated Ghidra address, so a low r2-style address
  (`wx ... @ 0x20` on a PIE) can be reverted too.
- Reads of unmapped addresses now return `ff` bytes, like r2's `px`/`p8`
  past EOF, instead of failing the whole command with a memory-access error.
  A partial read is padded with `ff` as well.
- `px` column labels now match r2 (right-aligned low-byte labels, e.g.
  ` 0 1` at offset 0 and `1011` at offset 0x10) and addresses below Ghidra's
  image base are treated as image-base-relative when the shifted address is
  mapped. Together these make r2-style literals such as `px 4 @@= 0x0 0x10`
  and `wx 9090 @ 0x10` address the same file bytes as r2 on PIE binaries.
- `pd <huge>` clamps the request to the daemon's instruction cap instead of
  failing with `disasm count is limited to 4096`, so an oversized count still
  prints everything that is available (r2 keeps printing too).
- `iS` no longer prints a header row, matching r2 (`iS~?` counts only the
  sections). The columns are unchanged.
- Daemon startup failures no longer dump Java/Python tracebacks to the CLI's
  stderr. The first line of the underlying exception is reported with the
  daemon log path; the full traceback stays in the log file.
- `ie` now prints radare2's entry-point table (header, separator and one
  `program` row) instead of a list of entry-point symbols. The r2 view is
  ELF-header derived, so `ie` and `ie~[0]` match the oracle; entry symbols
  remain available through `ies`.
- Ghidra project paths are now usable even when `GDARE2_DATA_DIR` contains
  characters Ghidra rejects (for example `#` or `%`). Ghidra validates every
  path element with `NamingUtilities.checkName`, so such a data directory
  used to fail every write command with a raw Java
  `IllegalArgumentException` traceback. gdare2 now keeps the projects in a
  deterministic sanitised mirror under the system temp directory.
- Raw binaries opened without language hints now keep the documented usage
  error: the daemon writes an error state before exiting and the client
  reports `BAD_ARGS` with exit status 2. The same path used to wait out the
  startup grace and report `CONNECTION` with exit status 3.
- A missing target path now fails before the daemon is spawned with
  `ERROR: cannot open ...: no such file or directory` and exit status 1,
  matching r2. It used to be treated as a hint-less raw binary and surface as
  `daemon failed to become ready` with exit status 3.
- `s entry0` (and any `@ entry0`) now resolves to the program entry point.
  radare2 synthesises an `entry0` flag, while Ghidra keeps the loader's own
  spelling (`_start`, `entry`, ...), so the r2 name used to fail with
  `ERROR: unknown name 'entry0'` and made a script exit non-zero even though
  the following commands ran.

### Changed

- `gdare2 -V` now reports the whole stack (gdare2, PyGhidra, Ghidra, Java,
  Python) and flags a missing installation or a Java version older than the
  one Ghidra requires, without importing PyGhidra or starting a JVM.  `-v`
  keeps the short form.

## [0.1.0] - 2026-11-14

First public release.

v2 compatibility batches A–C (G1–G18) and the first batch-D item (G19).

v3 batch A: command-language layer (`?` expression family, `@` temporary
modifiers, macros, `.cmd`/`.!cmd` interpretation, repeat-prefix output
accumulation) and the parity environment repair (radare2 6.2.6 + rebuilt
goldens).

v3 batch B: output/input format families (`pc` code-generation family,
compare variants `c2/c4/c8/cJ/cv`, yank variants `yj/y*/yp/yq/ys/yw/yz`,
flag subcommands `fc/fm/fo/fd`, `fs` flag spaces, seek gaps `sa/sC/sd`).

v3 batch C: search and graph completion (`/b` backward hex search, `agC`
call graph with DOT rendering, `axg` reference graph, explicit
not-supported decisions for the remaining `/` and `ax` variants).

v3 batch D: configuration and ecosystem (new keys `asm.offset`,
`scr.utf8`, `bin.demangle`, `cfg.sandbox`, `search.maxhits`; explicit
errors for unsupported r2 keys like `asm.emu`/`anal.*`; `--pipe-listen`
r2pipe-compatible TCP command channel; CLI option audit).

### Added

- Expanded radare2 command compatibility: `p6`/`p=`/`pj`/`pr`/`ph`/`pwd`,
  `pdq`/`pdC`/`pdJ`/`pd,`, `s:`/`s=`, `fn`/`fN`/`fx`, `e*`/`e-`/`e!`/`env`/
  `es`/`et`/`ev`, `bj`/`bf`/`bm`, `iD`/`iC`/`iV`/`iv`/`iT`/`iee`/`ies`,
  `Ch`/`Cs`/`Cm`/`Cf`/`Ct`/`CL`, and `tn`/`to`/`tk`/`tl`/`tx`.
- Search variants `/i`, `/d`, `/z`, `/m`, `/c` and `/R`; `/m` and `/c` share a
  deterministic built-in magic/crypto signature scanner.
- Write commands `wt`/`wv`/`wr`/`ws`/`ww`, including width and float variants
  for `wv`.
- Project snapshots now preserve hidden ranges, string/magic metadata, type
  comments, source lines, type links, no-return marks and notes; `Pc` emits
  replay commands for all of them.
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

- First-import analysis no longer cuts off at 180 seconds. The daemon-side
  cap defaulted to a hard 180 s, which truncated slow-arch imports (measured:
  i386 684 s, mipsel 665 s, big-endian MIPS 483 s) and silently cached a
  broken one-function database that later runs reused. The default is now
  unlimited; a cap can be set explicitly with the new client option
  `--analysis-timeout <sec>` (0 disables it).
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
