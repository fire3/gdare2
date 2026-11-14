# gdare2

[![PyPI](https://raw.githubusercontent.com/fire3/gdare2/main/assets/badges/pypi.svg)](https://pypi.org/project/gdare2/)
[![Python versions](https://raw.githubusercontent.com/fire3/gdare2/main/assets/badges/python.svg)](https://pypi.org/project/gdare2/)
[![CI](https://github.com/fire3/gdare2/actions/workflows/ci.yml/badge.svg)](https://github.com/fire3/gdare2/actions/workflows/ci.yml)
[![License: MIT](https://raw.githubusercontent.com/fire3/gdare2/main/assets/badges/license.svg)](https://github.com/fire3/gdare2/blob/main/LICENSE)

`gdare2` is a reverse-engineering tool that uses **Ghidra** as its analysis
backend while keeping its command line and output model close to **radare2**.
It exposes Ghidra projects, disassembly, decompilation, types, and write
operations through familiar r2-style commands, and keeps a resident daemon so
subsequent commands can respond in seconds.

## Why gdare2

- **Ghidra analysis with r2 habits**: common commands such as
  `s/pd/px/afl/afi/axt/axf/pdc/afv` work directly.
- **Two-process architecture with a JVM-free client**: the CLI only parses,
  manages sessions, and renders output; the PyGhidra daemon owns the Ghidra
  project.
- **Resident daemon**: the first import and analysis is slow; afterward,
  multiple clients share the same open program.
- **Read-only by default, writes require opt-in**: only requests using `-w` can
  write, and the daemon can also be forced read-only.
- **Batch-friendly**: `-qc`, `-j`, `~` filters, `|` pipes, `>` redirection, and
  `@@` iteration.
- **Regression testing against real Ghidra**: layered offline unit tests,
  real-Ghidra integration tests, a 22-configuration architecture matrix, and r2
  parity tests.

Current status: M0-M5 core capabilities and experience items are complete
(rc, completion, search, flags, scripts, assembly, parity golden files, the
22-configuration architecture matrix, and batch metadata). v1 is complete.
Attaching to a Ghidra GUI is not supported. In the 2026-11-13 v2 gap audit,
batches A/B/C (G1-G18) were closed: `iSS`/`tp`/`tc`, JSON filtering, `-j`,
`i`/`aflq`/`L`/`ej`, colors/comments, `--list-offset` paging,
`f*`/`C*`/`t*`/`iS*`/`ax*` export variants, `pf` formatting, multi-column and
sorted `~` filters, read-only `p` commands, completion and rc layering,
backtick substitution, `px` column layout, CI, and the offline test suite.
Batch D items G19 (`ih`/`iH`/`il`/`ir` ELF parsing) and G20-G24 (rasm2
fallback, miscellaneous commands, type formatting, comment sidecars, and
release engineering) are also complete. All v2 tasks G1-G24 are closed.

## Architecture

```text
gdare2 CLI  ──loopback HTTP/JSON──▶  gdare2d (PyGhidra daemon)
   │                                      │
   ├─ r2 syntax parsing                   ├─ Ghidra Project / Program
   ├─ seek / filters / pipes / redirects  ├─ auto-analysis and disassembly
   ├─ output rendering                    ├─ DecompInterface
   └─ session lease                       └─ Memory / Symbol / Comment / Type writes
```

- One target plus a set of import options maps to one daemon; the same program
  is reused.
- Ghidra project locks are exclusive: while the daemon has a project open,
  Ghidra GUI cannot open the same project. GUI attachment is not supported;
  close the daemon before opening the project in the GUI.
- Multiple CLIs can share one daemon. Write capability is decided per request,
  so one client using `-w` does not elevate another.

## Requirements

| Component | Recommendation |
|---|---|
| Ghidra | 12.2 PUBLIC, default `~/ghidra/current` |
| Java | JDK 25 (the Ghidra 12.2 baseline) |
| Python | 3.11+ (CI covers 3.11-3.14) |
| PyGhidra | 3.2.x (bundled with Ghidra) |
| radare2 | Optional; only needed for parity tests |

Set the Ghidra path:

```bash
export GHIDRA_INSTALL_DIR=$HOME/ghidra/current
```

## Installation

Install from PyPI:

```bash
python -m pip install gdare2
gdare2 -V
```

`pip install gdare2` installs PyGhidra. Ghidra, Java, and
`GHIDRA_INSTALL_DIR` still need to be prepared separately as described above.
The client process does not import PyGhidra; only `gdare2d` needs the JVM.

For source development:

```bash
uv sync --group dev
```

Offline environments can install PyGhidra first from the wheel bundled with
Ghidra:

```bash
uv pip install --python .venv/bin/python \
  --no-index -f "$HOME/ghidra/current/Ghidra/Features/PyGhidra/pypkg/dist" \
  'pyghidra>=3.2.0'
```

After activating the virtual environment, use `gdare2` directly; when it is
not active, use `.venv/bin/gdare2`.

## Quick start

```bash
# Open an ELF and enter the interactive REPL
gdare2 /bin/ls

# Run a single command without entering the REPL
gdare2 -qc 'pd 5' /bin/ls

# Seek to the entry point while opening
gdare2 -qc 'iI; s entry; pd 10' /bin/ls

# Raw binaries require a language and load base address
gdare2 -a x86 -b 64 -B 0x400000 blob.bin
```

The first open imports and analyzes the target; how long this takes depends on
its size. Subsequent commands reuse the daemon for the same target.

## Usage

### Opening and sessions

```bash
gdare2 /bin/ls                  # interactive
gdare2 -q /bin/ls               # quiet mode
gdare2 -j /bin/ls               # JSON output by default (for supported commands)
gdare2 -s main /bin/ls          # initial seek
gdare2 -n /bin/ls               # skip auto-analysis on first import
gdare2 --ephemeral /bin/ls      # close and delete the temporary project when done
```

The interactive REPL supports readline history and Tab completion. `q` exits
only the client; `.gclose` shuts down the daemon.

### Disassembly and memory

```bash
gdare2 -qc 's entry; pd 20' /bin/ls
gdare2 -qc 's entry; pdf' /bin/ls
gdare2 -qc 'px 64' /bin/ls
gdare2 -qc 's entry; p8 16; pv4' /bin/ls
gdare2 -qc 's entry; ao; ai' /bin/ls
gdare2 -qc 'sf; sF; so; sp' /bin/ls
```

Common seek commands: `s <addr|symbol>`, `s+`, `s-`, `sb` (basic block), `sf`
(function), `sF` (function end), and `so`/`sp` (next/previous instruction).

### Functions, basic blocks, and graphs

```bash
gdare2 -qc 'afl' /bin/ls
gdare2 -qc 's main; afi; afb; ab; ao' /bin/ls
gdare2 -qc 's main; agf' /bin/ls       # ASCII control-flow graph
gdare2 -qc 's main; agfj' /bin/ls      # JSON
gdare2 -qc 's main; agfd' /bin/ls      # Graphviz DOT
gdare2 -qc 'afc @ main; afC @ main' /bin/ls
gdare2 -qc 'axt @ main; axf @ main' /bin/ls
```

### Searching

```bash
gdare2 -qc '/x 488b' /bin/ls            # hex bytes
gdare2 -qc '/x 90?f' /bin/ls            # ?/./ preserve a nibble
gdare2 -qc '/p 488b' /bin/ls            # pattern search
gdare2 -qc '/a NOP' /bin/ls             # assemble, then search bytes
gdare2 -qc '/ entry' /bin/ls            # UTF-8 text
gdare2 -qc '/w hello' /bin/ls           # UTF-16 text
gdare2 -qc '/v4 0x12345678' /bin/ls     # 32-bit immediate
gdare2 -qc '/xj 488b' /bin/ls           # JSON
gdare2 -qc '/x 9090; //; /-' /bin/ls    # continue forward/backward
gdare2 -qc 'izz~ELF' /bin/ls            # whole-file strings
gdare2 -qe search.in=raw -qc '/x 488b' /bin/ls
```

Use `e search.from=0x...` and `e search.to=0x...` to bound the search.
`search.in=raw` maps results to file offsets.

### Decompilation, types, and comments

```bash
gdare2 -qc 's main; pdc' /bin/ls
gdare2 -qc 's main; afv' /bin/ls
gdare2 -qc 't~int; ts; tu; te; tt' /bin/ls
gdare2 -qc 'ts' /bin/ls
gdare2 -qc 'tf~main' /bin/ls
```

Writing comments requires `-w`:

```bash
gdare2 -w -qc 's main; CC eol comment; Cp plate comment; .gsave' /bin/ls
gdare2 -qc 's main; C.' /bin/ls
```

### Flags

```bash
gdare2 -qc 'f~entry; fq; f? entry' /bin/ls
# By default flags stay in the session. Writing them back to Ghidra requires
# -w and ghidra.flags.write=true.
gdare2 -w -qc 'e ghidra.flags.write=true; s entry; f demo_flag 4; .gsave' /bin/ls
gdare2 -qc 'fq~demo_flag' /bin/ls
```

### Writing, caching, and undo

All write operations require `-w`. With no arguments, `w` saves the program;
`w <text>` writes a string. The examples below assume `blob.bin` is an x86-64
raw binary loaded at `0x400000`; ELF/PE targets can omit `-a/-b/-B`.

```bash
# Write bytes and save
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 's 0x400000; wx 9090; .gsave; .gclose' blob.bin

# Write a string, zeros, file contents, and a memory copy
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 's 0x400000; w "AB"; w0 4; wf payload.bin; wd 16 8' blob.bin

# Undo/redo (daemon-local byte history)
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 's 0x400000; wx 9090; u; px 2; U; px 2' blob.bin

# Write cache: wx buffers in the client, wc+ commits once
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 'e io.cache=true; s 0x400000; wx 4142; wc; wc+; wq' blob.bin
```

Note: `wx` clears code units in the written range. Undo restores bytes only;
it does not roll back disassembly, functions, comments, or other metadata, and
the history is cleared when the daemon restarts.

Assembly uses the Ghidra SLEIGH assembler; mnemonics usually need to be
uppercase:

```bash
gdare2 -qc 'pa NOP' blob.bin
gdare2 -w -qc 's 0x400000; wa NOP; .gsave' blob.bin
gdare2 -w -qc 's 0x400000; wi4 0x12345678; w6d QUI=; .gsave' blob.bin
```

### JSON, filtering, pipes, and batch iteration

```bash
gdare2 -j -qc 'iI' /bin/ls
gdare2 -qc 'pd 50~+call' /bin/ls              # keep lines containing "call"
gdare2 -qc 'pd 50 | grep -i call' /bin/ls     # pipe to an external command
gdare2 -qc 'pd 50~+call > calls.txt' /bin/ls  # redirect
gdare2 -qc 'pd 1 @@f' /bin/ls                 # one per function
gdare2 -qc 'pd 1 @@i' /bin/ls                 # every instruction in the current function
gdare2 -qc 'pd 1 @@b' /bin/ls                 # every basic block
gdare2 -qc 'px 8 @@S' /bin/ls                 # every memory block
gdare2 -qc 'pd 1 @@=0x1000,0x2000' /bin/ls    # explicit address list
gdare2 -qc 'pd 1 @@f:^main$' /bin/ls          # function-name regex
```

### Configuration and rc

```bash
gdare2 -e scr.color=1 -e hex.cols=8 -qc 'px 16' /bin/ls
gdare2 -qc 'e io.cache=true; e search.from=0x1000; e' /bin/ls
```

rc files load in this order:

- System: `$XDG_CONFIG_HOME/gdare2/rc` (default `~/.config/gdare2/rc`)
- User: `~/.gdare2rc`

`-N` skips the user rc; `-NN` also skips the system rc. REPL history lives at
`$XDG_STATE_HOME/gdare2/history` (default `~/.local/state/gdare2/history`).

### Daemon management

```bash
gdare2 -L                       # list running daemons
gdare2 --status <instance-id>   # JSON status
gdare2 --kill <instance-id>     # stop a daemon
gdare2 -qc '.gstatus' /bin/ls   # current daemon/program info
gdare2 -qc '.gclose' /bin/ls    # save and close the current daemon
gdare2 --project /data/projects --project-name demo /bin/ls
```

Projects default to `~/gdare2-data`, which `GDARE2_DATA_DIR` can override.
`.gclose` with `-w` saves the program; read-only sessions do not save.

## Command overview

| Category | Main commands |
|---|---|
| Information | `iI`, `iS`, `is`, `ii`, `ie`, `iz`, `it`, `iM` |
| Disassembly/memory | `pd`, `pdf`, `pD`, `pi`, `p8`, `px`, `pv`, `ps`, `pc` |
| Search | `/`, `/x`, `/p`, `/a`, `/w`, `/v[1248]`, `/r`, `//`, `/+`, `/-`; `search.in=raw` |
| Functions/graphs | `afl`, `afi`, `af`, `afn`, `afu`, `afr`, `afvR`, `afvW`, `an`, `afc`, `afC`, `afx`, `afb`, `ab`, `ao`, `ai`, `agf` |
| xrefs | `axt`, `axf` |
| Decompilation/variables | `pdc`, `afv` |
| Types | `t`, `ts`, `tu`, `te`, `tt`, `tf`, `td`, `tc`, `tfc`, `t-`, `tf-`, `tp`, `tpv`, `tpx` |
| Signatures | `afs`, `afsj` |
| Comments | `C`, `C.`, `CC`, `CC-`, `Cd`, `Cb`, `Cp`, `Cr` |
| Flags | `f`, `fj`, `fq`, `f?`, `f-`, `fr`, `f.` |
| Analysis writes | `a8`, `ad` |
| Byte writes | `w`, `wq`, `wx`, `w0`, `wf`, `wd`, `wc`, `wc+`, `wc-`, `u`, `U`, `wi`, `w6d`, `w6e` |
| Assembly | `pa`, `wa`, `wa*`, `wa+`, `waf`, `waF` |
| Scripts/misc | `S`, `$`, `_`, `x`, `x8`, `xw`, `xq`, `xj`, `iE`, `ia`, `izz` |
| Iteration | `@@F`, `@@/x`, `@@/`, `@@.file`, `@@s:from to step`, `@!n`, `@{from to}` |
| Session/config | `s`, `b`, `e`, `q`, `.g`, `.gstatus`, `.gsave`, `.gclose`, `.gsync`, `.ganalyze`, `.ghelp`, `.gexec` |

Most query commands support a `j` suffix for JSON output; use `<command>?` for
per-command help.

### Types and signatures

```bash
gdare2 -w -qc "td 'struct demo { int field; char text[8]; };'; tc demo; .gsave" /bin/ls
gdare2 -qc 'tc demo; tfc~entry' /bin/ls
gdare2 -w -qc 's entry; afs "int entry(int value)"; .gsave' /bin/ls
gdare2 -qc 's entry; afsj' /bin/ls
gdare2 -w -qc 'tf- unused_function_type; .gsave' /bin/ls
```

`td` requires quoting the entire C declaration when it contains semicolons;
otherwise `;` is treated as a gdare2 statement separator. `tc` prints ANSI-C
declarations produced by Ghidra's `DataTypeWriter`. When writing a signature,
`afs` renames only Ghidra's default function name and does not overwrite a
user-defined name.

## Differences from radare2

gdare2 does not pretend that Ghidra is r2. It aims to support high-frequency
workflows while exposing differences explicitly:

- Function names, disassembly text, and decompiler output use Ghidra
  semantics; r2 formatting is not fabricated.
- `w` with no arguments saves the program; `w <text>` writes a string.
- `u/U` is daemon-local byte patch history, not Ghidra global undo.
- `f` writes session-local flags by default. Writing them back to Ghidra
  requires `-w` and `e ghidra.flags.write=true`.
- `pa/wa` use the Ghidra SLEIGH assembler by default, so mnemonics usually need
  to be uppercase. Use `--assembler=rasm2|auto` or
  `e asm.assembler=...` to switch backends.
- `/r` only walks defined strings; `izz` and `search.in=raw` return file
  offsets.
- `afr` is an approximate reanalysis that deletes and recreates a function;
  `an` has limited support for pure decompiler local variables.
- `.gexec` requires both the client and the daemon to pass `--allow-exec`, and
  also requires `-w`.
- `-B` only applies to raw binaries; Ghidra 12.2 has no corresponding language
  for `sh4`.
- `-A/-AA`, `--wait`, `--listen`, and `--assembler` are implemented.
  `--allow-exec` reports a clear error when `.gexec` is not enabled.

## Development and testing

```bash
# Offline unit tests
.venv/bin/python -m pytest -q

# Real-Ghidra integration tests (about 3 minutes)
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m real_ghidra tests/integration/test_real_ghidra.py

# 22-configuration architecture import matrix
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m arch_matrix
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python tools/arch_matrix.py

# r2 parity (/bin/ls and an ARM32 sample; golden files live in tests/golden)
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m parity

# Recapture golden files
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python tools/capture_r2_golden.py --target /bin/ls \
  --output tests/golden/ls.json

# Performance baseline
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python tools/perf_probe.py /bin/ls --output /tmp/perf-baseline.json
```

Directory boundary: `src/gdare2` is the client and must not import
`pyghidra`/`jpype`; only `src/gdare2d` depends on the JVM.
