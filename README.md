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

- **Ghidra analysis with r2 habits**: 370+ commands covering
  `s/pd/px/afl/afi/axt/axf/pdc/afv/t*/f*/C*`, the `?` expression family,
  `@` temporary modifiers, `@@` iteration, and r2-style grep/pipe/redirect.
- **The r2 command language, not just the commands**: integer expressions with
  `$` variables, numeric repeat prefixes (`3s+`), macros
  (`(name args; ...)`), `.cmd` output interpretation, and backtick
  substitution — so existing r2-style scripts mostly run as-is.
- **Two-process architecture with a JVM-free client**: the CLI only parses,
  manages sessions, and renders output; the PyGhidra daemon owns the Ghidra
  project.
- **Resident daemon**: the first import and analysis is slow; afterward,
  multiple clients share the same open program.
- **Read-only by default, writes require opt-in**: only requests using `-w` can
  write, and the daemon can also be forced read-only.
- **Automation-friendly**: `-qc`, `-j` JSON, `~` filters, `|` pipes,
  `>` redirection, r2 scripts via `-i`, and an r2pipe-compatible server via
  `--pipe-listen` — existing `r2pipe` Python clients can drive gdare2
  unchanged.
- **Regression testing against real Ghidra**: layered offline unit tests,
  real-Ghidra integration tests, a 22-configuration architecture matrix, and
  r2 parity tests against golden files.

## What gdare2 does

- **Analysis and information**: file/section/symbol/import/export/string
  inspection (`i*`), function lists and details (`afl`, `afi`), basic blocks,
  control-flow and call graphs (`agf`, `agC`), cross-references (`axt`,
  `axf`, `axg`), and decompilation with variable info (`pdc`, `afv`).
- **Read and write memory**: hexdumps (`px`, `p8`, `pv`, `ps`, `pj`), typed
  reads (`tp`), `pf` format strings, byte/string/immediate writes (`wx`,
  `wv`, `wi`, ...), a write cache, and byte-level undo/redo.
- **Types and metadata**: ANSI-C type parsing and declaration output
  (`td`, `tc`, `ts`, `te`), function signatures (`afs`), comments, flags with
  namespaces (`fs`), and per-session projects (`P`).
- **Command language**: integer expressions (`?v`, `$` variables), temporary
  seeks (`@`, `@@` iterators), macros, numeric repeat prefixes, grep/pipe/
  redirect, and r2-style scripts.
- **Interoperability**: an r2pipe-compatible server (`--pipe-listen`) for the
  standard Python `r2pipe` client, JSON output for most query commands, and
  code-array generation in a dozen languages (`pc*`).
- **Not supported** (explicit errors, never silent fallbacks): the debugger
  and ESIL, Ghidra GUI attachment, visual mode, sdb, zignatures, and JSON
  fields Ghidra cannot provide (`esil/opcode/family/type`).

## Architecture

```text
gdare2 CLI  ──loopback HTTP/JSON──▶  gdare2d (PyGhidra daemon)
   │                                      │
   ├─ r2 syntax parsing                   ├─ Ghidra Project / Program
   ├─ seek / filters / pipes / redirects  ├─ auto-analysis and disassembly
   ├─ output rendering                    ├─ DecompInterface
   ├─ macros / variables / flags          └─ Memory / Symbol / Comment / Type writes
   └─ r2pipe TCP/HTTP server (opt-in) ────┘ (via the same session)
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
| Python | 3.11+ (CI covers 3.11–3.14) |
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

### Functions, graphs, and xrefs

```bash
gdare2 -qc 'afl' /bin/ls
gdare2 -qc 's main; afi; afb; ab; ao' /bin/ls
gdare2 -qc 's main; agf' /bin/ls       # ASCII control-flow graph
gdare2 -qc 's main; agfj' /bin/ls      # JSON
gdare2 -qc 's main; agfd' /bin/ls      # Graphviz DOT
gdare2 -qc 's main; agC 2' /bin/ls     # call graph, 2 levels
gdare2 -qc 's main; agCd' /bin/ls      # call graph as Graphviz DOT
gdare2 -qc 'axt @ main; axf @ main' /bin/ls
gdare2 -qc 'axg' /bin/ls               # xref graph reaching the current function
```

### Expressions, macros, and the command language

```bash
gdare2 -qc '?v 0x10+0x20; ?vi 300; ?x hello; ?u 1234567' /bin/ls
gdare2 -qc '3s+; s' /bin/ls                    # repeat prefix
gdare2 -qc 'pd 2 @s:main' /bin/ls              # temporary seek by symbol
gdare2 -qc 'px 32 @e:hex.cols=8' /bin/ls       # temporary config
gdare2 -qc '(dump; s entry; pdf ~[0])' /bin/ls
gdare2 -qc '.(dump)' /bin/ls                   # call a macro
gdare2 -qc 's `? 0x1000+0x40`' /bin/ls         # backtick substitution
```

The numeric repeat prefix (`5pd 1`), `$` variables (`$0`…, `$?`, `$$`),
temporary seeks (`@addr`, `@s:name`, `@i:n`, `@B:n`, `@c:cmd`, `@x:hex`,
`@%env`, `@e:k=v`, `@F:space`), and `@@` iterators compose like r2.

### Searching

```bash
gdare2 -qc '/x 488b' /bin/ls            # hex bytes
gdare2 -qc '/x 90?f' /bin/ls            # ?/./ preserve a nibble
gdare2 -qc '/b 488b' /bin/ls            # search backward
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

Use `e search.from=0x...`, `e search.to=0x...`, and `e search.maxhits=N` to
bound the search. `search.in=raw` maps results to file offsets.

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

### Flags and flag spaces

```bash
gdare2 -qc 'f~entry; fq; f? entry' /bin/ls
gdare2 -qc 'fs imports; f my_label 4 @ entry; fs; fsj' /bin/ls
gdare2 -qc 'fd my_label; fc; fo 0x0 0xffffffff' /bin/ls
# By default flags stay in the session. Writing them back to Ghidra requires
# -w and ghidra.flags.write=true.
gdare2 -w -qc 'e ghidra.flags.write=true; s entry; f demo_flag 4; .gsave' /bin/ls
```

### Scripting output: `pf` and the `pc` family

```bash
gdare2 -qc 'pf 4xi @ entry' /bin/ls         # format string over memory
gdare2 -qc 's entry; pf.myfmt' /bin/ls      # named formats
gdare2 -qc 'pcg 16' /bin/ls                 # Go slice
gdare2 -qc 'pcJ 16' /bin/ls                 # JSON array
gdare2 -qc 'pct 16' /bin/ls                 # TypeScript
gdare2 -qc 'pcc 16' /bin/ls                 # C char array
```

The `pc` family covers C/C char/decimal/Go/Rust/Swift/TypeScript/JSON/
shell/Verilog/WAT/Fortran and quiet hexpairs, ready to paste into generated
code.

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

Assembly uses the Ghidra SLEIGH assembler by default; mnemonics usually need
to be uppercase. `--assembler=rasm2|auto` (or `e asm.assembler=...`) switches
to the radare2 assembler for languages SLEIGH cannot assemble:

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

### r2 scripts and r2pipe automation

Run r2-style scripts (macros, `?v`, `@` modifiers, `@@` iterators, `$`
variables all work):

```bash
cat > script.r2 << 'EOF'
(audit; s entry; pd 20~CALL; afl~+main)
.(audit)
?v $b
EOF
gdare2 -i script.r2 /bin/ls
```

Drive gdare2 with the standard `r2pipe` Python client:

```bash
pip install r2pipe
gdare2 --pipe-listen 127.0.0.1:9090 /bin/ls
```

```python
import r2pipe

r = r2pipe.open("http://127.0.0.1:9090/")   # or r2pipe.open("tcp://127.0.0.1:9090")
print(r.cmd("pd 5"))
print(r.cmdj("pdfj"))                       # JSON
print(r.cmd("afl~main"))
```

The server reuses the full command pipeline (`@`/`~`/`|`, macros, flags), and
write commands stay gated by `-w`. HTTP mode supports many commands per
client; the raw TCP mode answers one command per connection (matching r2's
behavior).

### Configuration and rc

```bash
gdare2 -e scr.color=1 -e hex.cols=8 -qc 'px 16' /bin/ls
gdare2 -qc 'e asm.offset=false; pd 2' /bin/ls   # hide the address column
gdare2 -qc 'e scr.utf8=false; e asm.lines=true; pd 2' /bin/ls
```

rc files load in this order:

- System: `$XDG_CONFIG_HOME/gdare2/rc` plus `rc.d/` fragments
- User: `~/.gdare2rc`
- Project: `.gdare2rc` files from the filesystem root down to the working
  directory

`-N` skips the user and project rc; `-NN` also skips the system rc.
`GDARE2_RCFILE` overrides the rc path. REPL history lives at
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
| Expressions | `?`, `?v`, `?vi[1248]`, `?vx`, `?X`, `?x`, `?b`, `?o`, `?u`, `?l`, `?e`, `?r`, `?s`, `?q`, `?=`, `?==`, `?btw`, `?eq/?ne/?le/?ge`, `?b64`, `?a`, `?j`, `?p`, `?P` |
| Information | `iI`, `iS`, `iSS`, `is`, `ii`, `ie`, `iee`, `ies`, `iz`, `it`, `iM`, `iC`, `iD`, `iV`, `iv`, `iT`, `ih`, `iH`, `il`, `ir` |
| Disassembly/memory | `pd`, `pdq`, `pdC`, `pdJ`, `pd,`, `pdf`, `pD`, `pi`, `p8`, `px`, `p6`, `p=`, `pj`, `pr`, `ph`, `pv`, `ps`, `pwd` |
| Code generation | `pc`, `pcc`, `pcd`, `pcb`, `pcg`, `pci`, `pcJ`, `pcq`, `pcr`, `pcS`, `pct`, `pcu`, `pcv`, `pcw`, `pcz`, `pcF` |
| Search | `/`, `/x`, `/b`, `/F`, `/p`, `/a`, `/w`, `/v[1248]`, `/r`, `/i`, `/d`, `/z`, `/m`, `/c`, `/R`, `//`, `/+`, `/-`; `search.in=raw` |
| Functions/graphs | `afl`, `afi`, `af`, `afn`, `afu`, `afr`, `afvR`, `afvW`, `an`, `afc`, `afC`, `afx`, `afb`, `ab`, `ao`, `ai`, `agf`, `agC` |
| xrefs | `axt`, `axf`, `axg`, `axF`, `axv`, `axff`, `ax*` |
| Decompilation/variables | `pdc`, `afv` |
| Types | `t`, `ts`, `tu`, `te`, `tt`, `tf`, `td`, `tc`, `tfc`, `t-`, `tf-`, `tp`, `tpv`, `tpx`, `tn`, `to`, `tk`, `tl`, `tx` |
| Signatures | `afs`, `afsj` |
| Metadata/comments | `C`, `C.`, `CC`, `CC-`, `Cd`, `Cb`, `Cp`, `Cr`, `Ch`, `Cs`, `Cm`, `Cf`, `Ct`, `CL` |
| Flags/spaces | `f`, `fj`, `fq`, `f?`, `f-`, `fr`, `f.`, `fn`, `fN`, `fx`, `fc`, `fo`, `fd`, `fs`, `fsj`, `fs*`, `fsq`, `fs-`, `fsr` |
| Analysis writes | `a8`, `ad` |
| Byte writes | `w`, `wq`, `wx`, `w0`, `wf`, `wd`, `wc`, `wc+`, `wc-`, `u`, `U`, `wi`, `w6d`, `w6e`, `wt`, `wv`, `wr`, `ws`, `ww` |
| Compare/yank | `c`, `cc`, `c1`, `c2`, `c4`, `c8`, `cJ`, `cv`, `y`, `yy`, `yx`, `yt`, `yf`, `yj`, `y*`, `yp`, `yq`, `ys`, `yw`, `yz` |
| Assembly | `pa`, `wa`, `wa*`, `wa+`, `waf`, `waF` |
| Scripts/misc | `S`, `$`, `_`, `x`, `x8`, `xw`, `xq`, `xj`, `iE`, `ia`, `izz`, `env`, `es`, `et`, `ev`, `e*`, `e-`, `e!`, `(macro)`, `.cmd` |
| Iteration/modifiers | `@@F`, `@@/x`, `@@/`, `@@.file`, `@@s:from to step`, `@!n`, `@{from to}`, `@s:`, `@i:`, `@B:`, `@c:`, `@x:`, `@%`, `@e:`, `@F:` |
| Session/config | `s`, `s:`, `s=`, `sa`, `sC`, `sd`, `b`, `bj`, `bf`, `bm`, `e`, `q`, `P`, `T`, `.g`, `.gstatus`, `.gsave`, `.gclose`, `.gsync`, `.ganalyze`, `.ghelp`, `.gexec` |

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
- `? <expr>` prints a single decimal line (r2 prints a representation table);
  use `?j` for the JSON representation.
- Flag subcommands follow analysis value over r2 6.x legacy semantics: `fc`
  lists flags in a range (r2 sets flag colors), `fm` aliases `bf`
  (r2 moves a flag), `fd` resolves a flag name to an address (r2 decomposes
  an address to flag+delta).
- `w` with no arguments saves the program; `w <text>` writes a string.
- `u/U` is daemon-local byte patch history, not Ghidra global undo.
- `f` writes session-local flags by default. Writing them back to Ghidra
  requires `-w` and `e ghidra.flags.write=true`.
- `pa/wa` use the Ghidra SLEIGH assembler by default, so mnemonics usually need
  to be uppercase. Use `--assembler=rasm2|auto` or
  `e asm.assembler=...` to switch backends.
- `/r` only walks defined strings; `izz` and `search.in=raw` return file
  offsets. `?p/?P` map addresses through the ELF program headers of the
  original file (raw-file view), not Ghidra memory blocks.
- `afr` is an approximate reanalysis that deletes and recreates a function;
  `an` has limited support for pure decompiler local variables.
- The debugger, ESIL, visual mode, sdb, and zignatures are not implemented;
  unsupported `e` keys (`asm.emu`, `anal.*`, `dbg.*`, ...) fail with an
  explicit reason instead of being silently ignored.
- `.gexec` requires both the client and the daemon to pass `--allow-exec`, and
  also requires `-w`.
- `-B` only applies to raw binaries; Ghidra 12.2 has no corresponding language
  for `sh4`.

## Development and testing

```bash
# Offline unit tests
.venv/bin/python -m pytest -q

# Real-Ghidra integration tests (about 5 minutes)
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m real_ghidra

# 22-configuration architecture import matrix
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m arch_matrix

# r2 parity (/bin/ls and an ARM32 sample; golden files live in tests/golden,
# captured with radare2 6.2.6)
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

## License

MIT — see [LICENSE](LICENSE).
