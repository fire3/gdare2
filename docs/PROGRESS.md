# gdare2 开发进度

更新时间：2026-11-13
最近验证：2026-11-13

## 当前状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 预研 | 完成 | PyGhidra 导入/分析/反编译/持久化已验证 |
| M0 骨架 | 完成 | 两进程链路、注册表、自动拉起、首批命令与测试 |
| M1 只读核心 | 基本完成 | 只读命令、搜索、JSON 变体、调用关系、session lease、ARM/裸二进制导入已验证 |
| M2 分析/图 | 完成 | `@@` batch、函数/块图、`ab/ao/ai`、`afln/afl+`、`afn/afu/a8/ad` 可用；架构矩阵可用 |
| M3 反编译/类型 | 基本完成 | `pdc/afv`、`t/ts/tu/te/tt/tf`、`td/tc/tfc/t-`、`tp/tpv/tpx`、`afs`、`C/CC/Cp` 已可用；复杂 C++ 类型与结构体值格式化仍受 Ghidra 限制 |
| M4 写入 | 完成（v1 范围） | `wx/w/w0/wf/wd`、`wa/wa*/wa+`、`wi`、`w6d/w6e`、`u/U`、`io.cache`+`wc+`、事务与只读门控已可用 |
| M5 兼容/体验 | 完成 | rc、readline、`-I/-i`、搜索、flags、脚本/变量、汇编、`.gexec`、parity 黄金文件、22 配置架构矩阵、batch meta 已完成 |
| v2 G1–G5 | 完成（2026-11-13） | `iSS`、`tp/tc`、JSON 过滤、`-j` 查找顺序与 loader-arg 修复；详见 [TASKS-v2.md](TASKS-v2.md) §10 |
| v2 G7/G9 | 完成（2026-11-13） | `i`/`aflq`/`L`/`ej`/`e?`；迭代器跳过无指令/不可读目标、重复注册校验 |
| v2 G6/G8/G10 | 完成（2026-11-13） | 颜色/注释/gutter/demangle/`cmd.batch`；`--list-offset` 分页；文档收尾 |
| v2 G11 | 完成（2026-11-13） | `f*`/`C*`/`CC*`/`t*`/`s*`/`b*`/`iS*`/`ax*` 导出变体；`CCu base64`；`~` 转义修复 |
| v2 G12 | 完成（2026-11-13） | `pf`/`pfj`/`pfs`/`pf.<name>`：标量、数组、偏移、命名格式、uleb128 |
| v2 G15 | 完成（2026-11-13） | `pdb`/`pC`/`pA`、`pxd/pxu/pxj`、`ps*`、`p8*`、`pvu/pvd/pvp`；`pdk/pdr` 明确不支持 |
| v2 G13 | 完成（2026-11-13） | `~` 多列/负索引/范围、按列排序、行范围、`~{}`；`pd` 字节列对齐 r2 |
| v2 G16 | 完成（2026-11-13） | rc 层级（rc.d/项目祖先/`GDARE2_RCFILE`）；参数补全 flag/函数/`$` 变量 |
| v2 G17 | 完成（2026-11-13） | 反引号替换；`@@f`/`@@F` 排除 external/thunk；`.cmd` 明确不做 |
| v2 G14 | 完成（2026-11-13） | `px` r2 列布局；`hex.pairs/offset/ascii` 生效 |
| v2 G18 | 完成（2026-11-13） | 离线 308 passed；`ruff check .` 干净；GitHub Actions CI |
| v2 G19 | 完成（2026-11-13） | 客户端 ELF 解析：`ih`/`iH`/`il`/`ir`；/bin/ls 与 readelf 一致 |
| v2 G24 | 完成（2026-11-13） | LICENSE/CHANGELOG/RELEASING/uv.lock/publish CI；动态版本 |
| v2 G20 | 完成（2026-11-13） | `e asm.assembler=ghidra/rasm2/auto`；`pa/wa//a` 回退 rasm2 |
| v2 G21 | 完成（2026-11-13） | `y`/`%`/`*`/`c`/`T`/`P`；前导引号与 `$()` |
| v2 G22 | 完成（2026-11-13） | 类型成员布局与 `tpx` 结构体输入 |
| v2 G23 | 完成（2026-11-13） | 注释 sidecar；`e ghidra.comments.all` |

## v2 G1–G5（2026-11-13）

- **G1 `iSS`**：新增 `src/gdare2/formats/elf.py`，从输入文件解析 ELF
  program headers；`iSS`/`iSSj` 不再 alias 到 `iS`，非 ELF 明确
  `NOT_SUPPORTED`。
- **G2 `tp`**：`_typed_values()` 用 `getattr` 取基础类型，修复
  `IntegerDataType` 没有 `getBaseDataType()` 的崩溃；`tp/tpv/tpx` 现可读取
  `int` 等内建类型。
- **G3 `tc <name>`**：只保留声明目标类型的行（typedef/struct/union/enum），
  内建类型回退 `getPrototypeString()`；`tc` 无参数保持全量。
- **G4 JSON 过滤**：`postprocess()` 在 `~`/`|` 前按行拆分多行 handler 输出，
  `aflj~entry`、`pdj~ENDBR` 与 r2 的逐行过滤一致。
- **G5 `-j`**：`invoke()`/`_dispatch_iterator()` 先解析 JSON 变体再查找 spec；
  `-j f` 现在返回 JSON，`<cmd>?` 帮助不受影响。
- **附带修复**：`gdare2d` 在 argparse 之前提取 `--loader-arg KEY VALUE`，
  `-loader-fileOffset` 这类以 `-` 开头的 Ghidra 选项不再被误判为缺失参数。

## v2 G7/G9（2026-11-13）

- **G7 元命令**：新增 `i`（文件信息，首行 `file`）、`aflq`（函数地址）、
  `L`（列 live daemon，与 CLI `-L` 共用 `registry.live_instances()`）、
  `ej`（配置 JSON）、`e?`/`e??`（配置键表）；`afl`/`aflq` 支持名称/glob 过滤；
  `-j` 映射补充 `i→ij`、`e→ej`（带参数时保持文本）。
- **G9 健壮性**：`@@F`/`@@S` 等迭代器跳过无指令函数和不可读 block，汇总为
  一条 `WARN`；`cmd.register()` 拒绝重复 pattern，删除 `wi` 的重复注册。
- **语义复核**：r2 的 `@@f` 是 functions（`?@@`），gdare2 行为已一致；
  `@@s:from to step` 已实现，`@@s:<symbol-pattern>` 是 gdare2 扩展。

## v2 G6/G8/G10（2026-11-13）

- **G6 渲染**：`scr.color` 输出 ANSI（TTY 自动开启、`NO_COLOR` 关闭）；
  `asm.comments` 输出 `;-- symbol:` 与 EOL 注释（默认关闭，避免分析器注释
  污染默认输出）；`asm.lines` 输出 `│ `/`└─` gutter；`asm.demangle` 对
  `_Z` 符号使用 Ghidra `DemanglerUtil`；`asm.flags=false` 隐藏符号注释与
  `pdi` 符号列；`cmd.batch=false` 改为逐目标 RPC。
- **G8 分页**：新增 `--list-offset N` 与 `e list.offset=N`；
  `functions/symbols/imports/exports/strings/strings_all` 支持 `offset` 并
  返回 `meta.total/shown/offset/limit/truncated`；截断提示下一页偏移。
- **`-o` 语义修正**：r2 的 `-o` 是按文件偏移映射，不是输出分页；gdare2
  明确拒绝并提示使用 `--list-offset`，避免静默错义。
- **G10 文档**：COMMANDS/PROGRESS/DIVERGENCES/README/TASKS 同步。

## v2 G11（2026-11-13）

- **导出变体**：`f*` 输出 `f name size @ addr`；`C*`/`CC*`/`C*.` 输出
  `CCu base64:`（plate/pre/repeatable 用 `Cp`/`Cb`/`Cr`）；`t*` 输出
  `td '<declaration>'`（daemon `type_c` 新增 `compact`）；`s*` 输出
  `f undo_<n> = addr`；`b*` 输出 `b 0x100`；`iS*` 输出
  `f section.<name> size @ addr`。
- **交叉引用全集**：daemon 新增 `xrefs_all`（ReferenceManager 全局迭代，
  上限 10000）；客户端 `ax*`/`axlj`/`axlq`/`axlc`。`axj` 在 r2 6.2.5 是
  写引用命令，gdare2 明确 `NOT_SUPPORTED`。
- **注释回放**：`CCu` 与所有注释写入命令接受 `base64:` 前缀。
- **解析修复**：`~` 过滤器中的反斜杠转义不再把分隔符本身吃掉
  （`iS*~\.text` 可正常使用）。

## v2 G12（2026-11-13）

- 新增 `src/gdare2/pf.py`：r2 `pf` 格式子集的纯客户端解析/渲染；支持
  `b c C w d i I x o q U f F g t p s S z Z n N u`、`[n]`（`[4]x` 与 `x[4]`）、
  `. : , ;`、`e`、`0` union；`B D E G T X r ?` 明确报错。
- `pf`/`pfj`/`pfs`/`pf.`/`pf.<name>`；命名格式存于 `Session.pf_formats`。
- `CommandSpec.consumes_repeat` 让 `4pf xx` 由格式层分组。
- `-j` 映射 `pf`→`pfj`、`pf.<name>`→`pfj.<name>`。

## v2 G15（2026-11-13）

- 反汇编：`pdb`/`pC`/`pA`。
- 内存：`pxd`/`pxu`/`pxj`；`p8s`/`p8d`/`p8x`/`p8,`/`p8*`/`p8b`/`p8f`。
- 字符串：`psz`/`psw`/`psp`/`psu`/`psx`/`psn`/`psj`（`fmt/strings.py`）。
- 数值：`pv` 扩展 `[p][width][u|d][j]`，新增 `pvu`/`pvd`/`pvp`。
- `pdk`/`pdr` 抛 `NOT_SUPPORTED`。

## v2 G13（2026-11-13）

- `~[n]`/`~[-1]`/`~[0,2]`/`~[0-2]`/`~[2-]`；`~$:n` 按列排序；行范围修正。
- `~{}` 重新格式化 JSON；`~?ea`/`~<>`/`~:)`/`~:}` 明确报 unsupported。
- `pd`/`pdi` 字节列改为连续 hexpairs（>8 字节 `..`），`~[1]` 与 r2 对齐。

## v2 G16（2026-11-13）

- rc 加载顺序：系统 `rc` → `rc.d/*`（排序）→ `~/.gdare2rc` → 根到 cwd 的
  `.gdare2rc`；`GDARE2_RCFILE` 覆盖；`-N`/`-NN` 语义见 DIVERGENCES §11.8。
- Tab 补全：命令/配置键之外，参数位置补全 flag/函数名与 `$` 变量。

## v2 G17（2026-11-13）

- 反引号命令替换（首行、嵌套上限 8、未闭合/过深报错）。
- `@@f`/`@@F` 与 `iter_targets` 排除 external、thunk 与非可执行入口；
  `/bin/ls` 的 `pd 1 @@f` 由 292 成功 + 122 跳过变为 292 行无告警。
- `.cmd` 与 `.g*` 命名空间冲突，明确不做并记入 DIVERGENCES。

## v2 G14（2026-11-13）

- `fmt/memory.py` 重写为 r2 布局：2 字节分组、表头低位偏移、ASCII 对齐。
- 新增并生效 `hex.pairs`/`hex.offset`/`hex.ascii`；`px`/`x` 同步。
- `pd`/`pdi` 列布局在 G13 完成。

## v2 G18（2026-11-13）

- 新增 `tests/test_config.py`（配置默认值/强制转换/只读/reflect）与
  `tests/test_info_formats.py`（ELF 段类型/权限/PN_XNUM/损坏头）。
- `.github/workflows/ci.yml`：Python 3.12/3.13 上跑 `ruff check .` 与离线 pytest。
- 全仓 `ruff check .` 清零；离线测试达到 **308 passed**。

## v2 G19（2026-11-13）

- `formats/elf.py` 扩展：头、节、动态段、DT_NEEDED、REL/RELA 重定位与符号名。
- `ih`/`ihj`/`iH`/`il`/`ilj`/`ir`/`irj`；非 ELF 明确 `NOT_SUPPORTED`。
- `/bin/ls`：14 个 program header、3 个 DT_NEEDED、325 条重定位，与
  `readelf -l/-d/-r` 一致。

## v2 G24（2026-11-13）

- 发布工程：MIT LICENSE、CHANGELOG、RELEASING、`uv.lock`、PyPI publish workflow。
- `pyproject.toml` 版本改为从 `src/gdare2/__init__.py` 动态读取。
- `uv build` 产出 sdist/wheel；`uvx twine check dist/*` 均 PASSED。

## v2 G20（2026-11-13）

- 新增客户端 `assembler.py`：Ghidra SLEIGH、rasm2 与 auto 三种后端。
- `pa`/`wa`/`wa*`/`wa+`/`waf`/`/a` 统一走后端选择；auto 回退输出 WARN。
- 真实 rasm2 验证：x86 `mov eax, 1`、ARM/PPC/RISC-V 常见指令可汇编。

## v2 G21/G22/G23（2026-11-13）

- G21：`y`/`yy`/`yx`/`yt`/`yf`、`%`、`*`、`c`/`cc`/`c1`、`T*`、`P*`；
  前导引号字面命令与 `$(cmd)` 替换；`dt` 明确报错。
- G22：`ts`/`tu`/`te` 成员布局与 `tpx` 结构体 hexpairs 输入。
- G23：Ghidra program options 中的注释 sidecar；`C` 默认只列用户注释。

## 验证基线（2026-11-13 实测）

| 套件 | 命令 | 结果 |
|---|---|---|
| 离线 | `.venv/bin/python -m pytest -q` | `337 passed`，0.50s |
| 真实 Ghidra | `GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra` | `24 passed`，308.13s |
| r2 parity | 同上 `-m parity` | `12 passed`（r2 6.2.5） |
| 架构矩阵 | 同上 `-m arch_matrix` | `2 passed`，6.41s |

环境：Ghidra 12.2 PUBLIC、PyGhidra 3.2.x、Python 3.13.15、radare2 6.2.5。

## 本次修复（2026-11-08，详见 ROADMAP §2.5）

1. **instance-id 指纹统一**：客户端与 daemon 共用 `registry.import_fingerprint()`；
   手工 `gdare2d` 与 `gdare2 target` 可互相发现。
2. **架构默认端序修正**：`ppc/mips/sparc` 默认 BE；`x86/RISCV` 的 BE 请求、
   `sparc/68000` 的 LE 请求、非法位宽明确报 `BAD_ARGS`。
3. **daemon 状态可见**：`info` 合并 `instance_id/state/pid/port/error`；
   `.g`/`.gstatus` 不再显示 `None`；注册表状态随 ready/error/draining 更新。
4. **CLI 选项生效**：`-A/-AA` 触发 `aa/aaa`；`--listen` 转发；`--wait` 为默认；
   `--assembler=rasm2` 与 `--allow-exec` 在实现前明确报错。
5. **手工 daemon 默认值**：`gdare2d --foreground --target /bin/ls` 可直接启动；
   `--attach` 不再要求目标文件。
6. **只读与超时**：daemon `--readonly` 要求已有且已分析项目；显式 `aa` 返回
   `READONLY`；`--analysis-timeout` 与 `e ghidra.decompile.timeout` 生效。
7. **只读文案统一**：所有写命令先走客户端 `require_write()`，错误包含
   `re-run with -w to allow writes`。
8. **loader 参数校验**：`--loader`/`--loader-arg` 用 Ghidra `Option.getArg()`
   校验；未知 loader/参数返回 `BAD_ARGS`，支持类名与显示名。
9. **`pdi` 独立布局**：增加 symbol 列（地址+symbol+字节+文本）；`pd` 保持原布局。
10. **`pdj` 决策**：保持 r2 6.2.5 顶层数组与 Ghidra 原生字段，不伪造
    `esil/opcode/family/type`；缺失字段写入 DIVERGENCES。

Phase A 剩余项已全部处理。后续进入 Phase B（命令面）与 Phase C（parity/矩阵）。

> **升级注意**：`instance_id` 指纹已规范化（忽略 `analyze`/`reimport`/`ephemeral`/
> `readonly` 等运行时选项）。旧版本创建的 `projects/<old-id>` 不会被自动复用；
> 升级后首次运行会按新 id 重新导入一次，之后恢复正常复用。

## Phase B 完成（2026-11-08）

- **flags**：`f`/`fj`/`fq`/`f?`/`f-`/`fr`/`f.`；默认只写会话内 flag，
  `-w` + `e ghidra.flags.write=true` 才写回 Ghidra；daemon 新增
  `symbol_create/symbol_rename/symbol_delete`。
- **脚本/变量/输出**：`S`、`$`/`$?`、`_`、`x`/`x8`/`xw`/`xq`/`xj`。
- **信息/类型**：`iE`/`iEj`、`ia`/`iaj`、`t-`、`tp`/`tpv`/`tpx`。
- **搜索/迭代**：`/r`、`cmd.hit`、`@@F`、`@@.file`、`@!n`。
- **汇编/写入**：`pa`、`wa`、`wa*`、`wa+`、`waf`/`waF`、`wi` 宽度/符号变量、
  `w6d`/`w6e`；SLEIGH 助记符通常需要大写。
- **信息/搜索补齐**：`izz`/`izzj`、`/p`、`/a`、`search.in=raw`、
  `@@/x`、`@@s:from to step`、`@{from to}`。
- **扩展命令/分析写入**：`.gexec`（客户端 + daemon 双重 `--allow-exec` 门控）、
  `afr`、`afvR`、`afvW`、`an`；`e ghidra.analysis.wait=skip` 跳过 `-A` 自动分析。
- **daemon 控制**：`--daemon-readonly` 转发 `--readonly`。

Phase B 剩余项已清零；后续进入 Phase C（parity、架构矩阵增强、batch meta）。

## Phase C 完成（2026-11-08）

- **parity 基础设施**：新增 `src/gdare2/parity.py`（名称归一化、`pdi` 解析、
  版本/hash 失效判断）、`tests/parity/`、`tests/golden/` 与
  `tools/capture_r2_golden.py`。黄金文件是结构化 JSON，记录 schema、r2/Ghidra
  版本、language ID 与目标 sha256；版本或目标变化时测试 skip 并提示重新生成。
- **`/bin/ls` 黄金文件**：`tests/golden/ls.json`；覆盖 `iI` 字段与
  entry/base 相对偏移、`iS` 命名节集合和 `.text` 大小/地址、`afl` 导入名集合
  与数量区间、入口 32 字节、`pd`/`pdi` 地址/长度/字节序列、`pdl` 行数、向后
  反汇编地址序列。
- **ARM32 黄金文件**：`tests/golden/upnpd.json`，样本
  `../vulfirm/OverFlow/R6700v3/upnpd`；样本缺失时 skip，可用
  `GDARE2_ARM_TARGET` 覆盖。
- **架构矩阵增强**：22 配置（新增 SuperH SH-2A/SH-2）；每项断言语言、位宽、
  端序与 `pd 1` 非空；JSON 输出 `ok/actual/bits/big_endian/pd_ok/info_ok/pd/
  image_base`。RISC-V 使用 `13000000` 探针；`sh4` 仍明确报错。
- **batch meta 透传**：`search`/`search_raw` 改为返回 `OpResult`；`batch`
  逐项保留 `meta`；客户端 `@@` 汇总子项截断并输出 `WARN`；`@@/x` 等搜索迭代也
  使用响应级 `meta` 判断截断。
- **性能与错误审计**：新增 `tools/perf_probe.py`、`docs/PERF.md` 与
  `docs/perf-baseline.json`；`tests/test_errors.py` 校验错误类、`EXIT_CODES` 与
  CLI 退出码；补齐 `CONNECTION=3`。函数/符号缓存评估为暂不实现（见 PERF.md）。
- **汇编冷启动超时**：首次 `pa`/`wa`/`/a` 的 SLEIGH 初始化实测 20–60 s，会超过
  通用 30 s RPC 超时。新增 `e ghidra.assemble.timeout`（默认 180 s），只对汇编
  op 生效，其他 op 仍使用 `ghidra.timeout`；集成测试恢复稳定。

parity 的已知限制：`pdl` 输出布局与 r2 不同，只比较行数；向后反汇编的指令边界
可能随解码器不同，只校验地址序列；函数数量不要求逐项一致，只比较导入名集合与
数量区间。

Phase C 剩余项已清零；v1 阶段全部完成。

## 已修复问题对照（原审查清单）

- C1 instance-id 指纹 → 已修复（A1）
- C2 `ppc/mips/sparc` 默认端序 → 已修复（A2）
- C3/C4 `.g/.gstatus` 状态与注册表状态 → 已修复（A3）
- C5 CLI 空转选项 → 已修复/明确报错（A4）
- C6 手工 `gdare2d` 参数 → 已提供默认值（A5）
- C7 daemon `--readonly` 语义 → 已修复（A6）
- C8 分析/反编译超时 → 已修复（A6）
- C9 只读错误文案 → 已统一（A7）
- C10 `pdj` 字段集 → 已决策：保持顶层数组与原生字段，不伪造缺失字段
- C11 `pdi`/`pd` 布局 → 已修复：`pdi` 增加 symbol 列
- C12 被忽略的 `-k` 不消费参数 → 已修复（A8）
- C13 `--loader-arg` 未校验 → 已修复（A8）
- 额外：`--attach` 无目标文件、daemon bootstrap 退出码/错误码回传 → 已修复

## P0 验收

```bash
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python \
  --no-index -f "$HOME/ghidra/current/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
uv pip install --python .venv/bin/python -e '.[test]'
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python tools/spike_pyghidra.py /bin/ls --project /tmp/gdare2-p0
```

结论：导入、自动分析、反编译和项目热重开全部通过；详见 `RESEARCH.md` 第 9 节。

## M0 验收记录

已完成：

- `pyproject.toml` 与 `gdare2` / `gdare2d` 入口；
- 参数、表达式、命令解析、`~` 过滤、管道/重定向、协议、注册表、自动拉起；
- loopback HTTP JSON RPC、bearer token、`/health`、`/info`、`/shutdown`；
- 单线程 Program executor 与请求级写入门控；
- Ghidra 导入、自动分析、项目复用、入口识别；
- 客户端命令：`s/s+/s-/s++/s--/sb/sf/sF/so/sn/sp/b`、
  `pd/pdf/pdfj/px/p8/pv/ps`、`iI/ij/iS/is/ii/ie/iz`、
  `afl/afi/af/aa/aaa/afb`、`axt/axf`、`e/q/?/.g/.gstatus/.gsave/.gclose`；
- daemon ops：`info/resolve_name/disasm/disasm_back/pdf/read_bytes/read_value/`
  `sections/symbols/imports/entries/strings/functions/function_at/basic_block/`
  `basic_blocks/create_function/xrefs_to/xrefs_from/analyze/save`；
- 离线测试 `42 passed`；真实 Ghidra 测试 `3 passed`。

第二轮（M1）新增：

- `pdi/pi/pdl/pD/pdj`、`pxw/pxq`、`p8j/pv1/pv2/pv4/pv8/pvj*`、`pc`；
- `iSS/iS./it/iM`、`afc/afC/afx/aflc`；
- `@@` 之外的 `~` 行范围/列选择/计数/排序、截断警告；
- session lease + heartbeat + `/sessions`，idle 只在无活跃 lease 时生效；
- 调用者/被调用者/函数内 xref；
- ARM32 ELF（`../vulfirm/OverFlow/R6700v3/upnpd`）导入与反汇编；
- 裸二进制 `-a x86 -b 64 -B 0x400000` 导入、自动反汇编与基址识别。

第三轮（M2）新增：

- `@@=`/`@@f`/`@@i`/`@@b`/`@@S`/`@@s` 目标枚举；`@@@` 为每个目标携带大小；
- `batch` RPC 在同一 executor 时间片顺序执行，单项失败不影响整批；
- `agf/agfj/agfd` 基本块图，`ab/abj`、`ao/aoj`、`ai/aij`；
- `afln`、`afl+`，以及 `afn` 重命名与 `afu` 调整函数边界；
- `afn/afu` 的 `-w` 门控、transaction、`.gsave` 保存与 daemon 重启后持久化；
- 修正 `.g/.gstatus/.gsave/.gclose` 的 dot 命令分发与 save 事务锁冲突；
- 统一适配 PyGhidra 返回的 Java 数组/iterator，覆盖 `BasicBlockModel` 路径。

第四轮（M2 收尾）新增：

- `a8 <hexpairs>` 写入并重新反汇编当前地址；
- `ad [n]` 按目标架构字宽创建数据；
- `a8/ad` 的只读门控、事务回滚、`.gsave` 持久化与重启后验证；
- `af` 增加 `aF` 别名。

第五轮（M3 开始）新增：

- daemon 级 `DecompInterface` 生命周期与超时参数；
- `pdc/pdcj` C 反编译输出（可直接配合 `@@` 迭代）；
- `afv/afvj` 从 `HighFunction.getLocalSymbolMap()` 提取参数/局部变量；
- `afv` 按 Ghidra `VariableStorage` 分类为 `reg/sp/other`。

第六轮（M3 类型/注释）新增：

- `t/tj` 类型列表/详情，`ts/tsj` 结构、`tu/tuj` 联合、`te/tej` 枚举、`tt/ttj` typedef；
- `tf/tfj` 基于 Ghidra 函数签名的 `getPrototypeString()`；
- `C/Cj/C.` 注释枚举，`CC/CC-/CC.`、`Cd/Cb/Cp/Cr` 注释写入与删除；
- 注释写入的 `-w` 门控、transaction、`.gsave` 与重启后可见性验证。

第七轮（M4 写入）新增：

- daemon `write_bytes/write_zero/write_file/write_copy/write_patches` 与 `undo/redo`；
- 客户端 `wx`（支持 `.`/`?` 半字节保留）、`w <text>`、`w0`、`wf -|file`、`wd`；
- `io.cache=true` 时补丁进入客户端缓存，`wc` 查看、`wc+` 一次 transaction 提交、`wc-` 丢弃；
- `w` 无参数保存，`wq` 提交缓存后保存并退出；缓存提交失败则不保存；
- `u/U` 使用 daemon 内存级字节补丁历史撤销/重做；
- 请求侧 base64 字节解码，写入后 `.gsave` 持久化与重启后可见性验证；
- 写入前清理写范围内的 code units，避免 Ghidra 的 instruction 冲突。

第八轮（M5 体验）新增：

- rc 文件：`$XDG_CONFIG_HOME/gdare2/rc`（系统）与 `~/.gdare2rc`（用户），用户后加载；
- `-N` 跳过用户 rc，`-NN` 跳过系统与用户 rc；rc 错误不会把会话标记为失败；
- REPL 使用 readline 历史（`$XDG_STATE_HOME/gdare2/history`）与 Tab 补全；
- 补全覆盖命令/别名与 `e` 配置键；
- 修正 `-I`（命令前）与 `-i`（命令后）脚本顺序；
- rc 在 CLI `-e` 之前加载，随后由 CLI 配置覆盖，保证命令行优先级。

第九轮（搜索）新增：

- daemon `search` op：按内存块搜索字节/掩码，支持前向、后向、范围与分页 `meta`；
- 客户端 `/ <text>`、`/x <hexpairs>`（支持 `.`/`?` 掩码）、`/w <utf16>`、`/v[1248] <num>`；
- `//`、`/+`、`/-` 基于客户端搜索历史继续前向/后向查找；
- `/j`、`/xj`、`/wj`、`/v*j` JSON 输出与 `-j` 默认映射；
- `search.from`/`search.to` 范围配置；`search.in=raw` 明确报不支持。

第十轮（架构矩阵）新增：

- `src/gdare2/arch_matrix.py`：20 个裸二进制架构/位宽/端序配置；
- `tools/arch_matrix.py`：一次 JVM 内批量导入并校验 Ghidra 语言 ID，支持 `--json`；
- `pytest -m arch_matrix`：先校验别名映射，再运行完整 20 配置导入矩阵；
- 修正 `sh4` 别名：Ghidra 12.2 无 SH-4 语言，改为明确报错并建议 `--ghidra-language`。

第十一轮（M3 类型写入与 batch 元信息）新增：

- `td '<C declaration>'` 通过 Ghidra `CParser` 定义 struct/union/enum/typedef/函数类型；
- `tc/tcj [name]` 通过 `DataTypeWriter` 输出 ANSI-C 声明，支持按名称或完整路径查找类型；
- `tfc/tfcj [name]` 输出 C 风格函数原型；`tf- <name|glob>` 删除已加载的函数定义类型；
- `afs [signature]` 获取/写入当前函数签名，使用 `CParserUtils` + `ApplyFunctionSignatureCmd`；
- `afs` 写签名保留用户自定义函数名，只重命名 Ghidra 默认名；参数列表可通过 `afsj` 查看；
- `td/tc/tfc/tf-/afs` 的类型与签名写入支持 `-w` 门控、transaction、`.gsave` 与重启后验证；
- RPC 增加 `OpResult`：`batch`/`iter_targets` 现在返回 `total/shown/truncated/errors` `meta`；
- `@@` 迭代使用服务端目标总数；目标截断时输出明确警告，batch 失败仍保持单项错误隔离；
- 未知 daemon op 统一返回 `UNKNOWN_OP`，不再混用 `NOT_SUPPORTED`。

第十一轮结束时的测试基线：离线 `69 passed`；真实 Ghidra `15 passed`；架构矩阵 `2 passed`。

验收命令：

```bash
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 5' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 's 0x106760; pd 5; px 16' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 20~+call' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc '/x 488b; / entry' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc '/xj 488b' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -j -qc 'iI' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 1 @@f:^entry$' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'agf @ entry; ab @ entry; ao @ entry; ai @ entry' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 's entry; afn demo_func; .gsave' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 's 0x400000; a8 9090c3; ad 1; .gsave' /tmp/blob.bin
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pdc @ entry; afv @ entry' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 't~int; ts; tf~entry' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc "td 'struct demo { int a; };'; tc demo; .gsave" /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 's entry; afs "int entry(int value)"; afsj; .gsave' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 'tf- demo_func_type; .gsave' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 's entry; CC demo comment; Cp demo plate; .gsave' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 's 0x400000; wx 9090; px 2; u; px 2; U' /tmp/blob.bin
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 'e io.cache=true; s 0x400000; wx 4142; wc; wc+; w' /tmp/blob.bin
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'e scr.color' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -N -qc 'e scr.color' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -L
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m arch_matrix
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python tools/arch_matrix.py
```

## 已知缺口

### 功能缺口

- `afB` 的 r2 语义已变为 Thumb 位宽切换，暂不按旧文档实现；
- 已知限制：`/r` 只遍历已定义字符串；`izz`/`search.in=raw` 返回文件偏移；
  `afr` 是删除+重建函数的近似重分析；`an` 对纯 decompiler 局部变量支持有限。

### 一致性与契约缺口

- `pdj` 顶层数组与 r2 6.2.5 一致，但字段集不同（缺 `esil/opcode/family/type` 等）；
  已决策不伪造缺失字段；
- ~~batch 子 op 的 `meta` 只汇总错误数~~ → 已修复：逐项保留并汇总截断；
- `--assembler=rasm2` 仍未实现，会明确报 `BAD_ARGS`（有意的显式拒绝）。

### 测试与 parity 缺口

- ~~`tests/parity/` 不存在~~ → 已建立；`pytest -m parity` 覆盖 `/bin/ls` 与 ARM32；
- ~~`tools/capture_r2_golden.py` 未实现~~ → 已实现并生成两份黄金文件；
- ~~架构矩阵只校验语言 ID~~ → 22 配置并断言 `pd 1`/`iI`；
- 架构矩阵仍不覆盖真实 ELF（只覆盖裸二进制导入）；
- 没有 ARM32 样本的独立真实 Ghidra 集成测试（parity 用例已实际导入该样本）；
- ~~没有性能基线~~ → 见 `docs/PERF.md` 与 `docs/perf-baseline.json`。

## 下一轮

详细任务、文件、测试与验收见 **[ROADMAP.md](ROADMAP.md)**。v1 的 Phase A–C
已全部完成。明确不支持 Ghidra GUI 打开时附着；daemon 独占项目是唯一运行形态。

没有必须推进的下一阶段。可选维护项：

1. `--assembler=rasm2` 回退（当前明确报 `BAD_ARGS`）；
2. `f` flag 视觉列（在 `pdi` 的 symbol 列之外增加 flag 列）；
3. 真实 ELF 架构矩阵（当前矩阵只覆盖裸二进制）；
4. ARM32 样本的独立 `-m real_ghidra` 用例。
