# gdare2 后续推进路线（细化）

> 本文把 `PROGRESS.md` 的“下一轮”拆到可执行任务级，作为 v1 收尾与
> 后续维护的实施依据。设计契约仍以 `DESIGN.md` 为准；命令映射以 `COMMANDS.md` 为准。
> 任何条目完成后，必须同步更新 `PROGRESS.md` 的验收记录与 `COMMANDS.md` 的
> 实现状态。

- 更新时间：2026-11-13
- 当前基线：M0–M5 完成，v1 收尾完成（Phase A–C 全部关闭）；v2 批次 A/B/C
  （G1–G24）已全部完成，P0/P1/P2 命令面与发布工程化关闭
- 目标：维护已完成的 v1；不做 Ghidra GUI 附着（2026-11-08 决定）
- **v2 任务**：v1 之后的兼容性补齐已拆分到
  [TASKS-v2.md](TASKS-v2.md)（2026-11-13 差距审计）；剩余 G19–G24 属 P2

## 0. 验证基线（2026-11-13 实测）

| 套件 | 命令 | 结果 |
|---|---|---|
| 离线 | `.venv/bin/python -m pytest -q` | `337 passed`，0.50s |
| 真实 Ghidra | `GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra` | `24 passed`，439.74s |
| r2 parity | 同上 `-m parity` | `12 passed`，96.21s |
| 架构矩阵 | 同上 `-m arch_matrix` | `2 passed`，7.92s |
| lint | `ruff check .` | 干净 |

## 0.1 历史验证基线（2026-11-08）

| 套件 | 命令 | 结果 |
|---|---|---|
| 离线 | `.venv/bin/python -m pytest -q` | `169 passed`，0.29s |
| 真实 Ghidra | `GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra` | `22 passed`，425.39s |
| r2 parity | `GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m parity` | `12 passed`，117.91s |
| 架构矩阵 | `GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m arch_matrix` | `2 passed`，8.44s |

环境：Ghidra 12.2 PUBLIC、PyGhidra 3.2.x、Python 3.13.15、radare2 6.2.5。

结论：核心读写链路稳定；v1 的 Phase A–C 已全部关闭。Ghidra GUI 附着明确
不做，daemon 独占项目是唯一运行形态。

## 1. 完成定义（Definition of Done）

### 1.1 v1 完成

- P0/P1 命令面全部可用，未实现命令明确返回 `NOT_SUPPORTED`；
- 默认只读、`-w` 写入门控、daemon 级 `--readonly` 都有自动化测试；
- `/bin/ls` 与 ARM32 样本的结构化 parity 黄金文件可重复通过；
- 架构矩阵覆盖设计目标配置，并验证 `pd 1`、`iI` 字段；
- 离线测试、真实 Ghidra 测试、parity、架构矩阵四层全绿；
- README、DESIGN、COMMANDS、DEV、PROGRESS、ROADMAP 状态一致；
- 明确不支持 Ghidra GUI 附着；daemon 独占项目，GUI 与 daemon 不同时打开同一项目。

## 2. 代码审查发现

### 2.1 正确性与一致性缺陷（必须先修）

> 状态：C1–C13 已在 2026-11-08 修复或决策，见 §2.5；C14（矩阵增强）与
> C15（batch meta）转入 Phase C。

| ID | 现象 | 证据 | 影响 | 修复方向 |
|---|---|---|---|---|
| C1 | 客户端与 daemon 的 `instance_id` 指纹不一致 | `src/gdare2/launcher.py:20` 的 `import_options()` 含 `"analyze"`，`src/gdare2d/__main__.py:67` 的字典不含；实测同一 `/bin/ls` 得到 `4196cf233b4d479c` 与 `52cfad3ccc90f8af` | 手工启动的 daemon 无法被客户端复用；未来 `-A` 生效后会按客户端选项分裂实例 | 抽出唯一的 `import_options_fingerprint()`，客户端与 daemon 共用；加单测断言两侧键集合一致 |
| C2 | `ppc`/`ppc64`/`mips`/`mips64`/`sparc`/`sparc64` 默认端序错误 | `src/gdare2d/import_plan.py:176` 的 `_is_big()` 只在名称以 `be` 结尾时返回真；实测 `resolve_alias("ppc")` → `PowerPC:LE:32:default`、`resolve_alias("sparc")` → `sparc:LE:32:default`；Ghidra 12.2 只有 `sparc:BE:*` | `-a ppc`/`-a mips` 选到错误语言；`-a sparc` 直接导入失败；矩阵因显式 `--endian big` 未暴露 | 按 r2 习惯给族默认端序：`ppc*`、`mips`/`mips64`、`sparc*` 默认 BE；`*le` 显式 LE；补别名单测 |
| C3 | `.g` / `.gstatus` 缺少 daemon 状态 | `src/gdare2/cmd/meta.py:45` 读取 `instance_id`/`state`，但 `src/gdare2d/ops/session.py:11` 只返回 `runtime.summary`；实测输出 `instance_id: None`、`state: None` | 用户无法从命令判断 daemon 是否就绪/只读；文档承诺的状态字段缺失 | 在 `info` op 合并 `instance_id/state/pid/port/readonly`，或让 CLI 使用 `/info` 端点并合并 summary；加单测 |
| C4 | 注册表状态文件长期停留在 `starting` | `src/gdare2d/__main__.py:123` 只写一次；`ready` 后不更新 | `--status` 与实际状态不一致，排障时误导 | 在 `ready`/`error`/`draining` 状态变化时原子重写状态文件，或在 `live_instance()` 中用 health 覆盖 `state` |
| C5 | 多个 CLI 选项被接受但没有行为 | `--wait`、`-A/-AA`、`--listen`、`--assembler`、`--allow-exec` 在 `src/gdare2/argv.py` 解析后未被 `launcher.py`/`cli.py` 使用 | 用户以为命令生效；`--listen 0.0.0.0` 尤其危险，daemon 仍只绑定 loopback | 能实现的实现（转发 `--listen`、`-A/-AA`）；不能实现的明确报 `NOT_SUPPORTED`，禁止静默忽略 |
| C6 | 手工 `gdare2d` 缺少默认项目参数 | `src/gdare2d/__main__.py` 要求 `--project` 与 `--project-name`，缺省时实测退出码 2；`DEV.md` §4.1 只能展示显式参数写法 | 开发者必须手工计算 instance-id 与项目路径，易错 | 给 `--project/--project-name` 合理默认值（由 data dir + instance id 派生），并更新 `DEV.md` |
| C7 | daemon `--readonly` 语义未落实 | `src/gdare2d/runtime.py:84` 即使 `readonly` 仍 `open_project(create=True)`、导入、分析并保存 | 审计/共享场景仍产生 bootstrap 写入，与 DESIGN §13.1 不符 | `readonly` 时要求项目/程序已存在且已分析；缺失时报 `NOT_READY`，不隐式导入 |
| C8 | 分析与反编译超时未生效 | `src/gdare2d/runtime.py:141` 的 `pyghidra.analyze()` 与 `task_monitor()` 无超时；`--analysis-timeout` 未使用；`ghidra.decompile.timeout` 未传给 `pdc/afv` | 大目标分析可能无限期占用 executor；`e ghidra.decompile.timeout` 无效 | 给 `task_monitor(timeout)` 传值并取消；`pdc`/`afv` 读取配置键；超时映射 `TIMEOUT` |
| C9 | 只读错误信息不统一 | `src/gdare2/errors.py` 的 `ReadOnlyError` 固定为 “read-only request cannot perform a write op”；`afn/afu/a8/ad/td/afs/CC` 依赖 daemon 报错 | DESIGN §13.1 要求错误包含 `re-run with -w to allow writes` | 统一 `ReadOnlyError` 文案，或所有写命令先走客户端 `_require_write()`；加测试 |
| C10 | `pdj` 字段集与 r2 不同 | `src/gdare2/cmd/print.py:29` 返回 `addr/bytes/size/text/mnemonic/symbol/call/jump/conditional`；r2 6.2.5 顶层也是数组，但含 `esil/opcode/disasm/family/type/refptr/type_num` 等 | 依赖 `esil`/`family` 的脚本不兼容；部分字段 Ghidra 无法提供 | **已决策**：保持顶层数组与原生字段，不伪造缺失字段；DIVERGENCES 记录 |
| C11 | `pdi` 与 `pd` 布局未区分 | 原实现把 `pdi` 作为 `pd` 别名；r2 6.2.5 的 `pd` 带 flag/注释缩进，`pdi` 是地址+flag+字节+文本的紧凑格式 | 依赖 `pdi` 紧凑布局的脚本/输出清洗需要适配 | **已修复**：`pdi` 增加 symbol 列（地址+symbol+字节+文本），`pd` 保持原布局 |
| C12 | 带值的被忽略短选项不消费参数 | `src/gdare2/argv.py:12` 的 `IGNORED` 中 `-k` 在 r2 中带值（`-k [OS/kern]`），当前直接继续，后续 token 被当作目标文件；`-E/-S/-t` 是布尔选项，无此问题 | `gdare2 -k linux /bin/ls` 会把 `linux` 当文件 | 区分 `IGNORED_BOOL` 与 `IGNORED_VALUE`，后者消费下一个参数 |
| C13 | `--loader-arg` 未校验 | `src/gdare2d/import_plan.py:39` 直接追加；DESIGN §8.4 要求未知 key 报 `BAD_ARGS` | Ghidra 只打 warning，用户误以为参数生效 | 通过 `Loader.getDefaultOptions()` 校验 key；未知 key 直接失败 |
| C14 | 架构矩阵只校验语言 ID | `tools/arch_matrix.py` 未验证 `pd 1`/`iI`；`DEV.md` §3 与 `PLAN.md` §8 的验收要求更高 | 语言正确但二进制无法反汇编的回归不会被发现 | 每个配置断言 `pd 1` 非空、`iI` 的 arch/bits/endian/base 正确 |
| C15 | batch 子 op 的 `meta` 未透传 | `src/gdare2d/ops/batch.py:18` 只汇总 `total/shown/errors` | 子 op 的分页/截断信息丢失；`@@` 无法提示子项截断 | 在 batch 结果中保留每项信封的 `meta`；客户端迭代时检查并汇总 |

### 2.2 命令面缺口（v1 P1 / P2）

| 族 | 缺口 | 现状 | 优先级 | 备注 |
|---|---|---|---|---|
| flags | `f`、`fj`、`fq`、`f name @ addr`、`f-`、`fr`、`f.` | 完全没有客户端 FlagStore | P1 | `is` 已能读符号，可作为种子；写回需 daemon symbol 写 op |
| 脚本/变量 | `S <file>`、`$`、`_`、`.cmd` | 只有 `-i/-I` 与 shell `!` | P1 | `Session.vars` 已有雏形，差命令层 |
| hexdump 变体 | `x`、`x8`、`xw`、`xq`、`xj` | 只有 `px/pxw/pxq` | P1 | 客户端基于 `read_bytes` 即可 |
| 信息 | `iE` 导出、`ia` 架构列表、`izz` 全文件字符串 | `ii/is/ie` 已有 | P1/P2 | `iE` 可基于 `symbols` 的 external/global 过滤 |
| 类型 | `t-` 通用删除、`tp/tpv/tpx` 类型化读取、`t*` | `tf-` 只删函数类型；`type_delete` op 已支持 `kind=None` | P1/P2 | `tt` 在 r2 中是 typedef 列表，不是“应用类型”；修正 COMMANDS |
| 分析 | `afr`、`afB`、`afvR/afvW`、`an` | 未实现；`afB` 的 r2 语义已变化 | P1/P2 | `afr` 可实现为重新分析函数，或明确 `NOT_SUPPORTED` |
| 搜索/迭代 | `/r`、`/p`、`/a`、`cmd.hit`、`search.in=raw`；`@@F`、`@@/x`、`@@.file`、`@@s:from to step`；`@!n`、`@{range}` | 只有 `/`、`/x`、`/w`、`/v`、基础 `@@` | P1/P2 | `cmd.hit` 依赖 `@@` 迭代 |
| 写 P2 | `pa`、`wa`、`wa*`、`wa+`、`waf/F`、`wi[1248]`、`w6` | 无 | P2 | 需要 `Assemblers.getAssembler`；不支持语言明确报错 |
| 扩展命令 | `.gsync`、`.ganalyze`、`.gexec`、`.ghelp` | 只有 `.g/.gstatus/.gsave/.gclose` | P1/P2 | `.gexec` 必须继续由 `--allow-exec` 双重门控 |
| daemon 控制 | 客户端暴露 `--daemon-readonly`、转发 `--listen`、`--analysis-timeout` | 无 | P1 | 与 C5/C7 一起做 |

### 2.3 测试与 parity 缺口（Phase C 已关闭）

1. ✅ `tests/parity/`、`tests/golden/` 与 `tools/capture_r2_golden.py` 已建立；
   `pytest -m parity` 有 12 个实际测试。
2. ✅ `/bin/ls` 与 ARM32 样本的结构化黄金文件已生成；`iI/iS/afl/px/pd/pdi/pdl`
   与向后反汇编都有 r2 对照。
3. ✅ 架构矩阵覆盖 22 配置，并校验语言/位宽/端序与 `pd 1`。
4. ⚠️ ARM32 样本在 parity 用例中实际导入；仍没有独立的 `-m real_ghidra` 用例。
5. ✅ 离线测试增至 169 条，覆盖 argv/launcher/registry/import_plan/session 等边界。
6. ✅ 性能基线见 `docs/PERF.md` 与 `docs/perf-baseline.json`。

### 2.4 文档同步（本次更新已处理）

| 文档 | 处理结果 |
|---|---|
| `DESIGN.md` 文首状态 | 已改为“M0–M4 核心已实现，M5 进行中”，并链接 PROGRESS/ROADMAP |
| `RESEARCH.md` §3 | 已补“P0 已完成，见 PROGRESS” |
| `DEV.md` §4.1 | 已改为显式 `--project/--project-name` 写法，并标注 A5 待补默认值 |
| `COMMANDS.md` | 已修正 `tt`/`u-U` 映射，新增 §14 实现状态与未实现清单 |
| `PLAN.md` §8 | 已拆为“已完成/待完成”，并链接 ROADMAP |
| `README.md` / `docs/README.md` | 已增加 ROADMAP 链接与 2026-11-08 验证日期 |

后续每完成一个 ROADMAP 任务，必须同步更新 `PROGRESS.md` 与 `COMMANDS.md`
的实现状态，避免文档再次漂移。

### 2.5 本次已修复（2026-11-08）

- **C1/A1** 统一 `instance_id` 指纹：`registry.import_fingerprint()` 只使用影响
  导入结果的键；客户端与 daemon 共用。新增 `tests/test_instance_id.py`。
- **C2/A2** `ppc/mips/sparc` 默认 BE；`mipsle/ppcle/sparc64` 等显式别名正确；
  `x86`/`RISCV` 的 BE 请求、`sparc`/`68000` 的 LE 请求、非法位宽均报 `BAD_ARGS`。
  新增 `tests/test_import_plan.py`。
- **C3/C4/A3** `info` op 合并 `instance_id/state/pid/port/error`；`.g`/`.gstatus`
  不再显示 `None`；注册表状态在 `ready`/`error`/`draining` 时重写。
  实测 `.g` 输出 `state: ready`。
- **C5/A4** `-A/-AA` 在命令前触发 `aa/aaa`；`--listen` 转发给 daemon；
  `--wait` 确认为默认行为；`--assembler=rasm2` 与 `--allow-exec` 在对应命令
  实现前明确报 `BAD_ARGS`，不再静默忽略。
- **C6/A5** `gdare2d` 自动推导 `--project` 与 `--project-name`；实测
  `gdare2d --foreground --target /bin/ls` 可直接启动并复用项目。
- **C7/A6** daemon `--readonly` 要求已有且已分析的项目；缺失时启动失败，
  不再隐式导入/分析/保存；显式 `aa` 返回 `READONLY`。
- **C8** `--analysis-timeout` 传给 `TaskMonitor`，超时映射 `TIMEOUT`；
  `e ghidra.decompile.timeout` 传给 `pdc`/`afv`。
- **C9/A7** 写命令统一客户端 `require_write()`；daemon 错误信息包含
  `re-run with -w to allow writes`。
- **C12** 被忽略的 `-k` 会消费其参数，避免把值当成目标文件。
- **C13** `--loader-arg`/`--loader` 校验：启动时用 Ghidra
  `LoaderService.getSupportedLoadSpecs()` + `Option.getArg()` 校验；未知 loader
  或未知参数返回 `BAD_ARGS`。支持类名与显示名（如 `BinaryLoader` / `Raw Binary`）。
- **C11** `pdi` 独立布局：新增 symbol 列（`address  symbol  bytes  text`），
  `pd` 保持原布局；`instruction_dict` 增加 `symbol` 字段。
- **C10** `pdj` 决策：保持 r2 6.2.5 的顶层数组形状与 Ghidra 原生字段
  （`addr/size/bytes/text/mnemonic/symbol/call/jump/conditional`），不伪造
  `esil/opcode/family/type`；缺失字段在 DIVERGENCES 记录。
- **额外修复**：`--attach` 不再要求目标文件；daemon bootstrap 失败返回非零退出码，
  并以 `BAD_ARGS`/`NOT_READY` 等原始错误码回传客户端；启动失败不再空等 180 秒。

Phase A 的剩余项已全部处理。C13（loader 校验）已完成；C14（架构矩阵增强）、
C15（batch 子 op meta）与 `pdi` 的 flag 列视觉细化转入 Phase C/B1。

> **升级注意**：instance-id 指纹现在只包含影响导入结果的键。旧项目的
> `projects/<old-id>` 目录不会被复用；升级后首次运行会按新 id 重新导入一次。

### 2.6 Phase B 完成（2026-11-08）

- **B1 flags（完成）**：`f`/`fj`/`fq`/`f?`/`f-`/`fr`/`f.`；默认会话内 flag，
  写回 Ghidra 需 `-w` + `e ghidra.flags.write=true`；daemon 新增
  `symbol_create/symbol_rename/symbol_delete`。
- **B2 脚本/变量/输出（完成）**：`S`、`$`/`$?`、`_`、`x`/`x8`/`xw`/`xq`/`xj`。
- **B3 信息/类型（完成）**：`iE`/`iEj`、`ia`/`iaj`、`izz`/`izzj`、`t-`、
  `tp`/`tpv`/`tpx`。
- **B4 搜索/迭代（完成）**：`/r`、`/p`、`/a`、`cmd.hit`、`search.in=raw`、
  `@@F`、`@@/x`、`@@.file`、`@@s:from to step`、`@!n`、`@{from to}`。
- **B5 汇编/写入（完成）**：`pa`、`wa`、`wa*`、`wa+`、`waf`/`waF`、
  `wi` 宽度/符号变量、`w6d`/`w6e`；Ghidra SLEIGH 助记符通常需要大写。
- **B6 扩展命令（完成）**：`.gsync`、`.ganalyze`、`.ghelp`、`.gexec`
  （需客户端 `--allow-exec` + daemon `--allow-exec` + `-w`）。
- **B7 daemon 控制（完成）**：`--daemon-readonly` 已转发；
  `e ghidra.analysis.wait=skip` 会跳过 `-A/-AA` 的自动分析。
- **分析写入（完成）**：`afr` 函数重建、`afvR`/`afvW` 变量读写引用、
  `an` 变量重命名。

已知限制（记录在 DIVERGENCES）：`/r` 只遍历已定义字符串；`izz`/raw search
返回文件偏移；`afr` 是删除+重建函数的近似重分析；`an` 对纯 decompiler
生成的局部变量可能只能重命名已有 Function 变量/参数。

剩余 Phase B：无。下一步进入 Phase C（parity、架构矩阵增强、batch meta）。

### 2.7 Phase C 完成（2026-11-08）

- **C1 parity 基础设施（完成）**：新增 `src/gdare2/parity.py`、
  `tests/parity/`、`tests/golden/`、`tools/capture_r2_golden.py`。黄金文件为
  JSON，头部记录 schema、r2 版本、Ghidra 版本、language ID 与目标 sha256；
  版本或目标变化时测试 skip 并提示重新生成。
- **C2 `/bin/ls` 黄金文件（完成）**：`tests/golden/ls.json`；断言 `iI` 的
  arch/bits/endian 与 entry/base 相对偏移、`iS` 命名节集合和 `.text` 大小/地址、
  `afl` 导入函数集合与数量区间、入口 32 字节、`pd`/`pdi` 的地址/长度/字节序列、
  `pdl` 行数、向后反汇编地址序列。
- **C3 ARM32 黄金文件（完成）**：`tests/golden/upnpd.json`，样本为
  `../vulfirm/OverFlow/R6700v3/upnpd`（sha256 记录在文件内）；样本缺失时 skip
  并提示路径，可用 `GDARE2_ARM_TARGET` 覆盖。
- **C4 架构矩阵增强（完成）**：矩阵增至 22 配置（新增 SuperH SH-2A/SH-2），
  每项断言语言/位宽/端序与 `pd 1` 非空；JSON 增加
  `ok/actual/bits/big_endian/pd_ok/info_ok/pd/image_base`。RISC-V 使用
  `13000000` 作为可解码探针；`sh4` 仍明确报错。
- **C5 batch 子 op meta（完成，C15）**：`search`/`search_raw` 返回
  `OpResult`；`batch` 每项保留 `meta`；客户端 `@@` 汇总子项截断并输出 `WARN`；
  `@@/x` 搜索迭代也使用响应级 `meta`。离线测试覆盖 meta 透传、单项错误隔离与
  WARN 文案。
- **C6 性能与错误审计（完成）**：新增 `tools/perf_probe.py`、`docs/PERF.md` 与
  `docs/perf-baseline.json`；`tests/test_errors.py` 校验错误类、`EXIT_CODES`
  与 CLI 退出码，并补齐 `CONNECTION=3`。函数/符号缓存评估结论为暂不实现，
  理由见 PERF.md。

已知限制（记录在 DIVERGENCES）：`pdl` 输出布局与 r2 不同，parity 只比较行数；
向后反汇编的指令边界可能随解码器不同，parity 只校验地址序列；函数数量不要求
逐项一致，只比较导入名集合与数量区间。

**Phase C 剩余项：无。**

### 2.8 GUI 附着不做（2026-11-08）

项目明确不支持在 Ghidra GUI 打开程序时附着：headless daemon 已覆盖全部分析
能力，GUI 附着只影响工作流，却需要自行解决 Ghidra 项目锁、GUI 线程模型与
事务/undo 冲突。运行约定是 daemon 独占项目；需要 GUI 时先关闭 daemon
（`.gclose` 或 `--kill`），再在 GUI 中打开项目。

## 3. 分阶段推进

### Phase A：一致性与契约修复（P0，预计 1–2 天）

目标：先把“看起来能用但行为不对”的问题清零，再扩命令面。

| 任务 | 文件 | 测试 | 验收 |
|---|---|---|---|
| A1 ✅ 统一 instance-id 指纹 | `src/gdare2/launcher.py`、`src/gdare2d/__main__.py`，新增共享模块或函数 | 新增 `tests/test_instance_id.py`：客户端/daemon 键集合一致；同目标同选项同 id | 手工 `gdare2d` 与 `gdare2 target` 能互相发现 |
| A2 ✅ 修正架构默认端序 | `src/gdare2d/import_plan.py` | 新增 `tests/test_import_plan.py`：`ppc/mips/sparc` 默认 BE，`*le` 默认 LE；`x86/RISCV` 与 `--endian big` 冲突时报 `BAD_ARGS` | `resolve_alias` 输出与 r2 习惯一致；矩阵仍全绿 |
| A3 ✅ 补齐 daemon 状态字段 | `src/gdare2d/ops/session.py`、`runtime.py`、`cmd/meta.py` | `tests/test_session.py` 增加 `.g/.gstatus` 字段断言 | `.g` 不再出现 `None`；`--status` 状态与 health 一致 |
| A4 ✅ CLI 选项契约 | `argv.py`、`launcher.py`、`cli.py`、`gdare2d/__main__.py` | `tests/test_argv.py` + 新增 launcher 测试 | `--listen` 真正转发；`--wait/-A/-AA` 有行为；`--assembler/--allow-exec` 未实现时明确报错 |
| A5 ✅ 手工 daemon 默认值 | `gdare2d/__main__.py` | 集成/手工 | DEV.md 的命令可直接启动 |
| A6 ✅ `--readonly` 与超时 | `runtime.py`、`ops/decompile.py`、`cmd/print.py` | 新增真实 Ghidra 测试：只读 daemon 不导入、不保存；超时映射 | `--readonly` 缺项目时报 `NOT_READY`；超时返回 `TIMEOUT` |
| A7 ✅ 只读文案与 JSON 形状 | `errors.py`、`cmd/*`、`cmd/print.py` | 单测断言错误含 `-w`；`pdi`/`pdj` 测试 | 文案一致；`pdj` 决策落地 |
| A8 ✅ 小修 | `argv.py` 忽略选项、`launcher.py` 启动错误、`runtime.py` loader 校验 | 单测 + 集成测试 | lint/测试通过 |

**Phase A 退出条件**

```bash
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
.venv/bin/gdare2 -qc '.g' /bin/ls | grep -E 'instance_id|state'   # 不再是 None
```

### Phase B：v1 命令面收尾（P1，预计 3–5 天）

按“对日常分析价值/实现成本”排序，建议顺序：

1. **B1 ✅ flags（P1，最高价值）**
   - 新增 `src/gdare2/flags.py`：`FlagStore`，播种自 `symbols` + `functions`；
   - 客户端：`f`、`fj`、`fq`、`f?`、`f name [size] @ addr`、`f name = addr`、
     `f-`、`fr`、`f.`；
   - daemon：新增 `symbol_create/symbol_rename/symbol_delete`（`writes=True`），
     写回受 `-w` 且 `e ghidra.flags.write=true` 双重控制；
   - 测试：只读会话创建会话内 flag；`-w` 写回；`.gsave` 后重启可见。
2. **B2 ✅ 脚本/变量/输出（P1）**
   - `S <file>` 读取脚本；`$name=value`、`$name` 读取；`_` 返回上次输出；
   - `x/x8/xw/xq/xj` 基于 `read_bytes` 的客户端 hexdump 变体；
   - 测试：脚本中的 `;`/`@`/`~` 与 `-i/-I` 一致。
3. **B3 ✅ 信息与类型（P1/P2）**
   - `iE` 导出、`ia` 架构列表、`izz` 全文件字符串（P2）；
   - `t- <glob>` 通用删除（复用 `type_delete`，`kind=None`）；
   - `tp/tpv/tpx`：按类型长度读内存并格式化；`tt` 保持 typedef 列表；
   - 测试：`t-` 删除后 `t` 不再出现；`tp int @ addr` 输出与 `pv4` 对齐。
4. **B4 ✅ 搜索与迭代（P1/P2）**
   - `/r` 遍历已定义字符串并正则匹配；`/p` 定长重复模式；`/a` 汇编后搜索；
   - `search.in=raw` 读取原始文件；`cmd.hit` 对每个命中执行命令；
   - `@@F`、`@@/x`、`@@.file`、`@@s:from to step`；`@!n`、`@{from to}`；
   - 测试：单次 batch、目标截断告警、`cmd.hit` 只影响命中项。
5. **B5 ✅ 写 P2（P2）**
   - `pa`、`wa`、`wa*`、`wa+`、`waf/F`、`wi[1248]`、`w6`；
   - 使用 `Assemblers.getAssembler(program)`；不支持的语言返回 `NOT_SUPPORTED`，
     可显式 `--assembler=rasm2` 回退；
   - 测试：`wa` 写入后可反汇编；`pa` 不写；只读门控。
6. **B6 ✅ 扩展命令（P1/P2）**
   - `.gsync` 重新拉取 summary/symbols/blocks；
   - `.ganalyze [all]` 触发分析并显示状态；
   - `.gexec` 仅在 `--allow-exec` 且 daemon 允许时可用；
   - `.ghelp` 生成扩展命令帮助；
   - 测试：未开启时 `NOT_SUPPORTED`/`READONLY`。
7. **B7 ✅ daemon 控制（P1）**
   - 客户端 `--daemon-readonly` 或环境开关；转发 `--listen`；
   - `--analysis-timeout` 与 `e ghidra.analysis.wait` 落地；
   - 测试：daemon 只读时 `-w` 仍被拒绝；`--listen` 真正改变绑定地址。

**Phase B 退出条件**

```bash
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
# 新增命令的黄金/单测全部通过
```

### Phase C：parity 与可靠性（P1，预计 2–3 天）

1. **C1 建立 parity 基础设施（完成）**
   - 新增 `tests/parity/`、`tests/golden/`、`tools/capture_r2_golden.py`；
   - 每个黄金文件头记录：r2 版本、Ghidra 版本、language ID、目标 sha256；
   - 归一化：函数名（`FUN_`/`sym.`/`fcn.`）、地址宽度、ANSI、助记符别名、
     行首空格；版本不匹配时提示重新生成而不是直接失败。
2. **C2 `/bin/ls` 黄金文件（完成）**
   - `iI`：arch/bits/endian/language/base/entry；
   - `iS`：块数量与关键块（`.text` 起止）；
   - `afl`：函数数量与若干函数名（归一化后）；
   - `px`：入口附近固定区域逐字节一致；
   - `pd`：地址/长度/文本结构（允许助记符差异归因）；
   - `pdi`、`pdl`、`pd -N`（向后反汇编）的行数/地址序列。
3. **C3 ARM32 样本黄金文件（完成）**
   - 使用 `../vulfirm` 的 ARM32 样本；记录 `sha256`；
   - 重复 C2 的结构化断言；
   - 若样本缺失，测试 skip 并提示路径。
4. **C4 架构矩阵增强（完成）**
   - 每个配置断言 `pd 1` 非空、`iI` 字段正确；
   - 目标配置补齐到设计值 22（新增 `SuperH:BE:32:SH-2A`/`SH-2`），并明确 `sh4` 仍报错；
   - 输出 JSON 包含 `ok/actual/bits/big_endian/pd_ok/info_ok`。
5. **C5 batch 子 op meta 透传（C15，完成）**
   - `batch` 每项保留 `meta`；客户端 `@@` 汇总子项截断；
   - 测试：子 op 截断时输出明确 WARN。
6. **C6 性能与错误审计（完成）**
   - 记录 `/bin/ls` 与 ARM 样本的首次导入/分析耗时、`afl`/`pd`/`pdc` 延迟；
   - 检查所有错误码与退出码（`BAD_ARGS=2`、`NOT_READY=3`、`TIMEOUT=4`）；
   - 评估函数列表/符号表缓存（`Program.getModificationNumber()` 作为失效键）。

**Phase C 退出条件**

```bash
uv run pytest
uv run pytest -m real_ghidra
uv run pytest -m parity
uv run pytest -m arch_matrix
uv run gdare2 -qc 'pd 5~+call:0[1]' /bin/ls
uv run gdare2 -j -qc 'afl' /bin/ls | jq .
```

## 4. 建议执行顺序（可直接拆 commit）

> Phase A–C 已在 2026-11-08 完成。以下保留为提交历史参考。

1. `fix: unify instance id fingerprint`（A1）
2. `fix: architecture alias endianness`（A2）
3. `fix: expose daemon state in info/.g`（A3/C4）
4. `feat: honour CLI daemon options`（A4/A5/B7）
5. `fix: readonly daemon and timeout handling`（A6/C7/C8）
6. `fix: unify readonly errors and JSON shapes`（A7/C9/C10/C11）
7. `test: add parity harness and /bin/ls goldens`（C1/C2）
8. `test: extend arch matrix assertions`（C4）
9. `feat: add flags family`（B1）
10. `feat: add types/search/iterator gaps`（B3/B4）
11. `feat: add P2 writes and dot commands`（B5/B6）
12. `docs: sync README/COMMANDS/DEV/PROGRESS`（随每步更新）

## 5. 决策待定（需要确认）

| 问题 | 选项 | 建议 |
|---|---|---|
| `pd` / `pdi` 是否共用渲染？ | 已决策：为 `pdi` 增加 symbol 列独立布局 | 当前 `pdi` 为“地址+symbol+字节+文本”；后续 B1 接入 FlagStore 后再决定是否增加 flag 列 |
| `-A/-AA` 语义 | `-A` 触发 `aa` / `-AA` 触发 `aaa` | 与 r2 保持一致，并在 `--attach` 到已分析项目时也执行 |
| `--allow-exec` 是否保留 | 实现 `.gexec` / 移除选项 | 保留但默认关闭；daemon 也需显式开关 |
| 架构矩阵目标 | 20 / 21（加 SH-2A）/ 22 | 先加 SH-2A 到 21；第 22 项等确认可用语言后再加 |
| `f` 是否进 v1 | 进 / 放到 v1.1 | 进 v1：r2 日常分析高度依赖 flags |
| `--daemon-readonly` 暴露方式 | 新选项 / 环境变量 | 新选项 `--daemon-readonly`，避免与 `-w` 混淆 |

## 6. 风险与缓解

| 风险 | 阶段 | 缓解 |
|---|---|---|
| Ghidra 语言缺失/别名错误 | A/C | 别名单测 + 矩阵实际导入 + 明确报错 |
| parity 文本差异导致假失败 | C | 只比结构；差异逐条归因；黄金文件带版本头 |
| ARM 样本缺失 | C | 测试 skip + 文档记录路径与 sha256 |
| 手工 daemon/instance-id 不一致 | A | 单一指纹函数 + 集成测试 |
| `--listen` 误用 | A/B | 默认 loopback；显式开启；文档警告 |
| 分析/反编译超时 | A | TaskMonitor 超时 + 错误码 `TIMEOUT` |
| 写入污染共享项目 | A/B | 默认只读；transaction；`--readonly`；临时项目测试 |
| 文档再次漂移 | 全程 | 每个 commit 同步 PROGRESS/COMMANDS；ROADMAP 作为唯一任务清单 |

## 7. 每次提交前的检查

```bash
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m parity
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m arch_matrix
.venv/bin/python tools/arch_matrix.py
```

要求：

- 新增/修改命令都有离线单测；涉及 Ghidra 行为的加真实集成测试；
- 修复缺陷必须带回归测试；
- 文档与实现同一提交更新；
- 不引入 `src/gdare2` 对 `pyghidra`/`jpype` 的依赖。
