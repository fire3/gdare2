# gdare2 v2 兼容性补齐任务书

> 本文是 v2 的实施依据：把 2026-11-13 对 gdare2 0.1.0 与 `../idare2`
> 的逐命令对比结果拆成可执行任务。设计契约仍以 [DESIGN.md](DESIGN.md) 为准，
> 命令映射以 [COMMANDS.md](COMMANDS.md) 为准；每完成一项，必须同步更新
> `PROGRESS.md`、`COMMANDS.md` 的“实现状态”，并勾选本文任务。
>
> 基线：Ghidra 12.2 PUBLIC、PyGhidra 3.2.0、Python 3.12.3、radare2 5.5.0。
> 对比方法：真实导入 `/bin/ls`，逐命令执行并核对 r2 输出；离线
> `pytest -q` = 169 passed（idare2 当前仓库实测 739 passed）。
>
> **进度（2026-11-13）**：G1–G19、G24 已完成并验证；G20–G23
> （批次 D 剩余）待做，详见 §10。

## 0. 结论与目标

gdare2 的进程模型、只读门控、写入事务、batch RPC、parity 黄金文件与 22 配置
架构矩阵是已有优势，v2 **不重做架构**。差距集中在三处：

1. **命令面覆盖**：约 153 个 pattern，idare2 有 491 条帮助行；大量 P0/P1
   命令只在文档里存在。
2. **输出/过滤层**：`~` 过滤器 156 行 vs 956 行；渲染层 142 行且无颜色；
   `pf` 完全缺失。
3. **文档与实现漂移**：`PROGRESS.md` 声称 P0/P1 全部可用，但 `i`、`aflq`、
   `L`、`ej`、`b+`、`C*`、`axj` 等实测不存在；`DIVERGENCES.md` 承诺的颜色、
   `-o`、rasm2 回退均未实现。

v2 的目标不是“命令数量追平 idare2”，而是：

- **不再有静默错误**：要么实现，要么 `NOT_SUPPORTED`，禁止 alias 到错误语义；
- **高频工作流可用**：`pd/px/pf/f*/C*/t*/i*/@@` 与脚本化输出；
- **文档 = 行为**：每条已声明命令都有测试或明确的未实现标记。

完成定义（v2 DoD）：

- 本文 P0 全部关闭，P1 至少 80% 关闭；
- 每条命令要么有真实 Ghidra 用例，要么返回 `NOT_SUPPORTED` 并在
  `COMMANDS.md` 标记；
- `pytest -q`、`-m real_ghidra`、`-m parity`、`-m arch_matrix` 全绿；
- README、PROGRESS、COMMANDS、DIVERGENCES、ROADMAP 与代码一致。

---

## 1. 优先级、工作量与批次

| 批次 | 内容 | 任务 | 预计 |
|---|---|---|---|
| A | 正确性止血 | G1–G10 | 2–3 天 |
| B | 命令面补齐 | G11、G15–G17 | 3–4 天 |
| C | 输出与体验 | G12–G14、G18 | 4–5 天 |
| D | 引擎与工程化 | G19–G24 | 1–2 周 |

优先级定义：

- **P0**：文档已声明可用，但实测报错/静默错误/返回错误数据；
- **P1**：r2 高频工作流或 idare2 已有、gdare2 缺失；
- **P2**：能力扩展或工程化，不影响现有工作流正确性。

---

## 2. P0 任务（批次 A）

### G1 `iSS` 独立实现，禁止 alias 到 `iS`

- **状态**：✅ 2026-11-13 已完成（客户端 ELF program header 解析）。

- **现状**：`src/gdare2/cmd/info.py:34` 把 `iSS`/`iSSj` 注册为 `iS` 的 alias。
- **证据**：`gdare2 -qc 'iS' /bin/ls` 与 `iSS` 输出逐字节相同（34 个 Ghidra
  memory block）；r2 5.5 的 `iSS` 是 ELF program headers（`/bin/ls` 17 行），
  `iS` 是 section（34 行）。
- **方案（二选一，必须显式）**：
  1. 推荐：在客户端新增轻量 ELF/PE 头解析（可与 G19 共用），`iSS` 输出
     `idx paddr size vaddr vsize perm name`；
  2. 若暂不解析：`iSS`/`iSSj` 返回 `NOT_SUPPORTED`，并在 `COMMANDS.md`
     标记 X，**不得**回落为 `iS`。
- **验收**：
  - `gdare2 -qc 'iSS' /bin/ls` 行数等于 `readelf -l /bin/ls` 的 `LOAD`
    等 program header 数；`iS` 保持 34 行；
  - `iSSj` 字段与 r2 对齐：`name/size/vsize/perm/paddr/vaddr`；
  - 非 ELF/PE 目标返回空列表或 `NOT_SUPPORTED`，不报内部异常。
- **测试**：新增 `tests/test_info_formats.py`（纯解析）+ real_ghidra 用例；
  parity 黄金文件增加 `iSS` 行数与首行字段。
- **涉及**：`src/gdare2/cmd/info.py`、新增 `src/gdare2/formats/elf.py`、
  `docs/COMMANDS.md`。

### G2 修复 `tp`/`tpv` 崩溃

- **状态**：✅ 2026-11-13 已完成（`getattr` 兜底 + 内建整数分支）。

- **现状**：`gdare2d/ops/types.py:233` 无条件调用
  `data_type.getBaseDataType()`；`IntegerDataType` 没有该方法。
- **证据**：`tp int @ entry` →
  `AttributeError: 'ghidra.program.model.data.IntegerDataType' object has no attribute 'getBaseDataType'`。
- **方案**：
  - `base = getattr(data_type, "getBaseDataType", lambda: data_type)()`；
  - `_typed_values()` 增加 `IntegerDataType`（以及 `BooleanDataType`、
    `CharDataType`）分支；
  - 结构体/联合暂返回 `None`（由 `tp` 打印原始字节），不要抛异常。
- **验收**：`tp int`、`tpv int`、`tp char`、`tp "int[4]"`、`tpx int <hex>`
  均有输出且退出码 0；未知类型名报 `NOT_FOUND`。
- **测试**：`tests/integration/test_real_ghidra.py` 增加上述五条；
  纯逻辑分支可抽到可单测的 helper。
- **涉及**：`src/gdare2d/ops/types.py`、`src/gdare2/cmd/types.py`。

### G3 `tc <name>` 只输出目标类型

- **状态**：✅ 2026-11-13 已完成（按行筛选目标声明）。

- **现状**：`gdare2d/ops/types.py:316` 用 `DataTypeWriter.write([dt])`，
  该 API 会连同依赖 typedef 一起写出。
- **证据**：`tc int` / `tcj int` 返回 40+ 行基础 typedef 前导，而不是 `int`
  的声明。
- **方案**：
  - 仅保留与请求类型同名/同路径的声明块（按 `DataTypeWriter` 输出分段后
    过滤），或改用 `DataType.getPrototypeString()` + 结构体 `DataTypeWriter`
    的单项输出；
  - `tc` 无参数时保持当前“全部类型 dump”行为。
- **验收**：`tc int` 输出 1 个声明块；`tc Elf64_Ehdr` 只输出该结构体；
  `tc` 无参数行数不变；`tcj int` 的 `declaration` 不含无关 typedef。
- **测试**：real_ghidra 断言声明块数量与类型名。
- **涉及**：`src/gdare2d/ops/types.py`、`src/gdare2/cmd/types.py`。

### G4 JSON 输出参与 `~` / `|` 按行处理

- **状态**：✅ 2026-11-13 已完成（`postprocess` 先拆行）。

- **现状**：`src/gdare2/session.py:542` 对 `lines` 列表元素做过滤；
  JSON handler 返回“一个含 `\n` 的字符串元素”，导致过滤只匹配整块。
- **证据**：`aflj~entry` 输出 2,909 行（未过滤）；`pdj 2~ENDBR` 同样未过滤。
- **方案**：
  - `postprocess()` 在 filter/pipe 之前统一
    `lines = [ln for block in lines for ln in block.splitlines()]`；
  - 保留 `pdc`、`pf` 等多行文本的按行语义（与 r2 一致）；
  - 注意空输出不要产生多余空行。
- **验收**：`aflj~entry` 只保留匹配行；`-j -qc 'afl'` 与 `aflj` 等价；
  `pdc|head`、`pdc~void` 正常工作；`>` 重定向仍写完整内容。
- **测试**：`tests/test_session.py` 增加 JSON+filter/pipe 用例；parity 增加
  `aflj~entry` 行数对比（只比结构）。
- **涉及**：`src/gdare2/session.py`。

### G5 修复 `-j` 对独立 JSON 命令无效

- **状态**：✅ 2026-11-13 已完成（查找 spec 前解析 JSON 变体）。

- **现状**：`src/gdare2/session.py:290` 先 `cmd.lookup()`，`:295` 才
  `_maybe_json()`；`f`→`fj` 映射后仍使用 `f` 的 handler。
- **证据**：`gdare2 -j -qc 'f' /bin/ls` 输出文本；`-qc 'fj'` 才是 JSON。
- **方案**：把 `_maybe_json()` 移到 `lookup()` 之前；对 `f <args>` 保持
  “带参数仍是写操作、不 JSON 化”的现有规则。
- **验收**：`-j -qc f` 以 `[` 开头；`-j -qc 'f main @ entry'` 不 JSON 化且
  行为不变；`-j` 对 `C/t/iS/afl/pd` 无回归。
- **测试**：`tests/test_cli.py` 或 `tests/test_session.py` 参数化断言。
- **涉及**：`src/gdare2/session.py`。

### G6 清理“假开关”配置键

- **状态**：✅ 2026-11-13 已完成（颜色、注释/标签、gutter、demangle、`cmd.batch`）。

- **现状**：以下键只在 `src/gdare2/config.py` 声明，代码从未读取：
  `scr.color`、`asm.lines`、`asm.comments`、`asm.flags`、`asm.demangle`、
  `cmd.batch`。
- **证据**：`e scr.color=3; pd 2` 无 ANSI；`e asm.comments=false` 无变化；
  `grep -rn` 仅命中 `config.py`/`cli.py` 赋值。
- **方案（逐键决策，写入任务完成记录）**：
  - `scr.color`：实现 0–3（最小：地址/字节/助记符/注释四色，TTY 自动开启）；
  - `asm.lines`：`pd`/`pdf` 输出 flow gutter（与 G14 一起做）；
  - `asm.comments`/`asm.flags`：`pd` 渲染 flag 与注释列；
  - `asm.demangle`：接入 Ghidra Demangler（失败保留原名）；
  - `cmd.batch`：实现 `false` 时逐目标 RPC，或删除该键并报 `unsupported`。
  不允许“接受但无行为”。
- **验收**：每个键有可见行为 + 一个单测；`e` 输出能区分“已实现/只读”。
- **测试**：`tests/test_config.py`（新增）＋ `tests/test_session.py`。
- **涉及**：`config.py`、`fmt/*`、`session.py`、`docs/DIVERGENCES.md §11.2`。
- **依赖**：G14（渲染）可先落地 `scr.color` 与 `asm.*`。

### G7 补齐 P0 元命令：`i`、`aflq`、`L`、`ej`

- **状态**：✅ 2026-11-13 已完成（`i`/`aflq`/`L`/`ej`/`e?`/`e??`）。

- **现状**：四条均 `unknown or unsupported command`，但
  `COMMANDS.md` 标 P0，`DIVERGENCES §2.4` 还承诺 `L`。
- **方案**：
  - `i`：复用 `ij`/`iI` 数据输出 key/value（与 r2 字段对齐）；
  - `aflq`：函数地址列表（`afl` 结果的第 1 列）；
  - `L`：客户端列注册表 daemon（复用 `registry.iter_states/live_instance`，
    输出与 `-L` 一致）；
  - `ej`：配置 JSON；`e?` 输出配置键表（当前只有命令摘要）；
    `e??` 作为 `e?` 别名。
- **验收**：四条命令在真实 daemon 下可用；`L` 与 `gdare2 -L` 行一致；
  `ej` 是合法 JSON；`e?` 列出所有键而非一行摘要。
- **测试**：`tests/test_cli.py`（`L`/`e?` 离线）+ real_ghidra（`i`/`aflq`）。
- **涉及**：`cmd/info.py`、`cmd/analysis.py`、`cmd/meta.py`、`cmd/misc.py`、
  `registry.py`。

### G8 `-o` 分页续读

- **状态**：✅ 2026-11-13 已完成（设计已修正为 `--list-offset` / `e list.offset`）。
- **设计修正**：r2 的 `-o` 是“按文件偏移映射”，不是输出分页。G8 改为
  `--list-offset N` + `e list.offset=N`；`-o` 明确报
  “file-offset mapping is not implemented”，避免与 r2 语义冲突。
- **方案**：
  - 列表 op（`functions/symbols/imports/exports/strings/strings_all`）增加
    `offset` 参数并返回 `OpResult(meta.total/shown/offset/limit/truncated)`；
  - 客户端这些命令读 `list.offset`，默认调用参数不变（offset=0 时不传）；
  - 截断时提示 `use --list-offset N to continue`。
- **验收**：`--list-offset 10 -qc afl` 等于 `afl` 的第 11 项起；`is`、`ii`、
    `iE`、`iz`、`izz` 同理；`-o` 返回 `BAD_ARGS` 并说明原因。
- **测试**：`test_argv.py`（选项）、`test_session.py`（offset 与告警）、
  real_ghidra（`afl`/`is` 分页与 `-o` 拒绝）。
- **涉及**：`argv.py`、`cli.py`、`config.py`、`session.py`、`cmd/{info,analysis}.py`、
  `gdare2d/ops/{info,analysis}.py`。

### G9 健壮性小修

- **状态**：✅ 2026-11-13 已完成（迭代器跳过无指令/不可读目标、重复注册校验、删除重复 `wi`）。

- **G9a** `pd 1 @@F` 对无指令 thunk 刷屏：
  `_dispatch_iterator()` 逐目标捕获 `NO_INSTRUCTION`，跳过并汇总
  `WARN skipped N targets`；`@@S` 跳过不可读 block。
- **G9b** 注册表重复：`cmd/assemble.py:90` 与 `:133` 重复注册 `wi`。
  在 `cmd.register()`/`command()` 装饰器中检测重复 pattern 并抛
  `ValueError`（参考 idare2 的做法），删除重复注册。
- **G9c** `@@s` 语义：r2 的语法是 `@@s:from to step`（已实现）；daemon
  另外支持 `@@s:<symbol-pattern>` 的符号迭代（gdare2 扩展）。`@@f` 在 r2
  中是 functions（大小写不敏感），不是 flags；gdare2 的行为已一致。
- **验收**：重复注册在导入期直接失败；`pd 1 @@F` 无大段 error；`@@S`
  只输出可读块。
- **测试**：`tests/test_registry.py` 增加重复检测；real_ghidra 断言
  `@@F` 的 stderr 行数上限。
- **涉及**：`cmd/__init__.py`、`cmd/assemble.py`、`session.py`、`gdare2d/ops/info.py`。

### G10 文档状态同步（与代码同批提交）

- **状态**：✅ 2026-11-13 已完成（COMMANDS/PROGRESS/DIVERGENCES/ROADMAP/README 已同步）。

- **现状**：`PROGRESS.md` 声称 P0/P1 命令面全部可用；`COMMANDS.md` 却把
  `i`、`aflq`、`L`、`ej` 标 P0 且未实现；`DIVERGENCES.md` 承诺的颜色、
  `-o`、rasm2 回退不存在。
- **方案**：
  - `PROGRESS.md` 改为“按任务 ID 记录”，未完成项链接本文；
  - `COMMANDS.md §14` 的“已实现”只保留有测试覆盖的命令；
  - `DIVERGENCES.md` 删除未实现承诺，或改写成“v2 计划（见 TASKS-v2 Gxx）”；
  - `ROADMAP.md` 顶部加一行链接到本文。
- **验收**：随机抽取 20 条“已实现”命令，`gdare2 -qc '<cmd>?'` 均可执行且
  文档描述与行为一致。
- **测试**：无代码测试；作为每个 PR 的检查项写入 `DEV.md §8`。

---

## 3. P1 任务（批次 B/C）

### G11 输出为 r2 命令的变体

- **状态**：✅ 2026-11-13 已完成（`f*`/`C*`/`CC*`/`C*.`/`t*`/`s*`/`b*`/
  `iS*`/`ax*`/`axlj`/`axlq`/`axlc`；`axj` 明确 `NOT_SUPPORTED`，
  因为 r2 6.2.5 中它是写命令）。

- **缺失**：`f*`、`C*`、`CC*`、`t*`、`s*`、`b*`、`axj`/`ax*`、`axt*`、
  `iS*` 等。
- **价值**：脚本/回归/迁移最常用；r2 的 `*` 变体是“可重放命令”，不需要
  解析表格。
- **方案**：为每族实现 `*` 后缀，输出 `f name size @ addr`、`CCu base64:...`、
  `td ...` 等；优先 `f*`/`C*`/`t*`/`ax*`。
- **验收**：`f*` 的输出喂回 `gdare2 -w` 能重建同名同址 flag；`C*` 同理；
  `t*` 只输出类型声明。
- **测试**：单测做“生成→回放”闭环（不依赖 r2）；parity 与 r2 比对首行形状。
- **涉及**：`cmd/{flags,comments,types,seek,xrefs}.py`。

### G12 `pf` 格式化打印

- **状态**：✅ 2026-11-13 已完成（`pf`/`pfj`/`pfs`/`pf.`/`pf.<name>`；
  标量、`[n]`（前缀与后缀）、偏移控制、`u`/`I`/`U`、命名格式）。

- **现状**：无 `pf`；idare2 有 444 行实现 + `test_pf.py`。
- **范围（v2 第一版）**：标量格式（`x b c d i u q X B C D I U Q`）、
  内联数组 `[n]`、偏移控制（`?`、`.`、`+`）、命名格式（`pf.name`）、
  `pfj`/`pfs`/`pf.`；不支持字符明确报 `BAD_ARGS`。
- **实现**：纯客户端解析 + `read_bytes`；不新增 daemon op。
- **验收**：`pf xx`、`pf 4xi`、`pf x[4]`、`pf.name xx` 输出与 r2 列布局
  一致（允许空格差异）；`pfj` 是合法 JSON。
- **测试**：新增 `tests/test_pf.py`（纯解析/格式化，无 JVM）。
- **涉及**：`src/gdare2/pf.py`（新增）、`cmd/print.py`、`DIVERGENCES.md`。

### G13 `~` 过滤器 v2

- **状态**：✅ 2026-11-13 已完成（多列/负索引/范围、按列排序、行范围、
  `~{}` JSON 美化；XML/C/七段码明确报 unsupported）。

- **现状**：156 行；`~[0,2]` 直接报 “multi-column selectors are not
  implemented yet”；无 JSON/XML/C 缩进、无按列排序、无 `~?ea`。
- **范围**：
  - 多列 `~[0,2]`、负索引 `~[-1]`、范围 `~[0-2]`；
  - `~$:` 按列排序、`~$+/-` 方向；
  - `~{}`/`~{:` JSON 缩进、`~<>` XML、`~:)`/`~:))` C 解析/高亮、
    `~:}` 大括号缩进、`~?ea` 七段码（可先明确拒绝）；
  - `~[n]` 列号与 r2 对齐：`pd` 渲染必须把整段字节作为一个字段（依赖 G14）。
- **验收**：与 r2 逐条对比 `~[1]`、`~[0,2]`、`~:0`、`~$`、`~$!`、`~?`；
  允许的差异写入 `DIVERGENCES`。
- **测试**：扩充 `tests/test_filter.py`，覆盖每个修饰符与其组合。
- **涉及**：`src/gdare2/filter.py`、`fmt/disasm.py`。

### G14 渲染层与颜色

- **状态**：✅ 2026-11-13 已完成（G6 的颜色/注释/gutter/demangle +
  G13 的 `pd` 列布局 + 本轮的 `px` 列布局与 `hex.pairs/offset/ascii`）。

- **现状**：`fmt/disasm.py` 40 行；无颜色、无 gutter、无 flag/comment 列；
  助记符大写、操作数无空格（`XOR EBP,EBP`）。
- **范围**：
  - `pd`/`pdi`/`pdf` 列布局对齐 r2：地址、整段字节、助记符/操作数分段；
  - `asm.lines`（gutter）、`asm.comments`（`;-- name:`、EOL 注释）、
    `asm.flags`（符号名替换）、`asm.demangle`；
  - `scr.color` 0–3，TTY 自动开启，`NO_COLOR` 尊重；
  - `px` 表头/ASCII 列对齐 r2；`hex.pairs/offset/ascii` 生效。
- **验收**：`pd 4` 与 r2 的列位置一致（忽略大小写与颜色）；`e scr.color=0`
  无 ANSI；`e asm.bytes=false` 仍工作；管道输出默认无颜色。
- **测试**：新增 `tests/test_fmt.py`（纯字符串断言）＋ parity 黄金文件。
- **涉及**：`fmt/{disasm,memory,listing}.py`、新增 `fmt/colors.py`、`config.py`。

### G15 `p` 族只读命令补齐（第二优先）

- **状态**：✅ 2026-11-13 已完成（`pdb`/`pC`/`pA`、`pxd`/`pxu`/`pxj`、
  `psz`/`psw`/`psp`/`psu`/`psx`/`psn`/`psj`、`p8s`/`p8d`/`p8x`/`p8,`/`p8*`/
  `p8b`/`p8f`、`pvu`/`pvd`/`pvp`；`pdk`/`pdr` 明确 `NOT_SUPPORTED`）。

- **范围**：`pdb`（当前基本块）、`pC`（分列）、`pA`（地址/类型/大小）、
  `pxd`/`pxu`/`pxj`、`psw/psp/psz/psj/psu/psx/psn`、
  `p8s/p8d/p8x/p8b/p8f/p8,/p8*`、`pvj` 已有则补 `pvu/pvd/pvp`。
- **验收**：每条有真实输出；不支持项（`pdk`/`pdr`）显式 `NOT_SUPPORTED`。
- **测试**：real_ghidra 参数化；格式类单测。
- **涉及**：`cmd/print.py`、`fmt/*`。

### G16 补全与 rc 层级

- **状态**：✅ 2026-11-13 已完成（fsrc/rc.d/项目祖先/`GDARE2_RCFILE`；
  参数位置补全 flag/函数与 `$` 变量）。

- **现状**：`completion.py:17` 只补命令名与 `e` 键；`rc.py:9` 只有两条路径。
- **范围**：
  - 补全 flag、函数名、`$` 变量/别名、搜索命中缓存；
  - rc 增加 `$XDG_CONFIG_HOME/gdare2/rc.d/*`、当前目录及祖先
    `.gdare2rc`、`GDARE2_RCFILE` 覆盖；
  - 历史文件路径保持 `XDG_STATE_HOME`。
- **验收**：交互模式 Tab 能补 `s <函数名>`、`f- <flag>`、`e asm.`；
  rc 加载顺序有单测。
- **测试**：新增 `tests/test_completion.py`；扩充 `tests/test_rc.py`。
- **涉及**：`completion.py`、`rc.py`、`cli.py`。

### G17 迭代器语义对齐

- **状态**：✅ 2026-11-13 已完成（反引号替换；`@@f`/`@@F` 排除
  external/thunk；`.cmd` 明确不做；迭代/截断沿用 G8/G9）。

- **现状（2026-11-13 复核）**：r2 的 `@@f` 就是 functions（`?@@` 输出
  `x @@f` = "run 'x' on all functions"），gdare2 已一致；`@@s:from to step`
  与 `@@S` 均已实现。G9 已让 `@@F`/`@@S` 跳过无指令/不可读目标。
- **剩余范围**：反引号命令替换、`.cmd` 输出当命令、`@@/x` 等搜索迭代的
  边界检查；`@@s:<symbol-pattern>` 目前是 gdare2 扩展，需在
  `COMMANDS.md` 标注。
- **验收**：`pd 1 @@f` 与 `pd 1 @@F` 行为一致；`@@S` 无
  `MemoryAccessException` 刷屏；反引号替换有单测。
- **测试**：`tests/test_session.py` 迭代器参数化 + real_ghidra。
- **涉及**：`session.py`、`parser.py`。

### G18 测试与 CI 补齐

- **状态**：✅ 2026-11-13 已完成（离线 308 passed；`ruff check .` 干净；
  `.github/workflows/ci.yml` 覆盖 Python 3.12/3.13）。

- **范围**：
  - 新增 `tests/test_config.py`、`test_completion.py`、`test_fmt.py`、
    `test_pf.py`、`test_info_formats.py`；
  - `real_ghidra` 增加 `iSS`、`tp/tc`、`-j f`、JSON+filter；
  - 增加 `.github/workflows/ci.yml`：离线 pytest + ruff；
  - `tools/arch_matrix.py` 保持可手动跑。
- **验收**：离线测试 ≥ 300；CI 在 PR 上跑绿；`ruff check .` 干净。
- **涉及**：`tests/**`、`.github/workflows/`、`pyproject.toml`。

---

## 4. P2 任务（批次 D）

### G19 轻量 ELF/PE 格式解析器

- **状态**：✅ 2026-11-13 已完成（ELF64/32 的 `ih`/`iH`/`il`/`ir`；
  PE 仍按 §8 明确不做）。

- 为 `iSS`、`ih`/`iH`、`il`、`ir` 提供真实数据；优先 ELF64/ELF32，
  PE 可选。
- 纯客户端、只读原始文件；不依赖 Ghidra 高层模型。
- 验收：`/bin/ls` 的 `iSS`/`il`/`ir` 与 `readelf -l/-d/-r` 条数一致。

### G20 rasm2 回退

- 让 `--assembler=rasm2` 真正可用；`pa/wa//a` 在 Ghidra assembler 失败或
  语言不支持时回退；输出标注 `assembler=rasm2`。
- 支持 `e asm.assembler=ghidra|rasm2|auto`；rasm2 路径可配。
- 验收：ARM/MIPS 常见指令可汇编；无 rasm2 时保持现有错误。

### G21 杂项命令与命令语言

- `y`（yank/paste：`yy/yx/yt/yf`）、`T`（文本日志）、`P`（会话快照）、
  `%`（环境变量）、`*`（指针读写）、`c/cc/c1`（块比较）、`dt`（类型化读）。
- 命令语言：`"`/`'` 引用命令、反引号替换、`$()`、`$` 别名（当前只有数值
  变量）。
- 验收：每条命令有 real_ghidra/离线用例；引用命令不参与 `@`/`~` 解析。

### G22 类型格式化增强

- 结构体/联合/位域/数组的可读布局；`ts/tu/te` 输出与 r2 字段对齐；
  `tpx` 支持结构体十六进制输入。
- 验收：`ts Elf64_Ehdr` 输出成员偏移/大小/类型；复杂 C++ 类型失败时显式
  `NOT_SUPPORTED`。

### G23 用户注释与 `C` 语义

- Ghidra 不区分用户/加载器注释；增加 sidecar（项目内 JSON 或 Ghidra
  自定义属性）记录 gdare2 写入的注释，`C` 默认只列 sidecar + 可选
  `e ghidra.comments.all=true` 列全部。
- 验收：`/bin/ls` 的 `C` 默认只显示用户注释；`CC`/`CC-` 与 sidecar 同步。

### G24 发布工程化

- **状态**：✅ 2026-11-13 已完成（LICENSE/CHANGELOG/RELEASING/uv.lock/
  publish.yml；动态版本；`uv build` 与 `twine check` 通过）。

- 增加 `LICENSE`、`CHANGELOG.md`、`RELEASING.md`、`uv.lock`、
  `.github/workflows/{ci,publish}.yml`；版本改为动态（`__version__`）；
  补齐 PyPI classifiers 与 `project.urls`。
- 验收：`uv build` + `twine check dist/*` 通过；CI 覆盖 Python 3.12/3.13。

---

## 5. 执行顺序与提交拆分

建议按 commit 粒度推进（每个 commit 必须自带测试）：

1. `fix(info): implement iSS from program headers`（G1，或显式 unsupported）
2. `fix(types): handle non-pointer types in tp`（G2）
3. `fix(types): emit only the requested declaration in tc`（G3）
4. `fix(session): filter JSON output line by line`（G4）
5. `fix(session): resolve -j form before command lookup`（G5）
6. `feat(meta): add i/aflq/L/ej`（G7）
7. `feat(cli): add --list-offset pagination`（G8）
8. `fix: harden iterators and duplicate command registration`（G9）
9. `chore(config): make declared keys effective or reject them`（G6）
10. `docs: sync command status with implementation`（G10）
11. `feat(print): add command-export variants`（G11）
12. `feat: implement pf format strings`（G12）
13. `feat(filter): r2 grep v2 modifiers`（G13）
14. `feat(fmt): r2 layout and colors`（G14）
15. `feat(print): p-family read variants`（G15）
16. `feat: completion and rc hierarchy`（G16）
17. `feat: iterator semantics`（G17）
18. `test: fill unit/real coverage and add CI`（G18）
19. 之后按需推进 G19–G24。

---

## 6. 验证矩阵

每次提交前至少运行：

```bash
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m parity
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m arch_matrix
.venv/bin/python -m ruff check .
```

P0 完成后的手工冒烟：

```bash
gdare2 -qc 'iI; iSS; is; aflq; i' /bin/ls
gdare2 -qc 's entry; tp int; tpv int; tc int; afv; pdc' /bin/ls
gdare2 -j -qc 'afl~entry; f; C' /bin/ls
gdare2 -qc 'pd 4~[1]; pdj 2~ENDBR; px 32' /bin/ls
gdare2 -qc 'pd 1 @@F' /bin/ls
gdare2 -qc 'e scr.color=3; pd 2' /bin/ls
gdare2 -L
```

---

## 7. 风险与对策

| 风险 | 任务 | 对策 |
|---|---|---|
| 自解析 ELF/PE 与 Ghidra 视图不一致 | G1/G19 | 只用于 header/segment/reloc；标注“原始文件视图” |
| `~` 列号改动破坏现有输出 | G13/G14 | 先补测试再改渲染，保留 `e asm.bytes` 语义 |
| `-o` 与现有截断告警冲突 | G8 | 统一走 `meta.total/offset`，保留无 `-o` 的告警 |
| Ghidra 类型 API 版本差异 | G2/G3/G22 | 全部用 `getattr`/`suppress` 防御，real_ghidra 覆盖 |
| 颜色影响脚本输出 | G6/G14 | 默认仅 TTY 开启，管道/重定向关闭 |
| 文档再次漂移 | G10 | 每 commit 同步 COMMANDS/PROGRESS，CI 不检查则人工 review |

---

## 8. 明确不做（v2 范围外）

- Ghidra GUI 附着/实时同步（项目锁约束，维持 v1 决策）；
- `pdk`/`pdr`/`pdg`/`pdd` 等无稳定对应的 Ghidra 能力；
- ESIL、调试器（`d*`）、`ae`/`ar`/`as`/`ap`；
- 伪造 Ghidra 无法提供的 JSON 字段（`esil/opcode/family/type`）；
- 与 r2 逐字节一致的文本输出（只保证结构与列语义）。

---

## 9. 附录：本次实测证据（2026-11-13）

环境：Ghidra 12.2 PUBLIC、PyGhidra 3.2.0、Python 3.12.3、r2 5.5.0。

| 用例 | 修复前 | 现状 |
|---|---|---|
| `pytest -q` | 169 passed | **176 passed** |
| `iSS` vs `iS` | 输出完全相同（34 行） | `iSS` 13 个 program header，`iS` 34 个 block |
| `tp int @ entry` | `AttributeError ... getBaseDataType` | 正常输出 `int size=4` |
| `tcj int` | 40+ 行基础 typedef 前导 | 单行 `int` |
| `tc Elf64_Ehdr` | 依赖 typedef + 结构体 | typedef + 结构体（无依赖前导） |
| `aflj~entry` | 2,909 行，未过滤 | 1 行，`"name": "entry"` |
| `-j -qc f` | 文本输出 | JSON 数组 |
| `e scr.color=3; pd 2` | 无 ANSI 输出 | 有 ANSI；`scr.color=0` 关闭，TTY 自动开启 |
| `gdare2 -o 2000` | `unknown option -o` | 明确报 `file-offset mapping is not implemented` |
| `--list-offset 10 -qc afl` | 不存在 | 等于 `afl` 第 11 项起 |
| `e asm.comments=true; pd 1` | 无变化 | 输出 `;-- symbol:` 与 EOL 注释 |
| `e asm.lines=true; pd 1` | 无变化 | 输出 `│ ` / `└─` gutter |
| `e cmd.batch=false; pd 1 @@F` | 无变化 | 逐目标 RPC，不使用 batch |
| `L` / `i` / `aflq` / `ej` | `unknown or unsupported command` | 全部可用（G7） |
| `pd 1 @@F` | 对 0x125000+ thunk 刷屏 | 跳过 112 个无指令目标，仅一条 WARN |
| `px 4 @@S` | 不可读块刷 `MemoryAccessException` | 跳过不可读块，无 ERROR |
| `C` | 1,544 条，含 `(FDE)` 注释 | 未变（G23 待做） |
| `--loader-arg -loader-fileOffset 0` | argparse 报缺失参数 | 正常传递 |
| `pytest -q`（idare2 仓库） | 739 passed | 对照基线 |

> r2 为系统 5.5.0，项目的 parity 目标是 6.2.5；文本/颜色细节以 6.2.5 为准，
> 本表只记录命令是否可用与结构差异。

## 10. 实施记录

### 2026-11-13：G24 完成（发布工程化）

| 任务 | 文件 | 验证 |
|---|---|---|
| 许可与变更记录 | `LICENSE`、`CHANGELOG.md`、`RELEASING.md` | 人工 |
| 动态版本 | `pyproject.toml` + `[tool.hatch.version]` | `uv build` → 0.1.0 |
| 锁文件 | `uv.lock`（`uv lock`） | `uv build` 使用锁文件 |
| 发布流程 | `.github/workflows/publish.yml`（tag → build → twine check → PyPI trusted publishing） | 配置需在 PyPI 侧完成 |
| 元数据 | MIT/3.12/3.13 classifiers、Issues/Changelog URL | `uvx twine check dist/*` 两项 PASSED |

### 2026-11-13：G19 完成（轻量 ELF 解析）

| 任务 | 代码 | 测试 |
|---|---|---|
| 头/节/动态/重定位 | `formats/elf.py`：`read_header`/`read_sections`/`read_dynamic`/`read_needed`/`read_relocations` | `test_formats_elf.py`（合成 ELF） |
| 命令 | `cmd/info.py`：`ih`/`ihj`/`iH`/`il`/`ilj`/`ir`/`irj`；`-j` 映射 | `test_session.py::test_elf_header_dynamic_and_relocation_commands` |
| 真实文件验证 | `/bin/ls`：段 14、库 3、重定位 325，与 `readelf -l/-d/-r` 一致 | 手工 + real smoke |

验证：离线 **313 passed**。

### 2026-11-13：G18 完成（测试与 CI）

| 任务 | 代码 | 测试 |
|---|---|---|
| 配置测试 | `tests/test_config.py`：每个默认值、布尔/整数强制、只读与 reflect | 42 项 |
| 格式测试 | `tests/test_info_formats.py`：段类型名、权限位、重名、PN_XNUM、损坏头 | 28 项 |
| 补全测试 | `tests/test_completion.py`（G16 已加） | 4 项 |
| `pf`/`fmt` | `tests/test_pf.py`、`tests/test_fmt.py`（G12/G13/G14 已加） | — |
| CI | `.github/workflows/ci.yml`：Python 3.12/3.13 + `ruff check .` + 离线 pytest | — |
| 全仓 lint | `ruff check --fix .` 清理历史遗留的 13 个 I/F/UP 问题 | — |

验证：离线 **308 passed**；`ruff check .` 干净；parity **12 passed**。

### 2026-11-13：G14 完成（渲染层收尾）

| 任务 | 代码 | 测试 |
|---|---|---|
| `px` 布局 | `fmt/memory.py` 重写：2 字节分组、r2 表头、ASCII 列对齐 | `test_fmt.py::test_hexdump_options` |
| 配置生效 | `hex.pairs`/`hex.offset`/`hex.ascii`；`print.py` 传入 | 同上；`test_session.py` |
| `pd` 列布局 | G13 已改为连续 hexpairs | `test_fmt.py` |

验证：离线 **238 passed**；真实 Ghidra 与 r2 6.2.5 的 `px 16` 逐列一致。

### 2026-11-13：G17 完成（迭代器与命令替换）

| 任务 | 代码 | 测试 |
|---|---|---|
| 反引号替换 | `session.py::_expand_backticks`：首行替换、嵌套上限 8、未闭合报错 | `test_backtick_substitution*` |
| 函数迭代器 | `ops/batch.py::_function_targets` 排除 external/thunk/非可执行入口 | `test_function_iterators_are_equivalent`；real `/bin/ls` 无跳过告警 |
| `.cmd` | 明确不做（与 `.g*` 命名空间冲突），记入 DIVERGENCES §11.9 | 文档 |
| `@@s` 扩展 | `@@s:<symbol-pattern>` 标注为 gdare2 扩展 | 文档 |

验证：离线 **238 passed**；真实 Ghidra `pd 1 @@f` / `pd 1 @@F` 均为 292 行且
无跳过告警；反引号 `s \`? 0x400000\`` 生效。

### 2026-11-13：G16 完成（补全与 rc 层级）

| 任务 | 代码 | 测试 |
|---|---|---|
| rc 层级 | `rc.py`：系统 rc + `rc.d/*`（排序）、`~/.gdare2rc`、根→cwd 的 `.gdare2rc` | `test_rc.py::test_rc_directories_and_project_ancestors` |
| 覆盖/跳过 | `GDARE2_RCFILE`；`-N` 跳过用户/项目，`-NN` 全部跳过 | `test_rcfile_override_and_skip` |
| 补全 | `completion.py`：参数位置补全 flag/函数/`$` 变量；`setup_readline(session)` | `tests/test_completion.py` |

验证：离线 **235 passed**。

### 2026-11-13：G13 完成（`~` 过滤器 v2）

| 任务 | 代码 | 测试 |
|---|---|---|
| 列选择 | `filter.py`：`[n]`/`[-1]`/`[a,b]`/`[a-b]`/`[a-]` | `test_filter.py` |
| 排序 | 整行 `$`/`$!`/`$!!`；按列 `$:n`/`$:n!`（负数从行尾） | 同上 |
| 行选择 | `:n`/`:a-b`（结束不含）/`:a-`/`:-1`/`:-2` | 同上 |
| JSON | `~{}` 重新格式化；`~{}:0` 美化后选行 | 同上 |
| 明确不支持 | `~?ea`/`~<>`/`~:)`/`~:}`/`~{:path` 抛 `UsageError` | 同上 |
| `pd` 列对齐 | `fmt/disasm.py` 字节列改为连续 hexpairs，>8 字节 `..` 截断 | `test_fmt.py` |

验证：离线 **229 passed**；真实 Ghidra（`/bin/ls`）确认 `pd 3~[1]` =
`31ed/4989d1/5e`、`~[0,2]`、`~$`、`~$!`、`ij~{}` 与 r2 形状一致。

### 2026-11-13：G15 完成（`p` 族只读命令）

| 任务 | 代码 | 测试 |
|---|---|---|
| `pdb`/`pC`/`pA` | `cmd/print.py`：基本块反汇编、双列布局、地址+助记符+大小+文本 | `test_print_read_variants` |
| `pxd`/`pxu`/`pxj` | 客户端 4 字节十进制 dump 与字节 JSON 数组 | 同上 |
| `ps` 家族 | 新增 `fmt/strings.py`（移植 idare2 解码）；`psz/psw/psp/psu/psx/psn/psj` | 同上 |
| `p8` 投影 | `p8s/p8d/p8x/p8,/p8*/p8b/p8f` | 同上 |
| `pv` | `[p][width][u|d][j]` 解析；`pvu/pvd/pvp` 及宽度组合 | `test_pv_variants` |
| 明确不支持 | `pdk`/`pdr` 抛 `UnsupportedError` | `test_print_family_explicit_unsupported` |

验证：离线 **221 passed**；真实 Ghidra（`/bin/ls`）确认每条命令有真实输出。

### 2026-11-13：G12 完成（`pf` 格式化打印）

| 任务 | 代码 | 测试 |
|---|---|---|
| 解析/渲染 | 新增 `src/gdare2/pf.py`（基于 idare2 实现，扩展 `u`/`I`/`U` 与 `x[4]` 后缀数组） | `tests/test_pf.py`（23 项） |
| 命令 | `cmd/print.py`：`pf`/`pfj`/`pfs`/`pf.`，前缀查找支持 `pf.<name>`/`pfj.<name>`/`pfs.<name>` | `test_pf.py` |
| 命名格式 | `Session.pf_formats`；定义/应用/列表/JSON/大小 | `test_named_pf_formats_define_apply_and_inspect` |
| 重复 | `CommandSpec.consumes_repeat`：`4pf xx` 由格式层分组，不再由会话循环重复 | `test_pf_repeat_and_json_output` |
| `-j` | `pf`→`pfj`、`pf.<name>`→`pfj.<name>` | `test_pf_repeat_and_json_output` |

验证：离线 **218 passed**；真实 Ghidra（`/bin/ls`）确认 `pf xx`、`pf 4xi`、
`pf x[4]`、`pf [4]x`、`pf.<name>` 定义/应用/大小/JSON 均可用。

### 2026-11-13：G11 完成（导出变体）

| 任务 | 代码 | 测试 |
|---|---|---|
| `f*` | `cmd/flags.py`；`f` 参数改用 `shlex.split`，支持带引号的 flag 名回放 | `test_session.py::test_export_variants_are_replayable` |
| `C*`/`CC*`/`C*.`/`CCu` | `cmd/comments.py`：base64 编解码、按 Ghidra kind 选 `CCu`/`Cp`/`Cb`/`Cr` | 同上；`test_comment_base64_payload_roundtrip_and_errors` |
| `t*` | `cmd/types.py` + daemon `type_c(compact=True)`，只输出可声明的 struct/union/enum/typedef | 同上 |
| `s*`/`b*` | `cmd/seek.py`：`f undo_<n> = addr`（r2 6.2.5 形状）/ `b 0x..` | 同上 |
| `iS*` | `cmd/info.py`：`f section.<name> <size> @ addr` | 同上 |
| `ax*`/`axlj`/`axlq`/`axlc` | daemon `ops/xrefs.py::xrefs_all`（`getReferenceIterator(minAddress)`）；`axj` 明确报 `NOT_SUPPORTED` | `test_all_xrefs_variants` |
| `~` 转义 | `parser.py::_scan` 先左到右解析转义再按方向查找分隔符；`iS*~\.text` 现在正确切分 | `test_parser.py` |

验证：离线 **195 passed**；真实 Ghidra 冒烟（`/bin/ls`）确认 `t*` 73 行
合法声明、`axlc`/`ax*`/`axlq`/`axlj` 可用、`iS*` 输出可回放。

### 2026-11-13：G6/G8/G10 完成（批次 A 收尾）

| 任务 | 代码 | 测试 |
|---|---|---|
| G6 颜色 | 新增 `fmt/disasm.py` 调色板与 `scr.color` 渲染；TTY 自动开启、`NO_COLOR` 关闭 | `tests/test_fmt.py`；real_ghidra |
| G6 注释/标签 | `instruction_dict` 增加 `comment`/`symbol_demangled`；`asm.comments` 输出 `;-- symbol:` 与 EOL 注释 | `test_fmt.py`；real_ghidra |
| G6 gutter | `asm.lines` 输出 `│ ` / `└─` | `test_fmt.py`；real_ghidra |
| G6 demangle | `_Z` 符号用 `DemanglerUtil` 生成 `symbol_demangled`；`asm.demangle` 控制 | `test_fmt.py` |
| G6 `cmd.batch` | `cmd.batch=false` 时逐目标 RPC，不再合并 batch | `test_session.py::test_cmd_batch_false_uses_individual_calls` |
| G8 分页 | `--list-offset`/`e list.offset`；`functions/symbols/imports/exports/strings/strings_all` 支持 `offset` 并返回 meta | `test_argv.py`、`test_session.py`、real_ghidra |
| G8 `-o` | `-o` 明确拒绝，提示 file-offset 未实现 | `test_argv.py`；real_ghidra |
| G10 文档 | COMMANDS/PROGRESS/DIVERGENCES/README/TASKS 同步 | 人工抽查 |

验证结果（2026-11-13 第三轮）：离线 **190 passed**；真实 Ghidra **24 passed**
（308.13s）；架构矩阵 **2 passed**；parity 因 r2 版本 skip。

### 2026-11-13：G7 完成

| 任务 | 代码 | 测试 |
|---|---|---|
| G7 `i` | `cmd/info.py` 抽出 `_info_lines`，新增 `i`（首行 `file`） | `test_session.py::test_file_info_config_and_function_addresses`；real_ghidra `test_meta_commands_and_iterator_skip` |
| G7 `aflq` | `cmd/analysis.py` 新增地址列表；`afl`/`aflq` 支持名称/glob 过滤 | 同上 |
| G7 `L` | `registry.live_instances()` 共享给 CLI `-L` 和命令 `L` | `test_session.py::test_list_daemon_instances`；real_ghidra |
| G7 `ej`/`e?` | `cmd/meta.py`：`e` 增加 `ej`；新增 `e?`/`e??`；parser 不再把 `e?` 当帮助 | `test_session.py`；real_ghidra |
| `-j` 映射 | `session._maybe_json` 增加 `i→ij`、`e→ej`（带参数时仍按文本） | `test_session.py` |

### 2026-11-13：G9 完成

| 任务 | 代码 | 测试 |
|---|---|---|
| G9a 迭代器跳过 | `session._dispatch_iterator` 跳过 `no instruction` 与不可读块，汇总 `WARN` | `test_session.py::test_iterator_skips_targets_without_instructions`；real_ghidra `pd 1 @@F`/`px 4 @@S` |
| G9b 重复注册 | `cmd.register()` 检测重复 pattern；删除 `wi` 的重复注册 | `test_session.py::test_duplicate_command_registration_is_rejected` |
| G9c 语义复核 | 确认 r2 `@@f` = functions、`@@s:from to step` 已实现；修正任务书描述 | 手工 `?@@` 对照 |

验证结果（2026-11-13 第二轮）：

- 离线 `pytest -q`：**180 passed**；
- `-m real_ghidra`：**24 passed**（362.57s）；
- `-m arch_matrix`：**2 passed**；
- `-m parity`：12 skipped（本机 r2 5.5.0 与黄金文件 6.2.5 不匹配）。

未关闭项：G6（颜色/渲染开关）、G8（分页续读，需要先修正 `-o` 与 r2 语义的
冲突）、G10（文档收尾）、G11–G24。建议下一批先做 G6 与 G8 的设计确认：
r2 的 `-o` 是"按文件偏移映射"，不是"输出分页"；G8 需要改用
`--list-offset` 或 `e list.offset`，并在 `DIVERGENCES` 记录。

### 2026-11-13：G1–G5 完成

| 任务 | 代码 | 测试 |
|---|---|---|
| G1 | 新增 `src/gdare2/formats/{__init__,elf}.py`；`cmd/info.py` 拆分 `iS`/`iSS` | `tests/test_formats_elf.py`；real_ghidra `test_segments_typed_reads_and_json_filter` |
| G2 | `gdare2d/ops/types.py::_typed_values` 使用 `getattr` 并覆盖 `AbstractIntegerDataType` | 同上（`tp int; tpv int; tpx int`） |
| G3 | `gdare2d/ops/types.py::_c_declaration_target` 按行筛选目标声明 | 同上（`tc int` / `tc Elf64_Ehdr`） |
| G4 | `session.py::postprocess` 前插入 `_split_output_blocks` | `tests/test_session.py::test_json_filter_and_pipe_are_line_oriented` |
| G5 | `session.py::invoke`/`_dispatch_iterator` 先映射 JSON 再查找 spec | `tests/test_session.py::test_json_default_resolves_separate_command_specs` |
| 附带 | `gdare2d/__main__.py::_split_loader_args` | real_ghidra `test_loader_arguments_are_validated` |

验证结果：

- 离线 `pytest -q`：**176 passed**；
- `-m real_ghidra`：**23 passed**（285.33s）；
- `-m arch_matrix`：**2 passed**；
- `-m parity`：12 skipped —— 本机 r2 5.5.0 与黄金文件的 6.2.5 不匹配，
  是环境限制，需在 r2 6.2.5 环境重跑。

未关闭项：G6–G24。下一批建议从 G7（`i`/`aflq`/`L`/`ej`）与 G9（迭代器/
重复注册）开始，这两组仍是“文档已声明但实测不可用”的部分。
