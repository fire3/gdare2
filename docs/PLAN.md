# gdare2 实施计划

> 从空仓库到可用 v1 的分阶段计划。每个里程碑都要有可运行的验收命令，
> 不以“代码写完”为完成标准。

- 更新时间：2026-11-08
- 当前进度：M0–M4 核心完成，M5 进行中，M6 未开始
- 任务级细化与缺陷清单：见 [ROADMAP.md](ROADMAP.md)

## 0. 实施原则

1. **先打通一条完整链路，再扩命令面。** M0 只做 `s/pd/px/q/?`，但必须走完
   CLI → RPC → daemon → Ghidra → 渲染 → 过滤/重定向。
2. **每个 op 都是可单测的函数。** daemon 的 Ghidra 访问与纯数据处理分离。
3. **未实现命令明确报错。** 禁止静默回退到相似命令。
4. **先只读，后写入。** 写入必须走 transaction + 只读门控。
5. **parity 只比较能比较的。** 先锁定 hexdump/info/结构，再处理反汇编文本差异。
6. **每个里程碑单独 commit。** 文档、实现、测试同步更新。

## 1. 阶段总览

| 阶段 | 目标 | 预计 | 关键产物 |
|---|---|---|---|
| P0 预研 | 验证 PyGhidra/项目锁/反编译/导入 | 2–4 天 | PoC 脚本 + 结论 |
| M0 骨架 | 两进程、RPC、`s/pd/px/q/?` | 1 周 | 可运行 CLI |
| M1 只读核心 | 导入、daemon 复用、`iI/afl/axt/pdf` | 1–2 周 | 日常只读可用 |
| M2 分析/图 | `a*`、基本块、图、batch `@@` | 1–2 周 | 函数级分析可用 |
| M3 反编译/类型 | `pdc/afv/t*/C*` | 1–2 周 | 反编译工作流 |
| M4 写入 | `wx/wf/u/U/wc+/w` | 1 周 | 可修改项目 |
| M5 兼容/体验 | parity、补全、rc、架构矩阵 | 2 周 | v1 候选 |
| M6 GUI 桥 | Ghidra 插件附着 | 2–4 周 | 类 idare2 GUI 体验 |

时间只是量级，不是承诺；以验收结果为准。

## 2. P0 预研（2–4 天）

### 目标

在写正式代码前，确认以下事实，避免架构返工：

1. Python 3.13 能安装并启动 PyGhidra。
2. `open_project(create=True)` 与项目锁行为符合预期。
3. `ProgramLoader` 能导入 ELF 和裸二进制，`-baseAddr` 生效。
4. `DecompInterface` 能在 headless daemon 中反编译。
5. 自动分析能在 headless 中完成，耗时可控。
6. 项目关闭/重开后分析结果持久化。
7. 只读 vs 写入 transaction 的行为符合预期。
8. `LoadResults.save()`/`close()` 后，项目内存在可重开的 Program。
9. 未知 loader 参数不会被静默忽略。

### 交付

- `tools/spike_pyghidra.py`（临时 PoC，可保留为开发工具）
- `docs/RESEARCH.md` 增补实测结论（版本、耗时、坑）
- 一份最小项目/程序路径约定

### 验收

```bash
python tools/spike_pyghidra.py /bin/ls
# 输出：language, image base, function count, first 5 functions, decompile of main
```

### 风险

- Python 3.14 下 JPype 安装失败 → 直接改用 3.13。
- Ghidra 项目锁导致 PoC 第二次运行失败 → 确认先 close 再重开。
- 自动分析耗时过长 → 记录基线，设计 `-n`/超时。
- 本机只有 Python 3.14 → 先 `uv python install 3.13`，再建 venv。

## 3. M0 骨架（1 周）

### 目标

打通完整链路：

```text
gdare2 -qc 's 0x1000; pd 5; px 16' target
```

### 任务

1. `pyproject.toml`，包名 `gdare2`，入口 `gdare2` / `gdare2d`。
2. 移植 idare2 纯模块：`argv.py`、`parser.py`、`expr.py`、`filter.py`、`pipe.py`。
3. `protocol.py`：信封 + bytes 编解码。
4. `client.py`：HTTP JSON-RPC、token、重试。
5. `registry.py`：状态文件、pid 检查、文件锁。
6. `launcher.py`：自动拉起 daemon、等待 `/health`。
7. `gdare2d/runtime.py`：PyGhidra 启动、项目打开、程序加载。
8. `gdare2d/server.py`：HTTP server、鉴权、请求队列。
9. `gdare2d/executor.py`：单线程 Program executor。
10. `ops/session.py`：`open_summary`、`status`、`session` lease。
11. `ops/disasm.py`：`disasm`。
12. `ops/memory.py`：`read_bytes`。
13. 客户端 `s`、`pd`、`px`、`q`、`?`、`e`、`b`。

### 验收

```bash
gdare2 -qc 'pd 5' /bin/ls
gdare2 -qc 's 0x1000; pd 5; px 16' /bin/ls
gdare2 -qc 'pd 5~call' /bin/ls
gdare2 -qc 'pd 3 > /tmp/out.txt' /bin/ls && cat /tmp/out.txt
gdare2 -L
```

要求：

- 首次命令能拉起 daemon；
- 第二次命令不重新导入；
- `~`/`>` 生效；
- `-q` 无 banner，退出码正确。

## 4. M1 只读核心（1–2 周）

### 目标

日常只读工作流可用。

### 任务

1. `import_plan.py`：语言别名、`-a/-b/--endian/-B/--ghidra-language`。
2. `ops/info.py`：`iI`、`ij`、`iS`、`is`、`ii`、`ie`、`iz`。
3. `ops/analysis.py`：`afl`、`afi`、`afb`、`afc`、`afC`。
4. `ops/xrefs.py`：`axt`、`axf`、`afx`。
5. `ops/disasm.py`：`pdf`、`pdi`、`pdl`、`pd -n`。
6. `ops/memory.py`：`p8`、`pv`、`ps`、`pr`。
7. 客户端 `i*`、`a*`、`s*`、`f` 列表。
8. 分页/截断 `meta`。
9. 黄金文件：`/bin/ls`、`vulfirm` ARM 样本。

### 验收

```bash
gdare2 -qc 'iI' target
gdare2 -qc 'afl' target | head
gdare2 -qc 'axt @ main' target
gdare2 -qc 'pdf @ main' target | head -40
gdare2 -qc 'iS' target
gdare2 -qc 'iz' target | head
```

要求：

- 函数/交叉引用/段/字符串结果非空；
- 第二次命令不重新分析；
- JSON 形式 `iIj/aflj/axtj` 可解析；
- 大列表有截断提示。

## 5. M2 分析、基本块与图（1–2 周）

### 任务

1. `ops/analysis.py`：`af`、`afn`、`afu`、`a8`、`ad`、`ab`、`ao`。
2. `ops/graph.py`：`agf`、`agfj`、`agfd`。
3. `BasicBlockModel` 封装与缓存。
4. `@@` 迭代器 + `batch`。
5. 客户端 `s` 的 `sb/sf/sF/so/sn/sp`。
6. `ai`、`afj`、`aflc/afln/afl+`。

### 验收

```bash
gdare2 -qc 'af @ 0x401000' -w target
gdare2 -qc 'afb @ main' target
gdare2 -qc 'agf @ main' target
gdare2 -qc 'agfd @ main' target | dot -Tpng > /tmp/g.png
gdare2 -qc 'pd 2 @@f' target
```

要求：

- 基本块起止/后继正确；
- `agf` ASCII 图可读；
- `@@f` 只一次 RPC（日志确认）。

## 6. M3 反编译、类型、注释（1–2 周）

### 任务

1. `ops/decompile.py`：`pdc`、函数签名、`afv`。**（已完成）**
2. `DecompInterface` 生命周期与超时。**（生命周期完成；超时配置待落实）**
3. `ops/types.py`：`t`、`ts`、`tu`、`te`、`td`、`tf`、`tc`、`tfc`、`tf-`。
   **（已完成）**
4. `ops/comments.py`：`C`、`CC`、`Cd`、`Cb`、`Cp`、`Cr`。**（已完成）**
5. 客户端 C 代码渲染/分页。**（基本完成；分页待补）**
6. `afv` 存储分类与 `DIVERGENCES.md` 对齐。**（已完成）**
7. 类型化读取：`tp`/`tpv`/`tpx`、`t-` 通用类型删除。**（待实现，见 ROADMAP B3）**
8. 函数签名写入：`afs`、`ApplyFunctionSignatureCmd`。**（已完成）**

### 验收

```bash
gdare2 -qc 'pdc @ main' target
gdare2 -qc 'afv @ main' target
gdare2 -qc 't' target | head
gdare2 -qc 'ts struct_name' target
gdare2 -w -qc 'CC hello @ main' target
gdare2 -qc 'C @ main' target
```

要求：

- 反编译失败有明确错误，不崩溃 daemon；
- 类型解析失败返回解析消息；
- 注释写入后重启 daemon 仍可见（保存后）。

## 7. M4 写入与撤销（1 周）

### 任务

1. `ops/write.py`：`wx`、`w`、`w0`、`wf`、`wd`。
2. transaction 包装与只读门控。
3. `io.cache` 客户端缓存 + `wc+` 批量提交。
4. `u`/`U`。
5. `w`/`wq` 保存。
6. 写后重开验证。
7. 失败回滚测试。

### 验收

```bash
cp target /tmp/target
gdare2 -w -qc 's main; wx 9090; w' /tmp/target
gdare2 -qc 'px 2 @ main' /tmp/target
gdare2 -qc 'wx 90 @ main' /tmp/target   # 应报 READONLY
gdare2 -w -qc 'wx 90 @ main; u' /tmp/target
gdare2 -w -qc 'e io.cache=true; wx 9090; wc+' /tmp/target
```

要求：

- 只读拒绝；
- 写入后重开可见；
- undo 生效；
- transaction 失败回滚；
- daemon 崩溃不产生半写状态（Ghidra transaction 保证）。

## 8. M5 兼容与体验（2 周）

> 当前状态：进行中。rc、readline、`-i/-I`、搜索、20 配置矩阵已完成；
> parity、flags、脚本/变量、部分命令面仍待补。任务级拆分见 ROADMAP Phase A–C。

### 8.1 已完成

1. `~`/`|`/`>`/`;`/`@` 基础语义与测试。
2. JSON 输出（`-j`、`j` 后缀）与常用命令映射。
3. REPL、readline 历史、Tab 补全。
4. rc 文件（`~/.gdare2rc`、`$XDG_CONFIG_HOME/gdare2/rc`）与 `-N/-NN`。
5. `-i/-I` 脚本顺序。
6. 内存搜索 `/`、`/x`、`/w`、`/v[1248]`、`//`、`/+`、`/-`。
7. 架构矩阵（20 配置）与 `tools/arch_matrix.py`。
8. `.g/.gstatus/.gsave/.gclose` 基础扩展命令。
9. Phase B 首批：`f` flags、`S`/`$`/`_`、`x`、`iE`/`ia`、`t-`/`tp`/`tpv`/`tpx`、
   `/r`、`cmd.hit`、`@@F`/`@@.file`/`@!n`、`pa`/`wa`/`wi`/`w6`、
   `.gsync`/`.ganalyze`/`.ghelp`、`--daemon-readonly`。

### 8.2 待完成

1. **一致性修复**（Phase A）：**已完成**。包括 instance-id 指纹、架构默认端序、
   daemon 状态、CLI 选项、`--readonly`、分析/反编译超时、只读文案、loader 参数
   校验、`pdi` 独立布局与 `pdj` 字段集决策。
2. **命令面收尾**（Phase B）：已完成 `f` flags、`S`/`$`/`_`、`x`、`iE`/`ia`、
   `t-`/`tp/tpv/tpx`、`/r`、`cmd.hit`、`@@F`/`@@.file`/`@!n`、
   `pa/wa/wi/w6`、`.gsync/.ganalyze/.ghelp`、`--daemon-readonly`；
   剩余 `izz`、`/p`、`/a`、`search.in=raw`、`@@/x`、`@@s`、`@{from to}`、
   `.gexec`、`afr`/`afvR`/`afvW`/`an`、`e ghidra.analysis.wait`。
3. **parity 基础设施**（Phase C）：`tests/parity/`、`tests/golden/`、
   `tools/capture_r2_golden.py`、`/bin/ls` 与 ARM32 样本黄金文件。
4. **架构矩阵增强**：每个配置校验 `pd 1` 与 `iI`；目标配置数补齐。
5. **性能与错误审计**：导入/分析基线、函数列表缓存、分页、退出码检查。
6. **batch 子 op meta 透传**。

### 验收

```bash
uv run pytest
uv run pytest -m real_ghidra
uv run pytest -m parity
uv run pytest -m arch_matrix
uv run gdare2 -qc 'pd 5~call:0[1]' target
uv run gdare2 -j -qc 'afl' target | jq .
```

要求：

- 离线测试 < 5s；
- 真实 Ghidra 测试可重复；
- parity 差异都有归因；
- 架构矩阵全部通过；
- 未实现命令明确报 `NOT_SUPPORTED`，不静默回退。

## 9. M6 GUI 桥（2–4 周，v2）

### 目标

让 `gdare2 --attach` 附着到 Ghidra GUI 中已打开的程序，体验接近 idare2 的 GUI 附着。

### 候选方案

**方案 1：Java Ghidra 扩展**

- 用 Java 写 Ghidra plugin；
- 在 plugin 内启动 loopback HTTP server；
- 通过 `PluginTool`/`ProgramManager` 获取当前 `Program`；
- 所有 Ghidra 调用调度到 Ghidra 任务线程/EDT；
- 复用 gdare2 RPC 协议，但 op 实现仍在 Python daemon 中不可复用。

**方案 2：PyGhidra console 桥**

- 用户在 Ghidra 的 PyGhidra console 运行 `import gdare2.bridge; gdare2.bridge.serve()`；
- 桥接器复用 Python op 实现；
- 需要把请求调度到安全的 Ghidra 线程；
- 依赖 PyGhidra 插件已启用。

**方案 3：Java 扩展 + 嵌入 CPython**

- Java 扩展负责生命周期/GUI 线程；
- 内部启动 PyGhidra interpreter 执行 Python op；
- 复杂度最高，但可复用最多代码。

建议先做方案 2 的原型；若线程模型不可靠，再做方案 1。

### 细化阶段

1. **D1 可行性原型**：在 PyGhidra console 中启动桥；验证线程模型、
   `PluginTool`/`ProgramManager` 取程序路径、项目所有权。
2. **D2 桥接器设计**：op 复用方式、调度到 Ghidra 线程、只读/写入策略、
   失败回退。
3. **D3 协议与发现**：registry `kind=gui`、`--attach gui:<endpoint>`、
   `/health` 增加 `kind`。
4. **D4 MVP 命令**：`pd/pdf/px/afl/afi/axt/pdc/afv/iI`，随后
   `wx/w0/CC/Cp/afn`。
5. **D5 验收**：GUI 不冻结、光标不动、写入可见、关闭后客户端明确报错。

### 验收

- Ghidra GUI 打开程序；
- `gdare2 --attach gui:...` 能 `pd/afl/pdc`；
- 不移动 GUI 光标；
- 写入在 GUI 中立即出现；
- 不破坏用户已有 undo 栈（或明确隔离）。

## 10. 任务优先级（v1）

### P0（必须有）

- daemon + 客户端 + 注册表
- `s`、`pd`、`pdf`、`px`、`p8`、`q`、`?`、`e`、`b`
- `iI`、`afl`、`axt`、`axf`
- `~`、`|`、`>`、`;`、`@`
- `-q`、`-c`、`-j`、`-w`、`-a/-b/-B`
- 只读门控
- 单元测试 + 真实 Ghidra 冒烟

### P1（v1 目标）

- `iS/is/ii/ie/iz`
- `afi/afb/afc/afC/afx`
- `pdc/afv`
- `t/ts/tu/te/td/tf`
- `C*`
- `wx/w/u/U/wc+`
- `@@`/batch
- 架构矩阵

### P2（v1.1/v2）

- `agf/agfj/agfd`
- `pa/wa`
- `pf`
- `izz`
- `iD`
- `P` 会话工程
- GUI 桥

## 11. 风险燃尽

| 风险 | 触发阶段 | 验证/缓解 |
|---|---|---|
| PyGhidra 安装失败 | P0 | Python 3.13 + 本地 wheel |
| 项目锁冲突 | P0/M0 | daemon 独占；文档；`--kill` |
| 分析耗时 | P0/M1 | 基线测量；`-n`；超时 |
| Ghidra 文本差异 | M5 | parity 只比结构 |
| 反编译失败 | M3 | 错误分类；超时；不崩 daemon |
| 写入污染 | M4 | 默认只读；transaction；临时项目测试 |
| daemon 生命周期 | M0 | 注册表/锁/健康检查/重试 |
| 类型解析 | M3 | 失败明确报错 |
| GUI 线程 | M6 | 原型先行；不阻塞 v1 |

## 12. 当前可执行的下一步

> 详细任务、文件、测试和验收见 [ROADMAP.md](ROADMAP.md)。

1. 统一客户端/daemon 的 instance-id 指纹（ROADMAP A1）。
2. 修正 `ppc/mips/sparc` 默认端序并补别名单测（A2）。
3. 补 daemon 状态字段与注册表状态更新，修复 `.g/.gstatus`（A3/C4）。
4. 落实 `-A/-AA`、`--wait`、`--listen`，给手工 `gdare2d` 合理默认值（A4/A5）。
5. 落实 `--readonly`、分析超时、反编译超时（A6/C7/C8）。
6. 建立 parity 基础设施与 `/bin/ls` 黄金文件（C1/C2）。
7. 扩展架构矩阵到 `pd 1`/`iI` 断言（C4）。
8. 实现 `f` flags 家族（B1）。
9. 补 `t-`/`tp`/`/r`/`/p`/`/a` 等命令面（B3/B4）。
10. 记录性能基线并审查错误码/退出码（C6）。
11. 完成 v1 后再启动 M6 GUI 桥原型（Phase D）。
