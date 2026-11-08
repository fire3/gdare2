# gdare2 开发进度

更新时间：2026-11-08
最近验证：2026-11-08

## 当前状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 预研 | 完成 | PyGhidra 导入/分析/反编译/持久化已验证 |
| M0 骨架 | 完成 | 两进程链路、注册表、自动拉起、首批命令与测试 |
| M1 只读核心 | 基本完成 | 只读命令、搜索、JSON 变体、调用关系、session lease、ARM/裸二进制导入已验证 |
| M2 分析/图 | 完成 | `@@` batch、函数/块图、`ab/ao/ai`、`afln/afl+`、`afn/afu/a8/ad` 可用；架构矩阵可用 |
| M3 反编译/类型 | 基本完成 | `pdc/afv`、`t/ts/tu/te/tt/tf`、`td/tc/tfc/t-`、`tp/tpv/tpx`、`afs`、`C/CC/Cp` 已可用；复杂 C++ 类型与结构体值格式化仍受 Ghidra 限制 |
| M4 写入 | 完成（v1 范围） | `wx/w/w0/wf/wd`、`wa/wa*/wa+`、`wi`、`w6d/w6e`、`u/U`、`io.cache`+`wc+`、事务与只读门控已可用 |
| M5 兼容/体验 | 进行中 | rc、readline、`-I/-i`、搜索、flags、脚本/变量、汇编、20 配置架构矩阵已可用；parity、`izz`、`/p`、`/a`、`.gexec` 等待补 |
| M6 GUI 桥 | 待开始 | Ghidra GUI 附着；方案与验收见 `ROADMAP.md` Phase D |

## 验证基线（2026-11-08 实测）

| 套件 | 命令 | 结果 |
|---|---|---|
| 离线 | `.venv/bin/python -m pytest -q` | `125 passed`，0.09s |
| 真实 Ghidra | `GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra` | `19 passed`，320.40s |
| 架构矩阵 | `GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m arch_matrix` | `2 passed`，6.69s |

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

## Phase B 首批（2026-11-08）

- **flags**：`f`/`fj`/`fq`/`f?`/`f-`/`fr`/`f.`；默认只写会话内 flag，
  `-w` + `e ghidra.flags.write=true` 才写回 Ghidra；daemon 新增
  `symbol_create/symbol_rename/symbol_delete`。
- **脚本/变量/输出**：`S`、`$`/`$?`、`_`、`x`/`x8`/`xw`/`xq`/`xj`。
- **信息/类型**：`iE`/`iEj`、`ia`/`iaj`、`t-`、`tp`/`tpv`/`tpx`。
- **搜索/迭代**：`/r`、`cmd.hit`、`@@F`、`@@.file`、`@!n`。
- **汇编/写入**：`pa`、`wa`、`wa*`、`wa+`、`waf`/`waF`、`wi` 宽度/符号变量、
  `w6d`/`w6e`；SLEIGH 助记符通常需要大写。
- **扩展命令**：`.gsync`、`.ganalyze`、`.ghelp`。
- **daemon 控制**：`--daemon-readonly` 转发 `--readonly`。

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

- `izz` 全文件字符串尚未实现（`iz` 仍只扫描已定义数据）；
- `/p`、`/a`、`search.in=raw`、`@@/x`、`@@s:from to step`、`@{from to}` 尚未实现；
- `.gexec` 尚未实现；`--allow-exec` 继续明确报 `BAD_ARGS`；
- `afr`、`afvR/afvW`、`an` 尚未实现；`afB` 的 r2 语义已变为 Thumb 位宽切换，暂不按旧文档实现；
- `e ghidra.analysis.wait` 尚未接入。

### 一致性与契约缺口

- `pdj` 顶层数组与 r2 6.2.5 一致，但字段集不同（缺 `esil/opcode/family/type` 等）；
  已决策不伪造缺失字段；
- batch 子 op 的 `meta` 只汇总错误数，尚未按单项保留；
- `--assembler=rasm2` 与 `--allow-exec` 在对应命令实现前明确报 `BAD_ARGS`
  （这是有意的显式拒绝，不是静默回退）。

### 测试与 parity 缺口

- `tests/parity/` 目录不存在，`pytest -m parity` 没有实际测试；
- `tools/capture_r2_golden.py` 尚未实现（`DEV.md` 已引用）；
- `/bin/ls` 与 ARM32 样本的结构化黄金文件尚未补齐；
- 架构矩阵覆盖 20 配置，目标为 22；且只校验语言 ID，未校验 `pd 1`/`iI`；
- 没有 ARM32 样本的真实 Ghidra 集成测试；
- 已补 argv/launcher/registry/import_plan 的边界回归测试（见新增测试文件）；
- 没有性能基线（导入/分析耗时、`afl`/`pd`/`pdc` 延迟）。

## 下一轮

详细任务、文件、测试与验收见 **[ROADMAP.md](ROADMAP.md)**。按以下顺序推进：

1. C1/C2 建立 `tests/parity/`、黄金抓取工具与 `/bin/ls` 黄金文件；
2. C4 扩展架构矩阵到 `pd 1`/`iI` 断言；
3. B3 补 `izz`；
4. B4 补 `/p`、`/a`、`search.in=raw`、`@@/x`、`@@s:from to step`、`@{from to}`；
5. B6 实现 `.gexec` 与 `--allow-exec` 双重门控；
6. B7 接入 `e ghidra.analysis.wait`；
7. 补 `afr`/`afvR`/`afvW`/`an` 或明确记录为不支持；
8. C15 透传 batch 子 op meta；
9. C6 记录性能基线并审查错误码/退出码。

M6 在 v1 收尾后启动，先做 PyGhidra console 桥原型；详见 `ROADMAP.md` Phase D。
