# gdare2

`gdare2` 是一个以 **Ghidra** 为分析后端、命令行与输出模型尽量兼容 **radare2** 的
逆向分析工具。它把 Ghidra 的项目、反汇编、反编译、类型与写入能力包装成熟悉的
r2 风格命令，同时保留一个常驻 daemon，让后续命令可以秒级响应。

## 为什么用 gdare2

- **Ghidra 的分析能力，r2 的操作习惯**：`s/pd/px/afl/afi/axt/axf/pdc/afv` 等常用命令可直接使用。
- **两进程架构，客户端无 JVM**：CLI 只做解析、会话与渲染；PyGhidra daemon 独占 Ghidra 项目。
- **常驻 daemon**：首次导入/分析较慢，之后多个客户端共享同一个已打开程序。
- **默认可读，显式可写**：只有 `-w` 的请求才能执行写操作；daemon 也可强制只读。
- **批处理友好**：`-qc`、`-j`、`~` 过滤、`|` 管道、`>` 重定向、`@@` 批量迭代。
- **真实 Ghidra 回归测试**：离线单测、真实 Ghidra 集成测试与 22 配置架构矩阵、r2 parity 分层运行。

当前已完成 M0–M5 核心能力与体验项（rc、补全、搜索、flags、脚本、汇编、
parity 黄金文件、22 配置架构矩阵、batch meta）。下一步为 M6 GUI 桥。状态见
[docs/PROGRESS.md](docs/PROGRESS.md)，后续任务见
[docs/ROADMAP.md](docs/ROADMAP.md)。

## 架构

```text
gdare2 CLI  ──loopback HTTP/JSON──▶  gdare2d (PyGhidra daemon)
   │                                      │
   ├─ r2 语法解析                         ├─ Ghidra Project / Program
   ├─ seek / 过滤 / 管道 / 重定向          ├─ 自动分析与反汇编
   ├─ 输出渲染                            ├─ DecompInterface
   └─ session lease                       └─ Memory / Symbol / Comment / Type 写入
```

- 一个目标 + 一组导入选项对应一个 daemon；同一程序会被复用。
- Ghidra 项目锁是独占的：daemon 打开项目时，Ghidra GUI 不能同时可写打开同一项目。
- 多个 CLI 可以共享同一个 daemon；写能力按请求区分，不会因为一个客户端带 `-w` 而提权。

## 环境要求

| 组件 | 建议 |
|---|---|
| Ghidra | 12.2 PUBLIC，默认 `~/ghidra/current` |
| Java | JDK 25（Ghidra 12.2 的基线） |
| Python | 3.12 或 3.13（避免系统 3.14 与 JPype 轮子不匹配） |
| PyGhidra | 3.2.x（Ghidra 自带） |
| radare2 | 仅 parity 测试需要，可选 |

设置 Ghidra 路径：

```bash
export GHIDRA_INSTALL_DIR=$HOME/ghidra/current
```

## 安装

```bash
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python \
  --no-index -f "$HOME/ghidra/current/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
uv pip install --python .venv/bin/python -e '.[test]'
```

也可以使用普通 pip；关键是 `pyghidra` 可用且 `GHIDRA_INSTALL_DIR` 指向 Ghidra。
激活虚拟环境后直接使用 `gdare2`；未激活时可使用 `.venv/bin/gdare2`。

## 快速开始

```bash
# 打开 ELF，进入交互式 REPL
gdare2 /bin/ls

# 不进入 REPL，执行一条命令
gdare2 -qc 'pd 5' /bin/ls

# 打开时直接 seek 到入口
gdare2 -qc 'iI; s entry; pd 10' /bin/ls

# 裸二进制必须提供语言和加载基址
gdare2 -a x86 -b 64 -B 0x400000 blob.bin
```

首次打开会导入并自动分析，耗时取决于目标大小；之后同一目标会复用 daemon。

## 常用用法

### 打开与会话

```bash
gdare2 /bin/ls                  # 交互式
gdare2 -q /bin/ls               # 安静模式
gdare2 -j /bin/ls               # 默认 JSON 输出（支持的命令）
gdare2 -s main /bin/ls          # 初始 seek
gdare2 -n /bin/ls               # 首次导入时跳过自动分析
gdare2 --ephemeral /bin/ls      # 命令结束后关闭并删除临时项目
```

交互式 REPL 支持 readline 历史和 Tab 补全；`q` 只退出客户端，`.gclose` 才关闭 daemon。

### 反汇编与内存

```bash
gdare2 -qc 's entry; pd 20' /bin/ls
gdare2 -qc 's entry; pdf' /bin/ls
gdare2 -qc 'px 64' /bin/ls
gdare2 -qc 's entry; p8 16; pv4' /bin/ls
gdare2 -qc 's entry; ao; ai' /bin/ls
gdare2 -qc 'sf; sF; so; sp' /bin/ls
```

常用 seek：`s <addr|symbol>`、`s+`、`s-`、`sb`（基本块）、`sf`（函数）、
`sF`（函数末尾）、`so`/`sp`（下/上一条指令）。

### 函数、基本块与图

```bash
gdare2 -qc 'afl' /bin/ls
gdare2 -qc 's main; afi; afb; ab; ao' /bin/ls
gdare2 -qc 's main; agf' /bin/ls       # ASCII 控制流图
gdare2 -qc 's main; agfj' /bin/ls      # JSON
gdare2 -qc 's main; agfd' /bin/ls      # Graphviz DOT
gdare2 -qc 'afc @ main; afC @ main' /bin/ls
gdare2 -qc 'axt @ main; axf @ main' /bin/ls
```

### 搜索

```bash
gdare2 -qc '/x 488b' /bin/ls            # 十六进制字节
gdare2 -qc '/x 90?f' /bin/ls            # ?/./ 表示保留半字节
gdare2 -qc '/p 488b' /bin/ls            # pattern 搜索
gdare2 -qc '/a NOP' /bin/ls             # 汇编后搜索字节
gdare2 -qc '/ entry' /bin/ls            # UTF-8 文本
gdare2 -qc '/w hello' /bin/ls           # UTF-16 文本
gdare2 -qc '/v4 0x12345678' /bin/ls     # 32 位立即数
gdare2 -qc '/xj 488b' /bin/ls           # JSON
gdare2 -qc '/x 9090; //; /-' /bin/ls    # 继续向后/向前
gdare2 -qc 'izz~ELF' /bin/ls            # 全文件字符串
gdare2 -qe search.in=raw -qc '/x 488b' /bin/ls
```

可用 `e search.from=0x...`、`e search.to=0x...` 限定范围。当前 `search.in=raw`
不支持，会明确报错。

### 反编译、类型与注释

```bash
gdare2 -qc 's main; pdc' /bin/ls
gdare2 -qc 's main; afv' /bin/ls
gdare2 -qc 't~int; ts; tu; te; tt' /bin/ls
gdare2 -qc 'ts' /bin/ls
gdare2 -qc 'tf~main' /bin/ls
```

注释写入需要 `-w`：

```bash
gdare2 -w -qc 's main; CC eol comment; Cp plate comment; .gsave' /bin/ls
gdare2 -qc 's main; C.' /bin/ls
```

### flags

```bash
gdare2 -qc 'f~entry; fq; f? entry' /bin/ls
# 默认只写会话内 flag；写回 Ghidra 需要 -w 且开启 ghidra.flags.write
gdare2 -w -qc 'e ghidra.flags.write=true; s entry; f demo_flag 4; .gsave' /bin/ls
gdare2 -qc 'fq~demo_flag' /bin/ls
```

### 写入、缓存与撤销

所有写操作都需要 `-w`。`w` 无参数时保存程序，`w <text>` 时写字符串。
以下示例假设 `blob.bin` 是加载到 `0x400000` 的 x86-64 裸二进制；ELF/PE 目标
可省略 `-a/-b/-B`。

```bash
# 写字节并保存
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 's 0x400000; wx 9090; .gsave; .gclose' blob.bin

# 写字符串、零、文件、内存拷贝
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 's 0x400000; w "AB"; w0 4; wf payload.bin; wd 16 8' blob.bin

# 撤销/重做（daemon 内存级字节历史）
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 's 0x400000; wx 9090; u; px 2; U; px 2' blob.bin

# 写缓存：wx 先入客户端缓存，wc+ 一次提交
gdare2 -a x86 -b 64 -B 0x400000 -w \
  -qc 'e io.cache=true; s 0x400000; wx 4142; wc; wc+; wq' blob.bin
```

注意：`wx` 会清理写范围内的 code units；撤销只恢复字节，不回滚反汇编、函数、
注释等元数据，daemon 重启后撤销历史清空。

汇编使用 Ghidra SLEIGH 汇编器，助记符通常需要大写：

```bash
gdare2 -qc 'pa NOP' blob.bin
gdare2 -w -qc 's 0x400000; wa NOP; .gsave' blob.bin
gdare2 -w -qc 's 0x400000; wi4 0x12345678; w6d QUI=; .gsave' blob.bin
```

### JSON、过滤、管道与批量迭代

```bash
gdare2 -j -qc 'iI' /bin/ls
gdare2 -qc 'pd 50~+call' /bin/ls              # 过滤包含 call 的行
gdare2 -qc 'pd 50 | grep -i call' /bin/ls     # 管道到外部命令
gdare2 -qc 'pd 50~+call > calls.txt' /bin/ls  # 重定向
gdare2 -qc 'pd 1 @@f' /bin/ls                 # 每个函数一条
gdare2 -qc 'pd 1 @@i' /bin/ls                 # 当前函数每条指令
gdare2 -qc 'pd 1 @@b' /bin/ls                 # 每个基本块
gdare2 -qc 'px 8 @@S' /bin/ls                 # 每个内存块
gdare2 -qc 'pd 1 @@=0x1000,0x2000' /bin/ls    # 显式地址列表
gdare2 -qc 'pd 1 @@f:^main$' /bin/ls          # 函数名正则
```

### 配置与 rc

```bash
gdare2 -e scr.color=1 -e hex.cols=8 -qc 'px 16' /bin/ls
gdare2 -qc 'e io.cache=true; e search.from=0x1000; e' /bin/ls
```

rc 文件按顺序加载：

- 系统：`$XDG_CONFIG_HOME/gdare2/rc`（默认 `~/.config/gdare2/rc`）
- 用户：`~/.gdare2rc`

`-N` 跳过用户 rc，`-NN` 同时跳过系统 rc。REPL 历史位于
`$XDG_STATE_HOME/gdare2/history`（默认 `~/.local/state/gdare2/history`）。

### daemon 管理

```bash
gdare2 -L                       # 列出运行中的 daemon
gdare2 --status <instance-id>   # JSON 状态
gdare2 --kill <instance-id>     # 关闭 daemon
gdare2 -qc '.gstatus' /bin/ls   # 当前 daemon/程序信息
gdare2 -qc '.gclose' /bin/ls    # 保存并关闭当前 daemon
gdare2 --project /data/projects --project-name demo /bin/ls
```

项目默认位于 `~/gdare2-data`，可用 `GDARE2_DATA_DIR` 覆盖。带 `-w` 的
`.gclose` 会保存程序；只读会话不会保存。

## 命令概览

| 类别 | 主要命令 |
|---|---|
| 信息 | `iI`、`iS`、`is`、`ii`、`ie`、`iz`、`it`、`iM` |
| 反汇编/内存 | `pd`、`pdf`、`pD`、`pi`、`p8`、`px`、`pv`、`ps`、`pc` |
| 搜索 | `/`、`/x`、`/p`、`/a`、`/w`、`/v[1248]`、`/r`、`//`、`/+`、`/-`；`search.in=raw` |
| 函数/图 | `afl`、`afi`、`af`、`afn`、`afu`、`afr`、`afvR`、`afvW`、`an`、`afc`、`afC`、`afx`、`afb`、`ab`、`ao`、`ai`、`agf` |
| xref | `axt`、`axf` |
| 反编译/变量 | `pdc`、`afv` |
| 类型 | `t`、`ts`、`tu`、`te`、`tt`、`tf`、`td`、`tc`、`tfc`、`t-`、`tf-`、`tp`、`tpv`、`tpx` |
| 签名 | `afs`、`afsj` |
| 注释 | `C`、`C.`、`CC`、`CC-`、`Cd`、`Cb`、`Cp`、`Cr` |
| flags | `f`、`fj`、`fq`、`f?`、`f-`、`fr`、`f.` |
| 分析写入 | `a8`、`ad` |
| 字节写入 | `w`、`wq`、`wx`、`w0`、`wf`、`wd`、`wc`、`wc+`、`wc-`、`u`、`U`、`wi`、`w6d`、`w6e` |
| 汇编 | `pa`、`wa`、`wa*`、`wa+`、`waf`、`waF` |
| 脚本/杂项 | `S`、`$`、`_`、`x`、`x8`、`xw`、`xq`、`xj`、`iE`、`ia`、`izz` |
| 迭代 | `@@F`、`@@/x`、`@@/`、`@@.file`、`@@s:from to step`、`@!n`、`@{from to}` |
| 会话/配置 | `s`、`b`、`e`、`q`、`.g`、`.gstatus`、`.gsave`、`.gclose`、`.gsync`、`.ganalyze`、`.ghelp`、`.gexec` |

大部分查询命令支持 `j` 后缀 JSON 变体；`<command>?` 查看单命令帮助。
完整映射见 [docs/COMMANDS.md](docs/COMMANDS.md)。

### 类型与签名写入

```bash
gdare2 -w -qc "td 'struct demo { int field; char text[8]; };'; tc demo; .gsave" /bin/ls
gdare2 -qc 'tc demo; tfc~entry' /bin/ls
gdare2 -w -qc 's entry; afs "int entry(int value)"; .gsave' /bin/ls
gdare2 -qc 's entry; afsj' /bin/ls
gdare2 -w -qc 'tf- unused_function_type; .gsave' /bin/ls
```

`td` 需要把包含分号的 C 声明整体引用起来，否则 `;` 会被当作 gdare2 语句分隔符。
`tc` 输出 Ghidra `DataTypeWriter` 生成的 ANSI-C 声明；`afs` 写入签名时只重命名
Ghidra 默认函数名，不覆盖用户自定义名称。

## 与 radare2 的差异

gdare2 目标不是“假装 Ghidra 是 r2”，而是兼容高频工作流并明确暴露差异：

- 函数名、反汇编文本、反编译输出使用 Ghidra 语义，不伪造 r2 格式。
- `w` 无参数是“保存程序”，`w <text>` 才是写字符串。
- `u/U` 是 daemon 内存级字节补丁历史，不是 Ghidra 全局 undo。
- `f` 默认只写会话内 flag；写回 Ghidra 需要 `-w` 且 `e ghidra.flags.write=true`。
- `pa/wa` 使用 Ghidra SLEIGH 汇编器，助记符通常需要大写。
- `/r` 只遍历已定义字符串；`izz`/`search.in=raw` 返回文件偏移。
- `afr` 为删除+重建函数的近似重分析；`an` 对纯 decompiler 局部变量支持有限。
- `.gexec` 需要客户端与 daemon 都显式 `--allow-exec`，并且 `-w`。
- `-B` 只对裸二进制生效；`sh4` 在 Ghidra 12.2 中无对应语言。
- `-A/-AA`、`--wait`、`--listen` 已生效；`--assembler=rasm2` 与 `--allow-exec`
  在对应命令实现前会明确报参数错误。详见 [docs/ROADMAP.md](docs/ROADMAP.md)。

完整列表见 [docs/DIVERGENCES.md](docs/DIVERGENCES.md)。

## 开发与测试

```bash
# 离线单测
.venv/bin/python -m pytest -q

# 真实 Ghidra 集成测试（约 3 分钟）
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m real_ghidra tests/integration/test_real_ghidra.py

# 20 配置架构导入矩阵
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m arch_matrix
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python tools/arch_matrix.py

# r2 parity（/bin/ls 与 ARM32 样本；黄金文件见 tests/golden）
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python -m pytest -q -m parity

# 重新抓取黄金文件
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python tools/capture_r2_golden.py --target /bin/ls \
  --output tests/golden/ls.json

# 性能基线
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python tools/perf_probe.py /bin/ls --output docs/perf-baseline.json
```

目录边界：`src/gdare2` 是客户端，不得导入 `pyghidra`/`jpype`；
`src/gdare2d` 才依赖 JVM。更多约定见 [docs/DEV.md](docs/DEV.md)。

## 文档

- 文档索引：[docs/README.md](docs/README.md)
- 背景调研：[docs/RESEARCH.md](docs/RESEARCH.md)
- 总体设计：[docs/DESIGN.md](docs/DESIGN.md)
- 命令映射：[docs/COMMANDS.md](docs/COMMANDS.md)
- 语义差异：[docs/DIVERGENCES.md](docs/DIVERGENCES.md)
- 实施计划：[docs/PLAN.md](docs/PLAN.md)
- 开发指南：[docs/DEV.md](docs/DEV.md)
- 开发进度：[docs/PROGRESS.md](docs/PROGRESS.md)
- 性能基线：[docs/PERF.md](docs/PERF.md)
- 后续路线：[docs/ROADMAP.md](docs/ROADMAP.md)
