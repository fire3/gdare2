# gdare2 开发与测试指南

> M0–M4 核心已完成；本文件固化环境、目录、调试和测试约定，并随里程碑更新。
> 任务级缺口与后续顺序见 [ROADMAP.md](ROADMAP.md)。

## 1. 环境基线

| 组件 | 建议版本/位置 |
|---|---|
| Ghidra | 12.2 PUBLIC，`~/ghidra/current` |
| Java | 25（Ghidra 12.2 要求） |
| Python | 3.12 或 3.13（**不要用系统 3.14**） |
| PyGhidra | 3.2.0（Ghidra 自带） |
| radare2 | 6.2.5，`~/.local/bin/r2` |
| 测试目标 | `../vulfirm`、`/bin/ls`、临时编译样本 |

### 1.1 Python 版本

Ghidra 12.2 声明支持 3.9–3.15，但随包分发的 JPype 轮子只到 cp313。
系统 Python 3.14.6 下可能触发源码构建或二进制不兼容。

固定：

```bash
uv venv --python 3.13 .venv
source .venv/bin/activate
```

如果 `uv` 下载 Python 超时，可按 AGENTS.md 使用代理：

```bash
export HTTPS_PROXY=http://localhost:10809
export ALL_PROXY=socks5://localhost:10808
```

如果 3.13 不可用，用 3.12。

### 1.2 安装 PyGhidra（离线）

```bash
python -m pip install --no-index \
  -f ~/ghidra/current/Ghidra/Features/PyGhidra/pypkg/dist \
  pyghidra
```

或者在线：

```bash
pip install "pyghidra==3.2.0"
```

设置：

```bash
export GHIDRA_INSTALL_DIR=~/ghidra/current
```

自检：

```bash
python - <<'PY'
import pyghidra
pyghidra.start(install_dir=__import__("pathlib").Path.home() / "ghidra/current")
from ghidra.program.model.listing import Program
print("PyGhidra OK")
PY
```

### 1.3 安装项目

使用 uv 的完整初始化流程：

```bash
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python \
  --no-index -f "$HOME/ghidra/current/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
uv pip install --python .venv/bin/python -e '.[test]'
```

如果已经激活虚拟环境，也可以用 `uv pip install -e '.[test]'`。

## 2. 目录约定

```text
src/gdare2/       # 客户端：无 JVM 依赖
src/gdare2d/      # daemon：依赖 pyghidra
tests/            # 离线单测默认
tests/integration # -m real_ghidra
tests/parity      # -m parity（待建立）
tests/golden      # parity 黄金文件（待建立）
tests/arch_matrix # -m arch_matrix
tools/            # spike、黄金文件抓取、矩阵汇总
docs/             # 本设计文档
```

**重要：** `src/gdare2` 不得 `import pyghidra` 或 `jpype`；否则客户端失去
“无 JVM 依赖”的优势。daemon 代码只在 `src/gdare2d`。

## 3. 测试分层

| 层 | 目录 | 依赖 | 运行 |
|---|---|---|---|
| T1 纯函数 | `tests/test_*.py` | 无 | `pytest` |
| T2 协议 | `tests/test_protocol*.py` | fake backend | `pytest` |
| T3 集成 | `tests/integration/` | PyGhidra | `pytest -m real_ghidra` |
| T4 parity | `tests/parity/` | PyGhidra + r2 | `pytest -m parity` |
| T5 架构矩阵 | `tests/arch_matrix/` | PyGhidra + 语言模块 | `pytest -m arch_matrix` |
| T6 GUI | 手工/集成 | Ghidra GUI + 插件 | M6 |

`pyproject.toml` 默认：

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra -m 'not real_ghidra and not parity and not arch_matrix and not gui'"
markers = [
  "real_ghidra: requires Ghidra + PyGhidra",
  "parity: requires radare2",
  "arch_matrix: imports one raw binary per architecture",
  "gui: requires a running Ghidra GUI bridge",
]
```

## 4. 开发循环

### 4.1 前台 daemon

`gdare2d` 会根据目标与导入选项自动推导项目位置和名称：

```bash
gdare2d --foreground --target /bin/ls --log-level debug
```

默认项目位置为 `$GDARE2_DATA_DIR/projects/<instance-id>`，项目名为
`<target-basename>-<instance-id[:8]>`。客户端与 daemon 现在共用同一份
import-options 指纹，因此手工启动的 daemon 可以被 `gdare2 /bin/ls` 复用。
需要固定位置时再显式传 `--project` / `--project-name`。

默认 Ghidra 项目位于 `~/gdare2-data/projects`，可用 `GDARE2_DATA_DIR` 覆盖。
Ghidra 不接受以 `.` 开头的路径元素，因此不要把它指到 `~/.local/...`。

另一个终端：

```bash
gdare2 --attach <id> -qc 'pd 5'
```

### 4.2 自动拉起

```bash
gdare2 -qc 'pd 5' /bin/ls
```

检查注册表：

```bash
gdare2 -L
cat ${XDG_RUNTIME_DIR:-/tmp}/gdare2-$(id -u)/*.json
```

### 4.3 日志

daemon 日志位置：

```text
${XDG_RUNTIME_DIR:-/tmp}/gdare2-<uid>/<instance-id>.log
```

建议日志字段：

- 请求 id/op/耗时；
- Ghidra transaction id；
- 异常堆栈（仅 daemon 日志，不返回客户端）；
- 项目/程序路径、语言 ID。

### 4.4 逃生舱

`--allow-exec` / `.gexec` 尚未实现，当前会明确报 `BAD_ARGS`。实现后计划：

```bash
gdare2 --allow-exec -qc '.gexec print(program.getName())' /bin/ls
```

默认关闭；生产环境不要开启。

## 5. 真实 Ghidra 测试

### 5.1 小目标

```bash
GHIDRA_TEST_TARGET=/bin/ls pytest -m real_ghidra
```

建议环境变量：

```bash
export GHIDRA_TEST_TARGET=/bin/ls
export GHIDRA_TEST_PROJECT=/tmp/gdare2-test-project
export GHIDRA_INSTALL_DIR=~/ghidra/current
```

### 5.2 ARM 固件

```bash
export GHIDRA_TEST_TARGET=../vulfirm/RCE/Tenda/httpd
pytest -m real_ghidra
```

### 5.3 裸二进制矩阵

```bash
pytest -m arch_matrix
python tools/arch_matrix.py
```

矩阵项：

- 语言 ID 正确；
- `pd 1` 有输出；
- `iI` 的 arch/bits/endian/base 正确；
- 导入不崩溃。

## 6. r2 parity

### 6.1 抓黄金文件

目标形态（Phase C 建立）：

```bash
r2 -e scr.color=0 -q -A -c 'pd 10' target > tests/golden/pd.txt
```

计划脚本：`tools/capture_r2_golden.py`（当前不存在，见 ROADMAP C1）。脚本必须：

- 记录 r2 版本、Ghidra 版本、language ID、目标 sha256；
- 生成可归一化的结构化输出，而不是仅保存原始文本；
- 版本不匹配时提示重新生成，而不是直接判失败。

### 6.2 规范化

必须抹平：

- 函数名：`sub_...` / `fcn....` / `FUN_...` / `LAB_...`；
- 地址宽度（除非配置一致）；
- 颜色/ANSI；
- 反汇编助记符别名；
- 行首沟槽/空格。

### 6.3 黄金文件头

每个文件记录：

```text
# r2: 6.2.5
# ghidra: 12.2
# language: x86:LE:64:default
# target-sha256: ...
```

版本不匹配时提示重新生成，而不是直接判失败。

## 7. 常见坑

### 7.1 Ghidra / PyGhidra

- **Python 3.14 可能装不上 JPype**；用 3.13/3.12。
- **项目独占**：daemon 打开项目后，GUI 不能打开同一项目。
- **`open_project()` 是可写打开**，会建锁；不要试图删锁文件。
- JVM 只能启动一次；daemon 内不要反复 `pyghidra.start()`。
- `Program` 不是线程安全的；所有访问走单线程 executor。
- Java 对象不要进 JSON；在 op 内转成 Python 基础类型。
- 反编译 `DecompInterface` 是独立进程；异常/超时要有兜底。
- `Assemblers.getAssembler` 对非 SLEIGH 语言会抛异常。
- `Memory.setBytes`、`SymbolTable.createLabel` 等写操作必须在 transaction 内。
- 自动分析可能修改程序；只读会话的 bootstrap 分析需要明确策略。
- Ghidra SLEIGH 汇编器通常要求大写助记符（如 `NOP`）；`pa/wa` 不支持的语言
  会返回 `NOT_SUPPORTED`。
- `f` 默认只写客户端 FlagStore；写回 Ghidra 需要 `-w` 且
  `e ghidra.flags.write=true`。

### 7.2 r2 兼容

- 修饰符顺序以 idare2 为准：`;` → `@` → `~` → `|` → `>`。
- 裸数字是十进制，`0x` 才是十六进制。
- `~:N` 是行选择，`~[n]` 是列选择。
- `s+4`/`b+16` 的数字粘在命令上。
- 未实现命令必须报错，不能回退。
- 一条语句失败不终止整行；批量模式退出码为 1。

### 7.3 daemon

- stale 注册表必须先检查 pid + `/health`，不能只看文件存在。
- 同时拉起同一实例需要文件锁。
- 只读会话不要保存；`--no-save-on-close` 要真的丢弃。
- `--linger 0` 后立刻重连可能撞上正在关闭的 daemon；客户端应重试。
- token 文件权限 0600，目录 0700。

### 7.4 测试

- 不要在仓库里的测试样本上直接写；先复制到临时目录。
- Ghidra 项目文件会被重写；测试项目放临时目录。
- 真实 Ghidra 测试可能因语言模块缺失失败；先跑 `/bin/ls`。
- parity 不要追求逐字节一致；先比结构。

## 8. 提交前检查

```bash
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m parity
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m arch_matrix
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python tools/arch_matrix.py
```

当前 `parity` 尚未建立，运行会得到 0 个测试；Phase C 完成后必须全绿。
`ruff` 不在当前 venv 中，可用系统/独立环境运行。

## 9. 参考

- `docs/RESEARCH.md`、`docs/DESIGN.md`、`docs/PLAN.md`
- `../idare2/docs/DEV.md`、`../idare2/docs/PROGRESS.md`
- `~/ghidra/current/support/analyzeHeadlessREADME.md`
- `~/ghidra/current/Ghidra/Features/PyGhidra/pypkg/README.md`
- `../aida-audit/backend/aida_audit/ghidra_export/AidaExport.java`
