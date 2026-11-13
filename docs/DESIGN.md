# gdare2 设计方案

> 用 Ghidra 作为分析后端，提供 radare2 风格命令行、输出和交互体验。

- 版本：0.1（立项设计）
- 日期：2026-11-07（实现状态更新：2026-11-08）
- 基线：Ghidra 12.2 PUBLIC、PyGhidra 3.2.0、radare2 6.2.5、idare2 0.1
- 状态：M0–M5 与 v1 已完成（Phase A–C 关闭）；不支持 GUI 附着；本文保留为架构契约

> 实现状态、已知缺口与后续顺序见 [PROGRESS.md](PROGRESS.md) 与
> [ROADMAP.md](ROADMAP.md)。本文描述的是目标设计；当实现与设计不一致时，
> 以 ROADMAP 的差距清单为准，并在实现后回写本文。

---

## 1. 目标与非目标

### 1.1 目标

1. **命令行兼容 r2**：`pd 10`、`pdf`、`px 64`、`s main`、`axt`、`afl`、
   `pd 10 @ 0x401000`、`pd~call`、`pd|head -5`、`pd > out.txt`、`pd;px 16`。
2. **输出模型兼容 r2**：地址宽度、列布局、`j`/`q`/`*` 后缀、错误信息位置。
3. **后端是 Ghidra**：反汇编、函数、交叉引用、类型、反编译、注释、搜索都来自
   Ghidra `Program`，不引入 r2 的 `r_anal`。
4. **交互可用**：首次启动后保持 daemon，后续命令秒级响应；REPL、历史、Tab 补全。
5. **脚本可用**：`-qc`、`-j`、退出码、stdin/stdout 行为稳定。
6. **可附着/可共享**：多个 CLI 客户端共享同一个 daemon；不支持 GUI 附着。
7. **可验证**：纯客户端单测、fake backend 协议测试、真实 Ghidra 集成测试、
   r2 输出 parity、架构矩阵测试。

### 1.2 非目标（v1 明确不做）

| 子系统 | 原因 |
|---|---|
| `d*` 调试器 | Ghidra 调试器需要 trace/DB 会话，与静态 CLI 模型不同 |
| `V` 可视模式、面板、缩放 | 终端 UI 成本高，不是核心价值 |
| ESIL / `ae` / `ar` | 依赖 r2 自有 VM，Ghidra 无对应语义 |
| zignatures / FLIRT | 用 Ghidra FunctionID/BSim 表达更自然，不做 r2 兼容层 |
| r2 二进制工程 `.prj` | 改用 JSON session/project 配置 |
| Ghidra GUI 附着/实时同步 | 明确不做；daemon 独占项目，GUI 与 daemon 不同时打开同一项目 |
| 完整 C++ 类型/模板恢复 | Ghidra 与 r2 的类型模型不同，只做常用 C 类型 |
| 所有 r2 命令 | 未实现命令必须明确报错，禁止静默回退 |

---

## 2. 架构总览

### 2.1 两进程、三层

```text
┌────────────────────────────────────────────────────────────────────┐
│ gdare2 CLI（纯 Python，无 JVM）                                    │
│                                                                    │
│  argv → parser → Session/命令注册表 → backend.call(op, args)       │
│                                      │                             │
│                                      ▼                             │
│  结构化结果 → fmt 渲染 → ~ 过滤 → | 管道 / > 重定向 / j 输出       │
└──────────────────────────────────┬─────────────────────────────────┘
                                   │ loopback HTTP + JSON-RPC
                                   │ Bearer token
┌──────────────────────────────────▼─────────────────────────────────┐
│ gdare2d（PyGhidra + Ghidra，常驻 daemon）                          │
│                                                                    │
│  HTTP server → 请求队列 → 单线程 Program executor                  │
│                              │                                     │
│                              ▼                                     │
│  op registry → Ghidra adapter → Program/Project                    │
│                              │                                     │
│                              ▼                                     │
│  DecompInterface / AutoAnalysisManager / transactions               │
└────────────────────────────────────────────────────────────────────┘
```

### 2.2 为什么客户端/服务端分离

- **启动成本**：JVM + Ghidra + 项目打开 + 自动分析远高于普通 CLI 进程。
- **项目锁**：Ghidra 同一项目只能被一个进程可写打开；必须由 daemon 统一持有。
- **可组合**：客户端可以远程连接 daemon，不需要在目标机器装 PyGhidra。
- **可测试**：客户端可以接 fake backend，daemon 可以单独测试。
- **与 idare2 同构**：命令层、op 层、信封和渲染层的心智模型一致。

### 2.3 为什么 seek 在客户端

r2 的 `$$` 是客户端概念。Ghidra `Program` 没有“当前光标”这个静态分析状态；
GUI 的当前地址属于 UI，不应被 CLI 修改。

- `s 0x401000` 只改 `Session.seek`；
- 每个 op 显式接收地址参数；
- 不提供 GUI 跟随/同步，daemon 与 GUI 不同时打开同一项目。

### 2.4 为什么渲染在客户端

如果把排版放在 daemon，`pd~call` 必须把 grep 表达式发到服务端，`|`/`>`/`j`
也要在两端各实现一次。客户端渲染保证：

```text
daemon op ──结构化 JSON──▶ 客户端 fmt ──文本行──▶ ~ ──▶ | / > / j
```

渲染层是纯函数，可用黄金文件离线测试。

---

## 3. 关键设计决策（ADR）

### ADR-1：使用 Python

**决定**：客户端与 daemon 都用 Python 3.12/3.13。

**理由**：PyGhidra 是 Python 绑定；idare2 的纯客户端层可直接移植；开发速度快。

**代价**：需要 JPype/JVM；Python 版本必须与 Ghidra 的二进制轮子兼容。

### ADR-2：常驻 daemon，而不是每命令启动

**决定**：默认 `gdare2 <target>` 自动发现/拉起 `gdare2d`，后续命令连同一实例。

**代价**：需要生命周期、注册表、stale 检测、日志与关闭命令。

### ADR-3：loopback HTTP + JSON-RPC

**决定**：daemon 绑定 `127.0.0.1` 随机端口，使用 Bearer token。

**理由**：跨平台、易调试（curl）、与 Nexus 的形态相似、可扩展到远程/SSE。

**备选**：Unix domain socket（更安全，但 Windows 兼容性差）；stdio（不适合多客户端）。

### ADR-4：默认只读

**决定**：客户端默认只读；未传 `-w` 时拒绝所有写 op；`w` 也只有在 `-w` 下保存。
daemon 对每个请求做第二次门控，并可用 `gdare2d --readonly` 强制整个实例只读。

**理由**：Ghidra 的 transaction 可以回滚，但误写仍会污染分析师的项目。

### ADR-5：op 只返回结构化数据

**决定**：daemon 不返回预格式化字符串（除极少数必须由 Ghidra 生成的文本，
如反编译 C 代码）。客户端负责所有列布局。

**例外**：反编译 C 文本、Ghidra 原生反汇编文本是后端产物；客户端只做缩进/着色/分页。

### ADR-6：不做 GUI 附着

**决定**：只支持 daemon 独占项目，不支持在 Ghidra GUI 打开程序时附着。

**理由**：headless daemon 已覆盖全部分析能力；GUI 附着只影响工作流，却需要
自行解决 Ghidra 项目锁（项目独占）、GUI 线程模型与事务/undo 冲突。需要 GUI
时先关闭 daemon，再在 GUI 中打开项目。

### ADR-7：复用 idare2 纯客户端层

**决定**：v1 直接移植 `argv/parser/expr/filter/pipe/fmt`，保留来源说明；
后续再抽公共包。

**理由**：这些模块已经过大量 r2 对齐测试；重写只会引入新差异。

---

## 4. 进程模型与生命周期

### 4.1 运行形态

| 形态 | 命令 | 行为 |
|---|---|---|
| 自动 daemon | `gdare2 target` | 查找/拉起 daemon，执行命令/REPL |
| 精确附着 | `gdare2 --attach <id>` / `gdare2 --attach auto` | 只连已有实例；`auto` 表示唯一健康实例，不 spawn |
| 禁止 spawn | `gdare2 --no-spawn` | 找不到就报错 |
| 前台 daemon | `gdare2d --foreground` | 调试/服务化 |
| 一次性 | `gdare2 --ephemeral -qc ...` | 起临时 daemon，命令结束即关闭 |
| 列出实例 | `gdare2 -L` | 读注册表，显示 pid/port/project/program |
| 关闭实例 | `gdare2 --kill <id>` / `.gclose` | 优雅关闭；可 `--no-save` |

### 4.2 daemon 状态机

```text
starting → loading_project → importing/analyzing → ready
                                   │                 │
                                   └──── error ──────┘
ready → busy(analysis/decompile) → ready
ready → draining → closed
```

- `starting`：JVM 启动、Ghidra 初始化。
- `loading_project`：打开/创建项目。
- `importing/analyzing`：首次导入和自动分析。
- `ready`：可接受请求。
- `busy`：长任务（分析、全量搜索）执行中；普通查询仍可排队。
- `draining`：拒绝新请求，等待当前请求和保存完成。

`gdare2 -L` 和 `gdare2 --status <id>` 读取这些状态。

### 4.3 注册表

默认目录：

```text
${XDG_RUNTIME_DIR:-/tmp}/gdare2-<uid>/
  <instance-id>.json      # pid, port, token, project, program, state, started_at
  <instance-id>.log       # daemon 日志
```

`instance-id` 与 8.1 的 `project-key` 使用同一派生值，由目标与导入参数共同决定，
避免目标文件或 `-a/-b/-B` 改变后误复用旧分析结果：

```text
sha256(canonical_target_path + ":" + size + ":" + mtime_ns +
       ":" + import_options_fingerprint)[:16]
```

`import_options_fingerprint` 覆盖语言、编译器、基址、loader 名与 loader 参数。

目标内容或导入参数变化时创建新项目；需要原地刷新时使用显式 `--reimport`。

启动时：

1. 读取注册表，检查 pid 是否存活、`/health` 是否响应、版本/协议是否匹配。
2. 若已有健康实例，直接复用。
3. 若 stale，清理并创建新实例。
4. 新实例先写 `starting` 状态，ready 后原子替换。

所有注册表文件权限 `0600`，目录 `0700`。

### 4.4 自动拉起的并发控制

两个 CLI 同时启动同一目标时，可能同时尝试拉起 daemon。使用 `<instance-id>.lock`
文件锁（`fcntl`/`msvcrt`）串行化：

1. 获得锁；
2. 再次检查注册表；
3. 仍无实例才 spawn；
4. 等待 `/health` 通过后释放锁。

### 4.5 idle 与 linger

- 客户端启动时调用 `session.open` 建立 lease；交互式客户端定期 `session.heartbeat`，
  退出时 `session.close`。批处理客户端在命令结束/连接关闭时释放 lease。
- `session.open` 参数为 `{pid, kind: "batch"|"interactive", tty, ttl}`，返回
  `lease`；客户端在 `ttl/3` 或每 30 秒（取较小值）内至少 heartbeat 一次。
- 默认 `--linger 3600`：最后一个 lease 结束后 daemon 再存活 1 小时，便于连续命令。
- `--linger 0`：最后一个 lease 结束后立即关闭。
- `--idle N`：daemon 无请求且无活跃 lease N 秒后自动关闭，默认取 linger。
- 交互式客户端只要 lease 有效，daemon 不会因 idle 关闭。
- 分析进行中不触发 idle 关闭。

### 4.6 崩溃恢复

- CLI 检测到连接失败时，清理 stale 注册表并提示可重新拉起。
- daemon 崩溃不影响磁盘上的 Ghidra 项目；重启后重新打开。
- 未保存的 transaction 由 Ghidra 在进程退出时丢弃。
- 只读会话不自动保存；写会话在 `w` 或正常关闭且 `--save-on-close` 时保存。

正常关闭顺序：

1. 停止接受新请求，进入 `draining`；
2. 等待当前 executor 请求结束（或超时后取消）；
3. 按策略保存，释放 `Program` consumer；
4. `project.close()` 释放项目锁；
5. 删除注册表/lease 文件；`--ephemeral` 删除临时项目目录。

项目锁由 Ghidra/OS 文件锁实现；进程崩溃后锁应随进程释放，不要手工删除 `.lock`。

---

## 5. RPC 协议

### 5.1 传输

```http
POST /rpc HTTP/1.1
Host: 127.0.0.1:<port>
Authorization: Bearer <token>
Content-Type: application/json

{"id":"...", "op":"disasm", "args":{...}, "allow_writes":false}
```

响应：

```json
{"ok": true, "result": [...], "meta": {"total": 42, "truncated": false}}
```

错误：

```json
{"ok": false, "error": {"code": "BAD_ADDRESS", "message": "...", "data": {...}}}
```

这不是完整的 JSON-RPC 2.0，而是为 op 分发设计的轻量 JSON 信封；字段名保留
后续兼容 JSON-RPC 的余地。`allow_writes` 是请求级写入能力，默认 `false`。

辅助端点：

- `GET /health` → `{"ok":true,"version":"0.1.0","state":"ready","protocol":1}`
- `GET /info` → 实例信息（需 token，只读，不含 token）
- `GET /sessions` → lease/客户端列表（需 token）
- `POST /shutdown` → 带 token 的优雅关闭
- `GET /events` → 预留 SSE（分析进度、program 变更），v1 可不实现

### 5.2 批量

`@@` 迭代必须合并为一次往返：

```json
{"op":"batch","allow_writes":false,"args":{"ops":[{"op":"disasm","args":{...}}, {"op":"disasm","args":{...}}]}}
```

`batch` 在同一个 executor 时间片内顺序执行，返回 `result` 数组；每项仍是独立信封，
单个失败不终止整批。

### 5.3 bytes

JSON 不能直接承载 bytes。统一使用：

```json
{"$gdare2.b64": "<base64>"}
```

客户端递归解码，daemon 递归编码。只解码“单键且值为 str”的精确形状，避免误伤普通 dict。

### 5.4 错误码

| 码 | 含义 | CLI 退出码 |
|---|---|---|
| `BAD_ARGS` | 参数/表达式错误 | 2 |
| `BAD_ADDRESS` | 地址无效或不可读 | 1 |
| `NOT_FOUND` | 函数/符号/类型不存在 | 1 |
| `NOT_FUNC` | 地址不在函数内 | 1 |
| `NO_DECOMPILER` | 反编译器不可用/失败 | 1 |
| `READONLY` | 只读请求拒绝写入 | 1 |
| `GHIDRA_ERROR` | Ghidra API 抛出的其他错误 | 1 |
| `NOT_READY` | daemon 尚未完成加载/分析 | 3 |
| `ANALYZING` | 分析进行中，暂不可服务 | 3 |
| `TIMEOUT` | op 超时 | 4 |
| `LOCKED` | 项目/程序被占用 | 3 |
| `UNKNOWN_OP` | 未注册 op | 1 |
| `NOT_SUPPORTED` | 已识别但 v1 不支持的命令/能力 | 1 |
| `INTERNAL` | 未分类异常 | 1 |

### 5.5 版本校验

- 协议版本 `protocol=1`；
- daemon 与客户端版本不一致时，`/health` 返回 `protocol` 与 `gdare2_version`；
- CLI 发现大版本不兼容时拒绝连接并提示 `gdare2 --kill` 或重启 daemon。

### 5.6 安全

- 默认只绑定 `127.0.0.1`。
- 每次启动生成 256-bit 随机 token，写入 0600 注册表。
- 请求必须带 `Authorization: Bearer`，常量时间比较。
- 默认禁用 `./gexec`（直接执行 Python）；需要 `--allow-exec` 且客户端也显式允许。
- 不提供任意文件读取 op；只允许打开用户指定的目标/项目。
- 远程监听（`--listen 0.0.0.0`）必须显式开启，并建议 TLS/SSH 隧道；v1 不做 TLS。

---

## 6. daemon 内部结构

### 6.1 单线程 Program executor

Ghidra `Program` 不是线程安全的。daemon 使用：

```text
HTTP worker threads → queue.Queue → 单个 executor thread → Ghidra API
```

所有 `Program` 访问都在同一线程。HTTP 线程只做解析、鉴权、编码。

长任务例外：

- 自动分析：在 executor 中启动，但用 `TaskMonitor` 支持取消；
- 反编译：`DecompInterface` 自带独立 decompiler 进程，仍在 executor 中同步等待；
- 全量搜索：可分块，但每个块仍在 executor 中执行。

### 6.2 op 注册表

与 idare2 相同的模式：

```python
@op("disasm", writes=False)
def disasm(ctx: Context, ea: int, count: int = 1, ...):
    ...
```

`invoke()` 负责：

1. 校验 op 是否存在；
2. 校验参数签名；
3. 只读门控；
4. 写 op 自动开 transaction；
5. 异常映射到错误码；
6. 返回值转 JSON。

### 6.3 Context

```python
@dataclass
class Context:
    program: Program
    project: Project
    readonly: bool
    config: dict[str, Any]
    task_monitor: TaskMonitor
    decompiler: DecompInterface
    session_id: str
```

客户端的 seek/blocksize 不进入 Context；作为 op 参数显式传递。

### 6.4 op 分组

| 模块 | 覆盖 |
|---|---|
| `ops/session.py` | open summary、session lease、save、close、status、analysis |
| `ops/info.py` | `i*` 文件/段/符号/导入导出/入口/字符串 |
| `ops/disasm.py` | `pd*`、`pD`、`pdf`、`pdi`、`pdl` |
| `ops/memory.py` | `px*`、`p8*`、`pv*`、`ps*`、`pc`、`pr`、`pf` |
| `ops/analysis.py` | `a*` 函数、基本块、图、调用者/被调用者 |
| `ops/xrefs.py` | `axt`、`axf`、`afx` |
| `ops/names.py` | 符号/标签/函数名、flags 同步 |
| `ops/types.py` | `t*`、`td`、`tu`、`te`、`tf` |
| `ops/comments.py` | `C*` |
| `ops/decompile.py` | `pdc`、`pdd`、`afv` |
| `ops/search.py` | `/x`、`/`、`/r`、`/v`、`/w` |
| `ops/write.py` | `wx`、`wa`、`w0`、`wd`、`wf`、`wc+`、`u`、`U` |
| `ops/assemble.py` | `pa`、`wa`、`wa*` |
| `ops/graph.py` | `agf`、`agfj`、`agfd` |

### 6.5 数据模型约定

daemon 返回的所有对象必须是普通 Python dict/list/str/int/bool/None/bytes：

- Java `Address` → `int`（`getOffset()` 或 `getUnsignedOffset()`）；
- Java `Function` → `{addr, name, size, ...}`；
- Java `Instruction` → `{addr, size, bytes, text, mnemonic, ...}`；
- Java `Reference` → `{from, to, type, ...}`；
- Java 集合/迭代器 → list；
- 二进制 → bytes（由信封编码）。

禁止把 Java 对象直接放入响应；JPype 对象不可 JSON 序列化，也会延长 JVM 生命周期。

---

## 7. 客户端 Session

### 7.1 状态

| 状态 | 说明 |
|---|---|
| `seek` | 当前地址 `$$` |
| `blocksize` | 默认 `0x100` |
| `flags` | 客户端标志表，播种自 Ghidra 符号/函数 |
| `config` | `e` 配置 |
| `vars` / `aliases` | `$` 变量、别名 |
| `seek_history` / `seek_future` | `s+`/`s-` |
| `write_cache` | `io.cache=true` 的补丁 |
| `last_output` | `_` 命令 |
| `json_default` | `-j` |
| `readonly` | `-w` 的反状态 |

### 7.2 配置键

只读（由 daemon 派生）：

- `asm.arch`
- `asm.bits`
- `cfg.bigendian`
- `ghidra.version`
- `ghidra.language`
- `ghidra.compiler`
- `ghidra.program`
- `ghidra.project`

可写（客户端行为）：

- `scr.color`、`scr.null`、`scr.interactive`
- `asm.bytes`、`asm.lines`、`asm.comments`、`asm.flags`、`asm.demangle`
- `hex.cols`、`hex.header`
- `search.in`、`search.from`、`search.to`
- `cmd.hit`、`cmd.batch`
- `io.cache`
- `ghidra.timeout`、`ghidra.assemble.timeout`、`ghidra.decompile.timeout`、`ghidra.analysis.wait`
- `ghidra.flags.write`（flag 是否写回 Ghidra symbol/label）

### 7.3 命令匹配

复用 idare2 的前缀注册表：

- `CommandSpec(pattern, usage, summary, handler, detail)`
- 最长匹配优先；同长度时字面字符更多者优先；
- 未知后缀报 usage error，不静默回退到基命令。

### 7.4 操作符

按 idare2 的剥离顺序：

```text
; → @ → ~ → | → >
```

具体实现以 idare2 `parser.py` 为准，避免重新发明优先级。

`@@`/`@@@` 迭代器在客户端生成 `batch` 请求；`@@f`、`@@i`、`@@b`、`@@S` 等
由客户端先取列表再批处理。

---

## 8. 导入、分析与项目

### 8.1 默认项目布局

```text
${GDARE2_DATA_DIR:-~/gdare2-data}/
  projects/
    <project-key>/
      <project-name>.gpr
      <project-name>.rep/
  cache/
  logs/                  # 可选持久日志；默认 daemon 日志在 runtime 目录
```

项目名使用目标文件名 + 短哈希，避免同名冲突。`project-key` 必须包含目标
规范化路径、文件大小/mtime 与导入参数（语言、编译器、基址、loader 参数），
不能只按文件名生成。

> 实现备注：Ghidra `ProjectLocator` 拒绝包含以 `.` 开头的路径元素，因此默认目录
> 不能放在 `~/.local/share` 下；`GDARE2_DATA_DIR` 可覆盖该位置。

### 8.2 首次导入

```text
gdare2 target
  → 计算 project key
  → 无项目：创建项目
  → results = ProgramLoader.builder().source(target)
       .name(...)
       .project(...)
       .language(...) / .compiler(...)   # 裸二进制或 --force-language
       .addLoaderArg("-baseAddr", "0x...") # 仅显式 -B
       .load()
  → results.save(monitor)              # load() 只创建未保存的 Program
  → results.close()                    # 释放导入结果
  → 自动分析（除非 -n）
  → save 分析结果
  → ready
```

首次导入/分析是 **bootstrap 写入**，即使 CLI 会话是只读也会持久化；这与 IDA 打开
数据库时执行自动分析类似。`--no-save-on-close` 只跳过最终自动保存，不回滚已经
完成的 bootstrap；需要完全丢弃时使用 `--ephemeral`（临时项目，退出删除）。

### 8.3 已有项目

```text
gdare2 --project <dir> --project-name <name> --program /path
gdare2 --attach <instance-id>
```

已有项目默认不重新分析。`-A` / `aa` 才会显式触发分析。

### 8.4 裸二进制参数

| 参数 | 映射 |
|---|---|
| `-a <alias>` | Ghidra Language ID 别名 |
| `--ghidra-language <id>` | 精确覆盖 |
| `-b 16/32/64` | 选择语言位宽 |
| `--endian big/little` | 选择 BE/LE 语言 |
| `-m <addr>` | 裸二进制映射地址，`addLoaderArg("-baseAddr", "0x...")` |
| `-B <addr>` | 仅裸二进制时同 `-m`；PIE 重定位 v1 不支持，明确警告 |
| `--compiler <id>` | `ProgramLoader.Builder.compiler(...)` |
| `--loader <name>` | 先在 `LoaderService` 中按类名/显示名解析，再 `ProgramLoader.Builder.loaders(Class|Predicate)` |
| `--loader-arg K V` | 额外 loader 参数，可重复 |

对于 ELF/PE/Mach-O，默认不强制语言；只有 `--force-language` 时才覆盖，并在
输出中警告“可能破坏格式相关分析”。

对于 ELF/PE/Mach-O，`-B` 不会传给 `BinaryLoader`；PIE 的基址重定位需要
`--force-base`。v1 不实现 `--force-base`，遇到 `-B` 应警告并忽略，而不是假装生效。

Ghidra 对未知 loader 参数只打 warning 并跳过，因此 `--loader-arg` 必须先用
`Loader.getDefaultOptions()` 校验 key；未知 key 报 `BAD_ARGS`，不能静默成功。

### 8.5 分析

| 命令 | 行为 |
|---|---|
| `aa` | 若 `GhidraProgramUtilities.shouldAskToAnalyze(program)` 为真，运行分析；已分析则 no-op |
| `aaa` | 重新运行全量分析（`AutoAnalysisManager.reAnalyzeAll`），需确认/`-A` |
| `af` | 在 seek 创建函数（需 `-w`） |
| `afr` | 重新分析当前函数；无直接 API 时明确报 unsupported |

分析状态：

- `GhidraProgramUtilities.shouldAskToAnalyze(program)` 判断是否未分析；
- `pyghidra.analyze(program)` 内部会 `reAnalyzeAll` 并标记已分析，不要在已分析
  程序上无条件调用，否则 `aa` 会变成昂贵的全量重分析；
- `markProgramAnalyzed(program)` 标记完成；
- 长分析通过 `TaskMonitor` 支持超时/取消；
- CLI `--wait` 等待；`-n` 跳过自动分析。

---

## 9. 反汇编与内存

### 9.1 `pd` 数据源

```text
Listing.getInstructionAt(ea) / getInstructionAfter(ea)
  → Instruction.getAddress()
  → Instruction.getBytes()
  → Instruction.toString()
  → Instruction.getFlowType() / getReferencesFrom()
```

输出目标（r2 形状）：

```text
            0x004013a4      e92bffffff     call 0x4012d4
```

客户端渲染列：行号（可选）、地址、字节、属性、反汇编、注释。

### 9.2 `pdf`

`Function.getBody()` + `Listing.getInstructions(body, true)`；
不依赖 Ghidra 的 pre-rendered listing 文本，以便拿到地址/字节/操作数。

### 9.3 `pD` 与越界

- 按字节推进，直到 `count` 字节或离开可执行/已定义区域；
- 遇到非代码数据时停止并返回 `meta.truncated=true`；
- 不跨 memory block 伪造指令。

### 9.4 内存读取

- `px`：`Memory.getBytes(addr, buf)`；
- `pv`：`Memory.getByte/getShort/getInt/getLong`，注意字节序；
- `ps`：优先 `Data`/`StringDataType`，否则手动读到 NUL；
- 不可读地址返回 `BAD_ADDRESS`，不返回零填充。

---

## 10. 函数、交叉引用、图

### 10.1 `afl`

```text
FunctionManager.getFunctions(true)
  → {addr, name, size, blocks, ...}
```

基本块数可由 `BasicBlockModel` 现算，可能较慢；`afl` 默认不计算块数，
`afl` 的 variant 或 `afi` 才计算。大项目列表需要分页/预算。

### 10.2 `axt` / `axf`

```text
ReferenceManager.getReferencesTo(addr)
  → Reference.getFromAddress() / getReferenceType()
  → 查所在函数与指令文本
```

类型映射：

| Ghidra | r2 |
|---|---|
| `isCall()` | `CALL` |
| `isJump()` | `JUMP` |
| `isData() && isRead()` | `DATA` |
| `isData() && isWrite()` | `DATA` |
| 其他代码引用 | `CODE` |

### 10.3 图

`BasicBlockModel(program).getBasicBlocks(function.getBody(), monitor)`：

- `agf`：ASCII 图；
- `agfj`：r2 形状 JSON；
- `agfd`：Graphviz DOT。

块 ID 使用起始地址；边来自 `CodeBlock.getDestinations(monitor)`。

---

## 11. 反编译与变量

### 11.1 `pdc`

```python
ifc = DecompInterface()
ifc.setSimplificationStyle("decompile")
ifc.openProgram(program)
res = ifc.decompileFunction(func, timeout, monitor)
if not res.decompileCompleted():
    raise DecompileError(res.getErrorMessage())
text = res.getDecompiledFunction().getC()
signature = res.getDecompiledFunction().getSignature()
```

反编译失败映射 `NO_DECOMPILER`；不可用时打印明确提示，退出码仍按命令失败处理。

### 11.2 `afv`

`DecompileResults.getHighFunction()`：

- `getLocalSymbolMap().getSymbols()` / `getSymbols()`
- `HighSymbol.getName()` / `getDataType()` / `getStorage()`
- `isParameter()`
- `VariableStorage` 分类为 register/stack/other

r2 的 `reg`/`sp`/`bp` 分类只能近似：Ghidra 的 storage 模型更抽象，
部分变量会落在 `other`，需在 `DIVERGENCES.md` 说明。

### 11.3 `pdf` 与 `pdc` 的分工

- `pdf`：Ghidra listing 反汇编，不自动反编译；
- `pdc`：反编译 C；
- `pdd`：如无稳定对应，明确报 unsupported（不要伪造）；
- `pdg`：r2ghidra 插件命令，非目标。

---

## 12. 类型、注释、符号

### 12.1 类型

- `t`/`tj`：`DataTypeManager.getAllDataTypes()`；
- `ts`：`Structure`；
- `tu`：`StructureComponent` 列表；
- `te`：`Enum` 成员；
- `td <decl>`：`CParserUtils` 解析 C 声明并加入 program data type manager；
- `tc`：用 `DataTypeWriter` 把类型写成 ANSI-C；`tf` 用
  `Function.getPrototypeString` / `FunctionSignature`。

Ghidra 的类型名、typedef 展开、指针显示与 r2 不同；客户端只负责布局。

### 12.2 注释

r2 `C*` 到 Ghidra `CommentType` 的映射：

| r2 | Ghidra |
|---|---|
| `CC` / `C` 普通注释 | `EOL` |
| `Cd` 数据注释 | `EOL`（数据地址） |
| `Cb` 块前注释 | `PRE` |
| `Cp` 函数/plate 注释 | `PLATE` |
| `Cr` repeatable | `REPEATABLE` |

不支持的子类型明确报错。

### 12.3 符号与 flag

客户端 `FlagStore` 初始播种：

- `SymbolTable.getAllSymbols(true)`；
- `FunctionManager.getFunctions(true)`；
- 外部符号单独标记。

`f name @ addr` 需要 `-w` 且 `e ghidra.flags.write=true`：

- 用 `SymbolTable.createLabel(addr, name, namespace, SourceType.USER_DEFINED)`；
- 重命名函数用 `Function.setName(name, SourceType.USER_DEFINED)`；
- 只读会话可创建会话内 flag，不写回 Ghidra。

---

## 13. 写入、事务、撤销与缓存

### 13.1 只读门控

- 客户端默认 `allow_writes=false`；只有 `-w` 才把它设为 `true`。
- RPC 请求信封携带 `allow_writes`；daemon 对 `writes=True` 的 op 再检查一次。
  `batch` 顶层继承该标志，单个子 op 不能自行提权。
- 多个客户端共享同一个 `Program`，但写能力是**请求级**的；一个客户端传
  `-w` 不会让另一个只读客户端获得写权限。
- `gdare2d --readonly` 可在 daemon 层强制拒绝所有写 op，适合共享/审计环境；
  此时带 `-w` 的客户端也会收到 `READONLY`。
- `--readonly` 要求项目已存在且已分析；缺少项目或需要 bootstrap 分析时直接失败，
  不做隐式导入/分析写入。
- `u/U` 也属于写 op，只读请求不能执行；undo 栈是共享程序的全局状态。
- 错误信息必须包含 `re-run with -w to allow writes`。

写入标志是防误操作的安全阀，不是安全边界；能读取 token 的同用户进程可以伪造它。
需要强制只读时使用 `gdare2d --readonly`。

### 13.2 transaction 策略

```python
with pyghidra.transaction(program, f"gdare2:{op}"):
    handler(...)
```

- 正常完成 → commit；
- 异常 → rollback；
- `readonly` → 不进入 handler，直接 `READONLY`；
- `io.cache=true` → 客户端缓存，`wc+` 时一次 transaction 提交所有补丁。

### 13.3 保存

- `w` → `program.save("gdare2", monitor)`；显式保存优先于 `--no-save-on-close`；
- `io.cache=true` 时 `w`/`wq`/`.gsave` 先提交未决缓存（等价 `wc+`），再保存；提交失败则不保存；
- `wq` → save + quit；
- daemon 正常关闭且 `save_on_close=true` → save；
- 只读会话正常关闭不 save；
- `--no-save-on-close` 只跳过关闭时的自动保存，不回滚已经完成的 bootstrap 导入/分析；
  需要完全丢弃时使用 `--ephemeral`，它使用临时项目目录并在退出时删除。

### 13.4 undo/redo

PyGhidra 当前的 `Program` 没有可用的 undo/redo API，因此采用 daemon 内存级字节补丁历史：

- 每个写 op 在写前读取旧字节，成功后记录 `(addr, before, after)`；
- `u` 逆序恢复最近一条记录的旧字节，`U` 重新应用新字节；
- `wc+` 的多个补丁作为一条历史记录，一次撤销；
- 只读会话 **不允许** `u/U`，因为 undo 也是修改程序状态；
- 只恢复字节，不回滚反汇编/函数/注释等元数据；daemon 重启后历史清空。

### 13.5 写操作最小集

当前已实现：

- `wx`（hexpairs）
- `w <text>`
- `w0`
- `wf <file>`
- `wd`
- `wc` / `wc+` / `wc-`（缓存）
- `u` / `U`（daemon 内存级字节历史）

待实现：

- `wa` / `wa*` / `wa+` / `waf` / `waF`（需要语言支持 SLEIGH assembler）
- `wi[1248]`、`w6`

其余写命令明确报 unsupported，避免误写。详见 ROADMAP Phase B5。

---

## 14. 汇编

```python
asm = Assemblers.getAssembler(program)
bytes = asm.assemble(addr, *lines)
```

- `pa`：只生成 hexpairs；
- `wa`：生成并 `Memory.setBytes`；
- `wa*`：只打印等价 `wx`，不写入；
- 若 `Assemblers.getAssembler` 抛 `UnsupportedOperationException`，
  返回 `NOT_SUPPORTED` 并建议 `--assembler=rasm2`（显式回退，不静默）。

汇编语法遵循 Ghidra/SLEIGH，不保证与 r2 的汇编语法一致。

---

## 15. 搜索

### 15.1 内存搜索

- `/x <hex>`：`Memory.findBytes(start, end, bytes, mask=null, forward=true, monitor)`；
- `/ <text>`：ASCII/UTF-8 编码后搜索；
- `/w <text>`：UTF-16LE/BE 编码后搜索；
- `/v <num>`：小端/大端立即数搜索；
- `/r <regex>`：遍历已定义字符串（`StringDataType`）并做正则；
- `/p <size>`：定长重复模式；
- `search.in=io.maps|raw|bin.sections` 控制范围。

实现状态：`/`、`/x`、`/w`、`/v[1248]`、`/r`、`/p`、`/a`、`cmd.hit` 与 `j`
变体已实现。`search.in` 支持 `io.maps` / `bin.sections`（按 Ghidra 内存块处理）
与 `raw`（原始文件）。

### 15.2 分页

返回 `{hits: [...], meta: {shown, total, truncated}}`；CLI 用
`--list-offset N` 或 `e list.offset=N` 继续。

### 15.3 `cmd.hit`

客户端把命中地址交给 `@@` 迭代器执行 `cmd.hit`，daemon 不执行命令。

---

## 16. CLI 设计

### 16.1 用法

```text
gdare2 [target] [options] [-c cmd]...
```

### 16.2 参数

A 档（实现，保留 r2 语义）：

> 实现状态（2026-11-08）：`-A/-AA` 已在命令前触发 `aa/aaa`；`--wait`
> 是默认行为（launcher 总是等待 ready）；`--listen` 会转发给 daemon；
> `--assembler=rasm2` 与 `--allow-exec` 在对应命令（`pa/wa`、`.gexec`）
> 实现前会明确报 `BAD_ARGS`，不再静默忽略。

| 参数 | 说明 |
|---|---|
| `-a <arch>` | 裸二进制架构别名 |
| `-b <bits>` | 16/32/64 |
| `-B <addr>` / `-m <addr>` | 加载基址 |
| `-A` / `-AA` | 等待/触发分析 |
| `-c <cmd>` | 执行命令，可重复 |
| `-e <k=v>` | 设置配置，可重复 |
| `-i <file>` / `-I <file>` | 命令后/命令前脚本 |
| `-j` | JSON 默认输出 |
| `-L` | 列出 gdare2 daemon 实例 |
| `-n` | 不自动分析 |
| `-N` | 不加载用户 rc；`-NN` 同时不加载系统 rc |
| `-q` / `-qq` | 安静/退出 |
| `-s <addr>` | 初始 seek |
| `-v` / `-V` | 版本 |
| `-w` | 允许写入 |
| `--endian big\|little` | 裸二进制端序 |
| `--` | 结束选项解析（标准语义） |

B 档（接受但警告）：

`-0`、`-1`、`-2`、`-E`、`-f`、`-k`、`-M`、`-nn`、`-Q`、`-S`、`-t`、`-T`、`-u`。

C 档（明确报错）：

`-d`/`-D`（调试器）、`-r`/`-R`（rarun2）、`-P`（rapatch）、`-x`/`-X`。

gdare2 专有长选项：

| 参数 | 说明 |
|---|---|
| `--attach <id>` / `--attach auto` | 附着指定实例；`auto` 选择唯一健康实例 |
| `--status <id>` | 查看指定实例状态 |
| `--kill <id>` | 优雅关闭指定实例 |
| `--no-spawn` | 不自动拉起 daemon |
| `--project <dir>` | Ghidra 项目父目录 |
| `--project-name <name>` | 项目名 |
| `--program <path>` | 项目内程序路径 |
| `--ghidra-language <id>` | 精确语言 ID |
| `--compiler <id>` | 编译器规格 |
| `--loader <name>` / `--loader-arg K V` | loader 覆盖 |
| `--force-language` | 强制覆盖格式识别 |
| `--force-base` | 强制格式文件重定位基址（v1 不实现，报 `NOT_SUPPORTED`） |
| `--linger <sec>` / `--idle <sec>` | daemon 生命周期 |
| `--timeout <sec>` / `--startup-timeout <sec>` | 超时 |
| `--wait` | 等待导入/分析完成再执行命令 |
| `--assembler ghidra` / `--assembler rasm2` | 汇编后端；默认 Ghidra，显式回退 rasm2 |
| `--ephemeral` | 临时项目 + 一次性 daemon，退出即删除 |
| `--no-save-on-close` | 关闭不保存 |
| `--reimport` | 目标或导入参数变化后强制重新导入 |
| `--allow-exec` | 允许 `.gexec` |
| `--listen <addr>` | 远程监听（默认关闭） |
| `--color <0-3>` | 颜色 |

daemon 专有选项：

| 参数 | 说明 |
|---|---|
| `--foreground` | 前台运行，便于调试 |
| `--target <path>` | 要打开/导入的目标 |
| `--readonly` | 强制整个 daemon 只读，拒绝所有写 op |
| `--analysis-timeout <sec>` | 自动分析超时 |
| `--log-level <level>` | 日志级别 |

### 16.3 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 命令失败，含明确报 `unsupported` 的命令（与 r2 的未知命令行为一致） |
| 2 | 参数错误 |
| 3 | 无法连接/打开/未就绪 |
| 4 | 传输/超时 |
| 130 | Ctrl-C |

### 16.4 提示符

```text
[0x00401000]> 
```

daemon 状态前缀：

- `[0x00401000|busy]>`：分析中；
- `[0x00401000|ro]>`：只读可省略，默认就是只读。

### 16.5 扩展命令

| 命令 | 说明 |
|---|---|
| `.ghidra` / `.g` | daemon/program/语言/状态信息 |
| `.gsave` | 等价 `w` |
| `.gclose [--no-save]` | 关闭 daemon |
| `.gsync` | 重新拉取符号/段/元信息 |
| `.ganalyze [all]` | 触发分析并显示状态 |
| `.gstatus` | 当前任务/分析状态 |
| `.gexec <python>` | 逃生舱，需 `--allow-exec` |
| `.ghelp` | 扩展命令帮助 |

---

## 17. 性能设计

### 17.1 缓存

daemon 内可缓存：

- 函数列表（program modification stamp 变化时失效）；
- 符号表快照；
- 内存块列表；
- 反编译结果（按 function + decompiler options 缓存，可选）。

`Program.getModificationNumber()` 或 `DomainObject` 的 change 计数可作为失效键。

### 17.2 分页与预算

- `afl` 默认最多返回 10000 项，超出 `meta.truncated=true`；
- `pd` 单次最多 4096 条指令；
- `px` 单次最多 1 MiB；
- 搜索最多返回 10000 命中；
- 通过 `--list-offset N`/`e list.offset=N` 继续。

### 17.3 批量

`@@` 和 `@@@` 默认走 `batch`；`e cmd.batch=false` 时退化为逐目标 RPC，
用于排障或避免一次请求过大。禁止在默认路径上做 N 次串行 HTTP 往返。

### 17.4 反编译缓存

`DecompInterface` 每个 daemon 持有一个，`openProgram()` 一次。
不同函数串行反编译；可配置超时（默认 30s）。

---

## 18. 测试策略

### T1 纯客户端

无 Ghidra、无 JVM：

- `test_argv.py`
- `test_parser.py`
- `test_expr.py`
- `test_filter.py`
- `test_pipe.py`
- `test_fmt_*.py`
- `test_config.py`

### T2 协议/分发

fake backend + fake Ghidra 对象：

- 信封编码/解码；
- op 注册表重复检测；
- 参数签名校验；
- 错误码映射；
- batch 行为；
- token/鉴权；
- stale 注册表处理。

### T3 真实 Ghidra

`-m real_ghidra`：

- 导入 ELF/PE/裸二进制；
- `pd`、`pdf`、`px`、`afl`、`axt`、`iI`、`iz`；
- 反编译 `pdc`；
- 类型 `td/ts/tu`；
- 写 `wx` + `w` + 重开验证；
- `u/U`；
- daemon 重启后项目持久化。

目标：

- `../vulfirm` 的 ARM32 固件；
- 本机编译的小 x86-64 ELF；
- 裸二进制架构矩阵。

### T4 r2 parity

`-m parity`，需要 r2：

- 对同一目标抓 `r2 -e scr.color=0 -q -A -c ...`；
- 规范化函数名（`FUN_...` vs `sym...` vs `sub_...`）；
- 规范化助记符/空格/地址宽度；
- 比较 hexdump 应尽量精确；
- 反汇编/反编译只比较结构（地址、字节数、行数、列数）。

黄金文件必须记录：

- r2 版本；
- Ghidra 版本；
- language ID；
- 目标 sha256。

### T5 架构矩阵

参考 idare2 的 22 配置矩阵，用裸二进制 + `-a/-b/--endian/-B`：

- x86 16/32/64；
- ARM 32 LE/BE；
- AArch64 LE/BE；
- MIPS 32/64 LE/BE；
- PowerPC 32/64 BE/LE；
- RISC-V 32/64；
- m68k；
- SPARC 32/64；
- SuperH4。

每个配置断言：导入成功、语言 ID 正确、`pd 1` 非空、`iI` 字段正确。

---

## 19. 目录结构

```text
gdare2/
├── pyproject.toml
├── README.md
├── docs/
│   ├── README.md
│   ├── RESEARCH.md
│   ├── DESIGN.md
│   ├── COMMANDS.md
│   ├── DIVERGENCES.md
│   ├── PLAN.md
│   └── DEV.md
├── src/gdare2/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                 # 入口、参数、批处理/交互式
│   ├── argv.py                # r2 风格参数（移植）
│   ├── parser.py              # 命令语法（移植）
│   ├── expr.py                # 表达式（移植）
│   ├── filter.py              # ~ 过滤（移植）
│   ├── pipe.py                # | > !（移植）
│   ├── config.py
│   ├── errors.py
│   ├── session.py
│   ├── flags.py
│   ├── protocol.py            # 信封、bytes 编解码
│   ├── client.py              # HTTP 客户端、重试、token
│   ├── registry.py            # daemon 注册表、锁、stale 检测
│   ├── launcher.py            # 自动拉起 daemon
│   ├── cmd/                   # 命令实现（a/p/i/s/f/t/C/w/...）
│   ├── fmt/                   # r2 渲染
│   └── compat/                # 从 idare2 移植的纯模块与来源说明
├── src/gdare2d/
│   ├── __main__.py            # daemon 入口
│   ├── server.py              # HTTP server、鉴权、请求队列
│   ├── runtime.py             # PyGhidra 启动、项目/程序打开
│   ├── executor.py            # 单线程 Program executor
│   ├── dispatch.py            # op 注册表、transaction、错误映射
│   ├── context.py
│   ├── import_plan.py         # 语言/loader/基址
│   └── ops/                   # Ghidra API 实现
├── tests/
│   ├── test_*.py
│   ├── integration/           # -m real_ghidra
│   ├── parity/                # -m parity
│   ├── arch_matrix/           # -m arch_matrix
│   └── fixtures/
└── tools/
    ├── capture_r2_golden.py
    └── arch_matrix.py
```

---

## 20. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| Ghidra 项目锁与 GUI 冲突 | 无法同时使用 | 明确不支持 GUI 附着；文档提示先关闭 daemon 再用 GUI |
| Python 3.14 无 JPype 轮子 | 无法安装 | 固定 3.12/3.13；启动时检查 |
| 自动分析太慢/卡死 | 首次体验差 | `-n`、`--analysis-timeout`、`TaskMonitor` 取消、状态轮询 |
| Ghidra 反汇编文本与 r2 差异 | parity 失败 | 只比较结构；规范化；记录版本 |
| 函数/符号命名差异 | 输出不可比 | 规范化 `FUN_`/`LAB_`/`sub_`；保留原名字段 |
| 反编译变量存储分类不完整 | `afv` 不精确 | 明确标记 `other`；文档说明 |
| 写入污染项目 | 数据损坏 | 默认只读；transaction rollback；备份/临时项目选项 |
| daemon stale/端口冲突 | 连接失败 | 注册表健康检查、文件锁、重试、`--kill` |
| 大项目列表/搜索 OOM | 客户端卡死 | 分页、上限、流式/批量、超时 |
| 类型解析复杂 | `td/tu` 不完整 | 只用 CParser/DataTypeParser；不支持明确报错 |
| 汇编语法差异 | `pa/wa` 失败 | 明确错误；可选 rasm2 回退（显式） |

---

## 21. 里程碑

| 里程碑 | 内容 | 验收 |
|---|---|---|
| M0 骨架 | 客户端/daemon 包结构、注册表、HTTP RPC、fake backend、`s/pd/px/q/?` | `gdare2 -qc 'pd 5; px 16' target` 返回 r2 形状输出 |
| M1 只读核心 | 导入、daemon 常驻、`iI`、`iS`、`afl`、`axf/axt`、`pdf`、`px` | 同一目标第二次命令秒级响应；daemon 重启复用项目 |
| M2 分析/信息 | `i*`、`a*`、`afb/afc/afC`、`agf`、`@@` batch | 函数、基本块、交叉引用、图可用 |
| M3 反编译/类型 | `pdc`、`afv`、`t*`、`C*` | 反编译 C 输出；类型列表/结构/函数签名可用 |
| M4 写入 | `wx/wf/wd/w0`、`u/U`、`io.cache`、`w` | `-w` 写入后重开项目可见；只读拒绝；undo 可用 |
| M5 兼容与体验 | `~`/`|`/`>` 完整、`j`、REPL、补全、rc、parity、架构矩阵 | r2 结构 parity 通过；22 配置矩阵通过 |

---

## 22. 待决问题

1. **客户端复用方式**：直接复制 idare2 纯模块，还是先抽 `r2compat` 包？
   建议 v1 复制并标注，M5 后再抽。
2. **daemon 是否支持同时打开多个 Program？** v1 一个 daemon 一个 Program；
   多程序用多个实例或 `--program` 切换（切换需要重新打开项目，成本高）。
3. **只读会话是否允许 `u/U`？** 建议不允许，因为 undo 修改程序状态。
4. **`aa` 是否允许自动触发分析？** 建议只在未分析时触发；已分析时 no-op。
5. **是否支持远程 daemon？** 协议已支持，v1 只绑定 loopback；远程需要 TLS/SSH 方案。
6. **反编译缓存是否跨请求保留？** 建议先不缓存，M5 再评估内存占用。

---

## 23. 参考

- idare2 设计：`../idare2/docs/DESIGN.md`
- idare2 命令映射：`../idare2/docs/COMMANDS.md`
- Ghidra 源码：`~/ghidra/current/Ghidra/**/lib/*-src.zip`
- PyGhidra：`~/ghidra/current/Ghidra/Features/PyGhidra`
- Ghidra headless：`~/ghidra/current/support/analyzeHeadlessREADME.md`
- Ghidra 语言定义：`~/ghidra/current/Ghidra/Processors/*/data/languages/*.ldefs`
- radare2 源码：`../radare2`
