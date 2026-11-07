# gdare2 背景调研

> 目标：判断“用 Ghidra 做 radare2 兼容 CLI”是否可行、Ghidra 侧有哪些硬约束、
> 哪种进程模型最合适，以及哪些能力必须接受语义差异。

## 1. 调研结论摘要

1. **可行，但不能照搬 idare2 的“无状态远程调用 + GUI 附着”模型。**
   idare2 依赖 `ida-nexus` 提供已认证的 loopback RPC，并能附着到正在运行的 IDA GUI。
   Ghidra 没有等价的通用 Python RPC；PyGhidra 是进程内 JPype 绑定，不是服务。
2. **Ghidra 项目是独占打开的。** `ProjectManager` 的契约明确写着 “A project can be
   opened by one user at a time”；可写打开会创建项目锁。PyGhidra 的
   `open_project()` 走可写路径。因此 GUI 和另一个 PyGhidra 进程不能同时打开同一个项目。
3. **Ghidra 启动和首次分析成本高，必须常驻。** 每次命令重新启动 JVM、打开项目、
   跑自动分析会带来数秒到数分钟延迟；交互式体验不可接受。
4. **最合适的 v1 形态是独立 daemon：** 一个 PyGhidra 进程持有项目与 `Program`，
   CLI 只做协议客户端。多个 CLI 调用共享同一份已加载分析结果。
5. **Ghidra 的 API 足以覆盖 r2 的核心命令面。** 反汇编、函数、基本块、交叉引用、
   内存、符号、类型、注释、搜索、反编译、汇编、事务/撤销都有对应 API。
6. **反编译与反汇编文本不可能与 r2/IDA 完全一致。** 输出“形状”可以高度兼容，
   但助记符风格、自动命名、类型恢复结果必然不同；只能在渲染层做规范化。
7. **GUI 附着应作为第二阶段。** 可行路径是 Ghidra 插件或 PyGhidra 控制台内启动
   一个桥接 RPC；但它需要处理 GUI 线程模型和项目所有权，不能阻塞 headless v1。

## 2. 参考实现：idare2

### 2.1 分层

`idare2` 的可复用价值不在 IDA 细节，而在分层：

```text
argv → parser → Session/命令分发 → 远程 op → 结构化结果 → fmt 渲染 → ~ / | / > 后处理
```

其中：

- **客户端状态**：seek、blocksize、flags、`e` 配置、`$` 变量、搜索历史、写缓存。
- **命令层**：声明式 `CommandSpec` 注册表，前缀匹配；帮助由同一份声明生成。
- **远程层**：单一 `execute(db, op, args)` 入口；`@op` 装饰器注册 handler；
  `writes=True` 的 op 自动创建 undo point。
- **信封**：`{"ok": true, "result": ...}` / `{"ok": false, "error": {...}}`；
  bytes 以 `{"$idare2.b64": "..."}` 穿过 JSON。
- **渲染在客户端**：这是 `~`、`|`、`>`、`j` 能统一作用于所有命令的关键。

这些设计可以直接迁移到 gdare2；需要替换的是 `nexus.py`、`rpc.py` 和
`remote/ops/*`，以及所有 `ida_*` / `ida_domain` 调用。

### 2.2 可直接复用的纯客户端模块

| idare2 模块 | 可复用性 | 说明 |
|---|---|---|
| `argv.py` | 高 | r2 风格参数解析，支持 `-qc` 这类合并短参数 |
| `parser.py` | 高 | `[.][times][cmd][~grep][@seek][|pipe][>file]` 语法 |
| `expr.py` | 高 | r2 表达式求值，裸数字按十进制 |
| `filter.py` | 高 | `~` 的完整语义 |
| `pipe.py` | 高 | shell 管道、重定向、反引号 |
| `config.py` | 中 | 配置表框架可复用，键值需要按 Ghidra 重写 |
| `flags.py` | 中 | 标志存储可复用，后端同步策略需重写 |
| `fmt/*` | 高 | 布局和颜色逻辑可复用，字段来源改为 Ghidra op |
| `cmd/*` | 中 | 命令模式/参数解析可复用，handler 调用的 op 名需替换 |
| `session.py` | 中 | 状态机可复用，把 `remote` 抽象成 backend 协议 |
| `nexus.py` / `rpc.py` | 低 | 与 Nexus 强绑定，需重写 |
| `remote/ops/*` | 低 | IDA API 绑定，需按 Ghidra API 重写 |

建议 v1 先以 **移植 + 标注来源** 的方式复用纯客户端模块，后续再抽成独立
`r2compat` 包，供 idare2/gdare2 共用。

### 2.3 idare2 的进程模型

- 批处理：打开/附着一次，执行 `-c`，退出；worker 依靠 keepalive 存活。
- 交互式：持有同一 lease，`persist_globals=True`。
- 附着 GUI：`DatabaseHandle.attach(instance)`，不抢占 GUI 光标。

`gdare2` 不能直接复用“每次 CLI 重新打开”的部分，因为 Ghidra 的打开/分析
成本远高于 IDA 的 worker 复用，而且项目锁是独占的。daemon 是必要抽象。

## 3. Ghidra 环境事实

> 以下版本/API 事实来自本机源码与安装目录核对；启动 JVM、导入、分析、反编译的
> P0 运行时验证尚未执行（本机暂无 Python 3.13 环境）。

本机基线：

| 组件 | 位置/版本 |
|---|---|
| Ghidra | `~/ghidra/current` → `ghidra_12.2_PUBLIC` |
| 构建日期 | 2026-10-16 |
| Java | OpenJDK 25.0.5 |
| PyGhidra | 3.2.0（随 Ghidra 分发） |
| JPype 预编译轮子 | cp39–cp313，manylinux x86_64/aarch64 等 |
| radare2 | `~/.local/bin/r2` 6.2.5（本机已有） |
| Python | 系统 3.14.6（不建议直接用于 v1） |

### 3.1 PyGhidra

PyGhidra 通过 JPype 在原生 CPython 中启动 JVM 并加载 Ghidra。关键 API：

- `pyghidra.start(install_dir=...)`：启动 JVM，初始化 headless Ghidra。
- `pyghidra.open_project(path, name, create=False)`：打开/创建 Ghidra 项目。
- `pyghidra.program_context(project, path)`：取得 `Program`，退出时释放。
- `pyghidra.program_loader()`：返回 `ProgramLoader.Builder`，用于导入。
- `pyghidra.analyze(program)`：在一个 transaction 中跑自动分析。
- `pyghidra.transaction(program, description)`：写入事务上下文管理器。
- `pyghidra.task_monitor(timeout)`：超时/取消监视器。
- `pyghidra.ghidra_script(...)`：运行 Java/PyGhidra/Jython 脚本。

注意：PyGhidra 3.2.0 的 `open_project()` 调用
`PyGhidraProjectManager.openProject(locator, False, True)`，即可写打开并重置 owner。
这会产生项目锁，不能和已打开同一项目的 Ghidra GUI 共存。

### 3.2 Python 版本风险

Ghidra 12.2 的 `application.properties` 声明支持 Python 3.9–3.15，但随包分发的
JPype 轮子只到 cp313。系统 Python 3.14.6 下直接 `pip install pyghidra` 可能触发
JPype 源码构建或二进制不兼容。

**结论：v1 固定 Python 3.12 或 3.13 的虚拟环境；3.14+ 作为后续验证项。**

### 3.3 项目锁与 GUI 冲突

从 Ghidra 源码可确认：

- `ghidra.framework.model.ProjectManager` 注释：项目同一时间只能被一个用户打开。
- `DefaultProject` 打开已有项目时构造 `DefaultProjectData(locator, true, resetOwner)`，
  第二参数表示可写项目；可写项目会建立 `ProjectLock`。
- `DefaultProjectData` 文档：`LockException` 在无法建立写锁（项目正在使用）时抛出。
- 只读 “View” 是 Ghidra GUI 的概念，不是 PyGhidra `open_project()` 的默认路径。

**架构含义：**

1. daemon 一旦持有项目，其他 PyGhidra 进程不能打开同一项目。
2. 多个 gdare2 CLI 必须连到同一个 daemon，而不是各自打开项目。
3. GUI 附着不能靠“再开一个 PyGhidra 进程”实现；必须在 GUI 进程内放一个桥。
4. 不要尝试删除 `.lock` 文件来强行共享项目，这会破坏 Ghidra 的并发假设。

### 3.4 事务、撤销与保存

Ghidra 的 `DomainObject` 要求所有修改在 transaction 内完成：

- `program.startTransaction(description)` / `endTransaction(id, commit)`；
- `program.withTransaction(description, callback)` 方便地提交或回滚；
- `program.canUndo()` / `undo()` / `canRedo()` / `redo()`；
- `program.save(comment, monitor)` 或 `DomainFile.save(monitor)` 落盘；
- `program.getDomainFile()` 可取得项目文件信息。

**映射到 r2：**

- 每个 `writes=True` op 开一个 transaction；
- 只读会话或失败时 `commit=False`；
- `u` / `U` 映射到 `undo()` / `redo()`；
- `w` 映射到 `program.save(...)`；
- `e io.cache=true` 时客户端缓存补丁，`wc+` 一次提交为一个 transaction。

## 4. Ghidra API 能力核对

以下均以 Ghidra 12.2 源码/接口为准。

### 4.1 程序与元信息

`Program` 提供：

- `getExecutablePath()` / `getExecutableFormat()`
- `getExecutableMD5()` / `getExecutableSHA256()`
- `getLanguage()` / `getLanguageID()` / `getCompilerSpec()`
- `getImageBase()`
- `getMemory()` / `getListing()` / `getFunctionManager()` / `getSymbolTable()`
- `getReferenceManager()` / `getDataTypeManager()`

足以实现 `iI`/`ij`、`it`、`ia` 的大部分字段。

### 4.2 反汇编

- `Listing.getInstructionAt(Address)`、`getInstructionContaining(Address)`
- `Listing.getInstructions(Address, forward)`
- `Instruction.getAddress()` / `getBytes()` / `getLength()`
- `Instruction.toString()`、`getMnemonicString()`、操作数表示
- `Instruction.getFlowType()`、`getReferencesFrom()`
- `Instruction.getComment(CommentType)` 读取注释

`pd`/`pdf`/`pD`/`pi`/`pdl` 等都可以由这些 API 组合。

### 4.3 函数与基本块

- `FunctionManager.getFunctionAt(entry)`、`getFunctionContaining(addr)`
- `FunctionManager.getFunctions(forward)`、`getFunctionCount()`
- `Function.getEntryPoint()` / `getName()` / `getBody()`
- `Function.getPrototypeString(...)` / `getParameters()` / `getLocalVariables()`
- `Function.getCalledFunctions(monitor)`、`getCallers()`
- `BasicBlockModel(program).getBasicBlocks(function.getBody(), monitor)`
- `CodeBlock.getFirstStartAddress()` / `getDestinations(monitor)` / `getSources(monitor)`

足以实现 `afl`、`afb`、`afc`、`afC`、`afi`、`agf`、`pdr`。

### 4.4 交叉引用

- `ReferenceManager.getReferencesTo(Address)` / `getReferencesFrom(Address)`
- `Reference.getFromAddress()` / `getToAddress()` / `getReferenceType()`
- `RefType.isCall()` / `isJump()` / `isData()` / `isRead()` / `isWrite()`

足以实现 `axt`、`axf`、`afxj`，并把类型映射为 r2 的 `CALL/JUMP/CODE/DATA`。

### 4.5 内存

- `Memory.getBlocks()`、`MemoryBlock.getStart()/getEnd()/getName()`
- `MemoryBlock.isRead()/isWrite()/isExecute()/getType()`
- `Memory.getByte(Address)`、`getInt()`、`getLong()`
- `Memory.getBytes(Address, byte[])`
- `Memory.findBytes(...)`、跨 block 迭代

足以实现 `px*`、`p8*`、`pv*`、`ps*`、`pr`、`pc`、`pf` 的读路径。

### 4.6 符号、导入导出、入口点

- `SymbolTable.getAllSymbols(includeDynamicSymbols)`
- `SymbolTable.getExternalSymbols()`、`Symbol.isExternal()`
- `SymbolTable.getExternalEntryPointIterator()`
- `Symbol.getName()` / `getAddress()` / `getSymbolType()` / `getParentNamespace()`

导入/导出需要区分 `SymbolType` 与 external namespace；不同格式（ELF/PE/Mach-O）
的细节可能不如 r2 的原始格式解析完整。

### 4.7 类型

- `Program.getDataTypeManager()`
- `DataTypeManager.getAllDataTypes()` / `getDataType(name)`
- `Structure` / `Union` / `Enum` / `TypeDef` / `Pointer` / `Array`
- `DataTypeParser` 解析简单类型表达式
- `CParserUtils.parseHeaderFiles(...)` / `parseSignature(...)` 解析 C 声明
- `DataTypeWriter` 把类型导出为 ANSI-C（`tc` 使用；`DataType` 本身没有
  `getCDeclaration()`）

足以实现 `t`、`tj`、`ts`、`tu`、`te`、`td`、`tf` 的大部分。
复杂 C++ 模板、位域、匿名结构体可能与 r2 的 `t` 语义有差异。

### 4.8 注释

- `Listing.getComment(CommentType, Address)` / `setComment(...)`
- `CommentType.EOL` / `PRE` / `POST` / `PLATE` / `REPEATABLE`
- `Function.setComment(String)`

可映射 `C*`，但 r2 的注释类型比 Ghidra 多，需要做映射表。

### 4.9 搜索

- `Memory.findBytes(start, end, bytes, mask, forward, monitor)`
- `Listing.getInstructions(...)` + 文本匹配
- `DataIterator` + `Data.getValue()` 搜索字符串

可覆盖 `/x`、`/`、`/r`（字符串正则）等；原始文件范围搜索可读输入文件。

### 4.10 反编译

- `DecompInterface.setSimplificationStyle("decompile")`
- `DecompInterface.openProgram(program)`
- `DecompInterface.decompileFunction(function, timeout, monitor)`
- `DecompileResults.decompileCompleted()` / `getErrorMessage()`
- `DecompileResults.getDecompiledFunction().getC()` / `getSignature()`
- `DecompileResults.getHighFunction()` 用于变量、参数、类型、语法树

Ghidra 反编译器是与 Ghidra 一起分发的独立进程，PyGhidra 会自动管理。
`pdc`/`pdf` 的 C 输出可用；`afv` 需要额外从 `HighFunction` 提取变量存储。

`pyghidra.analyze(program)` 会无条件执行 `reAnalyzeAll`，并在同一 transaction
中调用 `markProgramAnalyzed(program)`。实现 `aa` 时应先用
`GhidraProgramUtilities.shouldAskToAnalyze(program)` 判断，避免重复全量分析。

### 4.11 汇编

- `ghidra.app.plugin.assembler.Assemblers.getAssembler(program)`
- `Assembler.assemble(Address, String...)`
- 仅对 SLEIGH 语言可用；大多数常见架构有实现，但不是所有处理器都支持。

可用于 `pa`/`wa`/`wa*`。若语言没有 assembler，明确报错，或提供
`--assembler=rasm2|keystone` 的显式回退，不静默假装成功。

### 4.12 写入

可写 API：

- `Memory.setBytes(Address, byte[])`
- `Listing.clearCodeUnits(...)` / `createInstruction(...)`
- `FunctionManager.createFunction(...)` / `removeFunction(...)`
- `SymbolTable.createLabel(...)` / `removeSymbolSpecial(...)`
- `ReferenceManager.addReference(...)` / `deleteReference(...)`
- `Listing.setComment(...)`
- `DataTypeManager.addDataType(...)` / `replaceDataType(...)`

全部必须在 transaction 内。写路径需要单独的错误分类和 undo 策略。

## 5. 导入与语言选择

`ProgramLoader.Builder` 支持：

- `source(File|String|ByteProvider|byte[])`
- `project(Project)`
- `projectFolderPath(path)`
- `name(name)`
- `language(LanguageID|String)` / `language(Language)`
- `compiler(CompilerSpecID|String)`
- `loaderArgs(List<Pair<String,String>>)` / `addLoaderArg(name, value)`
- `loaders(Predicate<Loader>)` / `loaders(Class<? extends Loader>)`
- `load()` / `loadAll()`

重要语义：`load()` 返回 `LoadResults<Program>`，其中的 `Program` **尚未保存**；
导入后必须调用 `results.save(monitor)`，并在结束时 `results.close()` 释放资源。
否则项目目录中可能没有可重开的 program。

另外，未知的 loader 参数在 Ghidra 内部只打印 warning 然后跳过，不会抛错。
`gdare2` 必须在启动前校验 `--loader-arg` 和 `--loader`，避免“参数拼错但静默成功”。

`Builder.loaders()` 没有“按名字选择”的重载；`--loader <name>` 需要先通过
`LoaderService` 把显示名/类名解析成 `Class` 或 `Predicate`，解析失败报 `BAD_ARGS`。

裸二进制使用 `BinaryLoader`，其 loader option 包括：

- `Base Address`，命令行参数 `-baseAddr`
- `File Offset`
- `Length`
- `Block Name`
- `Overlay`

因此 `-B` 应映射为 `addLoaderArg("-baseAddr", "0x...")`，而不是自己改内存块。

### 5.1 常用语言 ID

| 别名 | 默认 Ghidra Language ID |
|---|---|
| x86 16 | `x86:LE:16:Real Mode`（保护模式用 `Protected Mode`） |
| x86 32 | `x86:LE:32:default` |
| x86 64 | `x86:LE:64:default` |
| arm / armle 32 | `ARM:LE:32:v7`（可按需指定 v8/Cortex） |
| armbe 32 | `ARM:BE:32:v7` |
| aarch64 / arm64 | `AARCH64:LE:64:v8A` |
| aarch64be | `AARCH64:BE:64:v8A` |
| mipsle 32 | `MIPS:LE:32:default` |
| mipsbe 32 | `MIPS:BE:32:default` |
| mipsle 64 | `MIPS:LE:64:default` |
| mipsbe 64 | `MIPS:BE:64:default` |
| ppc 32 | `PowerPC:BE:32:default` |
| ppc64 | `PowerPC:BE:64:default` |
| ppcle 32 | `PowerPC:LE:32:default` |
| ppc64le | `PowerPC:LE:64:default` |
| riscv 32 | `RISCV:LE:32:default` |
| riscv 64 | `RISCV:LE:64:default` |
| m68k | `68000:BE:32:default` |
| sparc 32 | `sparc:BE:32:default` |
| sparc 64 | `sparc:BE:64:default` |
| sh4 | `SuperH4:LE:32:default` / `SuperH4:BE:32:default` |

设计上允许 `-a` 使用 r2 风格别名，同时提供 `--ghidra-language` 精确覆盖。
运行时还应查询 `DefaultLanguageService`，对别名做模糊解析并给出候选列表。

## 6. 方案比较

### 方案 A：每个 CLI 进程内嵌 PyGhidra

```text
gdare2 CLI (Python + JPype/JVM + Ghidra) → 打开项目 → 执行 → 退出
```

优点：实现最短，无 RPC。

缺点：

- 每次命令支付 JVM 启动、项目打开、分析检查成本；
- 项目锁导致两个 CLI 不能并行，也不能和 GUI 共存；
- 交互式 REPL 只能单进程持有；脚本多次调用性能差；
- CLI 强依赖 JPype/Ghidra 安装，远程/容器场景不友好。

定位：只适合 `--embedded` 调试或极小规模的批处理，不作为默认。

### 方案 B：analyzeHeadless 一次性脚本

```text
gdare2 → subprocess(analyzeHeadless -postScript ...) → 解析 JSON → 退出
```

优点：不依赖 PyGhidra/JPype；成熟、稳定；适合 CI。

缺点：

- 每次冷启动；
- 项目仍然独占；
- 脚本参数/结果传输笨重；
- 不适合交互式；
- 需要为每个 op 写 Java/Python GhidraScript 或传参协议。

定位：CI/无 Python JVM 环境的后备；不是主架构。

### 方案 C：常驻 PyGhidra daemon + 瘦客户端（推荐）

```text
gdare2 CLI  ──HTTP/JSON──▶  gdare2d (PyGhidra + Ghidra)  ──▶ Project/Program
```

优点：

- 只启动一次 JVM/分析；
- 多个 CLI 调用共享同一 `Program`；
- 客户端无 JVM 依赖，可远程；
- 与 idare2 的“结构化 op”模型一致；
- 可做批处理、交互式、事件、长任务；
- 后续 GUI 桥可复用同一协议。

缺点：

- 需要 daemon 生命周期、注册表、锁与安全设计；
- 必须严格串行化 Ghidra 访问；
- 需要处理 stale PID、端口、版本不匹配；
- Ghidra 崩溃会影响所有客户端（可通过重启/注册表恢复）。

定位：默认架构。

### 方案 D：Ghidra GUI 插件桥

```text
Ghidra GUI (插件/PyGhidra console) ──RPC──▶ gdare2 CLI
```

优点：可附着正在运行的 GUI，用户体验最接近 idare2。

缺点：

- 需要开发/安装 Ghidra 扩展；
- GUI 线程模型复杂，不能随意在后台线程调用 Ghidra API；
- 项目已被 GUI 持有，外部 daemon 无法同时打开；
- 需要处理光标/事务/undo 与用户操作冲突。

定位：v2 增强；v1 不实现，但协议与 backend 抽象要为它留接口。

## 7. 现有本地参考

- `../idare2`：命令语言、Session、渲染、op 注册表、测试分层。
- `../idare2/docs/DESIGN.md`：完整设计文档范式。
- `../idare2/docs/COMMANDS.md`：r2 ↔ IDA 映射，可作为 Ghidra 映射的骨架。
- `../aida-audit/backend/aida_audit/ghidra_export/AidaExport.java`：
  Ghidra headless 脚本的实际 API 用法（函数、段、符号、反编译、xrefs）。
- `../aida-audit/backend/aida_audit/export_cmd.py`：
  `analyzeHeadless -import ... -postScript` 的调用方式与项目目录管理。
- `../radare2`：r2 源码与命令语义。
- `~/ghidra/current`：Ghidra 12.2 源码 zip、PyGhidra、语言定义、Decompiler 源码。

## 8. 调研结论

**采用方案 C。** 具体地：

1. `gdare2` 是纯 Python CLI，只依赖标准库；复用 idare2 的纯客户端层。
2. `gdare2d` 是 PyGhidra daemon，独占 Ghidra 项目，串行执行 op。
3. 通信使用 loopback HTTP + JSON-RPC + bearer token；状态文件用于发现 daemon。
4. 默认按目标路径自动拉起 daemon；支持 `--attach`、`--no-spawn`、`--ephemeral`。
5. 默认只读；`-w` 才允许 transaction 提交和 `program.save()`。
6. v1 只做 headless；GUI 桥在 M6 以后实现，复用相同 op 协议。
7. 反汇编/反编译输出以“r2 形状”为目标，不承诺逐字节一致；用 parity 测试锁定差异。

## 9. P0 实测结论（2026-11-07）

环境：Ghidra 12.2 PUBLIC、PyGhidra 3.2.0、JPype 1.5.2、Python 3.13.15、OpenJDK 25。

`tools/spike_pyghidra.py /bin/ls` 结果：

- JVM/Ghidra 冷启动约 2.3–3.3 秒；
- ELF 首次导入约 2.3 秒；
- 自动分析约 9.8 秒，414 个函数；
- 已保存项目热重开约 4.3 秒（含一次反编译）；
- `DecompInterface` 对目标函数约 0.05 秒；
- 分析结果和程序在项目关闭后可正常重开；
- `ProgramLoader` + `results.save()` 能持久化到 `ProjectData`；
- `ProgramDB` 没有 `getEntryPoint()`，入口需通过 `entry`/`_start` 符号或可执行的
  external entry 过滤；
- Ghidra 项目路径不允许包含以 `.` 开头的目录元素，默认数据目录需避开
  `~/.local/share`。
