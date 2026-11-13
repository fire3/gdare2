# gdare2 命令参考与 Ghidra 映射

> 本文件是命令映射设计稿。**状态列是优先级，不是实现状态**：
>
> - **P0**：M0/M1 必须实现，决定工具是否可用；
> - **P1**：v1 核心，M2–M4 实现；
> - **P2**：v1 增强或后续（M5+ / v1.1 / v2）；
> - **X**：v1 明确不做，报 `NOT_SUPPORTED`；
> - **[C]**：纯客户端实现，不调用 Ghidra；
> - **[W]**：写操作，需要 `-w`。
>
> 实际实现状态见文末 **§14 实现状态（2026-11-08）**；后续任务见
> [ROADMAP.md](ROADMAP.md)。`X` 状态的命令返回错误码 `NOT_SUPPORTED`，
> 退出码为 1；不要静默回退到相似命令。

## 0. 元命令

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `?` | 命令帮助 | 注册表生成 | P0 |
| `<cmd>?` | 单命令帮助 | `CommandSpec.detail` | P0 |
| `? <expr>` | 数学表达式 | 客户端 `expr.py` **[C]** | P0 |
| `?v` `?vi[1248]` `?vx` `?q` | 数值格式化 | 客户端 **[C]** | P1 |
| `?x` | 字符串 ↔ hexpair | 客户端 **[C]** | P1 |
| `?b` `?o` `?u` | 二进制/八进制/人类可读 | 客户端 **[C]** | P1 |
| `?f` `?h` `?l` `?s` `?r` `?e` | 位映射/哈希/长度/序列/随机/输出 | 客户端 **[C]** | P1 |
| `?V` | 版本 | daemon `/health` + 客户端版本 | P0 |
| `?P` `?p` | 物理/虚拟地址转换 | `Memory` block 映射 **[C]** + op | P2 |
| `?d` | 双端序反汇编 | 无稳定对应；**X** | X |

## 1. `s` — 定位

全部是客户端状态；只有名字解析需要查询 daemon。

| r2 | 说明 | gdare2 |
|---|---|---|
| `s` | 打印当前地址 | **[C]** |
| `s <addr>` | 定位 | 表达式求值 + 客户端历史 **[C]** |
| `s <name>` | 按符号/函数名定位 | `SymbolTable.getSymbols(name)` / `FunctionManager` |
| `s+` / `s-` | 历史前进/后退 | **[C]** |
| `s+ n` / `s- n` | 相对定位 | **[C]** |
| `s++` / `s--` | 按 blocksize 前后 | **[C]** |
| `s-*` | 清空历史 | **[C]** |
| `s[j*=!]` | 历史列表 | **[C]** |
| `s. <off>` | 相对 core 地址 | **[C]** |
| `s:` | 补零当前地址 | **[C]** |
| `sa` | 对齐 blocksize | **[C]** |
| `sb [addr]` | 基本块起始 | `BasicBlockModel.getBasicBlocks(...)` + `getFirstStartAddress()` |
| `sf [addr]` | 函数起始 | `FunctionManager.getFunctionContaining(addr).getEntryPoint()` |
| `sF [addr]` | 函数结束 | `Function.getBody().getMaxAddress()` |
| `so [n]` | 下一条指令 | `Listing.getInstructionAfter(addr)` |
| `sn [n]` | 下一条（跳过 call） | `Instruction.getFlowType().isCall()` 判断 |
| `sp [n]` | 上一条指令 | `Listing.getInstructionBefore(addr)` |
| `sN` | 下一个名字 | `SymbolTable.getAllSymbols(true)` 排序后二分 |
| `s=` / `s==` / `s=*` | 历史 | **[C]** |
| `s/ <data>` | 搜索下一个 | 复用 `/` |
| `sC <str>` | 定位到注释 | `Listing.getComment...` 遍历 |
| `sr <type>` | 定位到引用 | `ReferenceManager` |
| `sd` | 与各基址差值 | `Program.getImageBase()` + memory blocks |
| `s*` / `s,` | 历史命令/表格 | **[C]** |

## 2. `p` — 打印

### 2.1 反汇编

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `pd [n]` | 反汇编 N 条 | `Listing.getInstructionAt` / `getInstructionAfter`；`Instruction.toString()` | P0 |
| `pd -n` | 向前 N 条 | `Listing.getInstructionBefore` | P1 |
| `pd-- [n]` | 上下文 N+N | 前向 + 后向组合 | P2 |
| `pD [n]` | 反汇编 N 字节 | 按 `Instruction.getLength()` 推进 | P1 |
| `pdf` | 当前函数 | `Function.getBody()` + `Listing.getInstructions(body, true)` | P0 |
| `pdfj` | JSON | 同上 | P0 |
| `pdb` | 当前基本块 | `BasicBlockModel` + 包含 seek 的块 | P1 |
| `pdr` | 按块递归 | `BasicBlockModel` 块序 + 指令 | P2 |
| `pdr.` | 从当前块 | 同上 | P2 |
| `pi [n]` | 仅指令文本 | `Instruction.toString()`，客户端省列 | P1 |
| `pI [n]` | 含函数体 | 同 `pd` | P2 |
| `pdl` | 地址+长度+文本 | `Instruction.getLength()` + 文本 | P1 |
| `pdi` | 地址+symbol+字节+文本 | `Instruction.getBytes()` + `getPrimarySymbol()` | P1 |
| `pds` | 摘要 | 无稳定对应；**X** | X |
| `pdj` / `pdJ` | JSON | 同 `pd` | P0 |
| `pd*` | r2 命令 | 可渲染为 `wx`/`f` 命令；v1 不做 | X |
| `pdc` | C 伪代码 | `DecompInterface.decompileFunction` → `getDecompiledFunction().getC()` | P1 |
| `pdd` | 另一格式 | 无稳定对应；**X** | X |
| `pdg` | r2ghidra 图 | **X** | X |
| `pdk` | 类方法 | 无类模型；**X** | X |
| `pdu` / `pda` / `pde` | 其他扫描 | **X** | X |
| `pd,` | 表格 | 客户端渲染 | P2 |
| `pC` | 分列 | 客户端渲染 | P2 |
| `pA [n]` | 地址/类型 | `Instruction` + `Reference` | P2 |
| `pp` / `po` | 模式/块运算 | 客户端 + `Memory` | P2 |

### 2.2 汇编

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `pa <asm>` | 汇编为 hexpairs | `Assemblers.getAssembler(program).assemble(addr, line)` | P2 |
| `wa <asm>` **[W]** | 汇编并写入 | 同上 + `Memory.setBytes` | P2 |
| `wa*` | 只打印 `wx` | 同上，不写入 | P2 |
| `wa+` **[W]** | 写入并 seek 到末尾 | 同上 | P2 |
| `waf` / `waF` **[W]** | 文件汇编 | 读文件 + 同上 | P2 |
| `wao` | 修改指令 | 无稳定对应；**X** | X |

汇编语法遵循 Ghidra/SLEIGH；不支持的语言明确报错。

### 2.3 内存与数据

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `px [len]` | 十六进制转储 | `Memory.getBytes(addr, buf)` | P0 |
| `pxw` / `pxq` | 32/64 位字 | `Memory.getInt/getLong` | P1 |
| `pxd` / `pxu` | 十进制 | 同上 + 客户端渲染 | P1 |
| `pxa` | 有符号字节 | `Memory.getByte` | P2 |
| `p8 [len]` | hexpair | `Memory.getBytes` | P0 |
| `p8j` | JSON | 同上 | P0 |
| `p8f` | 文件形式 | 同上 | P2 |
| `ps` | 字符串 | `Data`/`StringDataType` 或读到 NUL | P1 |
| `psw` / `psp` / `psz` / `psj` | 宽/帕斯卡/NUL/JSON | 手动解码 | P1 |
| `pv[1248]` | 单值 | `Memory.getByte/getShort/getInt/getLong` | P1 |
| `pvj` / `pvh` | JSON/人类可读 | 客户端 | P1 |
| `pc` / `pcp` | C/Python 数组 | 客户端 | P1 |
| `pr [len]` | 原始字节 | `Memory.getBytes` | P1 |
| `pb` / `pB` | 位流 | 客户端 | P2 |
| `ph [algo]` | 哈希 | 客户端 `hashlib` | P2 |
| `pf <fmt>` | 格式化打印 | 客户端格式串 + `read_bytes` op | P2 |
| `pfj` / `pfs` / `pf.` | pf 变体 | 客户端 | P2 |
| `pt` | 类型化打印 | 客户端 + `DataType` op | P2 |
| `p=` | 熵/可打印字符 | 客户端 | P2 |
| `p-` | 直方图 | 客户端 | P2 |
| `p6d` / `p6e` | base64 | 客户端 | P2 |
| `pwd` / `pushd` / `popd` | 工作目录 | 客户端 | P2 |
| `pj [len]` | JSON | 客户端 | P1 |
| `pk` / `pK` / `pq` / `pz` | randomart/QR/zoom | **X** | X |

## 3. `i` — 信息

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `i` / `iI` / `ij` | 文件信息 | `Program.getExecutablePath/Format/MD5/SHA256`、`getLanguage`、`getCompilerSpec`、`getImageBase()` | P0 |
| `it` / `itj` | 哈希 | `Program.getExecutableMD5/SHA256`；可选原始文件 SHA1 | P1 |
| `ia` / `iaj` | 架构列表 | `LanguageID` / `CompilerSpec` | P1 |
| `iS` / `iSj` | 节/块 | `Memory.getBlocks()`：name/start/end/perm/type | P0 |
| `iSS` / `iSSj` | ELF program headers | 客户端 `formats/elf.py` 解析原始文件；非 ELF 返回 `NOT_SUPPORTED` | 已实现 |
| `iS.` | 当前块 | `Memory.getBlock(addr)` | P1 |
| `iSh` | 原始块头 | **X**（Ghidra 不保留原格式 section header） | X |
| `iSm` | 块内符号 | `SymbolTable.getSymbols(AddressSetView, ...)` | P2 |
| `is` / `isj` | 符号 | `SymbolTable.getAllSymbols(true)` | P1 |
| `iE` / `iEj` | 导出 | `SymbolTable` + `Symbol.isExternal()` / entry point | P1 |
| `ie` / `iej` | 入口点 | `SymbolTable.getExternalEntryPointIterator()` | P1 |
| `iee` / `ies` | 构造/入口符号 | 无直接对应；可查 init_array 符号 | P2 |
| `ii` / `iij` | 导入 | `SymbolTable.getExternalSymbols()` + namespace | P1 |
| `iic` | 导入分类 | **X** | X |
| `il` / `ilj` / `ilq` | 依赖库 | 外部 namespace / 原格式解析；部分格式可用 | P2 |
| `iM` | main 地址 | 符号 `main` / entry point | P2 |
| `ir` / `irj` | 重定位 | Ghidra 不暴露统一 relocation 表；**X**（按格式后续扩展） | X |
| `ih` / `iH` | 文件头 | **X**（Ghidra 高层模型不保留完整原始头） | X |
| `iz` / `izj` | 字符串 | 遍历 `Data` + `StringDataType` | P1 |
| `izz` / `izzj` | 全文件字符串 | 原始文件扫描或 `DataIterator` | P2 |
| `iC` / `iV` / `iv` / `iT` | 签名/版本 | **X** 或空结果 | X |
| `id` | DWARF DIE | Ghidra 无直接等价；**X** | X |
| `iD <lang> <sym>` | demangle | Ghidra demangler / 符号名 | P2 |
| `ic` / `icj` | 类 | Ghidra 无 C++ 类模型；**X** | X |
| `CL` / `CLj` / `CL*` | 源码行 | `SourceType` / `Program` source map；部分可用 | P2 |
| `iL` / `ik` / `im` / `iu` / `iw` / `i:` / `iO` | 其他 | **X** | X |

## 4. `a` — 分析

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `aa` | 分析全部 | 未分析时 `AutoAnalysisManager.startAnalysis` / `pyghidra.analyze`；已分析 no-op | P1 |
| `aaa` / `aaaa` | 深度分析 | `AutoAnalysisManager.reAnalyzeAll`；需确认 | P2 |
| `af` | 分析当前函数 | `FunctionManager.createFunction(...)` **[W]** | P1 |
| `afr` | 重新分析函数 | 无直接对应；可删后重建，风险高 | P2 |
| `afu [addr]` | 调整边界 | `Function.setBody(...)` **[W]** | P1 |
| `afn [name]` | 重命名函数 | `Function.setName(name, SourceType.USER_DEFINED)` **[W]** | P1 |
| `afna` | 自动命名 | Ghidra analyzer 风格；**X** | X |
| `afi` / `afij` | 函数详情 | `Function` 各 getter | P1 |
| `afl` / `aflj` / `aflq` | 函数列表 | `FunctionManager.getFunctions(true)` | P0 |
| `aflc` / `afln` / `afl+` | 计数/重命名/大小和 | 客户端基于 `afl` 结果 | P1 |
| `afb` / `afbj` | 基本块 | `BasicBlockModel.getBasicBlocks(function.getBody(), monitor)` | P1 |
| `afB [n]` | 第 n 块 | 同上 | P2 |
| `afc` | 调用者 | `Function.getCallers()` 或 `ReferenceManager` | P1 |
| `afC` | 被调用者 | `Function.getCalledFunctions(monitor)` | P1 |
| `afv` / `afvj` | 局部变量 | `HighFunction.getLocalSymbolMap()` + `VariableStorage` | P1 |
| `afvR` / `afvW` | 变量读写点 | `HighFunction` / `HighVariable` 使用点 | P2 |
| `afx` / `afxj` | 函数内 xref | `Instruction.getReferencesFrom()` | P1 |
| `axt [addr]` | 到 addr 的引用 | `ReferenceManager.getReferencesTo(addr)` | P0 |
| `axf [addr]` | 从 addr 出发 | `ReferenceManager.getReferencesFrom(addr)` | P0 |
| `axg` | 引用图 | 客户端 + xref op | P2 |
| `axj` / `ax*` | JSON/命令 | 客户端 | P1 |
| `ac` | 调用关系 | **X**（用 `afc/afC`） | X |
| `agf` / `agfj` / `agfd` | 函数图 | `BasicBlockModel` + `CodeBlock.getDestinations(monitor)` | P1 |
| `ab` / `abj` | 当前基本块 | `BasicBlockModel` | P1 |
| `ao` / `aoj` | 指令详情 | `Instruction` / `Reference` | P1 |
| `ai` / `aij` | 地址信息 | `Memory.getBlock(addr)` + `Program` | P1 |
| `an` **[W]** | 重命名变量/函数 | `Function.setName` / `HighSymbol` 重命名 | P2 |
| `a8 <hex>` **[W]** | 手工分析字节 | `Memory.setBytes` + `Listing.createInstruction` | P1 |
| `ad [size]` **[W]** | 数据分析 | `Listing.createData(...)` | P1 |
| `ah` | 分析提示 | **X** | X |
| `av` / `avg` | vtable/全局变量 | 无稳定对应；**X** | X |
| `ar` / `ae` / `as` / `ap` | 寄存器/ESIL/syscall/prelude | **X** | X |
| `aF` | `af` 别名 | 同 `af` | P1 |
| `a*` | 所有命令形式 | 部分渲染 | P2 |

## 5. `f` — 标志

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `f` | 列表 | 客户端 `FlagStore`（播种 symbols/functions） | P1 |
| `f name [sz] [@addr]` **[W]** | 创建 | `SymbolTable.createLabel(addr, name, namespace, USER_DEFINED)` | P1 |
| `f name = addr` | 简写 | 同上 | P1 |
| `f- name` **[W]** | 删除 | `SymbolTable.removeSymbolSpecial(symbol)` | P2 |
| `f- @addr` **[W]** | 按地址删除 | 同上 | P2 |
| `f--` **[W]** | 删除全部 | 逐个删除；需确认 | P2 |
| `f+ name` **[W]** | 不存在才建 | 同上 | P2 |
| `f*` / `f,` / `f=` | 渲染/表格/范围 | 客户端 | P2 |
| `f.` | 会话局部标签 | 客户端 | P2 |
| `f? name` | 是否存在 | 客户端 | P1 |
| `fq` | 仅名称 | 客户端 | P1 |
| `fn` / `fnj` | demangled 名称 | `Symbol.getName(true)` | P2 |
| `fN` | 当前 real name | 同 `fn` | P2 |
| `fr old new` **[W]** | 重命名 | `Function.setName` / `Symbol.setName` | P2 |
| `fx <flag>` | 地址 + hexdump | 客户端 + `px` | P2 |
| 其他 `f` 后缀 | — | **X**（明确报错） | X |

## 6. `t` — 类型

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `t` / `tj` | 列出类型 | `DataTypeManager.getAllDataTypes()` | P1 |
| `t*` | r2 命令 | 客户端渲染 | P1 |
| `ts <name>` | 结构布局 | `Structure` | P1 |
| `tu <struct>` | 成员 | `StructureComponent` / `getComponents()` | P1 |
| `te <enum>` | 枚举成员 | `Enum.getEnumEntries()` | P1 |
| `tc [name]` / `tcj` | C 声明 | `DataTypeWriter` 输出 ANSI-C | P1 |
| `td <decl>` **[W]** | 解析 C 声明 | `CParser` + `DataTypeManager.addDataType` | P1 |
| `t- <name>` **[W]** | 删除类型 | `DataTypeManager.remove(...)` | P2 |
| `tf- <name|glob>` **[W]** | 删除函数定义类型 | `DataTypeManager.remove(...)` + `FunctionDefinition` 过滤 | P1 |
| `tp` / `tpv` / `tpx` | 按类型读取/格式化 | `Data` + `DataType` 布局 | P2 |
| `tt` / `ttj` | 列出 typedef | `TypeDef` 过滤；当前已实现 | P1 |
| `tt <typename>` | 显示 typedef 对应的真实类型 | `TypeDef` + `getBaseDataType()` | P2 |
| `tf` / `tfj` / `tfc` | 函数签名 | `Function.getSignature()` / `getPrototypeString` | P1 |
| `afs [signature]` **[W]** | 获取/写入当前函数签名 | `CParserUtils.parseSignature` + `ApplyFunctionSignatureCmd` | P1 |
| `tn` / `tn-` | 重命名类型 | `DataTypeManager` rename | P2 |
| `to` / `dt` | 打开/删除类型 | **X** | X |

## 7. `C` — 注释

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `C` / `Cj` / `C*` / `C.` | 列表 | `Listing.getComment` 遍历 | P1 |
| `CC <text>` **[W]** | 普通注释 | `Listing.setComment(EOL)` | P1 |
| `CC-` **[W]** | 删除 | `setComment(EOL, "")` | P1 |
| `Cd` / `Cd.` **[W]** | 数据注释 | `setComment(EOL)` at data | P1 |
| `Cb` **[W]** | 块前 | `setComment(PRE)` | P1 |
| `Cp` **[W]** | 函数/plate | `Function.setComment` / `PLATE` | P1 |
| `Cr` **[W]** | repeatable | `setComment(REPEATABLE)` | P1 |
| `Ch` / `Cs` / `Cs-` | 隐藏/字符串注释 | **X** 或部分 | X |

## 8. `w` — 写入

全部 **[W]**，需要 `-w`。

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `w` | 保存程序 | `program.save("gdare2", monitor)` | P1 |
| `wq` | 保存并退出 | 同上 + `q` | P1 |
| `w <text>` | 写字符串 | `Memory.setBytes` | P1 |
| `w+ <text>` | 写并 seek 到末尾 | 同上 + 客户端 seek | P2 |
| `wx <hex>` | 写字节 | `Memory.setBytes` | P1 |
| `wa <asm>` | 汇编写入 | `Assemblers` + `Memory.setBytes` | P2 |
| `wa* <asm>` | 只打印 `wx` | 不写入 | P2 |
| `wa+ <asm>` | 写并 seek | 同上 | P2 |
| `waf` / `waF` | 文件汇编 | 读文件 + `wa` | P2 |
| `w0 [len]` | 写零 | `Memory.setBytes(b"\0"*n)` | P1 |
| `wd [off] [n]` | 内存拷贝 | 读源 + `setBytes` | P1 |
| `wf -|file` | 文件写入 | 读文件 + `setBytes` | P1 |
| `wc` / `wc+` / `wc-` | 写缓存 | 客户端缓存 + `wc+` 批量提交 | P1 |
| `wi[1248][+-][n]` | 整数读写 | `Memory.get*` / `set*` | P2 |
| `w6[d/e/x]` | base64 | 客户端解码 + `wx` | P2 |
| `u` / `U` | 撤销/重做（daemon 内存级字节历史） | daemon `write_undo/write_redo`；不调用 Ghidra undo | P1 |

## 9. `/` — 搜索

| r2 | 说明 | gdare2 → Ghidra API | 状态 |
|---|---|---|---|
| `/ <text>` | 文本搜索 | `Memory.findBytes`（ASCII/UTF-8） | P1 |
| `/x <hex>` | 字节搜索 | `Memory.findBytes` | P1 |
| `/v[1248] <num>` | 立即数 | 编码后 `findBytes` | P2 |
| `/w <str>` | 宽字符 | UTF-16 编码后 `findBytes` | P2 |
| `/r <regex>` | 正则 | 遍历字符串 `Data` + `re` | P2 |
| `/p <size>` | 重复模式 | 分块读内存 + 扫描 | P2 |
| `/a <asm>` | 汇编后搜索 | `Assemblers` 编码 + `/x` | P2 |
| `//` | 重复上次 | 客户端 `SearchState` | P1 |
| `/+` / `/-` | 下一个/上一个 | 客户端 | P1 |
| `search.in` | 范围 | `io.maps` / `raw` / `bin.sections` | P2 |
| `cmd.hit` | 命中命令 | 客户端 `@@` | P2 |
| `/j` | JSON | 客户端 | P1 |

## 10. 操作符

| 操作符 | 说明 | 状态 |
|---|---|---|
| `;` | 语句分隔 | P0 |
| `@ addr` | 临时 seek | P0 |
| `@!n` | 临时 blocksize | P1 |
| `@{from to}` | 临时范围 | P1 |
| `@e:` `@s:` `@v:` `@c:` `@B:` | 临时上下文 | P2 |
| `@@=` `@@==` | 显式地址列表 | P1 |
| `@@f` / `@@f:pat` | 所有函数 | P1 |
| `@@F` | 函数（带 size） | P2 |
| `@@i` | 当前函数指令 | P1 |
| `@@b` | 当前函数基本块 | P1 |
| `@@S` / `@@iS` | 所有内存块 | P1 |
| `@@s` | 符号 | P1 |
| `@@s:from to step` | 步进 | P2 |
| `@@ <flagglob>` | flag glob | P2 |
| `@@.file` | 地址文件 | P2 |
| `@@/x <hex>` | 搜索结果 | P2 |
| `@@@` / `@@@=` / `@@@f` / `@@@F` / `@@@i` / `@@@S` | 带 size 迭代 | P2 |
| `~` | grep | P0（移植） |
| `|` | shell 管道 | P0（移植） |
| `>` / `>>` | 重定向 | P0（移植） |
| `` `cmd` `` | 命令替换（取首行） | 已实现 |
| `.cmd` | 输出当命令 | **X**（与 gdare2 `.g*` 命名空间冲突，明确不做） |
| `!cmd` | shell | P1 |
| `H>` / `H>>` | HTML | X |

### 10.1 `~` 过滤器语法

| 修饰符 | 说明 | 示例 |
|---|---|---|
| `~word` / `~a,b` / `~a&b` | 任一命中 / 全部命中 | `pd 5~CALL` |
| `~+word` / `~!word` | 忽略大小写 / 取反 | `~+call`、`~!CALL` |
| `~^word` / `~word$` | 行首/行尾锚点 | `~^0x` |
| `~[n]` / `~[-1]` | 单列 / 倒数第一列 | `pd 5~[1]`（整段字节） |
| `~[a,b]` / `~[a-b]` / `~[a-]` | 多列 / 范围 / 到行尾 | `pd 5~[0,2]` |
| `~$` / `~$!` / `~$!!` | 整行升序 / 降序 / 反转原序 | `afl~$` |
| `~$:n` / `~$:n!` | 按第 n 列升序 / 降序 | `afl~$:0` |
| `~:n` / `~:a-b` / `~:-1` | 行选择（结束索引不含） | `ij~:0` |
| `~?` | 计数 | `afl~?main` |
| `~{}` / `~{}:0` | JSON 美化（再按行选择） | `ij~{}` |
| `~?ea` / `~<>` / `~:)` / `~:}` | 明确报 unsupported | — |

`pd`/`pdi` 的字节列是按 r2 形状渲染的整段十六进制（超过 8 字节以 `..` 截断），
因此 `~[1]` 取到整段字节而不是第一个字节。

## 11. 其余命令族

| 族 | 覆盖 | 状态 |
|---|---|---|
| `b` | `b`/`b n`/`b+`/`b-`/`bj` **[C]** | P1 |
| `e` | `e`/`e?`/`e k`/`e k=v`/`ej` | P0 |
| `L` | 列出 gdare2 daemon 实例 | P0 |
| `q` | `q`/`q!`/`q <ret>` | P0 |
| `S` | 执行命令脚本 | P1 |
| `T` | 文本日志 | P2 |
| `x` | `x`/`x8`/`xw`/`xq`/`xj` | P1 |
| `y` | 剪贴板 | P2 |
| `_` | 上次输出 | P2 |
| `%` | 环境变量 | P2 |
| `$` | 变量/别名 | P1 |
| `P` | 会话工程 JSON | P2 |
| `c` | 比较（`c`/`cc`/`c1`） | P2 |
| `k` / `o` / `m` / `z` / `=` / `#` / `d` / `g` | 不支持 | X |

## 12. gdare2 扩展命令

| 命令 | 说明 | 状态 |
|---|---|---|
| `.ghidra` / `.g` | backend、daemon、project、program、language、状态 | P0 |
| `.gsave` | 等价 `w` | P1 |
| `.gclose [--no-save]` | 关闭 daemon | P1 |
| `.gsync` | 重新拉取元信息/符号/块 | P2 |
| `.ganalyze [all]` | 触发分析并显示状态 | P1 |
| `.gstatus` | 当前任务/分析进度 | P1 |
| `.gexec <python>` | 直接执行 Python，需 `--allow-exec` | P2 |
| `.ghelp` | 扩展命令帮助 | P1 |

## 13. Ghidra op 一览

| op | 主要参数 | 返回 |
|---|---|---|
| `open_summary` | — | program/language/arch/bits/endian/base/entry |
| `info` | `kind` | 文件/段/符号/导入/导出/入口/字符串 |
| `disasm` | `ea`, `count`, `mode`, `before` | 指令列表 |
| `function` | `kind`, `ea`, `name` | 函数列表/详情/基本块/调用者 |
| `xrefs` | `ea`, `direction`, `kind` | 引用列表 |
| `memory` | `ea`, `length`, `kind` | bytes / 值列表 |
| `strings` | `ea`, `kind`, `all` | 字符串列表/单条 |
| `types` | `kind`, `name`, `decl`, `ea` | 类型列表/结构/成员/签名 |
| `type_define` | `decl` | 解析并保存 C 类型声明 |
| `type_c` | `name`, `kind`, `limit` | C 声明输出 |
| `type_delete` | `name`, `kind` | 删除类型/函数定义类型 |
| `type_read` | `name`, `ea`/`data`, `count` | 类型化读取的 bytes/values |
| `exports` | `limit` | 导出符号列表 |
| `strings_all` | `min_length`, `limit` | 全文件 ASCII 字符串扫描 |
| `function_reanalyze` | `ea` | 删除并重建函数 |
| `variable_refs` | `ea`, `name`, `kind` | 变量读/写引用 |
| `variable_rename` | `ea`, `old`, `new` | 重命名函数变量/参数 |
| `exec_python` | `code` | 需 `--allow-exec` + `-w` 的 Python 逃生舱 |
| `symbol_create` | `ea`, `name` | 创建 Ghidra label |
| `symbol_rename` | `name`, `new_name` | 重命名符号 |
| `symbol_delete` | `name`/`ea` | 删除符号 |
| `function_signature` | `ea` | 当前函数签名与参数 |
| `function_set_signature` | `ea`, `signature` | 解析并应用函数签名 |
| `comments` | `kind`, `ea`, `text` | 注释列表/更新 |
| `decompile` | `ea`, `timeout`, `kind` | C 文本/签名/变量 |
| `search` | `kind`, `pattern`, `from`, `to` | 命中列表 |
| `search_raw` | `data`, `mask`, `from`, `to` | 原始文件偏移命中列表 |
| `graph` | `ea`, `format` | blocks/edges |
| `write` | `kind`, `ea`, `bytes` | 写入结果 |
| `assemble` | `ea`, `text` | 汇编结果 bytes（不写入） |
| `assemble_write` | `ea`, `text` | 汇编并写入（transaction + undo） |
| `save` | `comment` | 保存结果 |
| `undo` / `redo` | — | 结果 |
| `batch` | `ops[]` | 信封数组 |
| `status` | — | daemon 状态 |
| `session` | `kind`, `lease`, `ttl` | open/heartbeat/close 与活跃客户端列表 |

## 14. 实现状态（2026-11-08）

> 本节记录当前代码的实际状态，避免把“优先级”误读成“已实现”。
> 详细差距、文件位置与推进顺序见 [ROADMAP.md](ROADMAP.md)。

### 14.1 已实现

| 类别 | 命令 |
|---|---|
| 定位/会话 | `s`、`s+`、`s-`、`s++`、`s--`、`s.`、`sb`、`sf`、`sF`、`so`、`sn`、`sp`、`s*`、`b`、`b*`、`q`、`?`、`?V`、`e`/`ej`/`e?`/`e??`、`L` |
| 反汇编/内存 | `pd`、`pdj`、`pdi`、`pi`、`pdl`、`pD`、`pdf`、`pdfj`、`pdc`、`pdcj`、`pdb`、`pC`、`pA`；`px`、`pxw`、`pxq`、`pxd`、`pxu`、`pxj`、`p8`、`p8j`、`p8s`、`p8d`、`p8x`、`p8,`、`p8*`、`p8b`、`p8f`；`pv` 及 `pvj/1/2/4/8/u/d/p`；`ps`、`psz`、`psw`、`psp`、`psu`、`psx`、`psn`、`psj`；`pc`、`pf`/`pfj`/`pfs`/`pf.`/`pf.<name>`；`pdk`/`pdr` 明确 `NOT_SUPPORTED` |
| 信息 | `i`、`iI`/`iIj`/`ij`、`iS`/`iSj`/`iS*`/`iSS`/`iSSj`、`iS.`、`ih`/`ihj`、`iH`、`il`/`ilj`、`ir`/`irj`、`it`/`itj`、`iM`、`is`/`isj`、`ii`/`iij`、`ie`/`iej`、`iz`/`izj` |
| 分析/图 | `afl`/`aflj`、`aflq`、`afln`、`afl+`、`aflc`、`afc`/`afcj`、`afC`/`afCj`、`afi`/`afij`、`afv`/`afvj`、`af`/`aF`、`afn`、`afu`、`a8`、`ad`、`aa`/`aaa`、`afb`/`afbj`、`ab`/`abj`、`ao`/`aoj`、`ai`/`aij`、`agf`/`agfj`/`agfd` |
| 交叉引用 | `axt`/`axtj`、`axf`/`axfj`、`afx`/`afxj`、`ax*`、`axlj`、`axlq`、`axlc`；`axj` 明确报 `NOT_SUPPORTED`（r2 中是写引用） |
| 类型/签名 | `t`/`tj`、`t*`、`ts`/`tsj`、`tu`/`tuj`、`te`/`tej`、`tt`/`ttj`、`tf`/`tfj`、`td`、`tc`/`tcj`、`tfc`/`tfcj`、`t-`、`tf-`、`afs`/`afsj`、`tp`/`tpv`/`tpx` |
| 注释 | `C`/`Cj`、`C*`/`CC*`/`C*.`、`C.`、`CC`、`CCu`、`CC-`、`CC.`、`Cd`、`Cb`、`Cp`、`Cr` |
| flags | `f`、`f*`、`fj`、`fq`、`f?`、`f-`、`fr`、`f.` |
| 搜索 | `/`、`/j`、`/x`、`/xj`、`/p`、`/pj`、`/a`、`/aj`、`/w`、`/wj`、`/v` 及 `v1/2/4/8`、`/r`、`/rj`、`//`、`/+`、`/-`；`search.in=raw` |
| 写入 | `w`、`wq`、`wx`、`w0`、`wf`、`wd`、`wc`、`wc+`、`wc-`、`u`、`U`、`wi` 及宽度/符号变量、`w6d`/`w6e` |
| 汇编 | `pa`、`wa`、`wa*`、`wa+`、`waf`/`waF` |
| 分析写入/变量 | `afr`、`afvR`、`afvW`、`an` |
| 脚本/杂项 | `S`、`$`、`_`、`x`/`x8`/`xw`/`xq`/`xj`、`iE`/`iEj`、`ia`/`iaj`、`izz`/`izzj` |
| 迭代 | `@@F`、`@@/x`、`@@/`、`@@.file`、`@@s:from to step`、`@!n`、`@{from to}` |
| 扩展命令 | `.g`、`.gstatus`、`.gsave`、`.gclose`、`.gsync`、`.ganalyze`、`.ghelp`、`.gexec` |

### 14.2 未实现（按 ROADMAP 阶段）

| 阶段 | 命令/能力 |
|---|---|
| Phase A | **已完成**（loader 参数校验、`pdi` 独立布局、`pdj` 字段集决策） |
| Phase B | **已完成**（含 `izz`、`/p`、`/a`、raw search、`@@/x`、`@@s`、`@{from to}`、`.gexec`、`afr`/`afvR`/`afvW`/`an`、`ghidra.analysis.wait`） |
| Phase C（parity） | **已完成**（`tests/parity/`、`tests/golden/`、`tools/capture_r2_golden.py`、`/bin/ls` 与 ARM32 黄金文件、22 配置矩阵 `pd 1`/`iI` 断言、batch 子 op meta 透传） |

### 14.3 已知语义差异

- `pdj` 顶层数组与 r2 6.2.5 一致，但字段集不同（缺 `esil/opcode/family/type` 等）；
  已决策不伪造缺失字段，现有字段包含 `symbol`。
- `pdi` 现已独立布局：`地址 + symbol + 字节 + 文本`；`pd` 保持原布局。
- `tt` 是 typedef 列表（与 r2 一致）；类型读取/格式化走 `tp`/`tpv`/`tpx`，
  当前覆盖整数、枚举、指针、char 数组；结构体只打印原始字节。
- `u/U` 只恢复字节，不回滚反编译/函数/注释/类型；daemon 重启后历史清空。
- `pa/wa` 使用 Ghidra SLEIGH 汇编器；助记符通常需要大写（如 `NOP`），
  不支持的语言明确报 `NOT_SUPPORTED`。`--assembler=rasm2` 仍未实现。
- 首次汇编会触发 SLEIGH 初始化（实测 20–60 s）；汇编 op 使用
  `e ghidra.assemble.timeout`（默认 180 s），其他 op 仍使用
  `e ghidra.timeout`（默认 30 s）。
- `f` 默认只写会话内 flag；写回 Ghidra 需要 `-w` 且 `e ghidra.flags.write=true`。
- `.gexec` 需要客户端 `--allow-exec`、daemon `--allow-exec` 与 `-w` 三重条件。
- `/r` 只遍历已定义字符串；`izz`/`search.in=raw` 返回文件偏移；`afr` 为
  删除+重建函数的近似重分析；`an` 对纯 decompiler 局部变量支持有限。
- `pdl` 输出 `地址 + 长度 + 文本`；r2 6.2.5 的 `pdl` 只打印长度，parity 只比较行数。
- `pd -N` 向后反汇编按地址升序输出；指令边界由解码器决定，parity 只校验地址序列。
- `batch` 的子 op 现在逐项保留 `meta`；`search`/`search_raw` 返回响应级 `meta`。

### 14.4 2026-11-08 已修复

- 客户端/daemon `instance_id` 指纹统一；`.g`/`.gstatus` 显示真实 `instance_id`/`state`。
- `ppc/mips/sparc` 默认 BE；单端序架构的冲突参数报错。
- `-A/-AA` 触发 `aa/aaa`；`--listen` 转发；`--wait` 为默认行为。
- `gdare2d` 自动推导项目路径/名称；`--attach` 不再要求目标文件。
- daemon `--readonly` 要求已有且已分析项目；`--analysis-timeout` 与
  `e ghidra.decompile.timeout` 生效。
- 写命令统一客户端门控，错误信息包含 `re-run with -w to allow writes`。
- 被忽略的 `-k` 消费其参数；daemon bootstrap 失败返回非零退出码。
- `--loader`/`--loader-arg` 用 Ghidra `Option.getArg()` 校验，未知值返回 `BAD_ARGS`；
  支持 `BinaryLoader` 类名与 `Raw Binary` 显示名。
- `pdi` 增加 symbol 列；`pdj` 增加 `symbol` 字段，缺失的 r2 字段不伪造。


### 14.5 2026-11-08 Phase B 首批实现
- flags：`f`/`fj`/`fq`/`f?`/`f-`/`fr`/`f.`；默认会话内，写回由
  `-w` + `e ghidra.flags.write=true` 控制；daemon 新增
  `symbol_create/symbol_rename/symbol_delete`。
- 脚本/变量：`S`、`$`、`$?`、`_`；`x`/`x8`/`xw`/`xq`/`xj`。
- 信息/类型：`iE`/`iEj`、`ia`/`iaj`、`t-`、`tp`/`tpv`/`tpx`。
- 搜索/迭代：`/r`、`cmd.hit`、`@@F`、`@@.file`、`@!n`。
- 汇编/写入：`pa`、`wa`、`wa*`、`wa+`、`waf`/`waF`、`wi` 宽度/符号变量、
  `w6d`/`w6e`。
- 扩展命令：`.gsync`、`.ganalyze`、`.ghelp`。
- daemon 控制：`--daemon-readonly` 转发 `--readonly`。
- 搜索/迭代补齐：`izz`/`izzj`、`/p`、`/a`、`search.in=raw`、`@@/x`、
  `@@/`、`@@s:from to step`、`@{from to}`。
- 分析写入与逃生舱：`afr`、`afvR`、`afvW`、`an`；`.gexec` 双重
  `--allow-exec` 门控；`e ghidra.analysis.wait=skip` 跳过 `-A` 自动分析。

### 14.6 2026-11-13 v2 G1–G5

- `iSS`/`iSSj`：改为解析输入文件的 ELF program headers（客户端
  `src/gdare2/formats/elf.py`），不再 alias 到 `iS`；非 ELF 返回
  `NOT_SUPPORTED`。r2 5.5 额外生成的 `ehdr` 行不再合成。
- `tp`/`tpv`/`tpx`：修复内建整数类型（`int` 等）上的
  `getBaseDataType()` 崩溃；整数、枚举、指针、char 数组均可格式化。
- `tc <name>`：只输出该类型自身的 typedef/struct/union/enum 声明，不再
  输出依赖类型前导；`tc` 无参数保持全量输出。
- JSON 输出：`~`/`|` 在渲染后按行处理，`aflj~entry`、`pdj~...` 与 r2 的
  过滤语义一致。
- `-j`：在命令查找前解析 JSON 变体；`-j f` 等独立 spec 命令现在返回
  JSON，`<cmd>?` 帮助不受影响。
- 附带修复：`gdare2d --loader-arg -loader-xxx value` 不再被 argparse
  误判为缺失参数；`DESIGN §8.4` 的 `K V` 接口保持不变。

### 14.7 2026-11-13 v2 G7/G9

- 元命令：新增 `i`（文件信息，首行 `file`）、`aflq`（函数地址）、
  `L`（列 live daemon，与 `-L` 共用 `registry.live_instances()`）、
  `ej`（配置 JSON）、`e?`/`e??`（配置键表）；`-j` 支持 `i`/`e`。
- `afl`/`aflq` 支持名称过滤：无通配符按子串，含 `*?[` 按 glob。
- 迭代器：`@@F`/`@@S` 跳过无指令函数与不可读 block，汇总一条
  `WARN: skipped N iterator target(s) without readable data`。
- 注册表：重复 pattern 在导入期直接抛 `ValueError`；`wi` 只注册一次。
- 语义复核：r2 的 `@@f` 是 functions；`@@s:from to step` 已实现，
  `@@s:<symbol-pattern>` 是 gdare2 扩展。

### 14.8 2026-11-13 v2 G6/G8/G10

- 颜色：`scr.color=1/2/3` 输出 ANSI（同一 256 色调色板）；stdout 为 TTY
  且未设置 `NO_COLOR` 时默认 1；`--color 0`/`e scr.color=0` 关闭。
- 反汇编注解：`asm.comments=true` 输出 `;-- symbol:` 与 EOL 注释（默认
  false）；`asm.lines=true` 输出 `│ `/`└─` gutter；`asm.demangle` 用于
  `_Z` 符号；`asm.flags=false` 隐藏符号注解与 `pdi` 符号列。
- 批处理：`cmd.batch=false` 时 `@@` 逐目标 RPC，不再合并为一次 `batch`。
- 分页：`--list-offset N` / `e list.offset=N` 作用于
  `afl/aflq/afln/afl+/is/iE/ii/iz/izz`；截断时提示下一页偏移。
- `-o`：r2 的文件偏移映射未实现，明确报
  `file-offset mapping is not implemented; use --list-offset`。
