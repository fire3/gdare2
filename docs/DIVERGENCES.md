# gdare2 与 radare2 的预期语义差异

> 目标不是“假装 Ghidra 是 r2”，而是让高频工作流兼容，同时把无法兼容的地方
> 明确暴露出来。任何“看起来像 bug”的差异都应该能在本文件找到解释。

## 1. 分析模型

### 1.1 `aa` 通常是 no-op

Ghidra 在导入/首次打开时跑自动分析。`gdare2` 的 `aa` 只在程序尚未分析时触发分析；
对已经分析过的项目通常是 no-op。保留 `aa` 只为脚本兼容。

`aaa` 会显式请求全量重分析，成本高，建议只在明确需要时使用。

### 1.2 函数名来自 Ghidra

r2 默认命名类似 `sym.main`、`fcn.00401000`；Ghidra 默认命名类似 `FUN_00401000`、
`LAB_00401000`、`main`。客户端不做“改名为 r2 风格”的伪造，只在渲染时提供
`sym.`/`fcn.` 前缀的可选规范化。

### 1.3 没有 r2 的 `anal.*` 调参

Ghidra 的分析器由 `AutoAnalysisManager` 和 analyzer options 控制，不是 r2 的
`anal.*` 配置树。相关 `e anal.*` 键应报 unsupported 或映射到
`ghidra.analysis.*`。

## 2. 进程与项目

### 2.1 项目独占

Ghidra 同一项目同一时间只能被一个进程可写打开。默认 `gdare2` 会拉起 daemon
独占项目；此时不能用 Ghidra GUI 打开同一项目。

这是 Ghidra 的硬约束，不是 gdare2 的 bug。

### 2.2 多个 CLI 共享 daemon

r2 每个进程独立打开文件；gdare2 的多个 CLI 默认连同一个 daemon，因此：

- 写入对其他客户端立即可见；
- 一个客户端的 undo 会影响共享程序状态；
- `q` 只断开客户端，不关闭 daemon（除非 `.gclose`/`--kill`）。

### 2.3 热启动

第一次打开项目可能很慢（JVM + 导入 + 分析）；后续命令应秒级。若每次命令都很慢，
说明 daemon 没有复用或项目被反复打开，应检查注册表/日志。

### 2.4 `-L` 的含义不同

r2 的 `-L` 用于列出插件；gdare2 的 `-L` 用于列出本地 daemon 实例。两者不兼容，
脚本中不要把 `-L` 当作插件列表使用。`L` 命令同样表示 daemon 实例列表。

## 3. 导入与架构

### 3.1 裸二进制必须给语言

Ghidra `BinaryLoader` 默认选择“第一个 preferred language”，这几乎肯定不是用户想要的。
gdare2 对裸二进制要求 `-a/-b/--endian` 或 `--ghidra-language`；缺失时明确报错。

### 3.2 架构名不是 r2 名

`-a arm` 会映射到 Ghidra `ARM:LE:32:v7`（或用户指定的 v8/Cortex），不是 r2 的
`arm` 插件名。需要精确控制时用 `--ghidra-language`。

### 3.3 SuperH 别名

`sh4` 别名在 Ghidra 12.2 中没有对应的 `SuperH4` 语言：内置 SuperH 模块只提供
`SuperH:BE:32:SH-1/SH-2/SH-2A`。gdare2 对 `-a sh4` 明确报错，请改用
`--ghidra-language SuperH:BE:32:SH-2A`（或实际匹配的 SH 型号）。

### 3.4 加载基址

`-B` 映射到 `BinaryLoader` 的 `-baseAddr` loader arg，不修改已有程序的内存块。
对 ELF/PE 默认忽略 `-B`；PIE 重定位需要 `--force-base`，v1 不实现，会明确警告/报错。

### 3.5 `iSS` 是原始 ELF 视图

`iSS`/`iSSj` 直接解析输入文件的 ELF program headers（客户端
`src/gdare2/formats/elf.py`），不是 Ghidra 的 memory block；`iS` 才是 Ghidra
视图。因此：

- PIE 或 `-B` 强制基址下，`iSS` 的 vaddr 仍是 ELF 链接时地址；
- 非 ELF 输入（裸二进制、PE）明确返回 `NOT_SUPPORTED`，不回落为 `iS`；
- r2 5.5 会额外合成一行 `ehdr`，gdare2 不合成，行数可能少 1。

## 4. 反汇编

### 4.1 文本格式

Ghidra 的 `Instruction.toString()` 与 r2 的 `pd` 文本不同：

- 助记符大小写/别名可能不同；
- 操作数顺序、立即数格式、符号显示可能不同；
- 函数调用目标可能显示为 `FUN_...` 而不是 `sym.imp...`；
- `;-- symbol:` 标签与 EOL 注释需要 `e asm.comments=true`（默认关闭，
  避免把 Ghidra 分析器注释混入默认输出）；颜色见 §11.2。

gdare2 渲染层会尽量对齐列布局，但不改写 Ghidra 的语义文本。

### 4.2 地址宽度

r2 根据架构和配置推导地址宽度；gdare2 默认按 `Program.getLanguage().getLanguageDescription().getSize()`
和镜像基址推导，`e asm.addrwidth` 可覆盖。

### 4.3 `pd` 越界

Ghidra 不会把数据“猜”成指令；`pd` 遇到未定义区域会停止。r2 可能继续按字节解码。
这是有意的保守行为，避免输出伪指令。

## 5. 反编译

### 5.1 输出不同

Ghidra 反编译器与 Hex-Rays/r2ghidra 的输出必然不同：

- 变量命名、类型恢复、结构体布局不同；
- 控制流简化程度不同；
- 注释/行号/函数签名格式不同。

`pdc` 只保证是 Ghidra 的 C 文本；不保证与 r2 的 `pdc` 逐行一致。

### 5.2 `afv` 存储分类

Ghidra `VariableStorage` 不直接对应 r2 的 `reg/sp/bp`：

- 寄存器变量 → `reg`；
- 栈变量 → `sp`；
- 其他（内存、复合、未分类）→ `other`。

`bp` 通常为空，因为 Ghidra 不暴露帧基址分类。

### 5.3 `pdd` / `pdg` / `pdk`

没有稳定对应或需要额外插件，v1 明确报 unsupported。

## 6. 类型

### 6.1 C 声明解析

`td` 使用 Ghidra 的 `CParserUtils`/`DataTypeParser`，支持常用 C 类型，但对：

- C++ 模板/类；
- 匿名结构体/联合；
- 复杂位域；
- 编译器扩展属性；

支持程度与 r2 不同。失败时返回 `BAD_ARGS` 和解析消息，不静默创建错误类型。

### 6.2 类型名与 typedef

Ghidra 可能把 typedef 展开或保留为 `TypeDef`，r2 的 `t` 列表格式也不同。
客户端只做渲染，不改变类型语义。

`tp`/`tpv`/`tpx` 支持内建整数、枚举、指针和 char 数组；结构体/联合仍输出
原始字节，不伪造成员值。

### 6.3 `td` / `tc`

`td` 使用 Ghidra `CParser`，支持常用 C 声明；包含 `;` 的声明必须整体引用，
例如 `td 'struct demo { int a; };'`。解析失败返回 `BAD_ARGS`，并由事务回滚，
不会留下半解析类型。

`tc <name>` 使用 Ghidra `DataTypeWriter`，但只保留声明目标类型的
typedef/struct/union/enum 行，不再输出依赖类型的前导；内建类型（如 `int`）
没有生成声明时输出其原型。`tc` 无参数仍输出全部类型。
同名类型可能位于不同 category，此时请使用完整路径（如 `tc /types.h/size_t`）。

### 6.4 `afs` 函数签名

`afs <signature>` 通过 `CParserUtils` 解析并使用 `ApplyFunctionSignatureCmd` 应用。
签名中的函数名只在 Ghidra 默认名称（如 `FUN_...`）上生效；用户自定义名称不会被覆盖。
参数存储由 Ghidra 调用约定和数据类型决定，可能与 r2 的寄存器/栈布局不同。

## 7. 符号与 flag

### 7.1 flag 写回

默认 flag 是会话内状态；`f name @ addr` 要写回 Ghidra 需要：

- `-w`；
- `e ghidra.flags.write=true`。

否则只影响当前客户端，重开项目后也不会持久化。

### 7.2 删除符号

Ghidra 删除符号可能影响引用/函数名；`f-`/`f--` 需要二次确认，且在只读会话中拒绝。

### 7.3 段权限是近似值

Ghidra `MemoryBlock` 只提供读/写/执行三个布尔属性，不保留完整的 Unix `rwx`
或文件格式 section flags。`iS` 的权限列是近似值，不应当作原始 section header。

### 7.4 导入/导出是符号视图

Ghidra 没有统一的 ELF dynamic symbol / PE export table API 供所有格式复用。
`ii`/`iE` 基于 `SymbolTable` 的外部符号、全局符号和 entry point 推断，
条目数/分类可能与 r2 的原格式解析不同；需要精确导出表时应保留原始格式解析器。

## 8. 搜索

### 8.1 范围

r2 的 `search.in=io.maps` 默认在映射内存中搜索；gdare2 的 `raw` 模式读原始文件，
`io.maps` 走 `Memory.findBytes`。两者在未初始化/非加载区域结果不同。

### 8.2 字符串正则

`/r` 只遍历已定义字符串（`StringDataType`），不会像 r2 那样扫描任意字节并猜测编码。
需要全文件扫描时用 `/x` 或 `izz`。

## 9. 写入

### 9.1 `w` 是保存程序

r2 的 `w` 是写字符串；gdare2 与 idare2 一致，把 `w` 定义为“保存 Ghidra program”。
为兼容 r2，`w <text>` 仍然写字符串，因此 `w` 是重载命令：无参数时保存，
有参数时写入。需要无歧义保存时使用 `.gsave`。

### 9.2 `io.cache`

`e io.cache=true` 时补丁先进入客户端缓存，`wc` 查看、`wc+` 一次性提交为一个
Ghidra transaction、`wc-` 丢弃。`w`/`wq` 会先提交未决缓存；提交失败则不保存。
这与 r2 的写缓存语义接近，但 undo 粒度不同（一个 transaction 而非每条补丁）。

### 9.3 写入会清理 code units

Ghidra 不允许 `Memory.setBytes` 直接覆盖已定义的指令。`wx/w0/wf/wd/wc+` 会先清理
写范围内的 code units；因此写入后原反汇编会消失，需要 `a8` 或重新分析才会恢复。
r2 本身不保存反汇编，所以没有这个步骤；这是 Ghidra 的项目模型差异。

### 9.4 `u/U` 只撤销字节

PyGhidra 暴露的 `Program` 没有可调用的 undo/redo API，因此 gdare2 的 `u/U` 使用
daemon 内存中的字节补丁历史：

- 只恢复写入前的字节，不回滚反汇编、函数、注释、类型等元数据；
- 历史只覆盖 `wx/w0/wf/wd/wc+` 产生的字节写入，不包含 `a8/ad`；
- 历史是 daemon 进程级且所有客户端共享；daemon 重启后清空；
- 历史最多保留 4096 条；成功的新写入会清空 redo 栈。

### 9.5 只读请求与 daemon 策略

默认只读。只读请求不仅拒绝 `wx`，也拒绝 `u/U`，因为 undo 会改变程序状态。
多个客户端共享同一个程序时，写能力是请求级的；`gdare2d --readonly` 可强制整个
daemon 只读。

## 10. 汇编

- Ghidra 的 SLEIGH assembler 只覆盖部分语言；
- 汇编语法是 Ghidra 语法，不是 r2/rasm2 语法；
- 不支持时明确报错，不静默调用外部汇编器；
- **v2 G20 尚未实现**：`--assembler=rasm2` 目前明确报 `BAD_ARGS`，不会回退。

## 11. 输出与 JSON

### 11.1 JSON 字段

gdare2 的 JSON 尽量对齐 r2 的字段名，但 Ghidra 没有的信息（如 r2 的 `esil`、
`cycles`、`family`）会缺失。缺失字段不伪造默认值。

JSON 使用多行 pretty 输出；`~`/`|` 在渲染后按行处理，因此
`aflj~entry`、`pdj~ENDBR` 与 r2 一样只保留匹配行，而不是过滤整块 JSON。

### 11.2 颜色

颜色在 stdout 为 TTY 且未设置 `NO_COLOR` 时默认开启（`scr.color=1`），
`--color 0`、`-e scr.color=0` 可关闭。当前 `scr.color` 1/2/3 使用同一套
256 色调色板（地址/字节/助记符/注释四类）；管道与重定向不自动去色，需要时
显式 `-e scr.color=0`。

### 11.3 分页

大列表通过 `--list-offset N` 或 `e list.offset=N` 继续，作用范围是
`functions/symbols/imports/exports/strings/strings_all`；截断时提示下一页
偏移。r2 的 `-o` 是“按文件偏移映射”，gdare2 尚未实现，传入会明确报
`file-offset mapping is not implemented; use --list-offset`。

`@@`/`@@@` 的目标枚举也带 `meta`：`total` 是服务端匹配总数，`shown` 是本次
保留数量，目标超过上限时会告警。`batch` 的 `meta` 目前汇总 `total/shown/errors`，
子 op 自己的 `meta` 暂不逐项透传。

## 12. 不支持的命令

以下命令 v1 明确不做，必须报 `unsupported`，不能回退到相似命令：

- `d*`、`g*`、`ae`、`ar`、`as`、`ap`；
- `V`、`v`、`pz`、`pk`、`pq`；
- `z`、`Z`；
- `k`、`m`、`o`、`=`、`#`；
- `pdg`、`pdd`、`pdk`、`pds`；
- `ih`、`iH`、`ir`、`ic`、`id`（按 Ghidra 能力）；
- GUI 附着/实时同步（已取消，明确不做）。

## 13. 已知的“看起来像 bug”

| 现象 | 原因 |
|---|---|
| 第一次命令很慢 | JVM/Ghidra 项目加载与首次分析 |
| 第二次命令仍慢 | daemon 未复用/项目被重开/分析未完成 |
| Ghidra GUI 打不开项目 | daemon 持有项目锁；本项目不支持 GUI 附着，先关闭 daemon |
| `pd` 在数据区停止 | Ghidra 不伪造指令 |
| `afv` 出现 `other` | Ghidra storage 分类与 r2 不同 |
| `pa` 报 unsupported | 该语言没有 SLEIGH assembler |
| `f` 改名后重开项目看不到 | 未 `-w` 或 `e ghidra.flags.write=false` |
| `u` 在只读会话失败 | undo 也是修改，默认只读 |
| `u` 后反汇编未恢复 | 只回滚字节，不回滚分析元数据 |

## 14. 当前实现差异（2026-11-08）

以下差异是当前实现的真实状态，不是设计目标；已修复项见 `ROADMAP.md` §2.5。

| 现象 | 当前实现 | 目标/说明 |
|---|---|---|
| `pdj` 字段集 | 顶层数组；字段 `addr/size/bytes/text/mnemonic/symbol/call/jump/conditional` | r2 6.2.5 顶层也是数组，但含 `esil/opcode/disasm/family/type` 等；已决策不伪造缺失字段 |
| `pdi` 布局 | 地址+symbol+字节+文本（symbol 列为空时保留空白） | r2 使用 flag/注释缩进体系；gdare2 的 symbol 列是其近似，完整 flag 列在 Phase B1 后评估 |
| `tt` | 列出 typedef（与 r2 一致） | 类型读取/转换走 `tp`/`tpv`/`tpx`；不要把 `tt` 当“应用类型” |
| `--assembler=rasm2` | 明确报 `BAD_ARGS` | `pa/wa` 已使用 Ghidra SLEIGH 汇编器；rasm2 回退尚未接入 |
| `.gexec` | 需要客户端 `--allow-exec` + daemon `--allow-exec` + `-w` | 三重门控是有意的安全边界；缺任一项都报错 |
| `afB` | 不实现，报 `NOT_SUPPORTED` | r2 6.2.5 中 `afB` 是 Thumb 位宽切换；旧文档的“第 n 个基本块”语义已过时，不做兼容层 |
| batch 子 op `meta` | 逐项保留；客户端 `@@` 汇总截断并输出 `WARN` | 已实现（Phase C5）；子 op 返回 `OpResult` 时透传 `meta` |
| daemon `--readonly` 下的显式 `aa` | 返回 `READONLY` | 只读 daemon 不允许重新分析；bootstrap 分析阶段已在启动前拒绝 |
| `pdl` 布局 | 地址 + 长度 + 文本 | r2 6.2.5 的 `pdl` 只打印长度（且解码失败后出现 0）；parity 只比较行数 |
| `pd -N` 向后反汇编 | 从入口向前解码，按地址升序输出 | 指令边界由解码器决定；parity 只校验地址序列、行数与上界 |
| parity 函数数量 | Ghidra 通常比 r2 识别更多函数 | parity 比较导入函数名集合与数量区间，不要求逐项一致 |
| parity `iS` | Ghidra 额外生成 segment/external/section-header 块 | parity 比较命名 section 子集与 `.text` 大小/相对地址 |
| parity 黄金文件 | 版本或目标 sha256 不匹配时 skip | 避免 r2/Ghidra/目标升级后产生假失败；提示重新运行抓取工具 |

### 14.1 已修复（2026-11-08）

- 客户端/daemon `instance_id` 指纹统一；手工 `gdare2d` 与客户端可互相发现。
- `ppc/mips/sparc` 默认端序改为 BE；`sparc` 只接受 BE；单端序架构的冲突参数报错。
- `.g`/`.gstatus` 显示真实 `instance_id`/`state`；注册表状态在 ready/error/draining 时更新。
- `-A/-AA` 触发 `aa/aaa`；`--listen` 转发给 daemon；`--wait` 为默认行为。
- `gdare2d` 自动推导 `--project`/`--project-name`；`--attach` 不再要求目标文件。
- daemon `--readonly` 要求已有且已分析的项目，不再隐式导入/分析/保存。
- `--analysis-timeout` 与 `e ghidra.decompile.timeout` 生效；超时映射 `TIMEOUT`。
- 写命令统一客户端门控，错误信息包含 `re-run with -w to allow writes`。
- 被忽略的 `-k` 会消费其参数；daemon bootstrap 失败返回非零退出码，
  并以 `BAD_ARGS`/`NOT_READY` 等原始错误码回传客户端。
- `--loader`/`--loader-arg` 使用 Ghidra `Option.getArg()` 校验；支持类名与显示名。
- `pdi` 增加 symbol 列；`pdj` 增加 `symbol` 字段并保持顶层数组。

### 14.2 Phase B 语义说明（2026-11-08）

- **flags**：`f` 默认只修改会话内 FlagStore；写回 Ghidra 需要 `-w` 且
  `e ghidra.flags.write=true`。`f` 列表播种自 Ghidra symbols 与 functions，
  因此会包含 `FUN_...`/`LAB_...` 等 Ghidra 名称。
- **`S` / `$`**：`S` 逐行交给客户端会话执行；`$` 只实现变量，不实现 r2 的
  完整别名/环境变量体系。`$?` 列出变量。
- **`x` 系列**：`x` 是 hexdump，`x8` 是 hexpairs，`xw`/`xq` 是 32/64 位字；
  `xj` 输出 `{addr,size,bytes}`。
- **`iE` / `ia`**：`iE` 基于非外部全局符号；`ia` 列出 gdare2 配置的 20 个
  裸二进制架构，不是 Ghidra 全部语言。
- **`tp` / `tpv` / `tpx`**：仅对整数、枚举、指针、char 数组做值解码；
  结构体/联合体打印原始字节。`tpx` 从 hexpairs 直接格式化，不访问内存。
- **`/r`**：只遍历已定义字符串（`StringDataType`），不会像 r2 那样扫描任意字节。
  `cmd.hit` 会对每个命中执行一次命令，并用内部标记防止递归。
- **`pa` / `wa`**：使用 Ghidra SLEIGH 汇编器，助记符通常需要大写；没有
  SLEIGH assembler 的语言返回 `NOT_SUPPORTED`。`--assembler=rasm2` 未实现。
- **`wi` / `w6`**：`wi` 宽度 1/2/4/8，`wi+`/`wi-` 为增减；`w6d` 解码 base64
  并写入，`w6e` 编码当前字节。
- **`.gsync`**：重新拉取 `info` 并清空 FlagStore，下次 `f` 会重新播种。
- **`izz` / `search.in=raw`**：扫描/搜索原始文件并返回文件偏移，不是虚拟地址；
  `izz` 为 ASCII 可打印串（默认最短 4 字节）。
- **`/p` / `/a`**：`/p` 等价于十六进制 pattern 搜索；`/a` 先用 SLEIGH 汇编
  再搜索结果字节，因此受语言/助记符大小写限制。
- **`/r`**：只遍历已定义字符串；r2 6.2.5 的 `/r` 是引用搜索，这是有意保留的
  gdare2 语义差异。
- **`afr`**：删除并重建函数，保留非默认函数名；不等同于 Ghidra 的完整重分析。
- **`an`**：优先重命名 Function 变量/参数；纯 decompiler 生成的局部变量可能
  无法持久化重命名。
- **`.gexec`**：在 daemon 进程内执行 Python，默认关闭；必须同时满足客户端
  `--allow-exec`、daemon `--allow-exec` 与 `-w`。
