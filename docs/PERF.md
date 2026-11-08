# 性能基线（Phase C6）

更新时间：2026-11-08

本文件记录 gdare2 的冷启动与常用命令延迟，并给出缓存评估结论。数据由
`tools/perf_probe.py` 生成，原始结果在 [perf-baseline.json](perf-baseline.json)。
基线只用于观察趋势，不是通过/失败门禁。

## 1. 采集方法

```bash
GHIDRA_INSTALL_DIR=$HOME/ghidra/current \
  .venv/bin/python tools/perf_probe.py /bin/ls \
  ../vulfirm/OverFlow/R6700v3/upnpd --output docs/perf-baseline.json
```

- 每个目标使用独立的临时 `GDARE2_DATA_DIR` 与 `XDG_RUNTIME_DIR`；
- `cold_open_ms` 是首次 `gdare2 -qc 'iI'`，包含导入与自动分析；
- 其余命令在同一个常驻 daemon 上重复 3 次，报告中位数；
- 每条命令都经过完整客户端进程启动，因此包含 Python 解释器启动成本；
- 结束时用 `.gclose` 关闭 daemon 并删除临时项目。

环境：Ghidra 12.2 PUBLIC、PyGhidra 3.2.x、Python 3.13.15、radare2 6.2.5。

## 2. 基线结果

### `/bin/ls`（x86:LE:64:default，536 个函数）

| 项目 | 耗时 |
|---|---|
| 冷启动（导入 + 自动分析 + 首次 `iI`） | 17809.13 ms |
| `iI`（warm） | 73.51 ms |
| `afl`（warm） | 85.75 ms |
| `is`（warm） | 143.65 ms |
| `pd 100`（warm） | 75.91 ms |
| `pdc`（warm） | 86.44 ms |

### `../vulfirm/OverFlow/R6700v3/upnpd`（ARM:LE:32:v8，1099 个函数）

| 项目 | 耗时 |
|---|---|
| 冷启动（导入 + 自动分析 + 首次 `iI`） | 94855.71 ms |
| `iI`（warm） | 68.60 ms |
| `afl`（warm） | 118.52 ms |
| `is`（warm） | 203.07 ms |
| `pd 100`（warm） | 76.18 ms |
| `pdc`（warm） | 86.62 ms |

## 3. 解读

- 每次 CLI 调用约 65–85 ms 是进程启动与 Python 导入的下限；REPL 会话内不会支付
  这部分成本。
- 冷启动主要由 Ghidra 导入与自动分析决定；ARM 固件约 100 s，与样本大小和函数
  数量正相关。
- `is` 与 `afl` 的额外时间来自 Java 集合遍历和逐项转换为 Python 字典；`pdc` 的
  中位数包含 decompiler 进程复用后的稳定开销。
- 这些数字与 Phase C 前的抽样一致，没有性能回归。
- 第一次执行 `pa`/`wa`/`/a` 时，Ghidra SLEIGH 汇编器初始化需要 20–60 s；
  同一 daemon 内的后续汇编约 0.3 s。客户端因此对汇编 op 使用独立的
  `ghidra.assemble.timeout`（默认 180 s），避免首次汇编被 30 s 的通用 RPC
  超时误杀。

## 4. 函数/符号缓存评估

ROADMAP C6 要求评估以 `Program.getModificationNumber()` 作为失效键的缓存。

结论：**暂不实现**。

理由：

1. warm `afl`/`is` 的 daemon 侧成本约 50–135 ms，其中相当一部分是命令行进程
   启动（约 65–85 ms），缓存只能压缩前者；
2. Ghidra 的 modification number 在事务提交时变化，作为失效键是正确的，但写命令
   （`wx`/`afn`/`CC`/`tc` 等）会频繁使缓存失效，收益集中在纯只读 REPL；
3. 缓存需要在 runtime 中保存完整的 Python 字典列表，ARM 样本 1099 个函数时的内存
   与失效一致性成本高于当前收益。

若后续出现大量 `afl`/`is` 连续调用的真实工作流，可按以下方案实现：
在 `GhidraRuntime` 中保存 `(modification_number, functions, symbols)`，op 入口先比较
`program.getModificationNumber()`，命中则直接返回浅拷贝。该方案不需要改变协议。

## 5. 错误码与退出码审计

`tests/test_errors.py` 覆盖错误类、`EXIT_CODES` 与 CLI 退出码的一致性：

| code | 退出码 | 场景 |
|---|---|---|
| `BAD_ARGS` | 2 | 参数/表达式/协议参数错误 |
| `NOT_READY` / `ANALYZING` / `LOCKED` / `CONNECTION` | 3 | daemon 未就绪、分析中、锁定或连接失败 |
| `TIMEOUT` | 4 | 请求或分析超时 |
| `READONLY` / `NOT_FOUND` / `NOT_FUNC` / `NOT_SUPPORTED` / `UNKNOWN_OP` | 1 | 普通命令错误 |
| 其他未知 daemon code | 1 | 兜底 |

审计中发现 `CONNECTION` 只存在于 `ConnectionFailure.exit_code`，未登记到
`EXIT_CODES`；Phase C 已补齐，daemon 返回同名错误时也会得到退出码 3。
