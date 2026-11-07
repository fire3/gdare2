# gdare2 开发进度

更新时间：2026-11-07

## 当前状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 预研 | 完成 | PyGhidra 导入/分析/反编译/持久化已验证 |
| M0 骨架 | 完成 | 两进程链路、注册表、自动拉起、首批命令与测试 |
| M1 只读核心 | 基本完成 | 只读命令、JSON 变体、调用关系、session lease、ARM/裸二进制导入已验证 |
| M2 分析/图 | 基本完成 | `@@` batch、函数/块图、`ab/ao/ai`、`afln/afl+`、`afn/afu/a8/ad` 已可用；剩黄金文件与架构矩阵 |
| M3 反编译/类型 | 进行中 | `pdc/pdcj`、`afv/afvj` 已可用；类型、签名与注释待补 |
| M4 写入 | 待开始 | `wx/wf/u/U/wc+` 与事务回滚 |
| M5 兼容/体验 | 待开始 | parity、补全、rc、架构矩阵 |
| M6 GUI 桥 | 待开始 | Ghidra GUI 附着 |

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

当前测试：离线 `51 passed`；真实 Ghidra `8 passed`。

验收命令：

```bash
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 5' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 's 0x106760; pd 5; px 16' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 20~+call' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -j -qc 'iI' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 1 @@f:^entry$' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'agf @ entry; ab @ entry; ao @ entry; ai @ entry' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 's entry; afn demo_func; .gsave' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -w -qc 's 0x400000; a8 9090c3; ad 1; .gsave' /tmp/blob.bin
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pdc @ entry; afv @ entry' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -L
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
```

## 已知缺口

- `afB` 当前 r2 语义已变为 Thumb 位宽切换，暂不按旧文档实现；
- `/bin/ls` 与 ARM32 样本的结构化黄金文件、架构矩阵尚未补齐；
- batch 还没有返回统一 `meta`（总数/截断）信息；
- 类型、函数签名、注释、搜索与通用写入命令尚未实现；
- `pdi/pdl/pd -n` 与 r2 parity 黄金文件尚未补齐；
- `-i/-I` 当前按打开后脚本处理；
- GUI 桥未开始。

## 下一轮

1. 建立 `/bin/ls` 与 ARM32 样本的结构化黄金文件；
2. 增加 `tools/arch_matrix.py` 与首批架构矩阵；
3. 完善 batch 分页 `meta` 与错误码一致性；
4. 继续 M3：函数签名、类型 `t/ts/td/tu` 与注释 `C*`。
