# gdare2 开发进度

更新时间：2026-11-07

## 当前状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 预研 | 完成 | PyGhidra 导入/分析/反编译/持久化已验证 |
| M0 骨架 | 完成 | 两进程链路、注册表、自动拉起、首批命令与测试 |
| M1 只读核心 | 基本完成 | 只读命令、JSON 变体、调用关系、session lease、ARM/裸二进制导入已验证 |
| M2 分析/图 | 进行中 | 已有 `af/afb`、`sb/sf/sF/so/sn/sp`；继续补 `@@`、`aflc/afln`、块图 `agf` |
| M3 反编译/类型 | 待开始 | `pdc`、`afv`、类型与注释 |
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

验收命令：

```bash
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 5' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 's 0x106760; pd 5; px 16' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -qc 'pd 20~+call' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -j -qc 'iI' /bin/ls
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/gdare2 -L
.venv/bin/python -m pytest -q
GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
```

## 已知缺口

- session lease、heartbeat 与活跃会话计数尚未实现；
- `@@`/`@@@` 迭代器与 batch RPC 尚未实现；
- 反编译、类型、注释、搜索、写入命令尚未实现；
- `pdi/pdl/pd -n` 与 r2 parity 黄金文件尚未补齐；
- `-i/-I` 当前按打开后脚本处理；
- GUI 桥未开始。

## 下一轮（M2）

1. 实现 `@@f`/`@@i`/`@@b` 与 batch RPC；
2. 补 `agf/agfj/agfd`、`ab/ao/ai`；
3. 补 `afn/afu/afln` 等写操作；
4. 建立 `/bin/ls` 与 ARM32 样本的结构化黄金文件；
5. 增加 `tools/arch_matrix.py` 与首批架构矩阵；
6. 继续完善分页 `meta` 与错误码一致性。
