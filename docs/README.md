# gdare2 设计文档索引

`gdare2` 是一个后端接入 Ghidra、命令行与输出模型尽量兼容 radare2 的逆向工具。
本目录保存调研、设计、实施计划、开发进度与后续路线。当前仓库已完成 M0–M5：
Phase B 命令面（flags、脚本/变量、搜索/迭代、类型化读取、汇编、`.gexec`、
分析写入等）与 Phase C（parity 黄金文件、22 配置架构矩阵、batch meta、
性能/错误审计）均已完成；v1 已完成，不支持 Ghidra GUI 附着。根目录 README
提供安装、快速开始与常用命令示例。

根目录入口见 [../README.md](../README.md)。

## 阅读顺序

1. [RESEARCH.md](RESEARCH.md) — 背景调研与关键技术事实
2. [DESIGN.md](DESIGN.md) — 总体架构、进程模型、协议与核心子系统
3. [COMMANDS.md](COMMANDS.md) — r2 命令 → Ghidra API 映射
4. [DIVERGENCES.md](DIVERGENCES.md) — 与 radare2 的预期语义差异
5. [PLAN.md](PLAN.md) — 里程碑、任务拆分与验收标准
6. [DEV.md](DEV.md) — 环境、调试与测试指南
7. [PROGRESS.md](PROGRESS.md) — 里程碑状态、验收记录与下一轮计划
8. [PERF.md](PERF.md) — 性能基线、缓存评估与错误码审计
9. [ROADMAP.md](ROADMAP.md) — 当前缺陷、细化任务、执行顺序与验收矩阵
10. [TASKS-v2.md](TASKS-v2.md) — v2 兼容性补齐任务书（P0/P1/P2、验收与提交拆分）

## 一句话结论

采用 **“纯 Python 客户端 + 常驻 PyGhidra daemon”** 的两进程架构：

- 客户端负责 r2 语法解析、会话状态、过滤/管道和输出渲染，不依赖 JVM；
- daemon 持有 Ghidra `Project` 与 `Program`，负责分析、反汇编、反编译、查询和写入；
- 双方通过 loopback HTTP + JSON-RPC 通信；
- Ghidra 的独占项目锁决定了 daemon 拥有项目，多个 CLI 客户端共享同一个 daemon；
- 只做 headless；不支持 Ghidra GUI 附着，daemon 独占项目。

## 文档状态

- 版本：0.1（立项设计）
- 更新日期：2026-11-13
- 调研基线：Ghidra 12.2 PUBLIC、PyGhidra 3.2.0、idare2 0.1/b2cd758、radare2 6.2.5
- 目标：v1 命令面与可靠性收尾已完成；v2 兼容性补齐按
  [TASKS-v2.md](TASKS-v2.md) 推进，批次 A（G1–G10）已完成
- 当前状态：M0–M5 与 v1 完成；2026-11-13 完成 v2 差距审计并关闭
  G1–G10（实测离线 190 passed、真实 Ghidra 24 passed、架构矩阵
  2 passed；parity 因本机 r2 5.5.0 与黄金文件 6.2.5 不匹配而 skip）
