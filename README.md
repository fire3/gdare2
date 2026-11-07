# gdare2

`gdare2` 是一个以 Ghidra 为分析后端、命令行与输出模型尽量兼容 radare2 的逆向工具。

当前处于**立项设计阶段**，仓库尚未包含实现代码。

- 文档索引：[docs/README.md](docs/README.md)
- 背景调研：[docs/RESEARCH.md](docs/RESEARCH.md)
- 总体设计：[docs/DESIGN.md](docs/DESIGN.md)
- 命令映射：[docs/COMMANDS.md](docs/COMMANDS.md)
- 语义差异：[docs/DIVERGENCES.md](docs/DIVERGENCES.md)
- 实施计划：[docs/PLAN.md](docs/PLAN.md)
- 开发指南：[docs/DEV.md](docs/DEV.md)

核心结论：纯 Python CLI + 常驻 PyGhidra daemon；loopback HTTP/JSON 通信；
daemon 独占 Ghidra 项目；客户端默认只读，`-w` 按请求开启写入能力。
