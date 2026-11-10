# cincta 开发约定

本仓库是 C17 Linux CLI 沙箱。公开范围和安全不变量见 `docs/design.md`，外部依赖见 `docs/dependencies.md`。

- 修改保护机制前阅读 `src/security.c`、`src/supervisor.c`、`include/cincta.h` 和对应对抗测试。
- 不允许限制安装失败后继续执行；不得自动关闭 Landlock/seccomp。
- 修改系统调用过滤时核对 native x86_64/aarch64、x32、参数跳转和替代入口。
- 修改回收时验证正常退出、超时、取消、CLI/monitor 单独故障、调用方退出和 clone 特殊退出信号。
- `make check`、`make test` 是检查入口；`make STATIC=1` 构建独立交付产物。
- 安全功能必须在真实 Linux 内核实测。Docker 与虚拟机分别记录；QEMU 用户态模拟不冒充真实 seccomp 验证。
- 结果使用 PASS/FAIL/BLOCKED，保留环境、源码/二进制指纹、原始样本，不把缺失能力算通过。
- 文档、CLI/结果契约和测试一起更新，变更说明记录行为、验证及实际限制。
- 安全设计、实现、测试由不同 Agent 分工并交叉审查；并行编辑避免同文件冲突。
- 不提交密钥、虚拟机镜像、构建缓存。发布包包含来源记录和 SHA256；稳定门槛未完成只能发布 preview。
- 本地开发计划、任务台账和原始运行报告不进入Git或默认交付包；正式文档保留可复现步骤和明确标注日期/源码版本的验证摘要。
