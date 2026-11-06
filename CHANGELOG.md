# Changelog

## 0.2.0-preview.1 — 2026-11-06 本地候选

- 启动前固定文件授权根，payload与可信文件worker使用同源Landlock对象。
- 可选seccomp notification broker，两阶段filter引导与listener/ptracer锁定。
- IPv4/IPv6、TCP/UDP、CIDR、端口范围及域名地址快照；复制参数后代执行，拒绝路由和FD委托旁路。
- 固定rw对象的受限metadata兼容；默认静态拒绝语义保留。
- 私有物理工作区双副本、diff、独占完整导出、保留/丢弃及显式workspace-exec；不自动写回。
- 可选委派cgroup v2业务树内存、pids、CPU带宽/累计预算、统计与回收。
- pidfd/signalfd/timerfd事件驱动与独立broker，慢通知不阻塞monitor取消。
- JSONL请求/决定/代执行结果及文件FD交付审计，额度与交付完整性检测；旧内核O_PATH原生回退明确标注。
- 六套独立测试统一入口、分环境报告及源码/二进制指纹，Docker/CI完整收集证据。

本节描述新增实现，不代表最终验收或外部审计已完成。实际内核/架构、PASS/FAIL/BLOCKED、性能和发布状态见docs/validation.md。

## 0.1.0-preview.1 — 2026-11-06

- 初始C17独立CLI和静态Linux二进制交付。
- Landlock ro/rw/rx、严格ABI6与显式ABI3兼容、raw经典seccomp BPF。
- 默认断网，显式IPv4/6 host，危险syscall和metadata/ioctl限制。
- 清空环境、关闭额外FD、rlimit、JSON结果与阶段计时。
- pidfd调用方退出监视、双subreaper、超时/取消及单层监管故障回收。
- 独立设计/实现/测试Agent交叉审查，真实VM/Docker验证，原始benchmark、CI、打包校验。

预览范围和平台验证状态见docs/validation.md；动态代理、COW、域名策略和树级cgroup配额不在本版。
