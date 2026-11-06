# Changelog

## 0.1.0-preview.1 — 2026-11-06

- 初始C17独立CLI和静态Linux二进制交付。
- Landlock ro/rw/rx、严格ABI6与显式ABI3兼容、raw经典seccomp BPF。
- 默认断网，显式IPv4/6 host，危险syscall和metadata/ioctl限制。
- 清空环境、关闭额外FD、rlimit、JSON结果与阶段计时。
- pidfd调用方退出监视、双subreaper、超时/取消及单层监管故障回收。
- 独立设计/实现/测试Agent交叉审查，真实VM/Docker验证，原始benchmark、CI、打包校验。

预览范围和平台验证状态见docs/validation.md；动态代理、COW、域名策略和树级cgroup配额不在本版。
