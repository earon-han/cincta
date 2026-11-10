# Linux机制与实现依据

实现以Linux UAPI、本仓库源码及真实内核测试为准。本文列出公开接口依据和相应实现位置，不包含本地调研日志或外部项目的源码下载记录。

| 机制 | 实现中的用途 | 主要源码 |
|---|---|---|
| Landlock | 固定ro/rw/rx对象，限制文件访问与执行，子孙继承规则 | `src/security.c` |
| 经典seccomp BPF | 检查架构、系统调用及标量参数，执行拒绝/放行/通知动作 | `src/security.c` |
| seccomp notification | 获取请求；固定地址空间、复制参数、校验请求；代执行并返回结果或FD | `src/broker.c`、`src/filebroker.c`、`src/network.c` |
| pidfd、subreaper与wait | 固定原调用方身份，监视退出，收养和回收后代 | `src/caller.c`、`src/preparation.c`、`src/supervisor.c` |
| cgroup v2 | 已委派子树中的业务树配额、统计及清理 | `src/resources.c` |
| 物理文件快照 | 独立baseline/tree、差异和完整导出，不自动写回源目录 | `src/workspace.c` |

## 官方接口资料

- [Landlock API](https://docs.kernel.org/6.12/userspace-api/landlock.html)：权限、ABI、继承及规则组合。
- [seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html)：过滤器执行与动作。
- [seccomp notification](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)：通知ID、响应和FD交付。
- [pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)和[subreaper](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)：进程身份和后代回收。
- [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)：控制器、委派、统计和进程迁移。

BPF不能解引用业务指针。动态敏感操作必须使用可信副本和固定对象代执行；审计中的原生CONTINUE不代表已观察到系统调用的完成结果。完整安全边界见[设计](design.md)、[网络](network.md)和[审计](audit.md)。

## 构建依赖与分发

项目许可证以根目录[LICENSE](../LICENSE)为准（MIT）。Linux UAPI headers、libc和测试用Python由构建系统提供；没有链接libseccomp。静态启动器不等于业务程序无需动态库或DNS配置。分发所用libc的版本和许可条件应随具体构建核对，不能把本项目MIT许可证当成所有链接组件的许可证。具体依赖见[部署条件](dependencies.md)。
