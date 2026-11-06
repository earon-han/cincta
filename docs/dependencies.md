# 外部依赖与运行前提

## 运行依赖

| 项目 | 要求 | 不满足时 |
|---|---|---|
| 操作系统/架构 | Linux 原生小端 x86_64 或 aarch64 | 拒绝构建/执行；macOS 只负责驱动 Linux 验证 |
| Landlock 严格模式 | ABI≥6；上游 Linux 6.12 起 | setup 拒绝执行 |
| Landlock `--compat` | ABI≥3；上游 Linux 6.2 起 | 不会跳过文件沙箱 |
| seccomp BPF | CONFIG_SECCOMP=y、CONFIG_SECCOMP_FILTER=y、可安装过滤器 | setup 拒绝执行 |
| LSM | CONFIG_SECURITY_LANDLOCK=y，且启动有效 LSM 列表包含 landlock | ENOSYS/EOPNOTSUPP 等需在探测结果呈现 |
| no_new_privs | 允许 PR_SET_NO_NEW_PRIVS，不能依赖 setuid 提权 | 拒绝执行 |
| 进程监管 | fork、pipe、poll、wait、prctl subreaper、信号发送允许 | 无法建立安全生命周期即拒绝执行 |
| pidfd_open | Linux 5.3 起；调用方进程身份句柄允许创建和 poll | 无法检测调用方退出即拒绝执行 |
| close_range | Linux 5.9 起；外层策略允许 flags=0 批量关闭 FD | 无法保证继承 FD 清理即拒绝执行 |
| procfs children | CONFIG_PROC_FS=y、CONFIG_PROC_CHILDREN=y，真实 procfs 挂载于 /proc，允许监管者读取自身 task/children | 无法建立可靠回收路径即拒绝执行；运行中失效报告清理未完成 |
| libc | 动态版本需要相应 ELF loader/libc；静态版本不依赖目标机 libc | 选择匹配发行版构建，或使用静态产物 |
| 目标程序依赖 | 二进制、loader、库、解释器及所需配置必须显式授权 | 业务 exec/open 返回权限错误 |

ABI 版本比版本号字符串可靠：发行版可能回移特性，也可能禁用 LSM。`/sys/kernel/security/lsm` 不可读时不据此直接断言 Landlock 缺失，使用 `landlock_create_ruleset(...VERSION)` 探测。`probe` 成功也不能预先证明所有路径规则、资源限制和实际 `restrict_self` 会安装成功。[Linux Landlock 文档](https://docs.kernel.org/6.12/userspace-api/landlock.html)

不要求 root、CAP_SYS_ADMIN、特权容器、用户 namespace、cgroup 委派、eBPF 加载权限或 seccomp user notification。这里的 BPF 是经典 seccomp 过滤器，不是需要特权加载的通用 eBPF 程序。pidfd_open 与 close_range 已早于本版最低内核提供，但容器外层策略仍可能单独禁用它们。[pidfd_open 手册](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)、[close_range 手册](https://man7.org/linux/man-pages/man2/close_range.2.html)、[proc children 手册](https://man7.org/linux/man-pages/man5/proc_tid_children.5.html)

## 容器与主机安全策略

容器使用宿主 Linux 内核，镜像里更新用户态并不会增加 Landlock ABI。Docker Desktop 同样取决于其 Linux VM 的内核。默认 Docker seccomp、AppArmor、SELinux 或其他外层策略会与 cincta 累加，不能被 cincta 放宽；发行版、Docker 版本和管理员策略不同可能影响 UAPI 可用性。[Docker seccomp 官方文档](https://docs.docker.com/engine/security/seccomp/)

应先在普通非特权、非 root 容器中运行 `probe` 和完整测试；不要把 `--privileged`、`seccomp=unconfined` 或 `apparmor=unconfined` 作为默认解决方案。外层策略拒绝 Landlock 或 seccomp 时记录 BLOCKED 和 errno，由部署者决定是否批准最小定向放行。`--compat` 不绕过容器策略。

建议容器禁用额外 capabilities，设定外层 pids/memory 限额，仅挂载测试需要的源码/数据。避免授予 Docker socket、宿主 `/proc`、设备节点和特权可写目录。`--network host` 是 cincta 策略选项，不是 Docker `--network=host`：它只表示本 CLI 放弃对目标命令对外网络目的地的约束，并不会改变容器 namespace。

## 构建、测试、分发依赖

源码构建需要 C17 编译器（GCC 或 Clang）、make、**Linux UAPI headers ≥6.2** 和 libc headers；源码通过 linux/version.h 和关键 syscall 宏在编译期强制检查，避免旧头文件静默漏掉过滤。无需 libseccomp/pkg-config/cgo。较新 Landlock ABI 位由固定 UAPI 定义提供，仍以运行时 syscall 探测为准，不能模拟内核能力。静态链接需要静态 libc 开发包，musl 或 glibc 的具体产物应在对应平台测试；本次交付使用 glibc 静态链接，不把未运行的 musl 产物算已验证。

测试和 Agent 示例需要 Python 3 标准库，部分回归探针由 C 编译。Docker 测试需要可访问的 Docker CLI/daemon、构建镜像及基础包来源；它不是运行 cincta 二进制的依赖。VM 验证需要实际 Linux VM，不能用 macOS 的 clang 编译成功代替。

分发 tar 包应包含 CLI、使用/设计/依赖文档、许可证、版本与 SHA256 校验值；不要把构建主机的动态二进制描述为普遍可移植。源码没有供应第三方沙箱实现；UAPI headers 在构建系统提供，遵循其 SPDX 与 syscall exception。参考项目许可证记录见 [调研记录](research.md)。

## 能力缺失与部署限制

- ABI3–4 没有设备 ioctl 的 Landlock 权限，但 BPF 在所有支持 ABI 上统一拒绝全部 ioctl，有效 ioctl 限制相同。ABI3–5 没有 signal/abstract UNIX scope，兼容结果必须列出 scope 差异；BPF 额外拒绝 signal-send 操作不能伪称具备内核 scope。
- 即使新版内核支持更多 Landlock 权利，本版也只声明已编码和已测试的权限集合。
- 运行用户为 UID0、具有保留 capabilities、可管理同 UID 外部进程或主动开放危险 stdio，都会改变威胁模型。建议普通用户执行。
- rlimit 不是全树配额；CLI 与 monitor 同时终止、系统 OOM 或不可中断任务时，外部服务管理器/cgroup 可提供更强回收边界。普通 monitor 单独崩溃由存活 CLI 的 subreaper 恢复路径处理。
