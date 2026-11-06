# 参考机制、版本与许可证记录

调研日期：2026-11-06。实现以 Linux UAPI 和本仓库测试为准，参考项目的功能声明不自动成为 cincta 能力。

## 固定参考版本

Sandlock 选择固定 tag `v0.8.7`，提交 `327c1aad3207eda3b618f4bf14fc4d192eed8cb8`。[官方 tag 列表](https://github.com/multikernel/sandlock/tags) 与 [提交页面](https://github.com/multikernel/sandlock/commit/327c1aad3207eda3b618f4bf14fc4d192eed8cb8) 已核对 tag 对应关系，提交中的 workspace package 标注 Apache-2.0。该提交 [LICENSE](https://github.com/multikernel/sandlock/blob/327c1aad3207eda3b618f4bf14fc4d192eed8cb8/LICENSE) 为 Apache-2.0、版权人为 Multikernel Technologies, Inc.。cincta 未复制 Sandlock 源码。

先读取上游当前 [架构文档](https://github.com/multikernel/sandlock/blob/main/docs/architecture.md) 与源码树，再通过本地 Linux VM 使用 GitHub API tree 和 raw URLs 下载固定提交的源码。以下 SHA256 是下载后实际计算值，文件保留在验证 VM 的 `/tmp/cincta-research-v087/`，不作为 cincta 的编译输入，也不随源码打包。固定版本并无 `docs/architecture.md`，该文档只作当前架构背景，不能当成 v0.8.7 的文件。

| 固定提交文件 | 字节数 | SHA256 |
|---|---:|---|
| LICENSE | 10776 | `acd4c12f36e0da77644436747d76bf58d44f807869f3f79623086d03b7688702` |
| crates/sandlock-core/src/landlock.rs | 36469 | `b4a9de4fc05265227fee3138c12215aaef04c9452ff18838e1afbb2f3eb6afab` |
| crates/sandlock-core/src/seccomp/bpf.rs | 15423 | `a4365665c65b8288843224b767fe7fb1c574287040fac63a5a3f24326afaec09` |
| crates/sandlock-core/src/seccomp/dispatch.rs | 61464 | `036413b6cae4cf5dc26ede68357db007357123e693fe2a32b441a4dfc9bb2b1d` |
| crates/sandlock-core/src/seccomp/notif.rs | 130768 | `c3906b563103a50ca80e0950de90dee46e43be241e2d1f7e8ef55584058897c9` |

固定源码核读重点：`landlock.rs` 的 `base_fs_access`/`write_access` 按 ABI 累加权限、`add_path_rule` 使用 O_PATH 并区分文件/目录、`compute_scope_mask` 先要求调用者检查 strict-unavailable、`confine_inner` 明确 handled 掩码并最终 restrict；`seccomp/bpf.rs` 的 `assemble_filter` 区分 deny/notification 且拒绝同一调用重叠，安装纯 deny 与 listener 使用不同入口；`notif.rs` 把延后决策和 FD 注入作为独立监管状态。研究只覆盖这些相关关键函数和通知状态定义，不声称已审计上游所有功能。

| 对象 | 研究结论 | 采用方式 |
|---|---|---|
| Landlock | 静态对象授权、规则继承，内核作最终决策 | 自主实现原始 syscall，不复制上游封装 |
| 经典 seccomp BPF | syscall/参数可过滤，不能解引用目标指针 | 自主生成过滤器，先检查架构 |
| Sandlock 启动序列 | fork 后限制，再 exec；静态内核规则与动态监管分层 | 借鉴分层原则，不移植其 Rust 运行时 |
| Sandlock notification supervisor | 公开架构列出网络代理、资源跟踪、COW 等动态功能 | 首版明确排除 |
| 动态 connect/bind/IP 决策 | 需要安全读取 sockaddr、身份与FD处理；TCP端口规则不等于IP策略 | 首版仅 none/host，不做伪IP白名单 |
| /proc 虚拟化和 COW | 需要拦截 open/getdents/rename 等以及一致性处理 | 首版不声明 |

## 官方机制依据

- [Linux 6.12 Landlock API](https://docs.kernel.org/6.12/userspace-api/landlock.html)：作为 ABI6 设计基线。跨目录 REFER 从 ABI2、TRUNCATE 从 ABI3、设备 IOCTL_DEV 从 ABI5、signal/abstract UNIX scope 从 ABI6 出现。预先打开 FD 不会因套用文件规则撤销原有读写能力，因此 exec 前关闭额外继承 FD；保留 stdio 是显式能力授权。层内规则授权取并集，层与层相交。
- [Linux seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html)：过滤器只检查 syscall 元数据，不能安全解析任意路径指针；必须先检查 syscall 架构以防编号混淆。cincta 使用 errno 拒绝危险调用，错误 ABI 终止进程；不使用 TRACE/USER_NOTIF。
- [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)：no_new_privs 与过滤器安装、过滤器继承、x32 与多ABI风险是过滤器审查重点。静态 denylist 减少攻击面，不构成独立完整隔离边界。
- [PR_SET_CHILD_SUBREAPER](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)：monitor 接管孤儿后代并 wait；只发送组信号不足以证明已回收。
- [PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)：该属性在 fork 子进程清除，故不能仅靠它保证后代清理。
- [pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)：调用方身份以进程句柄固定，通过 poll 等待整进程退出，避免父线程结束引发误取消。
- [proc children](https://man7.org/linux/man-pages/man5/proc_tid_children.5.html)：CONFIG_PROC_CHILDREN 提供直接子任务列表；并发退出时可能遗漏，因此只能重复枚举并结合 __WALL wait/ECHILD 判断，不能把单次快照当完整进程树。
- [Docker seccomp profiles](https://docs.docker.com/engine/security/seccomp/)：默认外层过滤与应用过滤叠加；容器环境必须实测，不应靠特权或 unconfined 掩盖依赖。

以上均为一手资料；设计是结合它们推导出的 cincta 选择，并非内核对本 CLI 的安全认证。

## 许可证与依赖清单

| 名称 | 用途 | 许可证/处理 |
|---|---|---|
| cincta C 源码与文档 | 原创实现 | 以仓库 LICENSE 为准 |
| Sandlock v0.8.7 | 研究参考，不链接或复制 | Apache-2.0；固定版本与核对状态如上 |
| Linux UAPI headers | 构建时系统接口 | 由目标系统 headers 包提供；逐头 SPDX 及 Linux syscall note 适用 |
| libc | 标准库和 syscall wrapper | 取决于构建选择；glibc/musl 随产物记录，静态发布保留相应许可 |
| Python 3 | 测试/示例工具 | 不打入 CLI；标准库许可由 Python 发行包提供 |

若未来复制任何参考代码、内嵌第三方实现或改变 libc 链接方式，须更新清单、保留所需声明并重新检查发布包，而不是继续沿用“无第三方运行时依赖”的概括。
