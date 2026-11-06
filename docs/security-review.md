# 独立安全设计与实现审查

日期：2026-11-06；对象：`0.1.0-preview.1` 的 C 原语、CLI、monitor、结果序列化与对抗测试。角色分工：主 Agent 集成 CLI/生命周期；kernel_security Agent 实现内核限制；tests_release Agent 实现验证/打包；security_design Agent 负责设计依据、独立审阅与提出修正，不修改实现代码。所有 Agent 使用相同工作区，因此这属于职责分离的代码审查，不等同于组织外部安全审计。

## 已检查的关键不变量

| 检查面 | 审阅结论 |
|---|---|
| 业务运行前安装 | payload 只有 no_new_privs、能力清理、Landlock、BPF 全部成功后才报告 ready 并 exec；失败调用 child_error 退出 |
| 文件规则 | 规则先固定 O_PATH FD；最终 symlink/特殊文件拒绝；单文件权限掩码不含目录专用位；所有错误路径释放 FD |
| ABI/截断 | ABI<3 拒绝；严格 ABI<6 拒绝；TRUNCATE/REFER 位均纳入；兼容不得跳过文件沙箱 |
| 多 syscall ABI | 先比对 AUDIT_ARCH，x86_64 再检查 x32 标志；不匹配 KILL_PROCESS；明确拒绝大端构建 |
| BPF 控制流 | deny 使用邻近短跳转；clone、prlimit64、fcntl、host-socket 分支逐条核对，分支后重新加载 syscall nr，未发现跳过检查的落点 |
| 组身份和后代 | setsid/setpgid/CLONE_PARENT/new namespace 禁止；clone3 返回 ENOSYS；monitor 作为 subreaper 回收后代；组首领回收后不再向数字 PGID 反复发信号 |
| 能力代理入口 | ptrace、process_vm、pidfd_getfd、io_uring、mount API、keyring 等路径拒绝；host 模式 socket 仅接受 IP family，socketpair 始终拒绝 |
| 生命周期 | CLI 用调用方 pidfd 转为取消；monitor 用控制管道 EOF 处理 CLI 死亡；CLI subreaper 处理 monitor 单独崩溃；正常退出也清理后台后代；清理必须 wait 到 ECHILD 才置 true |
| 结果文件 | 执行前独占创建，O_EXCL/NOFOLLOW，0600；payload 关闭该 FD；保护字段必须基于收到 ready，不能只根据 probe 判定 |
| 测试有效性 | 用真实内核 syscall 和受限业务程序，不用 mock 代替；严格/兼容分别统计；存在外层策略时 errno 不能唯一归因于 cincta |

## 审查提出并已落实的修正

| 问题 | 风险 | 实现处理 |
|---|---|---|
| 将 Landlock 当成所有文件操作的过滤器 | chmod/chown/时间/xattr 可能绕过内容访问规则修改未授权对象 | 拒绝完整 metadata 修改 syscall 族及新 *at 编号 |
| 只处理设备 ioctl | 普通文件 inode ioctl 和继承 TTY 可引入元数据修改或输入注入 | 两模式统一拒绝全部 ioctl，使用指南说明兼容性代价 |
| 仅禁 kill | tkill/tgkill/排队信号/pidfd 路径仍可影响同 UID monitor | ABI3–5 禁止全部 signal-send 入口；严格模式由 Landlock signal scope 限制目标 |
| host 直接允许全部 socket family | UNIX SCM_RIGHTS 可从外部接收已打开 FD；netlink 等扩大主机能力 | 只允许 AF_INET/AF_INET6，socketpair 拒绝 |
| 只使用单个 PDEATHSIG | fork 后代不继承该属性，后台任务可能残留 | 独立 monitor、固定 PGID、subreaper、控制管道 EOF |
| 只覆盖 CLI 退出 | 真正的 Agent 父进程退出未必导致 CLI 退出 | CLI 固定调用方 pidfd、poll检测整进程退出，并核对父进程身份变化，避免父线程退出误取消 |
| probe 的 ABI 查询成功被当成规则可安装 | 外层策略可允许查询却拒绝 restrict_self，误报 supported | 临时子进程实际创建/限制；安装失败保留 errno 并将可用 ABI 置零 |
| setup 前受信号却按 running 输出 | JSON 误报实际保护已经生效 | ready 握手独立记录；未确认限制时 stage 为 setup |
| 继承 FD 的异步通知能力 | fcntl 设置通知所有者/异步标志可向外部目标发送信号 | 拒绝 F_SETOWN/F_SETOWN_EX/F_SETSIG 及 O_ASYNC 设置 |
| 外部 PID 的资源/调度操作 | prlimit64、调度和进程内存操作可干扰同 UID 监控者 | prlimit64 仅允许 PID=0；相关调度/跨进程内存 syscall 拒绝 |
| 首次 killpg 与并发 fork | 扫描进程组时可能漏掉新后代，重复使用已回收 PGID 又可能误杀 | 保留组首领到首次 killpg；后续按 procfs 直接子进程列表发信号，wait前保持PID身份并重复处理新孤儿 |
| clone 后代 exit_signal=0 | 常规 waitpid 可能忽略非 SIGCHLD clone 后代 | 回收使用 __WALL |

## 测试解释与待验证项

源码审阅不能替代内核验证。实际结果必须保留环境和逐项原始证据；VM 与容器分开记录，容器共享 VM 内核不算第二种内核。ABI4 上兼容通过不代表 ABI6 scope 已验证；严格模式拒绝旧 ABI 是 fail-closed 用例通过，严格执行能力本身仍为 BLOCKED。

拒绝 bpf/unshare 等调用在 Docker 中可能也来自外层 seccomp、LSM 或能力检查；这些结果证明禁止行为被拒绝，但无法单独证明 cincta 的具体规则是唯一拒绝者。文件正反例、新 socket 正反例和额外 BPF 探针应结合不受限基线解释。清理验证应区分“已停止”与“已 wait 回收”，不能只看到 Z 状态就宣称无残留。

预览交付前至少执行：文件读取/写入/截断、规则重叠、路径逃逸、跨树 link/rename、继承 FD、网络 none/host、危险 syscall、超时/取消、业务异常、CLI SIGKILL、真实调用方退出、并发与资源限制。每项均允许 PASS/FAIL/BLOCKED，缺条件不能计为 PASS。新增封堵入口应持续补回归；denylist 的安全维护需要跟踪新 syscall 和已支持 syscall 的新参数。

稳定版仍需外部审计及两种原生架构严格模式的真实覆盖。未审计整个 Linux syscall 集合；不承诺抵御内核漏洞、不提供 namespace 隔离、全树资源硬配额或 CLI 与 monitor 同时被管理员 SIGKILL 后的完全清理。不可中断任务超过清理截止时间时结果必须为 cleanup_complete=false；这属于部署边界，需要服务管理器或 cgroup 提供更强外层控制。可信调用方提供的 stdio 和授权的可写目录仍是明确开放的能力。

## 结论

当前实现与本版冻结的静态保护范围一致，审查发现的上述边界问题已在源码中得到针对性处理。是否可发布以最终真实环境验证、未关闭问题及 [设计发布门槛](design.md) 为准；本文件不单独授予稳定版发布结论。
