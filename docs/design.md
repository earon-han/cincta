# v0.1 设计与能力边界

本设计冻结《实施计划.txt》的 B00/B03 首版范围。版本为 `0.1.0-preview.1`；预览版表示能力和验证记录可审查，不代表已通过独立渗透测试或稳定版发布门槛。

## 目标与语言

面向通用 Agent 的非交互 Linux CLI，采用 C17，直接调用内核 Landlock 和经典 seccomp BPF；不依赖 libseccomp、守护服务、容器管理器或 Agent 框架。C 与 UAPI 数据结构一致，产物可以静态链接、独立分发，也便于用户审阅。代价是内存安全和过滤器跳转正确性需要严格编译检查、限制数组规模及独立对抗测试；本版不引入复杂指针解析代理。Go 可用于上层 SDK，Rust 更适合大型监管器，但均不是本版交付的必要条件。

目标执行架构仅为 Linux 原生 x86_64 和 aarch64，小端 64 位。其他 syscall ABI 拒绝执行。macOS 是开发控制端，不能提供这些内核保护。

## 威胁模型

不可信命令可以执行原生代码、派生进程、操纵其地址空间和系统调用参数。攻击目标包括读取未授权内容、修改未授权文件、创建网络连接、改变进程身份和逃避回收。可信计算基包括 Linux 内核、启动器、生命周期 monitor、策略输入及调用方。调用方负责避免把秘密环境变量、危险设备、Docker socket、控制文件或攻击者可修改的可执行文件授予命令。

不防护内核漏洞、侧信道、可信外部同 UID 进程主动协助、主机管理员，以及获准写入数据引发的后续供应链攻击。没有 PID/mount/IPC/user namespace；路径名称和进程元数据不作虚拟化。Landlock 是对访问权限的收紧，不隐藏文件存在性。`stat/access` 等元数据探测并不等于获得文件内容读取权限。

## 首版能力矩阵

| 能力 | 默认严格模式 | 显式兼容模式 | 排除项 |
|---|---|---|---|
| 文件内容和目录访问 | Landlock 默认拒绝；显式 ro/rw/rx 授权 | 必须 ABI≥3；不跳过 Landlock | COW、回滚、路径隐藏、逐条 deny |
| 截断、跨目录链接/重命名 | 纳入 handled 权限 | 同左 | 将 chmod 等元数据操作误称为 Landlock 内容规则 |
| seccomp | 架构检查、危险 syscall 拒绝和参数检查 | 不允许缺失 | 完整 syscall allowlist、系统调用审计流 |
| 网络 none | 禁止新 socket/socketpair；禁止 io_uring 替代入口 | 同左 | DNS/域名/IP/端口白名单 |
| 网络 host | 用户主动豁免；只允许新建 AF_INET/AF_INET6 socket，不限制 IP 目的地 | 同左 | UNIX/netlink/raw 家族、HTTP 代理、TLS 检查、透明端口重映射 |
| IPC | ABI≥6 signal/abstract UNIX scope；SysV IPC 等由 BPF 收紧 | ABI3–5 缺失 scope 必须报告 | IPC namespace、外部协作者隔离 |
| 进程 | fork/exec 继承；不能离开固定进程组或创建 namespace | 同左；禁止全部 signal-send syscall，包括向内部子进程发送 | PID 隐藏、调试器、任意 clone3 特性 |
| 资源 | 超时和 rlimit | 同左 | cgroup 总量配额、总树内存/CPU/进程硬计量 |
| 生命周期 | 超时、取消、CLI 异常退出、monitor 单独崩溃时回收后代 | 同左 | CLI 与 monitor 同时被杀、内核不可中断任务的绝对清理保证 |

严格模式最低 Landlock ABI6，通常对应 Linux 6.12；兼容模式最低 ABI3，通常对应 Linux 6.2。实际能力以 syscall 探测为准，发行版回移和启动配置可能改变结果。兼容模式缺失旧 ABI 无法提供的 IPC scope，不跳过文件权限、截断保护或 BPF。设备 ioctl 的 Landlock 权利虽然 ABI5 才有，但 BPF 在各模式下均全部拒绝 ioctl，因此本版这项有效限制相同。`--compat` 在新内核上仍应用已实现的 scope。内核新增而本版未知的权利不自动纳入；不能把 ABI 更高解读为本版实现了该 ABI 的所有能力。

## 策略语义

CLI 参数即策略，不接受可执行配置。`--ro PATH` 授予读内容和列目录，`--rx PATH` 额外授予执行，`--rw PATH` 授予读写及常用创建、删除、重命名操作。**rw 不隐含执行**。解释器读取可写脚本仍可以解释执行，因此 rw 的不可直接 exec 不能代替程序可信性控制。规则由内核按对象和层次匹配，授权路径以 `O_PATH` 描述符固定，不以字符串前缀判定。规则对象必须事先存在；路径中间的符号链接会被解析，最终路径分量必须是普通文件或目录，不允许符号链接、设备等特殊文件。传入系统 `/bin` 等符号链接时应先 `realpath`。

同层规则是授权并集，父目录的宽授权不会被子目录窄授权撤回。需要隔离秘密时，应只授予必要的叶子目录。授权目录内现有 hardlink、bind mount、特殊文件和可信调用者并发修改均需纳入策略评估。主机可见目录不是自动安全的数据卷。

不隐式授予 `/usr`、`/lib`、`/etc`、`/tmp` 或 cwd。动态链接器、解释器、共享库、证书及配置文件要由用户明确授予。环境仅有固定 PATH/LANG 基线与 `--env` 显式值，不继承宿主变量；标准输入输出由调用方授权并保留，其他继承 FD 在 exec 前关闭。stdio 可以是文件、pipe 或 socket，必须视为可信调用方主动开放的能力和通信通道；`network=none` 不撤销这些既有通道。

为避免 Landlock 未覆盖的 inode 元数据修改，以及 TTY 控制和 FD 委托，BPF 在两种模式下均拒绝 chmod/chown/时间/xattr 修改族、全部 ioctl、socketpair 和非 IP socket。应用无法使用交互终端 ioctl、chmod 构建动作、UNIX socket IPC、netlink 查询或 debugger；这是一项明确兼容性取舍，不能宣传为任意 Linux 应用透明兼容。

## 启动与生命周期

```text
Agent -> CLI（调用方 pidfd、subreaper、控制管道写端）
             |
             +-> monitor（可信、subreaper、控制管道读端）
                    |
                    +-> payload（固定 PGID、rlimit、清理 FD、NNP、Landlock、BPF、exec）
```

业务开始前必须完成所有限制安装；任一步失败只报告 setup 错误，禁止降级后 exec。`probe` 的不可逆测试在临时子进程进行，不改变调用者限制。能力可探测不等于规则安装已成功，只有实际 setup 完成才在结果中声明相应保护已生效。

monitor 是 payload 的父进程与 subreaper；payload 及后代无法调用 setsid/setpgid、使用 CLONE_PARENT 或 namespace flags，clone3 以 ENOSYS 促使常规 libc 回退。CLI 退出使控制管道 EOF，monitor 终止整个进程组并回收孤儿。保留组首领身份直到首次 killpg，防止组号复用误杀。随后反复读取 `/proc/self/task/PID/children`，只向尚未 wait 的直接子进程发送 SIGKILL；subreaper 接管的新孤儿在后续迭代处理。使用 `waitpid(...,__WALL)` 包含 exit_signal=0 的 clone 后代。正常命令退出后也结束后台后代。取消和超时均不依赖业务配合。

CLI 通过 `pidfd_open` 固定调用方进程，并以 poll 检测整进程退出；没有采用只跟踪父线程的 PDEATHSIG 来判定调用方消失。CLI 自身也设置 subreaper，在 monitor 单独崩溃时接管并清理后代。CLI 与 monitor 同时被管理员 SIGKILL、主机断电或任务处于不可中断内核状态时，不能承诺在固定时间内全部回收。`cleanup_complete` 只有 wait 到 ECHILD 才成立；超出约两秒的清理截止时间要报告 false，不能仅根据发出了 SIGKILL 判定。普通调用方进程退出必须实测，不能只测显式 cancel。

procfs children 枚举在并发退出时不是完整快照，因此每轮重复枚举与回收，最终仍以 ECHILD 确认结束；枚举失败时不能宣称清理成功。所用 PID 均是本进程的直接子进程，在单线程监管者 wait 前保持身份有效，避免向已复用的外部 PID 发送信号。

## Agent 契约

入口包括 `cincta probe` 和 `cincta run [策略] -- COMMAND [ARG...]`。业务 stdout/stderr 保留原语义，启动器日志带 cincta 前缀写 stderr；调用方应按前缀识别自身日志，并使用结果 JSON 获得结构化状态，不解析业务 stderr 来判定安全状态。独立结果文件避免 JSON 混入 stdout。

JSON 使用 `schema_version` 版本标识，报告状态、失败阶段、实际保护、ABI、缺失保护、退出码/信号、超时/取消及清理结果。消费者不能仅看 CLI 返回零或 ABI 可用。CLI 的保留错误码与业务同值退出可能重叠，应以 JSON 状态消歧。具体字段和命令选项以 [使用指南](usage.md) 和可执行文件 `--help` 为准。

## 资源与并发

rlimit 是继承的逐进程限制：地址空间不是总树物理内存；CPU 秒不是树 CPU 预算；NPROC 通常按真实 UID 累计，其他同 UID 工作负载会共同消耗额度，root 或特权进程可能豁免。Docker 的 `--memory/--pids-limit` 可作为外层总量控制，但它们不是 cincta 本身能力。FD 限额和 core 禁用一并作用于业务。

各次运行独立进程组和控制管道；结果路径应置于命令不可写的可信目录并且每次唯一。没有全局共享的策略注册表或可复用通知监听器。输出流由调用者消费，避免业务输出反压导致阻塞。对共享工作目录的并发修改不提供事务保证。

## 决策记录与发布门槛

- ADR-001：选择 C17 + 内核 UAPI，减少运行时与构建依赖；静态产物为推荐交付形态。
- ADR-002：首版只实现静态内核决策。用户通知、指针读取和代理执行引入 PID/FD/内存竞态，不能以最小静态原型冒充这些动态能力。
- ADR-003：严格默认、显式 compat；缺失保护可见，安装失败必须拒绝执行。
- ADR-004：独立可信 monitor 负责生命周期，保留 PID/PGID 身份并回收后代。
- ADR-005：预览版需要 Linux VM 和 Docker 的真实日志、正反测试及残留检查；未运行项为 BLOCKED。稳定版还要求两种目标架构在严格模式实际通过、重复并发压力和独立安全复核，无未关闭高风险问题。

性能目标是暖启动固定成本 p95≤50ms（不含目标命令、镜像拉取和 VM 启动），只作工程预算。发布报告需保存环境、策略、源码标识、逐样本数据与失败数；没有样本时不宣称满足预算。
