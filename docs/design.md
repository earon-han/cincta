# v0.2 设计与安全边界

本设计把 v0.1 静态 CLI 扩展到动态出站网络、受限元数据操作、隔离工作区、业务树配额及审计。实施顺序见 [详细计划](implementation-plan-v02.md)，模块语义见各专项文档，真实状态见 [验证报告](validation.md)。版本 `0.2.0-preview.1` 不代表外部审计或所有平台稳定认证。

## 目标、语言和可信边界

采用 C17 与 Linux UAPI，可静态链接，不依赖 libseccomp 或 Agent 框架。代码目标为小端原生 x86_64/aarch64 syscall ABI；x32、i386 等替代 ABI 被过滤器拒绝。C 适合直接操作内核结构和独立分发；对应代价是显式管理 FD、内存、进程身份及过滤器跳转，必须独立复核和真实内核测试。

不可信业务可以执行任意原生代码、fork/clone/exec、操纵自己的指针/FD/线程并主动触发竞态。可信计算基包括内核、CLI、monitor、broker、短命 worker、策略输入和部署者提供的目录/委派。业务不能扩大权限；任何安装、代理、审计或清理失败都必须可观察。不会为通过测试而关闭保护、加入 privileged/unconfined 或修改主机全局 ptrace 策略。

不防御内核漏洞、侧信道、管理员、外部同 UID 可信协作者主动委托权限或获准写入数据造成的后续供应链影响。没有 mount/PID/user namespace 虚拟化；文件存在性和进程元数据不隐藏。保留 stdio 是显式能力授权，普通执行的 socket/file stdio 仍可通信。工作区模式进一步禁止可写普通文件 stdio 和额外 rw 根，防止写别名破坏源保护。

## 分层执行

```text
Agent -> CLI：调用方 pidfd、取消信号、独占结果/审计、准备工作区与资源
           -> monitor：subreaper、启动屏障、pidfd/signalfd/timerfd、故障及清理
                -> payload：固定 PGID、rlimit、NNP、Landlock、BPF、exec
                -> broker（动态模式）：notification、固定对象、策略决定
                     -> 有界 network/file workers：执行可能阻塞的可信操作
```

CLI/monitor 都是 subreaper，单独一层异常退出由存活层收养并清理。monitor 在业务实际结束后清理所有后台后代。独立 broker 避免 NOTIF_RECV 或慢网络/文件操作阻塞取消路径；broker 死亡使本次动态任务失败。可信 worker 也是回收对象，不因其可信就允许遗留。

运行阶段通过 pidfd、signalfd 和 timerfd 等待退出、取消和超时，不采用固定 10ms 空轮询。少量维护周期用于资源累计 CPU 预算、socket 引用回收、审计失败检测。准备guard负责monitor接管之前CLI异常退出的临时资源回收；快照复制计入总耗时但不计入当前monitor墙钟预算，最终故障覆盖须实测。清理阶段反复读取真实 procfs children，使用未 wait 的直接子进程身份发送信号，`__WALL` 包含 exit_signal=0 clone 子进程；只有 `ECHILD` 才声明回收完成。两层同时强杀、断电、内核不可中断任务不保证固定时间清理。

## 文件规则与固定对象

所有规则在业务开始前以 O_PATH 固定，保留根对象和规范路径。可信输出及工作区边界还使用固定FD的STATX_MNT_ID匹配mountinfo的挂载根，将bind子目录别名映射到底层文件系统路径，进行设备号与目录包含关系核对；不只比较绝对路径文本。初始化期间要求宿主挂载和目录布局可信、稳定。payload 与文件 worker 安装同一批固定根的 Landlock，不按业务运行期间可变的规则路径重新授权。最终 symlink/设备规则拒绝，目录中的符号链接访问仍受内核规则控制。

ro 为内容读取/枚举，rx 加执行，rw 加常用写入/截断/创建/删除/链接/重命名，不隐含执行。规则同层是并集；子路径的窄授权不能撤回父路径的宽授权。解释器可以解释可读脚本，因此 rw 不可直接 exec 不是代码可信性保证。无隐式 runtime、cwd、tmp 或配置文件权限。

默认拒绝 Landlock 不覆盖的 metadata 修改与 ioctl。可选 metadata broker 只对固定 rw 根内、属于当前 UID 的普通文件/目录操作，以 openat2 与 O_PATH 固定最终对象再执行；拒绝跨根、magic/symlink、特殊对象、setuid/setgid 权限、外部 UID/GID 和非 user.* xattr。不读取指针检查后 CONTINUE 授权。chmod 需要 fchmodat2(AT_EMPTY_PATH)，启动会无副作用探测，不可用时明确拒绝 `--metadata`。

## 动态通知与网络

不可信指针只作为请求输入。先打开目标进程 mem 固定地址空间、检查通知 ID、复制参数，副作用前再验证；监管者使用副本和自己固定的对象执行。ID 有效性与外部效果不能构成跨进程事务，已经发出流量或发生文件截断后，取消无法撤销这些获准效果。

两阶段过滤器在可信单线程引导期间传输 listener；第二层在 ready 前永久封堵新的 seccomp listener、PR_SET_SECCOMP、PR_SET_PTRACER 和 bootstrap FD 数字复用入口。listener/控制 FD 不进入用户代码。真实祖先monitor在私有通道上为broker打开目标mem，打开前后验证通知ID并仅传递固定地址空间FD；该通道在payload fork后创建，不被业务继承。这样支持fork子孙且不设置PR_SET_PTRACER例外或全局放宽；broker清空capabilities。monitor打开mem仍可能等待内核mm访问锁，普通本地文件系统的取消测试不构成任意文件系统下的绝对延迟上限。

网络 none 禁止新 socket；host 显式开放任意 IPv4/IPv6 目的地。allowlist 由 broker 创建/保留 TCP/UDP socket，以 O_PATH、S_ISSOCK、dev/inode 核对业务 FD 身份。dup/fork 共享同一对象，connect/send 指针复制后由 broker 执行，绝不 CONTINUE。危险路由选项、ancillary 数据、入站监听、UNIX/netlink/raw/socketpair 拒绝；只对登记 socket 代理安全 FIONBIO。

域名在业务前解析并固定实际 A/AAAA 地址和端口，运行期间不刷新。它不是应用层域名身份；初始 DNS 答案可以包含私网/loopback，共享 IP 也可能承载其他域名。需要更窄能力时用显式 IP/CIDR。socket 引用 GC 不是原子 FD 快照，扫描失败保守延迟回收，所有 registry/worker/消息大小有硬上限。[网络细节](network.md)

## 工作区和资源

工作区把源复制到独立 baseline 与 tree，业务只获得 tree rw/cwd。硬链接不复用源 inode，链接完整解析约束在根内；特殊文件拒绝。完成时在业务和后代全部回收后比较内容、独占导出完整树，或丢弃本次改动。没有自动写回，也不是按需 overlayfs COW。默认tree只有rw，显式workspace-exec才对同一固定tree增加rx，支持生成二进制的编译/测试工作流；它不是只准执行预先可信代码的保证。准备期间要求源静止；双副本和可选导出有实际磁盘成本，运行期磁盘配额由部署者提供。[工作区细节](workspace.md)

rlimit 保持逐进程/同 UID 语义。显式 cgroup v2 委派提供业务树 memory.max、pids.max、cpu.max 和定期采样的累计 CPU 预算；配置写入读回、业务 exec 前确认入组，后代继承。请求内存上限时，若存在 memory.swap.max 则配置为0。业务不能获得 cgroup 控制目录、其 bind 别名或可写祖先。monitor、broker 与可信 worker 在业务组外，因此树配额不包含可信代理成本；这些成本由 worker、socket、单请求和审计总量上限另外约束。[资源细节](resources.md)

## 审计与结果

stdout/stderr 保留业务含义；可信完成报告和 JSONL 独占新建，位于业务不可写的目录。schema_version=1 保留基础字段，v0.2 加入 dynamic、network_snapshot、workspace、resources 和 audit 对象。消费者必须判断实际保护、完整性和清理状态，不能只看退出0或 probe。

事件日志区分请求、策略决定、broker 实际结果与 FD 投递。syscall 模式增加请求通知和文件打开实际结果；少数引导/外层静态拒绝不经过通知，其他原生 syscall 只有请求没有完成结果。旧内核 O_PATH ADDFD 不可用时仅作明确记录的原生内核授权回退，不能冒充已观察业务返回值。UTF-8 与 target_bytes_hex 保留目标说明及原字节，日志不能静默截断。

审计默认64MiB/100万条，跨 worker 原子预留预算。写入/额度/投递完整性失败使本次运行失败。delivery_pending 检测效果完成后丢失记账，业务终止后给可信记账最多50ms，未归零则不能声明完整；无法回滚已经发生的获准效果。[审计细节](audit.md)

## 检查点与发布

设计、实现、自验证、独立测试由不同 Agent 分工；安全问题由所有者修复并交叉复核。设计评审记录不计运行 PASS，多 Agent 审查不等于外部审计。

发布须保留源码/二进制指纹、策略、环境、逐项 PASS/FAIL/BLOCKED、原始性能样本和实际容器安全配置。Linux VM 与 Docker 分开执行；默认 Docker 无 cgroup 委派的负例和最小委派正例分开记录。全系统 QEMU 与硬件原生明确区分，不以 qemu-user 代替 seccomp 验证。外部审计、远端 CI 和 GitHub 发布只有实际完成才声明。
