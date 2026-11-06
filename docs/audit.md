# v0.2 审计语义

审计日志采用独占新建的JSONL文件，与业务stdout/stderr及最终结果JSON分离。每条事件包含格式版本、单调时钟、通知ID、TID、native syscall编号/架构、目标快照、值和errno。调用方应等待任务及清理结束后再消费完整日志；不能用业务输出冒充可信审计。日志预算耗尽、追加/落盘失败或可信进程异常终止时，finish事件可能缺失；日志尚未创建的早期配置失败也没有生命周期事件。因此不能仅等待finish判断CLI是否结束，应结合CLI退出、结果JSON或早期stderr判定。

## 事件覆盖

| 事件 | 可以证明的事实 | 不能据此推断 |
|---|---|---|
| start / 生命周期事件 | 监管组件开始/结束相应步骤 | 所有保护都已安装 |
| request | seccomp通知入口被观察到 | syscall已执行或成功 |
| continue_request | 监管者允许内核继续处理 | 原指针内容不变、最终内核返回成功 |
| authorize / result | broker对复制参数作决定/实际代执行结果 | 原生其他调用的完成结果 |
| file_open_snapshot | 路径、flags及目录基准已复制或固定 | 文件一定获准打开 |
| file_open_result | 安装等价Landlock后的可信worker实际open结果；value是worker内部FD或-1 | 此FD已成功交付给业务 |
| file_open_delivery | ADDFD+SEND将FD交付业务的结果；value是业务FD或-1 | 业务已读取/写入多少数据 |
| file_open_native_fallback | 旧内核不能ADDFD传递有效O_PATH句柄，转交业务自身内核权限检查 | 原生调用已成功、实际返回FD、原路径/how快照保持不变 |

`--audit`记录监管和broker事件；`--audit-syscalls`增加受通知覆盖的native syscall请求，并对open/openat/openat2/creat代执行，取得实际打开结果。少数bootstrap调用及第二层静态filter直接拒绝的入口、外层seccomp提前拒绝、其他架构被内核直接终止等，不会产生等价的入口通知。所有调用的返回值、每次read/write的真实字节数不是当前通知接口的覆盖承诺。此日志不命名为“全部系统调用入口与出口完整追踪”。

多层seccomp中ERRNO优先于USER_NOTIF。默认Docker可能使新系统调用直接得到ENOSYS，而不进入cincta通知；同一入口在cincta静态ERRNO模式下又可能返回EPERM，因为相同action优先级取最近安装filter的数据。验收逐入口保留返回errno、是否见request/deny及外层Seccomp状态；外层过滤使内层观察无法证明时记BLOCKED，不把拒绝冒充审计观察成功，也不放宽Docker profile。[内核filter优先级](https://docs.kernel.org/userspace-api/seccomp_filter.html)

## 文件打开的可信执行

真实祖先monitor通过只向可信broker开放的私人socketpair接收内存请求，先检查notification ID，打开 `/proc/TID/mem` 固定原地址空间，再复核同一ID，并经SCM_RIGHTS传递句柄。broker收取和复制参数后也复核ID。当前实现不设置PR_SET_PTRACER例外、不修改Yama配置；祖先访问路径支持业务fork出的子孙，不让兄弟broker依赖不会继承到fork后代的ptracer例外。hidepid、目标关闭dumpable或其他LSM仍可能拒绝procfs访问，相应操作必须失败。相对路径使用通过 `/proc/TID/cwd` 或 `/proc/TID/fd/N` 固定的目录对象，worker不会重新使用业务的目录FD数字。openat2的IN_ROOT语义保留。结构长度限制4096字节，未知非零扩展和过短结构明确拒绝。

可信worker在实际打开之前清空capabilities、设置no_new_privs，并使用启动时固定的授权根安装与业务一致的Landlock文件规则。先以O_PATH固定目标并检查文件系统类型，排除procfs；已有对象通过worker自身固定FD重开，缺失文件先固定父目录，再以basename、O_NOFOLLOW与RESOLVE_BENEATH创建。最终读写/截断授权由内核Landlock检查，绝不依赖字符串前缀放行。worker只继承执行所需的listener、audit和固定目录FD；策略FD在安装Landlock后关闭。实际open后使用ADDFD_FLAG_SEND原子注入并响应，CLOEXEC标志保持，调用方umask从proc状态取快照。

文件worker数量上限32；慢文件打开不阻塞主monitor。文件worker由broker派生，在payload的 `--tree-*` cgroup配额之外；该上限是可信工作进程数限制，不是整套cincta服务的总内存/CPU硬配额。取消、超时或监管故障时worker与业务一起被收养、终止并实际回收；只有wait到ECHILD才算清理完成。

## 元数据兼容模式

默认静态策略仍拒绝metadata写入；显式 `--metadata` 才通过通知broker代执行已授权rw对象上的有限操作。目标必须落在启动时固定的rw规则根内、所有路径分量均不跟随symlink、对象为普通文件/目录且owner匹配启动用户。FD变体会把目标FD路径映射回固定规则，并核对实际dev/inode。只读对象、链接及越界路径不会因为broker代执行而获得额外权限。

支持普通chmod/fchmod/fchmodat、utimensat、同有效UID/GID（或-1保持不变）的chown/fchownat，以及user.*的set/remove xattr；mode只允许低9位0777，拒绝setuid/setgid/sticky，xattr值最多64KiB。尚未实现的传统utime/utimes/futimesat和新setxattrat/removexattrat变体返回EOPNOTSUPP；不能把通知入口存在当成该变体已实现。部分带非零flags的*at变体也明确拒绝。

broker对已固定O_PATH对象使用 `fchmodat2(AT_EMPTY_PATH)`，这项能力从Linux6.6提供；main启动前实际探测该调用，内核过旧或外层策略禁用时125拒绝，不静默回退到可变路径。[Linux chmod/fchmodat手册](https://man7.org/linux/man-pages/man2/fchmod.2.html)

## 日志配额与时间

`--audit-max-bytes` 默认67108864（64MiB），`--audit-max-records` 默认1000000，均须正整数。共享原子预留计数覆盖多个可信进程的并发追加；超过任一预算时拒绝该次追加、设置limit_exceeded和audit_failed并终止运行。最终audit对象报告records/bytes、max_bytes/max_records、complete、limit_exceeded、delivery_pending和native_open_fallbacks。有效UTF-8目标按原文本保留，非法字节会JSON转义，target_bytes_hex保留逐字节快照用于无损核对。

DNS解析、工作区复制及cgroup准备在执行timer建立前；diff/export在执行结束及进程回收后，不受 `--timeout-ms` 执行预算约束。追加/落盘错误必须失败，但不承诺底层阻塞存储操作能在固定时间内返回；不能把执行timer当成包含准备、导出和fsync的端到端硬超时。

## 显式兼容性边界

- metadata的FD/cwd路径捕获为PATH_MAX字节缓冲，允许最多4095字节的目标并明确追加NUL；readlink满缓冲或内核拒绝更长路径时返回ENAMETOOLONG。捕获或实际执行失败必须有非零errno，不能以残留的零errno伪装成功。回归同时核对4094/4095字节对象的真实权限变化与结果事件，以及4096字节对象的拒绝、权限不变和deny事件。
- 审计模式的文件打开统一通过openat2，额外设置RESOLVE_NO_MAGICLINKS。magic FD链接不会跟随，避免解析到可信worker持有的内部对象。
- 旧内核的ADDFD使用fget而拒绝O_PATH（EBADF），上游fget_raw支持在较新内核才出现。仅在有效O_PATH源FD且实际ADDFD明确EBADF、尚未注入任何FD时，记录失败与native fallback后CONTINUE，由业务自身的Landlock/BPF最终授权。普通文件FD、模糊失败及网络/metadata绝不套用此fallback；原生调用可能使用变化后的path/how，实际结果未知，不能用worker结果冒充成功。该分支的/proc/self是业务自身，不会暴露可信worker的主体。[上游O_PATH ADDFD修复](https://lkml.iu.edu/2609.3/02887.html)
- 所有procfs对象在实际内容打开前以O_PATH与fstatfs检查并拒绝，交付前再次复核；相对目录基准位于procfs时提前拒绝。普通symlink别名也按固定对象类型检查。`/proc/self`在worker中代表不同进程，尤其不能把可信worker的mem等FD交给不可信业务。需要原生procfs行为的工作负载不能在该文件打开代理模式下透明运行。
- 新建文件时，如果最终组件在复制后被并发替换成symlink，明确拒绝。向dangling symlink指向的缺失目标创建文件也返回拒绝；不以重新跟随可变路径换取兼容性。
- 传统open/openat对未知flags的宽松处理可能被openat2的严格EINVAL取代。O_PATH保留路径描述能力，不授予内容读写。O_TMPFILE由实际内核和Landlock决定，不伪造支持。
- 复制后的cwd、dirfd、umask与路径构成一次请求快照，并发修改不保证与原始多线程调用的线性化时点完全一致。业务不能借此获得超出固定Landlock规则的权限。
- 通知ID在执行前有效，不代表文件副作用与最终响应是事务。目标可以在open/create/truncate期间因信号或取消撤销通知；已经发生的获准文件副作用不能自动撤销。日志分别记录实际操作和交付，工作区快照用于隔离这类获准写入。
- 如果审计追加失败，运行必须标记audit_failed并停止。已经成功的ADDFD+SEND或外部网络/文件副作用不能靠日志失败回滚；不得报告完整审计成功。
- 文件worker的共享delivery_pending在父进程fork之前增加，覆盖初始化、实际open/create/truncate副作用、结果落盘及响应/回退全流程；只有处理完成的正常退出路径才递减，fork失败由父进程撤销计数。被SIGKILL的worker保留pending，即使停在open与结果落盘之间也不能误报完整。正常业务结束后的可信记账有最多50ms收尾窗口；清理后仍有pending必须标记审计不完整并返回125。native_open_fallbacks计数单独报告旧内核原生回退请求，不把它算成完整出口观察。

测试入口：`python3 tests/file_audit_test.py --binary build/cincta --environment linux-vm --report reports/v02-file-audit-vm.json`；Docker内单独运行并记录不同环境标签。19项正常操作包括fork后由child打开并写入文件、核对child的真实打开与交付审计；另加1项故障注入：令O_CREAT|O_TRUNC的FIFO写端open阻塞，在结果产生前向可信worker发送SIGKILL；断言清理完成、pending仍非零、audit.complete=false且退出125。代码编译或配置存在不能替代真实通知、拒绝、FD交付和工作进程中断测试。

模块开发记录：在Linux6.8 VM，RPC改动前的独立文件审计19项曾19 PASS、0FAIL、0BLOCKED，报告为 `reports/v02-file-audit-pending-vm.json`。其中故障注入实际得到退出125、清理完成、audit.complete=false、delivery_pending=1。该记录只覆盖原业务进程，不能证明fork后子进程的Yama兼容性；最终20项必须覆盖新加入的fork写入回归。旧内核O_PATH交付和非法指针errno问题修复前为14 PASS、4FAIL；为保留可追溯证据，用固定缺陷快照重新实际执行，记录为 `reports/v02-file-audit-development-reproduction.*`，它是明确的开发缺陷复现，不计入最终验收。最终组合版本与Docker仍由统一验证流程重新执行。
