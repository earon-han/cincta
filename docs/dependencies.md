# 外部依赖与部署条件

v0.2 的基本静态运行、动态能力和树级资源有不同依赖。请求某项能力但无法建立它时明确失败，不把它降为“尽力而为”的权限保护。最终兼容矩阵及实际配置见 [验证报告](validation.md)。

## 基本执行

| 项目 | 要求与失败行为 |
|---|---|
| OS/架构 | Linux 小端原生 x86_64/aarch64 syscall ABI；其他架构拒绝构建/执行；macOS只作控制端 |
| Landlock | 严格 ABI≥6（上游6.12起），显式--compat ABI≥3（上游6.2起）；无保护不执行 |
| LSM配置 | CONFIG_SECURITY_LANDLOCK及必要SECURITY支持，启动有效LSM列表启用landlock |
| seccomp | CONFIG_SECCOMP、CONFIG_SECCOMP_FILTER，外层策略允许安装经典filter及no_new_privs |
| 生命周期 | fork/pipe/socketpair、poll、wait、subreaper、pidfd_open、pidfd_send_signal（guardian以signal0预检权限）、signalfd、timerfd、信号和close_range可用 |
| procfs | CONFIG_PROC_FS、CONFIG_PROC_CHILDREN，真实/proc可读取自身children、fd及所需mountinfo，statx(STATX_MNT_ID)可用以识别bind子目录别名；不可读时拒绝相关保护 |
| runtime文件 | 业务二进制、loader、共享库、解释器及配置逐项显式授权；静态启动器不自动授予这些路径 |
| 身份 | 推荐普通UID、无额外capabilities；payload清空caps和设置NNP，不借setuid提权 |

以实际 ABI/syscall 探测为准，内核版本字符串不证明特性启用或未被外层策略禁止。`probe`在短命子进程安装基础Landlock/seccomp；成功不保证动态通知、具体路径、元数据或cgroup能建立。[Landlock API](https://docs.kernel.org/6.12/userspace-api/landlock.html)

兼容模式在ABI3–5缺少signal/abstract UNIX scope，结果明确报告；静态BPF额外禁止所有signal-send syscall，包括自身信号，不把它伪称内核scope。新内核的--compat仍安装可用scope。未知新ABI权利不会自动纳入本版。

## 动态网络、metadata和syscall审计

| 项目 | 要求 |
|---|---|
| seccomp notification | NEW_LISTENER、NOTIF_RECV/SEND/ID_VALID，以及ADDFD/SEND相关ioctl实际可用 |
| 目标地址空间读取 | 同UID监管者可打开真实/proc/TID/mem；先固定mm再核对通知ID，不依赖pidfd_getfd |
| Yama/ptracer | 真实祖先monitor在通知ID双重验证间打开目标mem，经私有通道传FD给broker；不设置PR_SET_PTRACER例外，不放宽全局ptrace_scope；更严格LSM/ptrace_scope仍可能拒绝 |
| 凭证与dumpable | broker/worker清空capabilities；SELinux/AppArmor、hidepid、dumpable等仍可能拒绝访问，不能绕过 |
| 对象固定 | openat2、O_PATH及真实procfs FD链接可用；用户指针不能作为CONTINUE授权依据 |
| metadata chmod | fchmodat2(AT_EMPTY_PATH)，上游Linux6.6起；无副作用探测不可用时--metadata启动125 |
| DNS | 域名在可信启动阶段getaddrinfo一次性解析；依赖主机resolv.conf/hosts/NSS与网络配置，静态glibc不等于无DNS配置依赖 |
| 审计存储 | 业务不可写、可独占创建/追加/fsync的可信本地文件系统及足够容量；额度/IO/完整性失败停止任务 |

内核最低版本已包含基础notification接口，但发行版回移、外层seccomp/LSM仍会影响可用性。基本静态模式不要求动态notification。两阶段filter引导结束后禁止业务安装新listener或扩大ptracer；内部FD不泄露到用户代码。[seccomp notification说明](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)

旧内核可能无法通过ADDFD传递O_PATH；仅该明确EBADF情形可退回业务自身内核Landlock/BPF检查，并记录native fallback，实际返回值未知。普通FD交付失败、网络/metadata授权绝不使用此兼容回退。syscall审计的文件打开模式额外拒绝procfs及magic FD链接，防止worker主体混淆，可能影响依赖/proc自省的程序。[审计边界](audit.md)

metadata只支持固定rw根内由当前UID拥有的普通文件/目录：chmod低9位、保留当前UID/GID或-1的chown、utimensat及user.* xattr；不提供任意chmod/chown/ACL/安全xattr透明兼容。默认静态模式继续禁止这些修改。ioctl默认禁止；allowlist网络只对已登记socket代理FIONBIO，其他ioctl仍不开放。

## 工作区和资源

工作区需要普通文件系统、openat2及真实/proc/self/fd用于固定对象和安全清理，不要求overlayfs、mount权限、user namespace或root。源准备期间应静止；双副本、导出与审计均消耗真实磁盘空间。文件/字节上限不代替运行期磁盘quota。需要编译并运行生成物时，显式workspace-exec增加tree执行权限，metadata及工具所需只读目录仍要单独配置。只接受受控普通文件/目录和可完整解析的根内相对链接；不复制所有者、ACL、capabilities或特殊文件。[工作区说明](workspace.md)

树级配额需要cgroup v2挂载、cpu/memory/pids控制器及真实委派：创建/配置/迁移/删除子组权限，parent controller已启用，调用者处于允许迁移的子树。cincta不静默启用全局controller、不chown主机控制目录；伪造普通目录拒绝。memory.max与OOM组行为生效，memory.swap.max存在时设0。CPU百分比为带宽，累计CPU预算由采样终止，可能因采样/调度超量。[cgroup v2文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)

配额覆盖payload业务进程树，monitor/broker/可信worker留在组外；代理CPU、socket buffer、消息复制和日志成本不计入该业务组，由固定worker/socket/message上限和审计总量另行约束。需要全服务资源边界时，部署者还应为启动器/监管服务提供外层cgroup与磁盘quota。

## Docker与其他外层安全策略

容器使用宿主内核，镜像升级不会增加Landlock ABI。验证基本和动态功能时保留默认seccomp/AppArmor，使用非root、cap-drop ALL和no-new-privileges；不以privileged/unconfined作为默认解决方案。外层拒绝应记录真实errno和BLOCKED/FAIL，不把--compat当外层策略绕过。[Docker seccomp文档](https://docs.docker.com/engine/security/seccomp/)

默认Docker一般把/sys/fs/cgroup只读挂载。完整测试在该环境验证无委派拒绝，树配额正例保持BLOCKED；正例必须另建专用委派、匹配UID、仅bind所需子树RW，并满足共同祖先迁移权限。若委派不在私有cgroup namespace根内，可能需要明确--cgroupns=host或由运行时在容器自身根内准备委派。这项额外部署条件和完全默认容器分开记录，seccomp/AppArmor仍保持默认。[资源部署说明](resources.md)

不要授予Docker socket、危险设备、宿主可写/proc或控制目录。--network host是cincta的目的地豁免选项，不是Docker的network=host，也不改变容器namespace。

## 构建、测试和分发

需要C17 GCC/Clang、make、libc开发文件和Linux UAPI headers≥6.2；源码检查关键syscall宏，避免旧头文件静默漏掉过滤。无需libseccomp/pkg-config/cgo。静态构建需要静态libc开发包；glibc/musl和架构的实际验证必须分别记录，不能把未运行的产物算通过。

完整套件需要Python3标准库和C编译器（工作区ctypes适配、网络线程探针和文件审计探针）。Docker验证另外需要daemon/镜像来源；不是二进制运行依赖。全系统QEMU可验证目标架构的真实内核，但须标为TCG/仿真；qemu-user不能替代Landlock/seccomp验证。

构建与发布流程的额外回归使用Git（临时仓库、干净/脏树检查）及binutils/readelf（真实ELF静态/动态检查）。CI和Docker构建环境需提供这些工具；它们不是cincta运行依赖。入口为`python3 tests/build_release_test.py`和`python3 tests/package_test.py`。

分发包包含静态CLI、公开源码与构建/测试文件、文档、示例、许可证、精选验证摘要及来源/SHA256信息，不包含本地计划和原始运行报告。Git工作树必须干净；没有.git的导出源码打包需显式提供完整40位CINCTA_SOURCE_REVISION。二进制来源未提供时为unknown；显式CINCTA_BINARY_SOURCE_REVISION仅记录调用方声明，不能当作验证。远端CI、推送、发布和外部审计必须实际完成才声明。
