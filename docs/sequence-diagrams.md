# 按进程阅读执行时序

对照代码基线：`4983eab`，`0.2.0-preview.1`。本文仅补充阅读图，不改变执行行为。

所有 `participant` 方框都代表真实进程；自调用箭头表示该进程中的函数执行或系统调用，注释说明内核处理。标为“内核转交”的跨进程箭头表示 seccomp 通知/响应，不表示业务主动给 broker 发送 IPC，也不是 Unix signal。各图的垂直顺序表示必要的先后关系；`par` 内的分支并发推进。

示例把业务命令设为 `/bin/bash -c ...`。payload 经 `execve` 变成 Bash，PID 不变；外部命令如 curl 通常另有子进程。各子孙继承已安装的保护。CLI、monitor、broker、guardian 都是同一程序通过 fork 分出的不同进程。

原调用方在当前PID namespace不可见时不能绑定其生命周期，会通过结果中的 `protections.caller_bound=false` 明确报告，取消需由容器运行时等发送信号。

## 1A. 初始化：配置、工作区与资源准备

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent调用进程
    participant C as CLI进程
    participant G as guardian进程（可选）
    A->>C: 启动 cincta run，传入策略和 Bash argv
    C->>C: caller_capture：固定原调用方 TGID pidfd
    C->>C: 解析文件、网络、工作区、资源、审计选项
    opt 启用工作区
        C->>C: 校验源目录、父目录及挂载别名边界
    end
    opt 工作区 / cgroup / 网络allowlist需要准备
        C->>G: preparation_start：fork
        G->>G: 固定CLI身份，创建并固定私有准备容器
        G-->>C: READY，共享准备上下文
        Note right of G: 监视CLI和原调用方<br/>未交接时负责故障清理
    end
    opt 启用工作区
        C->>C: workspace_prepare：源 → baseline → tree
        C->>C: tree设为cwd和rw根；按需增加rx
    end
    opt 网络allowlist
        C->>C: network_prepare：解析协议、CIDR、端口及DNS地址快照
    end
    C->>C: security_pin_policy：O_PATH固定授权根
    C->>C: 校验可信输出、挂载身份及所请求能力
    C->>C: result_open；broker_open准备共享状态和可选审计文件
    Note right of C: broker_open不创建broker<br/>此时尚未安装业务Landlock/BPF
    opt 请求cgroup委派资源
        C->>G: preparation_resources：R命令
        G->>G: resource_prepare：创建业务组，设置并读回配额
        G-->>C: 准备结果
    end
```

工作区实际复制由 CLI 执行，guardian 负责准备容器身份和故障兜底；baseline 与 tree 是独立物理副本。无任何上述准备需求时不创建 guardian。任何必需校验或准备失败都不会进入业务执行。

源码：[main](../src/main.c)、[preparation](../src/preparation.c)、[workspace](../src/workspace.c)、[resources](../src/resources.c)。

## 1B. 初始化：进程启动、保护安装及listener交接

```mermaid
sequenceDiagram
    autonumber
    participant C as CLI进程
    participant G as guardian进程（可选）
    participant M as monitor进程
    participant T as probe短命子进程
    participant P as payload进程 → Bash
    participant R as broker进程（动态模式）
    C->>C: supervise：设为subreaper，建立控制管道
    C->>M: fork monitor
    Note right of M: 等待CLI的启动许可G
    opt guardian存在
        C->>G: D命令：交接清理责任给monitor
        G-->>C: ACK并退出
        C->>C: waitpid回收guardian
    end
    C->>M: 发送启动许可G
    M->>M: monitor_run：准备信号和调用方检查
    M->>T: security_probe：fork
    T->>T: 试装最小Landlock和ALLOW过滤器
    T-->>M: 返回能力后退出
    M->>M: waitpid回收probe，设置subreaper并确认能力
    M->>M: 建立业务启动屏障及可选listener传输socketpair
    M->>P: fork payload
    P->>P: 设置进程组，等待业务启动许可G
    opt cgroup已启用
        M->>M: resource_attach：业务入组并核验
    end
    M->>M: 建立业务pidfd及超时/维护timerfd
    M->>P: 发送业务启动许可G
    P->>P: 关闭多余FD，设置rlimit和cwd
    P->>P: security_apply：NNP、清capabilities、Landlock、seccomp
    Note right of P: compile_filter生成BPF<br/>安装NEW_LISTENER时内核返回listener FD
    alt allowlist / metadata / audit-syscalls任一启用
        P->>M: SCM_RIGHTS传递listener FD
        par payload完成可信引导
            P->>P: security_lockdown：安装第二层封锁，关闭内部FD
            P-->>M: ready：保护已安装
            P->>P: execve Bash，PID不变
        and monitor建立动态监管
            M->>M: 接收listener；创建私有内存RPC通道
            M->>R: fork；子进程调用broker_run
            R->>R: 清capabilities，poll listener并处理通知
        end
    else 静态模式
        P-->>M: ready：保护已安装
        P->>P: execve Bash，PID不变
    end
```

NNP 指 `no_new_privs`。保护安装失败时 payload 报错退出，不执行 Bash。Bash 不必等 broker 被调度后才 exec；若先命中 USER_NOTIF，其发起调用的线程在内核等待。两个 G 是不同管道上的两道屏障。私有内存 RPC 通道在 payload fork 后创建，不会被业务继承。单独 `--audit` 不创建 listener/broker。

源码：[supervise / monitor_run / payload](../src/supervisor.c)、[security_probe / security_apply / security_lockdown](../src/security.c)。

## 2A. Bash访问文件：静态seccomp与Landlock

本图不启用 `--audit-syscalls`，例子为 Bash 内建 `printf hi > output.txt` 和外部 `cat input.txt`。

```mermaid
sequenceDiagram
    autonumber
    participant P as Bash业务进程
    participant F as cat业务子进程（按需）
    P->>P: openat output.txt，申请创建/写入
    Note right of P: 内核先执行seccomp BPF<br/>ERRNO/KILL可在文件操作前拒绝<br/>ALLOW后进入文件打开路径，执行Landlock及其他权限检查
    alt 系统调用和目标文件权限均允许
        P->>P: openat返回FD；内建printf执行write；close
    else seccomp或文件权限检查拒绝
        P->>P: 获得错误；KILL动作则终止进程
    end
    opt 执行外部cat命令
        P->>F: fork后execve cat
        Note right of F: 子进程继承Landlock/BPF<br/>execve仍需允许调用并具备目标执行权限
        F->>F: openat input.txt，申请读取
        Note right of F: 同样先经过seccomp<br/>再由内核文件路径上的Landlock等检查决定是否成功
        F->>F: 成功后read；close；退出
    end
```

Landlock/BPF 不是用户态服务进程，因此不另画参与方方框。Landlock 并非在每次普通 `read/write` 时重新按路径授权；成功打开的 FD 本身就是已有能力。路径打开、执行等检查与后续 FD 操作要分别理解。stdio 也是调用方已授予的能力。开启 syscall 审计时，支持的文件打开会走图3的文件 worker 分支。

源码：[install_landlock / compile_filter](../src/security.c)、[payload](../src/supervisor.c)。

## 2B. Bash调用curl：网络策略如何生效

```mermaid
sequenceDiagram
    autonumber
    participant P as Bash业务进程
    participant N as curl业务子进程
    participant R as broker进程（allowlist分支）
    participant W as 网络worker进程（按需）
    P->>N: fork后execve curl，继承保护
    N->>N: socket IPv4/IPv6 TCP或UDP
    alt network none
        Note right of N: 内核seccomp拒绝新建socket
        N->>N: socket失败，无法建立本次连接
    else network host
        Note right of N: seccomp允许匹配的IPv4/IPv6 socket<br/>没有allowlist目的IP/端口检查
        N->>N: 由内核直接执行socket/connect
    else network allowlist
        N-->>R: 内核转交socket通知，调用线程等待
        R->>R: handle_socket：检查family/type/protocol并创建、登记socket
        R-->>N: ADDFD+SEND：内核安装业务FD并返回
        N-->>R: connect触发内核通知，携带地址指针
        R->>R: 固定socket身份，复制地址，核验通知ID
        R->>R: address_allowed：协议、IP/CIDR、端口匹配
        alt 目的端点允许
            R->>W: fork，继承broker socket和地址副本
            W->>W: 再核验通知ID；实际connect
            W-->>N: NOTIF_SEND：内核返回真实结果/errno
            W->>W: 完成记账并退出
        else 目的端点不允许
            R-->>N: NOTIF_SEND：内核返回EACCES
        end
    end
```

本图为突出网络模式差异，未启用 syscall 审计；其通知接管见图3。端点白名单由可信 broker 执行，不是 Landlock 检查 IP。域名已在图1A解析为地址快照。`sendto/sendmsg/sendmmsg` 同样复制并检查目标；已连接 socket 的普通 `write` 使用已获准 peer，不表示每个数据包都经过 broker。库、证书、配置等文件仍受 Landlock 文件授权限制。图中网络 worker 不安装业务文件 Landlock；文件打开 worker 则必须安装，见图3。

源码：[network_handle / handle_socket / handle_connect / handle_send](../src/network.c)。

## 3. USER_NOTIF：接收、参数固定、代执行与响应

listener 已按图1B传递；本图展开单条通知。箭头上“内核”表示通过 seccomp 通知设施转交。

```mermaid
sequenceDiagram
    autonumber
    participant P as 业务进程
    participant M as monitor进程
    participant R as broker进程
    participant W as 可信worker进程（按需）
    P->>P: 发起系统调用；内核执行BPF得到USER_NOTIF
    Note right of P: 仅发起调用的线程等待<br/>其他业务线程仍可能修改共享内存或FD
    P-->>R: 内核将请求放入listener队列，FD变为可读
    R->>R: poll；broker_drain；NOTIF_RECV取得id/pid/data
    opt 需要读取业务指针参数
        R->>M: 私有RPC：请求固定目标mem FD，附通知ID/TID
        M->>M: ID_VALID → 打开proc/TID/mem → ID_VALID
        M-->>R: SCM_RIGHTS传回固定地址空间FD
        R->>R: 再核验ID，复制地址/路径/数据到可信内存
    end
    R->>R: 固定业务对象，按操作类型进行授权
    alt 拒绝请求
        R-->>P: NOTIF_SEND：内核向业务返回errno
    else 静态策略允许原生执行（例如审计普通调用）
        R-->>P: NOTIF_SEND，flags=CONTINUE
        P->>P: 内核继续原系统调用；文件操作仍受Landlock等约束
    else 敏感请求由可信方代执行
        alt metadata
            R->>R: 固定rw根内对象，核验类型/所有权，执行受限修改
            R-->>P: NOTIF_SEND：内核返回代执行结果
        else 文件打开或可能阻塞的网络操作
            R->>W: fork，传递已捕获参数和固定对象
            Note right of R: broker继续处理其他通知<br/>不等待worker完成
            alt 文件打开worker
                W->>W: 安装同源固定根Landlock，清理多余FD，safe_open
            else 网络worker
                W->>W: 用已授权地址副本和broker socket实际connect/send
            end
            alt 成功创建需交给业务的文件FD
                W-->>P: ADDFD+SEND：内核原子安装FD并回复
            else 返回值或操作错误
                W-->>P: NOTIF_SEND：内核返回value/errno
            end
            W->>W: 完成审计/交付记账并退出
        end
    end
    R->>R: 本批最多32条；无待处理通知则提前返回
    R->>R: 回到broker_run，进行GC、worker回收及故障检查
```

敏感指针操作使用可信副本代执行，不采用“检查地址后 CONTINUE、让业务重读可变指针”的授权方式。`socket()` 不需要读取业务地址指针，由 broker 直接创建并 `ADDFD+SEND`，见图2B。文件打开审计有一个明确例外：旧内核无法 ADDFD 传递 O_PATH 时，仅在该特定失败条件下记录 native fallback，再在业务已有 Landlock 下 CONTINUE；这不算观察到原生调用完成。

一批32条是数量上限，不是时间上限；poll就绪与接收之间通知可能失效，RECV仍可能阻塞。已经发生的获准网络/文件副作用不能由通知取消回滚。审计失败或交付记账不完整会使最终任务失败。

源码：[broker_drain / broker_memory_open / broker_service_memory](../src/broker.c)、[filebroker_handle / perform_open](../src/filebroker.c)、[network_handle](../src/network.c)。

## 4. 补充：正常结束、超时或取消后的回收

```mermaid
sequenceDiagram
    autonumber
    participant C as CLI进程
    participant M as monitor进程
    participant P as 业务进程
    participant R as broker进程（若存在）
    participant W as worker进程（若存在）
    alt 业务结束
        P-->>M: pidfd可读，monitor观察到退出
    else 执行超时
        M->>M: timerfd到期
    else 调用方取消
        C->>M: 控制管道发送取消信号值
    end
    Note right of M: monitor也直接监视原调用方pidfd<br/>broker故障同样触发失败清理
    M->>M: resource_kill（若启用）
    M->>P: SIGKILL业务进程及其进程组，回收后台业务
    opt 启用审计
        M->>M: 最多50ms等待可信交付记账收尾
    end
    M->>R: signal_children(true)：统一SIGKILL直接子进程
    Note over M,W: broker退出后，存活worker由subreaper收养
    M->>W: 后续清理轮次SIGKILL收养的worker
    M->>M: 反复读取children，waitpid使用__WALL回收
    alt 清理确认到ECHILD
        M->>M: resource_finish；workspace_finish：diff/export/keep/discard
    else 不能确认无后代
        M->>M: 标记清理失败，保留工作区，不导出
    end
    M->>M: 检查delivery_pending，完成审计并写result JSON
    M-->>C: monitor退出，CLI通过waitpid取得状态
    C->>C: 检查残留，必要时故障恢复；收尾并返回
```

循环有清理时间预算，不承诺不可中断内核任务一定及时退出；只有实际观察到 `ECHILD` 才声明 `cleanup_complete=true`。CLI/monitor任一层单独失效由存活subreaper兜底，两层同时被强杀不在该保证内。broker通常由上述统一清理终止；它自身遇到审计、通知或poll错误也会返回125。listener HUP时它等待monitor终止，而非提前报告故障退出。

源码：[monitor_run / signal_children / finish / supervise](../src/supervisor.c)、[broker_run](../src/broker.c)。
