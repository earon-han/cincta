# 细粒度网络策略与动态代理

`--network allowlist --allow-net tcp:HOST_OR_CIDR:PORT[-PORT]` 启用出站目的端点白名单。可重复规则；UDP用 `udp:`。IPv6地址必须加方括号，例如 `tcp:[::1]:443`、`udp:[2001:db8::/32]:10000-11000`。端口范围1–65535，协议仅TCP/UDP，没有隐式DNS、loopback或代理例外。

## 域名和解析语义

域名在不可信业务启动前由可信启动器解析成IPv4/IPv6地址快照，执行期间不自动刷新。结果中的 `network_snapshot` 列出实际获准地址和来源规则。该权限代表“这些IP上的这些端口”，不是HTTP Host、TLS SNI或证书身份；共享IP上的其他虚拟主机同样可达。DNS变化后新IP不会被自动放行，重新运行才重新解析。业务自身需要DNS时，必须另外明确允许所需UDP/TCP53端点及配置文件读取。启动前的解析不在 `--timeout-ms` 执行预算内；在业务中实际发起的网络操作受执行阶段取消/超时管理。

数字IP要求标准inet_pton形式；127.1、2130706433、0x7f000001等旧式数字语法即使系统resolver接受也会在执行前拒绝，避免被误当域名授权。

## 内核与broker分工

经典BPF不能读取sockaddr，因此不能直接实现IP白名单；Landlock的TCP端口授权也不能区分同端口的不同IP。此模式使用seccomp notification：

1. `socket`由可信broker创建，只允许AF_INET/AF_INET6 TCP stream或UDP datagram。ADDFD+SEND原子注入FD并返回，broker保留同一socket的引用。
2. broker通过真实procfs的 `/proc/TID/fd/FD` 用O_PATH固定对象，在notification ID验证后fstat，比较S_ISSOCK、st_dev、st_ino，查找自己持有的socket。dup/fork继续指向同一对象；未知socket拒绝，不只信任readlink显示的inode字符串。
3. `connect/sendto/sendmsg/sendmmsg/setsockopt` 的指针参数先复制到broker内存，再校验notification ID并判断不可变策略。
4. broker使用自己的socket和已经复制的参数执行，绝不通过CONTINUE让目标重新读取已授权指针。其他线程改变地址或FD只能影响业务自身的并发语义，不能放行一个未授权地址。

网络broker通过仅由可信进程持有的私人socketpair请求真实祖先monitor固定目标内存。monitor先验证notification ID，打开 `/proc/TID/mem` 固定mm，再验证同一ID，随后经SCM_RIGHTS把FD传给broker；broker收取后再次验证ID，复制参数后及外部效果前也复核。sendmmsg需要回写msg_len时明确申请O_RDWR句柄，其他读取使用O_RDONLY。之后通过固定FD读取/回写，防止PID退出复用把操作转到其他进程。通知被取消的瞬间仍可能已经发生获准的外部操作，不能承诺取消能回滚已发出的网络流量。

本模式不依赖pidfd_getfd、CAP_SYS_PTRACE或PR_SET_PTRACER例外，也不修改主机Yama配置。使用真实祖先monitor进行procfs访问，可覆盖业务fork出的子孙，避免让兄弟broker依赖不会继承给fork后代的ptracer例外。外层Yama/LSM、hidepid或目标主动关闭dumpable仍可能拒绝访问，此时操作失败，不继续原始syscall。Docker需允许seccomp通知、ADDFD等ioctl及祖先的procfs访问。

## 能力和有意限制

- IPv4/IPv6、CIDR、端口范围、TCP/UDP和域名快照均按相同端点策略判断。IPv4-mapped IPv6同时适用IPv4规则；带非零scope-id的IPv6目标拒绝，避免把接口范围误称全局IP身份。
- 未连接UDP socket的sendto/sendmsg/sendmmsg目标逐条授权。已连接socket的write/writev/sendfile/splice等只能使用已经授权的peer；原始connect入口始终经broker。
- sendmsg ancillary控制信息一律拒绝，防止IP_PKTINFO、IPv6 routing等改变出站目的；setsockopt只允许普通buffer、keepalive、timeout、linger、TCP_NODELAY及IPv6_V6ONLY等明确列出的选项。IP_OPTIONS、IPV6_RTHDR、SO_BINDTODEVICE等不放行。
- ioctl仅允许对registry已固定的broker-owned socket执行FIONBIO，启用/关闭非阻塞标志的整数参数先复制再执行，兼容Python等运行时的socket timeout；其他ioctl仍拒绝。
- bind/listen/accept、UNIX/netlink/raw socket、socketpair拒绝；此策略为出站授权，不提供入站服务器能力。
- 单条send操作最多1MiB、最多64个iovec；sendmmsg最多64条且整个batch payload≤1MiB，先复制并授权全batch，再执行。已发送的部分按真实消息数返回，msg_len回写失败不会自动重发。
- 阻塞connect/send操作由有上限的可信短命worker执行，不阻塞主监管循环；最多64个worker、512个保留socket。达到上限返回资源错误。

broker保留socket会延长其生命周期；broker循环周期调用network_gc，扫描固定payload进程组内每个进程的每个 `/proc/PID/task/TID/fd`，包含CLONE_THREAD但不共享CLONE_FILES的私有线程FD表。连续两遍扫描取引用并集、核对task集合，成员变化、目录读取、FD状态读取或关闭目录出错时，本轮保守保留全部broker副本。超过16384个task时同样保守保留并返回扫描失败，避免无界内存消耗。调用方在共享state的gc_deferred累计延期，后续重试，不把正常procfs并发变化终止为监管故障；512个保留socket上限始终生效。当前最终结果JSON尚未导出gc_deferred，不能从日志缺少延期事件推断每次扫描都完整。

procfs不是原子FD快照：即使两遍task集合相同，跨线程fork/dup/close交接仍可能与读取交错，因此GC不构成透明正确性保证，存在延迟FIN或业务操作失败的可用性边界。GC不参与地址授权，不能放宽端点策略。网络worker由broker派生，并纳入monitor的subreaper和强制回收。可信broker/worker不在 `--tree-*` 的payload叶组内；它们另受worker数量、socket保留数和单次缓冲大小上限约束，需要整个服务总量配额时由外层服务cgroup提供。

## 审计与验证

observer在外部效果前记录authorize，执行后记录result，并携带同一复制出来的目标IP/端口和实际返回值/errno。预先审计失败时拒绝执行；效果后审计失败时触发监管失败，已完成外部效果不能撤销。ADDFD+SEND已经回复成功后发生审计错误，同样由共享故障标记中止任务，不能伪装成未发生效果。

每个可能产生外部效果或注入FD的操作还通过observer发出一对delivery_begin/delivery_end。socket在ADDFD+SEND前begin、结果记录完成后end；connect/send worker在fork前begin，成功、失败、通知已取消或fork失败路径均配对end；sendmmsg整个batch只计一对，同时逐条保留发送结果和最终batch_result。setsockopt/FIONBIO同步效果也纳入计数。begin日志失败时没有计数、也不执行；不得对未成功begin的操作调用end。end事件的errno仅表示通知回复的投递错误，实际操作errno保留在result事件；意外投递错误应由observer设置共享audit_failed。

monitor终止业务后给可信worker最多50ms完成已开始的结果记录，再执行强制清理。若worker或broker被杀导致delivery_pending没有归零，结果必须报告审计失败，不能声称记录完整；该计数是丢失可检测机制，不能撤销已完成的操作或保证磁盘故障时审计成功。日志写入失败后可回复EIO的路径会回复EIO，已由ADDFD+SEND或通知响应返回给业务的结果无法事后改写，最终任务结果仍标记失败。sendmmsg已发送部分保留真实消息数，避免把审计或msg_len回写故障诱发成重复发送。

`tests/network_test.py` 使用本地TCP/UDP echo服务器，覆盖IP/CIDR/域名、IPv6、地址与端口拒绝、connected UDP、sendmsg/sendmmsg、控制信息/路由选项/原始socket拒绝、dup、close/EOF和线程私有FD表回归。最后一项会用系统C编译器构建 `network_thread_fds.c`，通过不带CLONE_FILES的CLONE_THREAD创建私有FD表、主线程关闭socket并等待多个GC周期后再从私有表连接。必须分别在本地Linux VM与Docker运行并保存报告。编译成功不代表网络安全验证完成。
