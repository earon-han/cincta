# v0.2 独立设计与威胁模型审查

审查日期：2026-11-06。角色：独立设计/安全审查 Agent；实现由其他 Agent 完成。基线为 `d63904f` 的 v0.1，本文先冻结新增机制的安全不变量，实际实现审阅与实测结论在文末持续追加。本文不把设计可行性当作实现已经完成或测试已经通过。

## 1. 本轮必须补齐的能力及判定

| 能力 | 可接受的实现语义 | 不可冒充的能力 |
|---|---|---|
| 动态网络监管 | 可信 broker 复制请求，在其持有的对象上完成操作，并返回模拟结果 | 按用户指针内容检查后让原 syscall CONTINUE |
| IP/CIDR/端口/域名策略 | 协议、地址和端口都检查；DNS在可信侧解析，实际连接使用已检查的二进制地址 | 只检查字符串域名/HTTP Host；只限制TCP端口就声称限制IP |
| 树级资源 | cgroup v2独立叶组，exec前移入；内存/进程/CPU带宽分别报告 | RLIMIT_NPROC当每run进程数；cpu.max当累计CPU时间 |
| 工作区写隔离 | 独立物理快照或经过验证的reflink；仅快照可写；显式导出/丢弃 | hardlink复制当COW；不具备mount能力却声称原路径透明重映射 |
| 文件metadata兼容 | 对固定且已授权的对象代执行最小必要操作 | 按检查过的pathname或/proc字符串前缀直接放行原调用 |
| 审计 | 明确请求、决定、代执行结果和原生CONTINUE的区别 | 把入口通知当成功退出结果；把部分syscall日志当完整追踪 |
| 多平台交付 | 每架构真实Linux内核执行，VM与Docker分开留证 | QEMU用户态或交叉编译当作原生seccomp验证 |

“实现某可选能力”包括依赖探测、明确失败和真实正反用例，不意味着任意默认环境都能提供该能力。请求的保护无法建立时必须在业务执行前失败；结果不允许用rlimit等较弱机制代替请求的树级配额。部署者显式启用的较重依赖应在使用指南中写出。

## 2. 动态网络 broker：可接受方案

### 2.1 官方接口给出的约束

seccomp notification会暂停调用线程并把请求交给监听者。`CONTINUE`继续执行时仍使用业务地址空间中的参数，其他线程可以在检查后改写它；notification ID有效性也会因退出或信号中断变化。ADDFD可向目标安装FD，SEND标志能把注入与返回合成一个原子动作。设计必须以复制后的数据代执行，或保留足以独立拒绝危险变参的内核策略。[Linux seccomp notification手册](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)

`pidfd_getfd`复制目标FD还受ptrace访问检查和外层容器策略限制，不能仅因pidfd_open可用就推定它可用。这里把其作为可选诊断能力，不作为默认Docker路径的必需依赖。[pidfd_getfd手册](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)

### 2.2 broker创建并保留socket

推荐实现：所有允许的新IP socket都经通知，由broker创建并用ADDFD注入目标；broker保留同一个open file description的引用，直到本run结束。注册表记录所属run、`st_dev/st_ino`、family/type/protocol、当前状态。目标socket FD被dup或fork继承后，仍可通过其内核对象身份匹配到原注册对象。

connect/sendto/sendmsg等请求到达后：

1. 校验syscall架构、参数长度、通知ID和请求属于本次运行。
2. 读取目标FD指向对象的内核身份；只能匹配本run仍由broker持有的socket。普通文件和其他run对象拒绝。
3. 把sockaddr、payload、必要长度一次性复制进有大小上限的broker缓冲区，再次校验ID。
4. 对复制数据执行策略判断，在broker原FD上实施获准操作。
5. 返回实际代执行结果；绝不对授权过的可变网络指针使用CONTINUE。

这里FD被另一个线程关闭/重用，最多导致本次操作针对一个先前观察到、仍固定属于本run的socket，而不能把broker变成对任意外部对象操作的代理。注册表持有引用使相同socket inode不能被释放复用；还应比对设备号、类型，并明确禁止跨namespace迁移。

### 2.3 必须封堵的替代入口

- 仅AF_INET/AF_INET6且只允许已实现的type/protocol；raw、packet、UNIX、netlink、socketpair全部拒绝或独立实现，不得顺带开放。
- sendto/sendmsg/sendmmsg均须经过broker。即使本次看见TCP或空目的地址，也不能CONTINUE：FD可被并发换成可指定目的地的UDP socket。
- sendmsg控制消息默认全部拒绝，除非某种类型已有专门安全证明；IP_OPTIONS、IPV6_RTHDR、透明代理及其他可改变路由/目的地的setsockopt不应默认放行。对setsockopt使用明确安全列表。
- io_uring、兼容架构socketcall、pidfd_getfd获取外部FD、namespace切换等继续封堵。
- AF_UNSPEC断开、bind、listen、accept、已连接UDP默认目的地变更，均须有明确规则；首版未实现的操作返回明确不支持，不能绕开注册表。
- 为防目标安装新listener覆盖通知路径，用户代码开始前必须永久禁止seccomp()和prctl(PR_SET_SECCOMP)。
- 目标启动时继承的stdio是调用方额外授予的能力。任何扩展继承FD必须单独建模，不能把任意已连接socket放进目标后仍声称绝对断网。

保留socket引用有真实代价：目标close不一定立即触发TCP FIN，文件描述符资源可能持续占用到run结束；必须限制注册表大小、拒绝无限socket创建、记录关闭/回收语义。该方案可安全提供能力，但不应宣称对任意网络程序完全透明。

### 2.4 不接受的代理捷径

普通HTTP_PROXY/CONNECT代理也不能只靠Landlock开放一个TCP端口来保证“仅连代理”。Landlock网络授权的端口维度不是IP/域名维度；恶意程序仍可能连接其他IP的同一端口。需要broker安全代执行connect、独立网络namespace，或显式预开通道协议。HTTP Host不是可靠目的地授权凭据。[Landlock 6.12 API](https://docs.kernel.org/6.12/userspace-api/landlock.html)

域名授权应是准确DNS名（统一大小写，明确尾点/IDNA/通配符规则），由可信侧解析一次并把结果固定到该run策略。CNAME、多个A/AAAA、IPv4-mapped IPv6和解析失败均要定义；连接时使用已经验证过的地址，不能再次按名字解析。若策略允许刷新，刷新产生新策略版本并记录审计。对共享IP或CDN，域名解析结果只代表网络地址能力，不承诺TLS身份或HTTP内容隔离。

## 3. listener引导与监管失效

两阶段filter引导可行：可信单线程payload先安装静态限制+通知filter，唯一bootstrap socket允许向monitor传递listener；发送后立即安装第二个静态lockdown filter，再关闭listener和transport，最后报告ready并exec。

要求：两filter之间绝无用户代码/用户线程执行；第二filter失败必须退出；永久拒绝新的seccomp安装与PR_SET_SECCOMP。第一filter里对bootstrap sendmsg的FD数值例外必须由第二filter永久封堵，避免关闭后相同FD数值复用成为绕过。transport槽位占用或永久限制产生的兼容代价要记录。monitor端只接收恰好一个预期SCM_RIGHTS FD，拒绝控制消息截断或额外FD。

monitor应在可轮询listener就绪后调用NOTIF_RECV；信号/目标退出可使请求失效，失效ID不能被当作内部成功。代执行网络操作有严格超时和缓冲/请求上限，不能让慢DNS、connect或流量把取消路径永久阻塞。监听器意外丢失或broker错误时执行失败并清理，禁止退到host网络模式。

## 4. 文件metadata兼容性

Landlock未覆盖的metadata操作继续由BPF拦截。需要支持chmod/时间戳等时，broker只能从固定rw根FD出发，通过openat2受约束解析固定目标对象，再针对该对象完成代执行；不按已检查的原路径CONTINUE。[openat2接口](https://man7.org/linux/man-pages/man2/openat2.2.html)

对原始payload FD执行fchmod等，不能只从/proc读字符串并检查前缀；必须固定对象，证明该对象属于授权根，并在可控对象上执行。无法证明时拒绝。拒绝设置setuid/setgid位；chown至多保留当前UID/GID或-1，不允许可信root broker替无权目标扩大所有权。broker自己的capabilities和身份权限也必须收紧，避免代执行超出目标正常身份能力。

## 5. 工作区快照、导出与丢弃

不依赖mount权限的实现可使用物理文件副本：源树只读，快照树读写，cwd转向快照，完成后生成新增/修改/删除清单。丢弃即删除快照，源树无需“回滚”；导出默认写到新的可信目录，不自动覆盖原源树。reflink成功可优化，但hardlink源文件不能作为副本。

文件遍历不跟随symlink，复制link本身；拒绝设备/套接字/FIFO等特殊对象，或为其单列安全语义。使用目录FD和受约束的相对路径处理，拒绝跨目录逃逸和结果/控制文件被嵌入业务快照。源目录并发改变必须检测并失败，或显式声明为非原子快照，不宣称时间点一致性。diff/export阶段同样面对不可信内容和symlink，不能在业务完成后失去安全检查。

审查需要覆盖：外部symlink、目录symlink、嵌套源/目标、目标替换、硬链接、删除、权限变化、空文件/大文件、深目录、无权限源、并发源变化、导出路径已经存在、取消和CLI/monitor故障后残留。

## 6. cgroup v2资源与清理

cgroup v2控制器作用于子树；cpu.max控制带宽，memory.max控制内存上限，pids.max约束任务数量，不能混写为同一种“资源预算”。创建叶组、设置所请求控制器、验证读取结果，并在业务进入组后才释放exec屏障；monitor留在组外。已创建的后代不会因稍后迁移父进程而自动迁移，所以必须在首次业务fork前就入组。[内核cgroup v2文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)

部署要求：真实cgroup2挂载、控制器可用、专用子树的明确写权限/委派。通过fstatfs验证文件系统类型，不可用普通目录里的同名文件伪造成功。默认Docker只读cgroup环境应验证请求后明确拒绝；正向容器验证可只bind一个预先委派的专用子树，继续保留默认seccomp/AppArmor和无额外capabilities，并将这一额外部署条件单独记录。

payload不得获得写cgroup控制目录的授权，否则可写cgroup.procs迁移逃离配额；需要拒绝覆盖控制子树的rw授权，且不得泄露控制FD。取消时可用cgroup.kill增强整树终止，但实际回收仍由wait确认；删组成功或populated=0不等于没有僵尸。缺控制器、权限不足、初始化中途失败和清理失败都要有测试。

## 7. 审计的可证明范围

至少分开记录请求入口、策略决定、broker代执行结果、生命周期、清理/导出状态。通知后CONTINUE的操作只能证明请求被观察到；没有出口观察就不能把它记作成功。原生file open的路径字符串可能并发改变，审计记录应标为请求快照；实际文件授权仍由Landlock内核检查。

若声称“完整所有syscall审计”，必须解释：静态更高优先级拒绝是否也有事件、每个线程的入口和出口、restart/信号中断、exec/exit、通知覆盖、外层seccomp提前拒绝、事件丢失与磁盘写失败。做不到这些时应使用精确覆盖标签，不能把部分通知日志命名成完整审计。

## 8. 发布与独立验证门槛

设计审查不代替实现审查。实现落盘后至少检查：通知内存快照、ID与任务身份、注册对象固定、filter优先级、控制FD关闭、监听者故障、无界阻塞、cgroup入组屏障、快照导出与路径处理。每项声明能力需要正向、拒绝、无能力和故障注入用例。

真实VM与默认安全Docker分别运行，容器bind委派子树的资源正例另列环境；不能将host改宽权限作为所有容器的隐藏前提。x86_64和aarch64分别编译并实际在真实Linux内核验证，用户态QEMU不算seccomp原生证据。公开外部审计属于外部工作，不能把多个AI Agent互审说成第三方审计。

## 9. 实现复审记录

2026-11-06 已逐段静态复核新增 `security.c`、`broker.c`、`network.c`、`resources.c`、`workspace.c` 和各自header。监视器仍在整合，以下是复核中发现并反馈给实现者的事项；具体关闭状态必须随最终代码再次确认。

| 项目 | 观察 / 风险 | 要求的修复或边界 |
|---|---|---|
| metadata根重新realpath | **高风险**：可写中间symlink可把每次重新解释的rw规则指向启动时未授权的另一个对象 | 启动前固定所有policy O_PATH FD和canonical目标；LL、metadata和file worker均复用同一组固定根，绝不每请求重新生成授权根 |
| 工作区源别名 | 额外rw目录中可能有指向source文件的hardlink/bind别名，字符串祖先/后代检查不足以保证源数据不变 | workspace模式拒绝额外rw授权，或实现完整别名检查并准确声明例外 |
| 网络GC枚举 | 顶层TGID fd扫描会漏掉未共享FD表的线程；并发fork/dup也可能使快照漏引用 | 扫task线程，对读/遍历失败保守保留；把不可避免的可用性边界写明，不把GC作为授权依据 |
| broker凭证 | root监管者残留capabilities可能使代执行绕过payload本应受的DAC限制 | 独立broker在业务开始前清NNP/capabilities，使用不高于payload的身份；管理权限留在monitor |
| 审计字符串 | UTF-8逐byte转u00xx导致路径解码乱码；固定小缓冲静默截断长路径 | 可逆字节编码或正确UTF-8；完整记录或显式truncated/原长度，禁止静默损失 |
| notification接收 | poll就绪与RECV之间请求可被信号撤销，ioctl可能阻塞，fcntl非阻塞不能单独证明取消路径有界 | 把可阻塞通知处理隔离为独立可信broker进程，monitor只做可唤醒生命周期事件循环；broker死亡触发整体清理 |

已核对的不变量：BPF邻近跳转能回到syscall nr；动态引导允许listener传递但第二filter永久拒绝seccomp/PR_SET_SECCOMP和bootstrap FD消息例外；审计分类复用同一BPF编译器而非另写漂移的allow/deny表；网络lookup固定目标O_PATH再检查通知ID，匹配sockfs设备/ino/类型与broker注册对象；网络指针复制后代执行，setsockopt明确白名单；cgroup使用真实cgroup2验证、身份核对和配额readback；工作区不hardlink复用源inode，不跟随文件/目录symlink复制或删除。

整合方向更新为：CLI → monitor → 独立broker及payload；网络/file worker由broker派生。独立broker用于隔离可能阻塞的NOTIF ioctl和文件操作，monitor必须能在broker阻塞或崩溃时完成取消与子树收养清理。监听器、控制FD、固定policy FD的保留/关闭要按这四层逐一确认。

修复复核进展：metadata与文件worker已经改为复用启动前固定的policy FD；workspace模式拒绝额外rw授权及外部可写普通文件stdio；broker启动清capabilities；审计改为完整动态单次write、正确UTF-8和可逆target_bytes_hex。上述修改已在源码中复核，但运行结果仍待统一实测。

新增file-open broker审查指出主体转换风险：worker未exec，`/proc/self/environ`、`/proc/self/mem`和FD链接会指向可信worker，而非payload。实现已经通过提前O_PATH固定对象、fstatfs拒绝procfs、NO_MAGICLINKS、从固定对象实际打开、worker关闭非必要FD进行收紧；这也是审计模式明确的兼容性边界。不能只检查用户路径的字符串前缀，因为普通symlink同样可以指向procfs。

旧内核可能拒绝ADDFD注入O_PATH对象。仅当broker自己仍持有的有效O_PATH FD在实际注入时返回EBADF，允许记录独立native-fallback事件并CONTINUE原请求：最终open仍由payload自身Landlock+BPF检查，故不依据读过的可变指针授予例外。该分支只能声称请求快照和worker观察，不得声称取得原生syscall的实际返回值。普通读写FD、metadata、网络授权不可采用此fallback，也不可把其他不明注入错误泛化成放行。

其余部署边界须写明：树配额若只包含payload后代，不包括组外broker/代执行worker的内存、CPU和socket成本；这些可信辅助工作仍须有总量上限。cgroup控制目录还需考虑bind挂载别名，realpath不会消除bind别名。完整syscall日志有磁盘增长成本，应限量并在审计失败时终止，或明确依赖外层容量配额。

以上是源码/设计审查结论，不计运行PASS。所有实际结果以最终validation与reports原始证据为准。
