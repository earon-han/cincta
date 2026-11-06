# v0.2 独立设计与威胁模型审查

本文为实现阶段复审记录；P10后续全新代码审查发现的问题、修复及最终结论以[最终代码审查](final-code-review.md)与[修复台账](review-resolutions-v02.md)为准。

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

独立broker在listener就绪后调用NOTIF_RECV；信号/目标退出可使请求失效，失效ID不能被当作内部成功。代执行操作保持缓冲、socket和worker总量上限，执行阶段的墙钟预算及取消由monitor管理；DNS准备与内核阻塞的范围另行说明。监听器意外丢失或broker错误时执行失败并清理，禁止退到host网络模式。

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

2026-11-06 已逐段静态复核新增 `security.c`、`broker.c`、`network.c`、`resources.c`、`workspace.c` 和各自header。下表保留开发期间发现并反馈给实现者的事项；最终关闭状态见9.1–9.5。

| 项目 | 观察 / 风险 | 要求的修复或边界 |
|---|---|---|
| metadata根重新realpath | **高风险**：可写中间symlink可把每次重新解释的rw规则指向启动时未授权的另一个对象 | 启动前固定所有policy O_PATH FD和canonical目标；LL、metadata和file worker均复用同一组固定根，绝不每请求重新生成授权根 |
| 工作区源别名 | 额外rw目录中可能有指向source文件的hardlink/bind别名，字符串祖先/后代检查不足以保证源数据不变 | workspace模式拒绝额外rw授权，或实现完整别名检查并准确声明例外 |
| 网络GC枚举 | 顶层TGID fd扫描会漏掉未共享FD表的线程；并发fork/dup也可能使快照漏引用 | 扫task线程，对读/遍历失败保守保留；把不可避免的可用性边界写明，不把GC作为授权依据 |
| broker凭证 | root监管者残留capabilities可能使代执行绕过payload本应受的DAC限制 | 独立broker在业务开始前设置NNP并清capabilities，使用不高于payload的身份；管理权限留在monitor |
| 审计字符串 | UTF-8逐byte转u00xx导致路径解码乱码；固定小缓冲静默截断长路径 | 可逆字节编码或正确UTF-8；完整记录或显式truncated/原长度，禁止静默损失 |
| notification接收 | poll就绪与RECV之间请求可被信号撤销，ioctl可能阻塞，fcntl非阻塞不能单独证明取消路径有界 | 把可阻塞通知处理隔离为独立可信broker进程，monitor只做可唤醒生命周期事件循环；broker死亡触发整体清理 |

已核对的不变量：BPF邻近跳转能回到syscall nr；动态引导允许listener传递但第二filter永久拒绝seccomp/PR_SET_SECCOMP和bootstrap FD消息例外；审计分类复用同一BPF编译器而非另写漂移的allow/deny表；网络lookup固定目标O_PATH再检查通知ID，匹配sockfs设备/ino/类型与broker注册对象；网络指针复制后代执行，setsockopt明确白名单；cgroup使用真实cgroup2验证、身份核对和配额readback；工作区不hardlink复用源inode，不跟随文件/目录symlink复制或删除。

整合方向更新为：CLI → monitor → 独立broker及payload；网络/file worker由broker派生。独立broker用于隔离可能阻塞的NOTIF ioctl和文件操作，monitor必须能在broker阻塞或崩溃时完成取消与子树收养清理。监听器、控制FD、固定policy FD的保留/关闭要按这四层逐一确认。

首轮修复已复核：metadata与文件worker复用启动前固定的policy FD；workspace模式拒绝额外rw授权及外部可写普通文件stdio；broker启动清capabilities；审计使用完整动态单次write、正确UTF-8和可逆target_bytes_hex。最终实测证据按统一验证报告与源码指纹记录。

新增file-open broker审查指出主体转换风险：worker未exec，`/proc/self/environ`、`/proc/self/mem`和FD链接会指向可信worker，而非payload。实现已经通过提前O_PATH固定对象、fstatfs拒绝procfs、NO_MAGICLINKS、从固定对象实际打开、worker关闭非必要FD进行收紧；这也是审计模式明确的兼容性边界。不能只检查用户路径的字符串前缀，因为普通symlink同样可以指向procfs。

旧内核可能拒绝ADDFD注入O_PATH对象。仅当broker自己仍持有的有效O_PATH FD在实际注入时返回EBADF，允许记录独立native-fallback事件并CONTINUE原请求：最终open仍由payload自身Landlock+BPF检查，故不依据读过的可变指针授予例外。该分支只能声称请求快照和worker观察，不得声称取得原生syscall的实际返回值。普通读写FD、metadata、网络授权不可采用此fallback，也不可把其他不明注入错误泛化成放行。

其余部署边界须写明：树配额若只包含payload后代，不包括组外broker/代执行worker的内存、CPU和socket成本；这些可信辅助工作仍须有总量上限。cgroup控制目录还需考虑bind挂载别名，realpath不会消除bind别名。完整syscall日志有磁盘增长成本，应限量并在审计失败时终止，或明确依赖外层容量配额。

以上是源码/设计审查结论，不计运行PASS。所有实际结果以最终validation与reports原始证据为准。

### 9.1 最终代码复核与关闭状态

最终复核已覆盖 `main.c`、`supervisor.c`、`security.c`、`broker.c`、`filebroker.c`、`network.c` 与结果输出。已经在源码确认：monitor使用signalfd、pidfd、timerfd唤醒，NOTIF_RECV及业务文件/网络代执行位于独立broker或worker；payload在exec屏障后才移入独立cgroup，完成安装和lockdown才报告ready；payload的policy FD在通知过滤安装前关闭。monitor与CLI分别作为subreaper，按尚未回收的直接子进程终止并以ECHILD确认清理，保留进程组leader身份直到最后一次killpg。

网络GC现扫描所有task线程的FD表，以两遍引用并集、稳定task集合及所有读取成功为回收条件；非原子fork/dup扫描仍有已声明的可用性边界，不参与端点授权。网络代执行在fork前记录delivery_begin并增加共享pending，实际结果和响应后记录delivery_end；清理时非零pending判审计失败。审计存储新增跨worker原子预留配额，默认64MiB与100万记录，超过配额明确终止。cgroup保护已加入固定RW根的fstatfs检查及全部cgroup2 mountinfo祖先检查，覆盖预存在的bind挂载别名；树内存限制在memory.swap.max存在时写0并读回确认。

本轮新发现的四项问题已逐项修复；其中可信输出别名进一步发现反向子目录bind情形，现已加入挂载身份映射。这里的关闭只表示代码与独立复核结论，真实VM/Docker结果以最终测试源码指纹为准：

| 项目 | 风险与复现条件 | 已核对的修复 |
|---|---|---|
| 关闭stdio时可信FD进入0/1/2 | **高风险**：main在supervise补齐stdio之前创建result/audit/policy FD；调用方预先关闭stdout等槽位，可信FD可能被payload作为stdio继承并篡改 | **源码关闭**：main入口在任何内部open或prepare前补齐0/1/2，并恢复信号/子进程回收语义 |
| 可信输出的bind别名 | **高风险**：仅realpath排除RW祖先无法识别指向输出parent的bind别名；payload可经另一授权路径改写audit/result或导出文件 | **源码关闭并由另一Agent独立复核**：固定FD取得STATX_MNT_ID，按精确mountinfo记录映射底层FS路径，按同设备祖先关系检查；包括 `/rw/sub` 单独bind到 `/alias` 的反向子目录情形。根inode祖先检查及RW下额外挂载拒绝继续作为补充 |
| 文件/metadata实际效果窗口 | file worker仅在ADDFD前增加pending，漏掉open/create/truncate已经发生但结果尚未记录时被杀的窗口；metadata同样存在效果与结果之间窗口 | **源码关闭**：file worker在父broker fork前计pending，fork失败或统一worker_exit递减，强杀保留非零；metadata在实际操作前增加pending、结果记录后递减 |
| 预开cgroup写FD | 规则检查不覆盖调用方把cgroup.procs作为可写stdio传入，可能直接迁移逃离树配额 | **源码关闭**：显式树配额模式检查标准FD的cgroup2文件系统类型及写访问模式并拒绝 |

此外，树配额当前统计payload及其后代，组外broker和有上限的代执行worker资源不包含在该配额内。main的DNS解析、工作区复制准备和最终export/fsync也不由monitor墙钟timer直接界定；应在使用指南中精确说明预算范围。源树含嵌套mount已在准备前明确拒绝，workspace-parent与源的关系、export/output与源/私有根的关系、所有额外RO/RX规则与源/私有根的双向重叠，均纳入同一挂载身份映射；合法单文件RO/RX规则使用O_PATH而非强求O_DIRECTORY。安全校验已先于result独占创建；更早语法、授权根、目录布局错误仅输出stderr，避免被拒绝的输出别名先在源树产生空result。

映射要求：对固定对象以AT_EMPTY_PATH取得STATX_MNT_ID，并确认返回mask包含该位；核对fstat与statx设备号，按mount ID精确选择mountinfo第1项，再核对第3项设备号，用第4项root和相对于第5项mountpoint的路径后缀组成FS内路径。字段转义、路径组件边界、长度与缺失记录均需拒绝错误，不以最长路径前缀猜测stacked mount。STATX_MNT_ID从Linux5.8提供，早于本项目最低运行内核；必须允许statx及可读mountinfo。初始化期间宿主挂载和目录布局应稳定可信；暴露overlay底层存储或不同服务器导出同一物理数据等跨文件系统别名，不属于通用VFS bind身份检查能证明的范围，部署者不得授予这种外部写通道。[statx接口](https://man7.org/linux/man-pages/man2/statx.2.html)、[mountinfo字段定义](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)

这一最后的边界修复由本审查Agent实现，另一独立Agent逐段检查映射、转义、设备号、调用覆盖和共享上下文生命周期；VM/Docker执行由根Agent统一进行。新增输出边界用例真实核对samefile后才测试拒绝，不创建mount或改容器profile。启动失败结果后移到workspace/resource/guardian清理之后；共享ctx在unmap前复制并重定向cwd、规则和结果引用，避免使用已经解除的映射。

最后的启动失败审计补丁已复核：成功写入finish才设置共享audit_finished；main在清理后补齐缺失的finish并fsync，不依赖是否指定result，正常monitor已完成的日志不重复补记。审计文件创建失败显式标audit_failed；启用审计时，结果只有在state存在、没有审计失败且finish已经记账时才报告complete=true。配置清理失败明确cleanup_complete=false及退出125，不在清理之前伪报成功。

### 9.2 祖先内存读取RPC与阻塞边界

不采用PR_SET_PTRACER例外：它不能替代任意fork后代的实际访问检查。独立broker通过私有SOCK_SEQPACKET向payload真实祖先monitor请求内存FD，monitor在打开 `/proc/TID/mem` 前后校验同一listener上的通知ID，broker接收后再次校验。通道在payload fork后才创建，因此payload从未继承任何端点；所有请求由单线程可信broker串行提交，已复制的TID/ID来自实际seccomp通知。文件与网络worker在fork前完成请求捕获，文件worker随后关闭无关FD。

本轮对两处recvmsg接收增加错误立即返回、缓冲清零和实际控制消息容量内的长度检查；拒绝额外控制类型，关闭额外SCM_RIGHTS描述符，并使用MSG_CMSG_CLOEXEC。该修复避免错误路径解析未初始化控制缓冲；仍须纳入最终Linux编译和RPC回归。

monitor并非无条件“绝不阻塞”：Linux的mm_access会在打开proc mem时取得可杀等待的exec_update_lock，文件系统、内核和exec竞态也可能影响完成时间。现有方案隔离了NOTIF_RECV和业务I/O，但不提供任意内核/存储停顿下的绝对取消时限；fsync、清理和导出同样有这一系统边界。若部署需要更强时限，应进一步隔离实际祖先内存opener并由独立控制者管理，不能只把普通本地文件系统测试当作形式化上限。[Linux 6.8 mm_access实现](https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/fork.c)

### 9.3 新内核替代入口复核

核对Linux 6.18、7.0及当前上游syscall表，native x86_64与asm-generic/aarch64编号一致。需要明确拒绝 `open_tree_attr=467`、`file_setattr=469`；当前上游另有 `fchroot=472`，也应预先拒绝。旧构建头缺少宏不能成为省略限制的理由，应使用已核实的固定编号。`file_getattr=468`为只读查询，不等同metadata写入口；未发现listns=470、rseq_slice_yield=471构成当前要求中的写权限替代入口。[Linux 7.0 x86 syscall表](https://raw.githubusercontent.com/torvalds/linux/v7.0/arch/x86/entry/syscalls/syscall_64.tbl)、[asm-generic syscall定义](https://raw.githubusercontent.com/torvalds/linux/v7.0/include/uapi/asm-generic/unistd.h)

`file_setattr`直接按路径或AT_EMPTY_PATH对象调用vfs_fileattr_set，改变文件系统标志和扩展属性配置，走独立于ioctl/chmod的入口；不能借当前metadata兼容开关CONTINUE。`open_tree_attr`复用vfs_open_tree并可执行挂载属性修改，应与全部mount入口同样拒绝。上游fchroot包含特殊FD_FAILFS_ROOT及NNP分支，不能只依赖清空CAP_SYS_CHROOT阻止它。本地现已按固定编号拒绝这三项；审计模式复用同一分类返回EPERM，不因通知化而放行，已有独立静态/动态拒绝用例，实际结果须列入最后测试证据。[file_setattr实现](https://raw.githubusercontent.com/torvalds/linux/v7.0/fs/file_attr.c)、[open_tree_attr实现](https://raw.githubusercontent.com/torvalds/linux/v7.0/fs/namespace.c)、[上游fchroot实现](https://raw.githubusercontent.com/torvalds/linux/master/fs/open.c)

### 9.4 准备守护与交接

新增preparation guardian已静态复核：由guardian创建并固定0700容器，CLI仅在其内准备快照；cgroup由同一创建者通过RPC配置。D移交命令优先于父死亡处理排空，CLI收到ACK并回收guardian后才释放monitor的G屏障；没有G的monitor等status真正EOF后根据共享身份清理，不启动业务。guardian不持有将来执行控制管道的写端，递归删除使用目录FD且不跟随symlink，不猜测同UID目录归属。

这一机制覆盖CLI取消和死亡时仍有创建者存活的情况，不声称guardian自身在mkdtemp成功到身份登记之间被强杀也能无残留；不可中断存储与整机故障同样不作固定时间回收保证。对应部署与实测阶段边界已写入 `docs/preparation.md`。

### 9.5 源码冻结结论

本轮已经识别的权限越界、可信输出别名、FD泄漏、准备阶段交接及审计完整性阻断项，均已修复并完成源码交叉复核；**当前没有剩余已知的源码冻结阻断项**。允许以当前源码指纹冻结候选版本，进行最后VM、Docker和架构/压力验证。只有最终受测指纹与交付指纹一致、相关必需用例没有FAIL或未解释BLOCKED，才能依据验证报告宣称交付完成。

这一结论是多Agent源码/威胁模型审查，不是外部第三方审计或内核漏洞不存在的证明。本文明确的部署、兼容性、资源和阻塞边界继续适用；未运行的环境或案例不得由“源码可冻结”推定为PASS。
