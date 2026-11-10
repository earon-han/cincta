# v0.2 使用指南与结果契约

下载二进制包后，在包所在目录校验压缩包，再解包核对程序：

```sh
sha256sum -c cincta-0.2.0-preview.1-linux-aarch64.tar.gz.sha256
tar -xzf cincta-0.2.0-preview.1-linux-aarch64.tar.gz
cd cincta-0.2.0-preview.1-linux-aarch64
sha256sum -c BINARY_SHA256
install -Dm755 cincta "$HOME/.local/bin/cincta"
```

x86_64使用对应架构文件名。包中附公开源码、构建脚本、测试、离线文档、示例和历史验证摘要；进入包根目录可用`sha256sum -c SOURCE_SHA256`核对所附源文件，不包含本地开发计划或原始运行报告。SOURCE_REVISION记录干净Git来源或导出者声明；BINARY_SOURCE_REVISION未提供时为unknown，不能由源码HEAD推定二进制来源。PACKAGE_INFO区分来源取得方式，显式声明也不等于构建验证。

## 安装和能力探测

源码静态交付：`make STATIC=1`默认使用build-static目录；安装：`make BUILD=build-static STATIC=1 install PREFIX=$HOME/.local`。动态构建`make`默认使用build目录，需要兼容libc。`make package`另在build-release目录构建静态产物，Git工作树须干净；打包拒绝有ELF解释器的动态程序。静态启动器仍不包含业务程序自己的loader/库。下载包先在同目录校验SHA256，再安装对应架构。完整环境要求见 [dependencies.md](dependencies.md)。

先运行`cincta probe`，检查schema_version、landlock_abi、landlock_errno、seccomp、seccomp_errno、strict_supported、compat_supported。缺少能力时probe仍可返回0，消费者必须检查字段。probe只验证基础原语；动态broker、metadata和资源会在请求时再次验证，失败不执行业务。

`cincta run [OPTIONS] -- COMMAND [ARGS...]`要求明确的`--`，按字面argv执行，不隐式启动shell。需要shell语法时显式传`/bin/sh -c ...`。

## 基本策略

| 参数 | 语义 / 默认值 |
|---|---|
| --ro PATH | 内容读取、目录枚举 |
| --rw PATH | 读写/截断及目录内常用创建、删除、链接、重命名；不直接执行 |
| --rx PATH | 读取、执行 |
| --cwd PATH | 业务启动工作目录，默认调用时目录；不自动授予文件权限 |
| --compat | 显式接受ABI3–5缺少IPC scopes，仍要求Landlock+BPF |
| --network none / host / allowlist | 默认none；host开放任意IPv4/6；allowlist启用动态端点策略 |
| --env KEY=VALUE | 显式变量，后者替换同名项；默认仅PATH=/usr/bin:/bin、LANG=C |
| --result PATH | 独占新建0600完成JSON，不能覆盖已有文件或symlink |
| --timeout-ms N | monitor运行阶段墙钟超时，默认30000；0不限 |
| --memory-mb N | 逐进程RLIMIT_AS，默认512MiB |
| --cpu-seconds N | 逐进程RLIMIT_CPU，默认30秒 |
| --processes N | 同真实UID共享RLIMIT_NPROC，默认256 |
| --nofile N | RLIMIT_NOFILE，默认128，至少16 |

路径必须绝对、规则对象已存在，最终分量不能是symlink。规则最多128条，环境最多128项（含默认项）；运行时FD也需要足够限额。根对象在启动前固定，授权是并集，不能以子目录ro撤销父目录rw。解释器读取rw脚本仍可解释执行。无隐式runtime/cwd/tmp/config授权。

例如`--cwd /workspace/project`使业务相对路径`output.txt`从该目录解析；可写时还需`--rw /workspace/project`。cwd不执行chroot，也不改变文件系统根目录。

Ubuntu示例：

```sh
work=$(mktemp -d)
result_dir=$(mktemp -d)
cincta run --rx /usr/bin --rx /usr/lib --rw "$work" --cwd "$work" \
  --env TASK_LABEL=demo --result "$result_dir/run.json" -- \
  /bin/sh -c 'echo "$TASK_LABEL" > output.txt; cat output.txt'
```

其他发行版可能需要真实/usr/lib64等目录；传入前可用realpath确定。HOME、证书、DNS配置、代理和秘密都不自动继承。结果/审计/diff/export目录必须在业务rw授权之外，且父目录已存在并可信。

## 动态网络和metadata

`--allow-net`可重复；有规则且未显式指定网络模式时自动选择allowlist。规则与显式none/host冲突会拒绝。

```text
--network allowlist --allow-net tcp:example.com:443
--allow-net tcp:192.0.2.0/24:8000-8100
--allow-net udp:192.0.2.53:53
--allow-net tcp:[2001:db8::/32]:443
```

只有列明的TCP/UDP目的地址和端口可用；没有隐式DNS/loopback例外。域名启动前解析为固定IP快照，在network_snapshot中报告。它不验证应用层身份，首次DNS答案也可能含私网地址；需要DNS时显式授权resolver端点/配置，TLS证书同样单独授权。危险路由选项、ancillary、raw/UNIX/netlink/socketpair和入站监听不支持。网络GC有保守延期/可用性边界，参见 [network.md](network.md)。

`--metadata`允许broker对固定rw根内、由当前UID拥有的普通对象作受限修改：chmod低9位；chown只保留本UID/GID或-1；utimensat；user.* xattr。符号链接/跨根/特殊对象/setuid/setgid/其他安全xattr拒绝。需要fchmodat2(AT_EMPTY_PATH)，不可用时启动125。默认仍拒绝metadata修改。其他ioctl保持拒绝；allowlist socket只开放安全的FIONBIO代理。

## 隔离工作区

| 参数 | 语义 |
|---|---|
| --workspace SOURCE | 建立独立baseline/tree；tree自动作为cwd与rw根 |
| --workspace-parent DIR | 私有根的父目录，默认/tmp |
| --workspace-diff PATH | 独占新建JSON变更清单 |
| --workspace-export DIR | 独占新建完整最终树，供调用方审查 |
| --workspace-keep | 保留私有快照，默认完成后丢弃 |
| --workspace-exec | 显式给同一tree额外rx，允许运行副本内二进制 |
| --workspace-max-files N | 每棵树条目上限，默认100000 |
| --workspace-max-bytes N | 每棵树普通文件字节上限，默认1GiB |

workspace与自定义cwd冲突；布局验证要求statx(STATX_MNT_ID)及可读mountinfo。禁止额外rw授权、原目录相交授权以及可写普通文件stdio，避免hardlink/bind别名改到原目录。输出用管道、终端或/dev/null。源应在准备期间静止；快照是物理双副本，不是按需overlay COW，也不是整目录原子快照。条目/字节上限不提供运行期磁盘quota。

```sh
source_dir=$(mktemp -d)
result_dir=$(mktemp -d)
printf input > "$source_dir/input.txt"
cincta run --rx /usr/bin --rx /usr/lib --workspace "$source_dir" \
  --workspace-diff "$result_dir/diff.json" --workspace-export "$result_dir/export" \
  --result "$result_dir/run.json" -- /bin/sh -c 'cat input.txt; echo output > output.txt'
```

编译后执行需要显式workspace-exec，常见C工作流还需metadata、头文件读取和快照内临时目录：

```sh
cincta run --rx /usr/bin --rx /usr/lib --ro /usr/include \
  --workspace "$source_dir" --workspace-exec --metadata --env TMPDIR=. \
  --result "$result_dir/build.json" -- /bin/sh -c 'cc hello.c -o hello; ./hello'
```

该例要求源中存在hello.c；runtime和工具配置仍按实际发行版补充授权，不能把编译器的所有隐式路径都自动放开。

只在业务及所有后代回收后计算diff/export；失败保留快照便于复核，清理不完整时不导出。原目录不自动写回，discard丢弃本次变更；diff/export不是跨目录原子事务。[完整工作区语义](workspace.md)

## 整棵业务进程树资源

`--cgroup-parent PATH`必须是已正确委派的cgroup v2父组；请求限额而无有效委派启动125，不退回rlimit。

| 参数 | 语义 |
|---|---|
| --tree-memory-mb N | memory.max与OOM组行为；memory.swap.max存在时设0 |
| --tree-pids N | 业务进程树任务数，包括线程 |
| --tree-cpu-percent N | CPU带宽；100为一个CPU，200为两个CPU，范围1–1000000 |
| --tree-cpu-ms N | 周期采样的整组累计CPU预算，可能有调度/采样超量 |

业务在exec屏障前入组，后代继承。可信monitor/broker/worker在组外，这些代理开销不计入payload配额；需要全服务预算时额外设置外层cgroup/磁盘配额。默认Docker通常不能委派，负例与最小委派正例分开验证。[部署说明](resources.md)

## 审计与机器结果

`--audit PATH`独占JSONL，`--audit-syscalls`必须和audit一起使用。日志默认最多64MiB/100万条，可用`--audit-max-bytes N`、`--audit-max-records N`调整。额度/IO/完整性失败使任务失败，不能用业务stdout伪造可信审计。

事件分别表示请求、内核continue决定、broker授权/实际结果、文件实际open和FD投递。其他原生syscall没有完整出口结果；少数bootstrap、第二层静态拒绝、外层拦截也不经通知。旧内核O_PATH回退单独标注，不能由worker打开成功推断业务原生调用成功。原始目标字节以target_bytes_hex保留。[audit.md](audit.md)

结果schema_version=1，新增字段为兼容扩展。调用方等CLI结束再读；CLI被杀时等待存活monitor完成写入。业务stdout/stderr原样继承，沙箱日志写stderr加cincta前缀，但前缀也可被业务伪造，结构化判断必须用结果文件。

| 字段 | 含义 |
|---|---|
| version、status、stage、message | 版本、ok/exit/signal/timeout/cancelled/resource_limit/setup_error及阶段/原因 |
| exit_code、signal、timed_out、cancelled | 退出/取消信息，区分墙钟超时与资源预算 |
| cleanup_complete | 已实际wait到无后代；false表示清理不完整 |
| elapsed_ms、phase_ms | 总耗时和setup/run/cleanup；准备耗时计入总量，故障恢复计时另按恢复路径解释 |
| protections | 实际确认生效的Landlock ABI、seccomp、network、IPC scope |
| unsupported | 缺失保护原因 |
| dynamic、network_snapshot | 动态监管是否确认生效、实际解析授权地址 |
| workspace | enabled、source/root/tree、copied_files/copied_bytes、changes、retained、exported、executable |
| resources | enabled/path/removed/populated、内存/pids峰值、CPU用量/节流、OOM/pids拒绝、swap_disabled、预算触发及memory_peak_supported/pids_peak_supported |
| audit | enabled/path/mode、records/bytes、上限、complete、limit_exceeded、delivery_pending、native_open_fallbacks |

旧内核没有原生pids.peak等接口时，峰值来自周期采样，只是实际峰值的下界；检查对应*_peak_supported标志，不能把采样值当内核精确峰值。

结果文件在执行前独占打开，故障恢复使用同一个FD。早期参数、授权根固定、输出身份/挂载布局校验及创建错误可能没有有效JSON；应同时处理退出码和stderr。audit.complete描述承诺范围内的记录完整性，不表示观察了每个syscall出口，O_PATH回退计数必须单独考虑。

| CLI退出码 | 含义 |
|---|---|
| 0 | 业务成功且清理/输出完成 |
| 业务非零值 | status=exit，业务可能返回保留码 |
| 124 | 墙钟超时 |
| 125 | 参数、保护、监管、审计、输出或清理失败 |
| 126 / 127 | exec被拒 / 不存在 |
| 128+信号 | 信号终止或取消；累计CPU资源预算目前返回137并标resource_limit |

## 生命周期、验证与示例

SIGTERM/SIGINT/SIGHUP取消CLI；运行阶段用pidfd/signalfd/timerfd监视业务、调用方和监管故障。调用方的启动线程退出不等于整个进程退出；容器PID1无可见父进程，由运行时发送取消信号。正常业务返回也回收后台子孙。CLI或monitor单独死亡由存活subreaper兜底，broker死亡使动态任务失败；两层同时强杀、断电和不可中断内核任务不保证固定时限。

业务终止后，可信记账最多有50ms收尾，delivery_pending未归零必须报告审计失败。发出SIGKILL或成为僵尸不代表完成回收。快照复制等准备耗时计入elapsed/setup，但当前--timeout-ms预算从monitor开始，复制不计入该墙钟预算。准备guard用于未移交monitor前的CLI异常退出清理；其最终覆盖与实测以验证报告为准，不把它说成硬全流程墙钟限制。

`make test`默认八套独立测试；非空TESTFLAGS沿用legacy入口，明确只运行基础套件。`make test-all TEST_LABEL=linux-vm`强制完整验证。委派正例在已正确入组的launcher中设置`CINCTA_CGROUP_PARENT=/delegated/path`。报告位于reports/v02-标签，是本地生成文件，不进入Git或默认交付包；需要留档时单独保存整个报告目录。通用框架无关示例见 [agent.py](../examples/agent.py)。

调用方按CLI启动时可见的父进程TGID绑定。当前PID namespace隐藏父进程时（如部分docker exec/PID1），结果protections.caller_bound=false，并列出caller_lifetime_unavailable_in_pid_namespace；此时由容器runtime信号控制取消，不能声称自动观察外部调用方退出。
