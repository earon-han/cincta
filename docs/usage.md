# 使用指南

## 安装

推荐静态 Linux 产物：校验 SHA256 后把 `cincta` 放入 PATH。源码：`make clean && make STATIC=1`；安装：`make install PREFIX=$HOME/.local`。无需 libseccomp。动态构建 `make` 需要兼容的 libc；静态启动器不依赖目标 libc，但动态业务仍需其解释器和库。环境详情见 [dependencies.md](dependencies.md)。

先执行 `cincta probe`，读取 schema_version、landlock_abi、landlock_errno、seccomp、seccomp_errno、strict_supported、compat_supported。缺失能力时 supported=false，probe 本身仍可返回0。probe 在短命子进程实际安装原语，不证明特定业务策略可用；执行时再次校验。

## 命令和策略

`cincta run [OPTIONS] -- COMMAND [ARGS...]`。必须使用 `--`；不经过隐式 shell，需要时显式传 `/bin/sh -c ...`。

| 参数 | 语义 / 默认值 |
|---|---|
| `--ro PATH` | 内容读取、目录枚举 |
| `--rw PATH` | 读写、截断，目录内创建/删除/链接/重命名；不直接执行 |
| `--rx PATH` | 读取、执行 |
| `--cwd PATH` | 默认当前目录；不自动授予目录权限 |
| `--network none\|host` | 默认 none；host 开放任意目的 IPv4/6 |
| `--compat` | 显式接受 ABI3–5 缺少 IPC scopes；仍须 Landlock + BPF |
| `--timeout-ms N` | 墙钟，默认30000；0不限 |
| `--memory-mb N` | RLIMIT_AS，默认512 MiB |
| `--cpu-seconds N` | RLIMIT_CPU，默认30秒 |
| `--processes N` | RLIMIT_NPROC，默认256；与同 UID 任务共享 |
| `--nofile N` | RLIMIT_NOFILE，默认128，至少16 |
| `--env KEY=VALUE` | 显式变量，可重复；同名后者替换前者 |
| `--result PATH` | 新建0600 JSON文件，已有文件/symlink拒绝 |

路径必须绝对且已存在，最多128条。只接受目录/普通文件，最终路径元素不能是 symlink，请先 `realpath`。父路径 symlink 会解析，授权固定到打开的 inode；策略目录树必须可信。授权为并集，不能用子目录ro撤销父目录rw。解释器可读取并解释rw脚本，因此rw不含exec不是代码可信性控制。

无任何隐式 runtime/cwd/tmp 授权。环境默认仅 `PATH=/usr/bin:/bin`、`LANG=C`，最多128项（含默认项）；HOME、密钥、代理不自动继承。显式传入秘密或 loader 变量属于调用方授权。结果应放在业务不可写的可信目录。

Ubuntu 示例：

```sh
work=$(mktemp -d)
result_dir=$(mktemp -d)
cincta run --rx /usr/bin --rx /usr/lib --rw "$work" --cwd "$work" \
  --env TASK_LABEL=demo --result "$result_dir/run.json" -- \
  /bin/sh -c 'echo "$TASK_LABEL" > output.txt; cat output.txt'
cat "$result_dir/run.json"
```

ABI3–5内核显式加 `--compat`。其他发行版可能还需真实 `/usr/lib64` 等目录。证书、DNS、解释器配置需按业务显式授权。

## 网络和兼容边界

none 拒绝所有新 socket/socketpair，以及连接/发送/接收入口和 io_uring；host 允许 AF_INET/AF_INET6 TCP/UDP，不检查地址、域名或端口。UNIX、netlink、其他family和socketpair始终禁止，避免通过 SCM_RIGHTS 委托外部FD。标准FD 0/1/2保留，其他继承FD全部关闭；socket/file stdio是调用方主动授予的能力，none不撤销它。

所有 ioctl、chmod/chown、时间戳和xattr修改均被拒绝，即使路径rw。TTY控制、调试器、inotify、SysV/POSIX消息队列、namespace/mount不支持。兼容模式缺scope时禁止全部信号发送syscall（包括向自身）；依赖raise/pthread cancellation的程序可能不兼容。静态危险syscall拒绝列表不是完整allowlist。

## 结果协议

stdout/stderr保留业务输出；沙箱日志写stderr且前缀 `cincta:`。业务可伪造该前缀，结构化判定必须使用JSON。调用方等CLI退出后读取；CLI被杀时等monitor结束写入。结果为 `schema_version=1`。

| 字段 | 含义 |
|---|---|
| status | ok / exit / signal / timeout / cancelled / setup_error |
| stage, message | 阶段和原因；monitor代表监管进程异常 |
| exit_code, signal | CLI结果码和终止/取消信号 |
| timed_out, cancelled | 超时/取消标记 |
| cleanup_complete | 已实际wait到无后代；false表示清理不完整 |
| elapsed_ms | monitor单调时钟耗时 |
| phase_ms | setup/run/cleanup；根据限制安装完成握手计时 |
| protections.landlock_abi | 实际确认生效的ABI；未完成确认时0 |
| protections.seccomp | 确认安装成功 |
| protections.network | none/host；未生效为unconfined |
| protections.ipc_scoped | ABI6 scopes是否启用 |
| unsupported | 缺失保护的原因 |

早期参数错误/结果文件无法创建可能只有stderr和125，无JSON。能力可用不代表setup成功；安装失败绝不exec。阶段计时为毫秒粒度，早期失败无完整分段；monitor故障恢复仅覆盖恢复耗时，不作性能样本。结果文件启动前独占打开，故障恢复使用同一个FD。

| CLI退出码 | 含义 |
|---|---|
| 0 | 业务成功且已清理 |
| 业务非零值 | 结合status=exit判定 |
| 124 | 超时 |
| 125 | 配置/保护/监管/结果/清理失败 |
| 126 / 127 | exec被拒 / 不存在 |
| 128+信号 | 业务信号终止或取消 |

业务值可与保留码重叠，JSON消歧。清理失败时CLI125，JSON保留业务结果及 cleanup_complete=false。

## 生命周期和资源

SIGTERM/SIGINT/SIGHUP取消CLI。取消、超时立即SIGKILL工作组；正常返回后也回收后台后代。monitor是subreaper，反复读真实procfs children，在wait前对固定子进程身份发送信号，含无SIGCHLD clone；仅ECHILD才算完成。等待约2秒，内核不可中断任务可能导致清理不完整。

CLI用pidfd监视调用方**进程**，仅启动线程退出不取消。作为容器PID1运行时getppid=0，没有namespace内调用方可监视，由容器运行时向CLI发送取消信号。CLI单独SIGKILL由monitor管道EOF兜底；monitor单独崩溃由CLI第二层subreaper兜底。两层同时强杀、内核崩溃或断电不保证清理。僵尸不算回收完成。

AS/CPU逐进程、NPROC按真实UID累计，root可能豁免。这些不是总树配额；输出量、磁盘、总树内存/CPU由调用方额外提供cgroup/独立UID/磁盘配额，并持续消费输出。通用框架无关调用见 [agent.py](../examples/agent.py)。
