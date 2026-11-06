# cincta

C17 实现、可静态交付的 Linux CLI 沙箱，面向通用 Agent 的非交互命令执行。文件访问由 Landlock 限制，系统调用由经典 seccomp BPF 限制，动态能力由可信 broker 处理；基本运行无需 root、特权容器或 user namespace。

当前预览版本：`0.2.0-preview.1`。功能与验证状态分开记录，最终实测以 [验证报告](docs/validation.md) 为准；原有 v0.1 证据保留在 `reports/`，不算作新版本通过。

| 能力 | v0.2 行为 |
|---|---|
| 文件授权 | 默认拒绝，显式 ro/rw/rx；启动前固定规则对象，限制安装失败不执行 |
| 动态网络 | IPv4/IPv6、TCP/UDP、CIDR、端口范围和启动时域名地址快照 |
| 元数据兼容 | 可选 `--metadata`，只对固定 rw 普通对象代执行受限 chmod/chown/时间/xattr 操作 |
| 工作区 | 独立物理快照、差异查看、独占导出、保留或丢弃；显式workspace-exec支持构建后执行，不自动写回原目录 |
| 资源 | rlimit；显式委派 cgroup v2 时提供业务进程树内存、pids、CPU 带宽/累计预算 |
| 生命周期 | pidfd/signalfd/timerfd 事件驱动，超时、取消、单层监管故障及后代回收 |
| 结果与审计 | 独立 JSON 完成报告；可选 JSONL 请求、决定、代执行结果与交付记录 |

## 构建与检查

目标为 Linux 小端 x86_64/aarch64。需要 C17 编译器、make、libc 开发文件和 Linux UAPI headers ≥6.2；完整测试需要 Python 3 和 C 编译器。无需 libseccomp。macOS 可作为控制端，实际保护必须在 Linux 中运行。

```sh
make
make check
make test                         # 八套独立实核测试，报告不覆盖历史证据
make test-legacy TESTFLAGS="--mode compat"  # 只运行原有基础回归
make BUILD=build-static STATIC=1  # 独立静态交付产物
./build-static/cincta probe
```

严格模式要求 Landlock ABI ≥6（通常 Linux ≥6.12）；显式 `--compat` 要求 ABI ≥3（通常 Linux ≥6.2）。动态网络/metadata/syscall 审计另外需要可用的 seccomp notification、ADDFD、procfs 和祖先监管者读取目标地址空间的权限；`probe` 的基础能力成功不证明所有增强功能可用。完整条件见 [外部依赖](docs/dependencies.md)。

## 最小执行

以下 runtime 目录适用于 Ubuntu merged-/usr；其他发行版应通过 `realpath` 确认真实路径。没有隐式 runtime、工作目录或临时目录授权。

```sh
work=$(mktemp -d)
result_dir=$(mktemp -d)
./build/cincta run --rx /usr/bin --rx /usr/lib --rw "$work" --cwd "$work" \
  --result "$result_dir/run.json" -- \
  /bin/sh -c 'printf hello > answer; cat answer'
cat "$result_dir/run.json"
```

`rw` 不包含直接执行权限；重叠规则是授权并集。授权路径必须存在，最终分量不能是 symlink。结果和审计文件必须是新文件，并位于业务不可写的可信目录。

## 隔离工作区

```sh
source_dir=$(mktemp -d)
result_dir=$(mktemp -d)
printf original > "$source_dir/input.txt"
./build/cincta run --rx /usr/bin --rx /usr/lib --workspace "$source_dir" \
  --workspace-diff "$result_dir/diff.json" \
  --workspace-export "$result_dir/export" --result "$result_dir/run.json" -- \
  /bin/sh -c 'printf sandbox > output.txt; cat input.txt'
```

命令在副本内工作，原目录不自动写回。快照使用真实复制，具有数据/条目上限；它不是 overlayfs 按需 COW。工作区模式禁止额外 rw 授权以及可写普通文件 stdio，防止 hardlink/bind 别名绕过原目录保护。业务输出使用管道、终端或 `/dev/null`。需要执行副本内新生成的二进制时显式加 `--workspace-exec`；默认 rw 仍不包含执行。详见 [工作区说明](docs/workspace.md)。

## 网络、资源与审计

默认 `--network none`。`--network host` 开放任意 IPv4/IPv6 目的地；`--network allowlist --allow-net tcp:example.com:443` 只开放启动时解析出的 IP/端口，可重复规则，UDP 用 `udp:`，IPv6 用 `[地址]`。域名规则是 IP 能力快照，不验证 HTTP Host、TLS SNI 或证书；业务需要 DNS/证书/配置文件时仍须显式授权。[网络说明](docs/network.md)

树级资源必须提供已有的 `--cgroup-parent` 委派，不能从只读默认 Docker 自动获得。默认容器验证无委派拒绝；有委派正例使用单独记录的最小 RW 子树配置，保持默认 seccomp/AppArmor。[资源说明](docs/resources.md)

`--audit PATH` 保存事件，`--audit-syscalls` 增加 syscall 请求和文件打开代执行结果。它不等于全部系统调用入口/出口追踪；旧内核 O_PATH 原生回退单列，不能由请求推断完成。日志默认限制 64MiB/100万条，写入或完整性失败终止任务。[审计说明](docs/audit.md)

## 验证和交付

```sh
sh scripts/validate.sh linux-vm
# 默认安全配置、非 root、无 capabilities 的 Docker 验证
# 默认无 cgroup 委派时，资源正例保持 BLOCKED，不算 PASS。
docker build --target test -t cincta-test .
docker run --name cincta-verify --cap-drop ALL --security-opt no-new-privileges cincta-test
docker cp cincta-verify:/src/reports/. reports/
docker rm cincta-verify
sh scripts/package.sh build-static/cincta
(cd dist && sha256sum -c *.sha256)
```

PASS、FAIL、BLOCKED 分开记录。容器使用宿主内核；全系统 QEMU 可以运行真实目标架构内核，但必须标明仿真，不能叫作硬件原生测试。CI 配置存在不表示远端 CI 已运行。

- [详细实施计划](docs/implementation-plan-v02.md) · [任务台账](docs/progress.md)
- [设计与威胁模型](docs/design.md) · [独立设计审查](docs/v02-design-review.md)
- [使用及结果契约](docs/usage.md) · [依赖](docs/dependencies.md) · [验证记录](docs/validation.md)
- [通用 Agent 示例](examples/agent.py) · [参考研究](docs/research.md) · [变更记录](CHANGELOG.md)

许可证：[Apache-2.0](LICENSE)。独立实现，没有引入 Sandlock 源码或其运行依赖。
