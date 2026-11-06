# cincta

独立交付的 C17 Linux CLI 沙箱，使用 **Landlock + 经典 seccomp BPF**，面向通用 Agent 的非交互命令执行。无需 root、特权容器、user namespace、libseccomp 或常驻服务。

当前版本：`0.1.0-preview.1`。首版实现静态路径授权、默认断网、危险系统调用限制、资源限额、超时/取消、后代回收和 JSON 结果。已实测并交付aarch64；x86_64是尚待原生验证的源码目标。动态通知代理、域名白名单、COW、cgroup 树配额不在本版范围。

## 构建和运行

在 Linux x86_64/aarch64 上，需要 C 编译器、make、libc 开发文件和 Linux UAPI 开发头文件（6.2+）。macOS 只能作为开发控制端。

```sh
make
make test
make clean && make STATIC=1
./build/cincta probe
```

严格模式要求 **Landlock ABI ≥6（通常 Linux ≥6.12）**，兼容模式要求 **ABI ≥3（通常 Linux ≥6.2）**。同时需要 Landlock LSM 启用、seccomp filter、可读 procfs 和允许相关 syscall 的外层安全策略。以实际探测结果为准。

```sh
mkdir -p /tmp/cincta-demo
# Ubuntu merged-/usr 示例；其他发行版请用 realpath 确定实际目录。
./build/cincta run --rx /usr/bin --rx /usr/lib \
  --rw /tmp/cincta-demo --cwd /tmp/cincta-demo \
  --result /tmp/cincta-result-unique.json -- \
  /bin/sh -c 'printf hello > answer; cat answer'
```

结果文件必须是不存在的新文件，并放在业务不可写的可信目录。所有文件权限均须显式授权，包括动态链接器、库和工作目录；`rw` 不包含直接执行权限，重叠授权是并集。规则不接受最终符号链接，请传其真实目标。旧内核可显式加 `--compat`，这会报告缺失的 IPC scopes；没有静默关闭文件或 seccomp 保护的模式。

默认禁止 socket。`--network host` 只开放 IPv4/IPv6 socket，允许任意 IP/端口；UNIX/netlink socket 仍禁止。标准输入输出是调用方主动授权的既有通信能力。所有 ioctl 及 chmod/chown/时间戳/xattr 修改均被禁用，部分构建工具可能不兼容。

## 文档与验证

- [使用指南与结果契约](docs/usage.md)
- [设计、威胁模型与决策](docs/design.md)
- [外部依赖、内核和安全策略](docs/dependencies.md)
- [固定版本参考研究](docs/research.md)
- [独立安全审查](docs/security-review.md)
- [实测报告与性能](docs/validation.md)
- [实施任务台账](docs/progress.md)
- [通用 Agent 调用示例](examples/agent.py)

```sh
sh scripts/validate.sh linux-vm
docker build --target test -t cincta-test .
docker run --rm --cap-drop ALL --security-opt no-new-privileges cincta-test
make package
(cd dist && sha256sum -c *.sha256)
```

`reports/` 保存真实运行数据，PASS、FAIL、BLOCKED 分开统计。容器使用宿主内核，不能补齐宿主缺失的 Landlock。资源限额是逐进程/同 UID 语义，需要总量隔离时由调用方额外配置 cgroup 或容器限额。

许可证：[Apache-2.0](LICENSE)。本项目独立实现，没有引入 Sandlock 源码或其运行依赖。
