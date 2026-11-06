# x86_64 全系统验证

本入口在 ARM Linux 构建机上交叉编译静态 x86_64 程序，然后通过 **qemu-system-x86_64 TCG 全系统仿真**启动真正的 x86_64 Linux 内核。所有 Landlock、seccomp、通知、进程和文件系统检查都在该内核中执行。

这不是 QEMU 用户态模拟，也不是 x86 硬件原生运行。不能把本套件计为 x86 原生硬件压力测试或完整 Docker/x86 平台矩阵。ARM Linux VM 与 Docker 完整验收由其他入口执行，本入口补充实际 x86 syscall ABI 和架构过滤验证。

## 环境与依赖

构建机需要 Linux、make、Python3、gzip、cpio、curl、timeout、qemu-system-x86_64，以及 `x86_64-linux-gnu-gcc` 和相应静态 libc/Linux UAPI 开发文件。普通 x86_64 构建机也可以把 `CINCTA_X86_CC=cc`。

本次环境是本地 Lima `jiuwen-lite` 内的 Ubuntu24.04/aarch64，采用 QEMU8.2.2 TCG。官方 Alpine3.23 netboot 文件来自：

- `https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/netboot/vmlinuz-virt`
- `https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/netboot/initramfs-virt`

这些是会更新的发布通道地址。脚本保留下载缓存及每次实测 SHA256，报告同时记录实际内核版本和 ABI。需要复现同一内核时保留缓存；不要把以后下载的新文件当成已经实测的旧版本。官方目录没有相应 `.sha256` 独立文件，本入口记录本地实算指纹，不声称完成额外发行签名验证。

脚本需要 root 权限解包 initramfs 设备节点和启动验证环境；**被测 cincta 和业务命令在客体中均为普通 UID501/GID1000**。自定义 PID1 仅负责挂载真实 procfs/sysfs/devtmpfs、启用 loopback、准备测试夹具、最小 cgroup 委派并降权，不属于产品运行依赖。无需外部网络服务或 VM 网卡。

## 运行

在 Linux 构建机上的仓库根目录：

```sh
sudo env CINCTA_X86_VM_DIR=/tmp/cincta-x86-vm sh scripts/validate_x86_vm.sh
```

脚本用独立构建目录，不污染常规 `build/`。QEMU 参数包括 `-accel tcg -cpu max -smp 2 -m 768 -nic none`；启动参数明确启用 Landlock/Yama LSM，内核不具备原语时套件报告 BLOCKED，不能用静态编译通过替代内核保护。

## 覆盖与证据

冻结源码 `eebc7700ea70a6586007b7e38c126a9af88d507f` 已通过 `git archive` 完整导出，清空本任务交叉构建目录后重新编译，并在 Linux6.18.60-0-virt / Landlock ABI7 中，以严格模式完成 **34 PASS、0 FAIL、0 BLOCKED**。被测 cincta 与业务命令均为普通 UID501。套件覆盖：

- 内容默认拒绝、单文件读取和目录写入、只读拒绝。
- no_new_privs、默认断网、ptrace/bpf/namespace/io_uring/进程组限制、clone3回退。
- **x32 syscall 编号与 int80/i386 架构入口实际触发 SIGSYS**。
- 元数据默认拒绝及固定授权对象 chmod。
- 动态 TCP/UDP 允许路径与实际本地 echo 通信。
- 文件打开实际结果审计、审计上限拒绝。
- 工作区快照/导出及源目录不变。
- 具备客体委派条件时的 cgroup 树配额和累计 CPU 预算。
- 超时、取消、CLI/monitor 单独 SIGKILL 后后代实际回收。

`reports/v02-x86-kernel.json` 保存环境、probe、逐条结果、PASS/FAIL/BLOCKED、被测二进制/内核/initramfs SHA256；`reports/v02-x86-serial.log` 保存完整串口输出；`reports/v02-x86-source-sha256.txt` 保存源码与二进制清单。`reports/v02-x86-provenance.json` 补充冻结提交和来源核对：清单22个条目全部与该提交或取回的被测二进制相符，二进制 SHA256 为 `04638adbe2cd0a52dd0aaf966d45b03874f64d30138a46964d7c190fd434d461`。开发轮证据不能混入最终验收总数。

本 x86 产物由 GNU libc 交叉工具链静态链接。链接器对 `getaddrinfo` 给出 NSS 可能需要匹配 glibc 共享库的通用提示；本套件实际测试的是数值 IP 的 TCP/UDP，未验证 x86 产物在缺少 NSS 运行库时的域名解析。因此不能仅凭 `file` 的“statically linked”结果宣称 x86 域名/NSS 场景完全没有动态依赖。部署域名策略时必须另行验证目标环境；其他平台或其他libc产物的验证结果不能代替本 x86 产物验证。

## 在 ARM Linux 构建机打包 x86_64 产物

确认上述全系统测试通过后，在相同源码目录中执行：

```sh
CINCTA_SOURCE_REVISION="$(git rev-parse HEAD)" \
CINCTA_BINARY_SOURCE_REVISION=eebc7700ea70a6586007b7e38c126a9af88d507f \
CINCTA_PACKAGE_ARCH=x86_64 \
CINCTA_PACKAGE_VERSION=0.2.0-preview.1 \
sh scripts/package.sh /tmp/cincta-x86-vm/build/cincta
```

`CINCTA_PACKAGE_ARCH` 必须与二进制 ELF64 的 `e_machine` 相符；错误架构在打包前拒绝。交叉打包必须明确提供 `CINCTA_PACKAGE_VERSION`，并与 `include/cincta.h` 中的版本一致。脚本不执行异架构二进制，包内 `PACKAGE_INFO` 记录目标架构、构建机架构和版本来源；实际被测二进制身份以报告 SHA256 为准。原生打包不传这两个参数时，仍通过原生程序的 `--version` 读取版本。

导出的源码目录没有 `.git` 时，`CINCTA_SOURCE_REVISION` 必须由导出者提供实际提交号，并核对包内 `SOURCE_SHA256`。`SOURCE_REVISION` 表示本次打包所用源码与文档的提交；`BINARY_SOURCE_REVISION` 表示二进制构建、受测核心对应的提交，默认与前者相同，也可通过 `CINCTA_BINARY_SOURCE_REVISION` 显式记录。只更新测试、文档和交付证据后重新打包既有受测二进制时，应分别记录这两个来源，并确认核心源文件指纹一致；不能把显式版本号当成构建来源验证。

二进制包也包含原始《实施计划.txt》，`SOURCE_SHA256` 纳入该文件。包内 `BINARY_SHA256` 使用相对文件名 `cincta`，解包并进入包根目录后可直接执行 `sha256sum -c BINARY_SHA256` 核对实际程序。`SOURCE_SHA256` 对应打包时的源文件内容，应在相同来源的完整源码树中核对，不能在仅含程序、文档和示例的二进制包中校验未附带的 C 源码。打包本身不替代测试，也不把前一开发轮的二进制算作最终源码产物。

此轻量 guest 不运行 Docker，也没有完整发行版应用、长期压力或硬件性能结论。TCG 时钟/调度性能不作为产品暖启动预算依据。

## 开发期夹具修正

扩展套件首轮曾报告31 PASS/1 FAIL：CLI SIGKILL返回137正确，但夹具未确认后代清理，旧夹具没有输出PID/结果细分诊断。随后八次完整boot均为32 PASS/0 FAIL；这些重复开发数据保存在 `reports/v02-x86-development-repeats/`，不能混入最终验收总数。

复核发现夹具只等待PID文件存在，可能在业务已创建文件、尚未写入PID时读到空字符串并把它解析为0。已改为等待完整、带换行的正PID；新增一个延迟写PID的确定性夹具回归，并在超时用例中独立检查实际PID从procfs消失。最新34项开发轮通过。该修正证明夹具现在不会把空文件当PID；早期失败缺少细分证据，不据此捏造已经确认的产品故障根因。
