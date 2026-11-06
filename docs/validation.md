# 验证与预览交付记录

## v0.2 最终本地验收

日期：2026-11-07。版本：`0.2.0-preview.1`。最终产品与测试冻结提交：`eebc7700ea70a6586007b7e38c126a9af88d507f`。本轮实现/模块自测完成后，已按用户追加P10启动全新代码审查Agent及两位只读子审查者；主Agent独立复现、逐项讨论确认并修复F1–F4，最后重新完整验收。[原始审查及最终闭环](final-code-review.md)、[逐项修复台账](review-resolutions-v02.md)、[机器汇总](../reports/v02-summary.json)。多Agent审查不冒充外部安全审计。

### 真实内核功能验证

| 环境 / 原始报告 | PASS | FAIL | BLOCKED |
|---|---:|---:|---:|
| [arm64-linux68-vm](../reports/v02-arm64-linux68-vm/summary.json) | 241 | 0 | 1 |
| [arm64-linux68-docker](../reports/v02-arm64-linux68-docker/summary.json) | 222 | 0 | 20 |
| [arm64-linux70-vm](../reports/v02-arm64-linux70-vm/summary.json) | 312 | 0 | 0 |
| [arm64-linux70-docker](../reports/v02-arm64-linux70-docker/summary.json) | 293 | 0 | 19 |
| [arm64-linux68-docker-delegated](../reports/v02-arm64-linux68-docker-delegated/resources.json) | 9 | 0 | 0 |
| [arm64-linux70-docker-delegated](../reports/v02-arm64-linux70-docker-delegated/resources.json) | 9 | 0 | 0 |
| [arm64-linux68-docker-alias](../reports/v02-arm64-linux68-docker-alias.json) | 12 | 0 | 0 |
| [arm64-linux70-docker-alias](../reports/v02-arm64-linux70-docker-alias.json) | 12 | 0 | 0 |
| [x86-kernel](../reports/v02-x86-kernel.json) | 34 | 0 | 0 |
| 合计（不同执行配置中的检查次数） | 1144 | 0 | 40 |

两本地Lima VM分别是Ubuntu24.04 / Linux6.8.0-147 / Landlock ABI4，以及Ubuntu26.04 / Linux7.0.0-34 / ABI8。VM以UID501运行。默认Docker29.1.3以UID10001、builtin seccomp、docker-default AppArmor、cap-drop ALL、NNP和私有cgroup namespace验证，无额外挂载。

四主ARM环境均运行同一交付原件，SHA256为e4a33692…；Docker先构建冻结源码测试镜像，再用该原件覆盖固定`/src/build/cincta`，保留测试源码及默认USER。[不可变镜像与程序身份](../reports/v02-reviewed-image-provenance.json)记录来源镜像、派生Dockerfile、镜像ID及镜像内实测SHA。单suite未单独输出哈希的报告由test_all固定路径、总清单及不可变镜像链关联，不把缺字段说成直接哈希证明。GCC15独立构建检查也通过，但最终四环境均执行GCC13产物。

40项BLOCKED分解：旧内核严格模式各1（VM/Docker共2），默认Docker无委派的资源正例各6（共12），默认Docker无宿主bind夹具的别名用例各12（共24），外层过滤导致内层新syscall审计不可观察各1（共2）。显式委派和真实夹具配置的9项/12项正例另列，不回填默认配置的BLOCKED。两个观察BLOCKED保留，不能用拒绝替代“见到request/deny”；原生VM同入口有严格审计断言。ABI不足不以compat冒充严格模式。

资源正例采用已部署专用cgroup父组、匹配UID501、`--cgroupns=host`及必要子树/报告目录RW挂载，保留默认seccomp/AppArmor与cap-drop/NNP。别名正例只增加专用宿主夹具bind，覆盖根/子目录反向bind、source parent/export及RO/RX/私有baseline拒绝；各自security/command附件记录实际配置。内核LSM、Yama、controllers、编译器与源码指纹在各VM environment.json和各环境summary.json。[依赖](dependencies.md)、[委派复现](resources.md)

x86是QEMU TCG全系统启动真实Linux6.18.60 / ABI7、UID501严格模式的34项smoke；不是qemu-user或原生x86硬件。源码清单、实际boot initramfs（区别原始Alpine归档）、内核及guest四程序SHA均核对。[x86来源](../reports/v02-x86-provenance.json)；覆盖窄于ARM完整发行版套件，不宣称硬件性能或所有应用兼容。

### P10修复和额外验证

- F1：原调用方身份在准备前固定，guardian监视原TGID死亡并先终止CLI再清理，D/ACK/G及payload屏障复核；四环境preparation各15项，包含自然退出、停止CLI、DNS-only、缓冲D与既有故障。现有caller线程/进程、CLI/monitor故障回归也通过。
- F2：根权限/mtime以`.`计入diff，复制量/预算不含根；四环境模块各21项及CLI纯根chmod/mtime/不变回归通过。
- F3：支持4095合法FD路径，截满显式ENAMETOOLONG、错误防零errno；四环境共12个边界回归同时核对业务fstat、父driver dirfd stat和审计，消除伪成功。
- F4：无可见parent不限PID1；结果`caller_bound=false`及unsupported准确报告runtime信号控制。两内核实际Docker exec正常执行、SIGTERM取消、payload真正回收各3 PASS。[6项额外证明](../reports/v02-docker-exec-linux68.json)、[另一内核](../reports/v02-docker-exec-linux70.json)
- 同一ARM原件在全新FROM scratch镜像以UID10001、默认安全profile完成probe及受限自执行；实际容器导出的/cincta SHA一致、无loader/libc/.so，共5 PASS。[scratch证明](../reports/v02-delivery-scratch/summary.json)
- 四主环境各100次、并发8的组合任务，共400 PASS：真实工作区复制/写入/chmod、TCP echo、审计完整且pending=0、导出、原源不变及临时目录回收。组合任务包括复制和密集通知成本，不套用基本启动预算；原始样本见各stress.json。

以上额外项与主1144检查分开，不重复叠加。源码、字段、逐条计数、180个附加result与本轮主报告逐对象一致性、128份JSONL、原始性能及产物哈希已由独立审查Agent复核。正式归档仍须在最终文档提交后生成并逐项校验。

### 基本启动性能

主8组各100次沙箱和100次直接基线，共800受限执行、800基线，逐样本退出均0、沙箱cleanup_complete均true。墙钟包含创建、限制安装、执行、回收与结果fsync，非单次内核成本；每份原始报告包含策略、源码/二进制身份和phase_ms。

| 环境 | 并发 | 中位ms | p95 ms | 失败/样本 |
|---|---|---:|---:|---:|
| arm64-linux68-vm | 串行 | 5.14 | 22.43 | 0/100 |
| arm64-linux68-vm | 并发8 | 4.89 | 10.94 | 0/100 |
| arm64-linux68-docker | 串行 | 1.06 | 1.29 | 0/100 |
| arm64-linux68-docker | 并发8 | 2.34 | 3.57 | 0/100 |
| arm64-linux70-vm | 串行 | 1.01 | 1.79 | 0/100 |
| arm64-linux70-vm | 并发8 | 7.82 | 12.83 | 0/100 |
| arm64-linux70-docker | 串行 | 1.17 | 1.38 | 0/100 |
| arm64-linux70-docker | 并发8 | 4.10 | 5.91 | 0/100 |

基本暖启动主样本满足p95≤50ms工程目标，不推广到任意机器或负载。P10之前候选在QEMU/镜像构建共享负载下曾p95=65.57ms、max=100.13ms、0失败；该轮不满足50ms目标，原始数据保留在[历史共享负载](../reports/v02-before-P10/v02-arm64-linux68-vm/concurrent-shared-load.json)，不计本轮800样本，也不冒充当前修复二进制的数据。

### 证据卫生与历史

最终四环境八suite在全新空`CINCTA_REPORT_DIR`中完整运行，整体替换primary目录，避免源码包自带历史reports使附件索引残留。源码/测试和产物不变。首次修复集成数据保存在`reports/v02-initial-reviewed-run/`，初始候选完整证据保存在`reports/v02-before-P10/`，均排除最终统计。

`v02-preflight-4437fcb`保留早期JSON契约及guardian ESRCH夹具失败，`v02-preflight-e4c29f5`保留Docker观察预期错误；`v02-review-*`保留原候选缺陷复现、主Agent确认、隔离修复自测和中间x86候选。它们不是当前版本FAIL或最终通过数字。原始审查初轮FAIL保留，最终关闭结论在报告末尾。

### 产物和门槛

```text
aarch64 e4a33692eefc944b4e500872df9963d5a2610c084b79e0bb65ad82f44a2a9180
x86_64  04638adbe2cd0a52dd0aaf966d45b03874f64d30138a46964d7c190fd434d461
```

两种GNU libc静态产物均有实际内核验证；musl未完成验证。静态getaddrinfo/NSS仍有配置/匹配运行库条件，scratch自执行不证明独立DNS/NSS。两个架构包与源码包包含文档、原始计划、源/测试/证据，包内SOURCE_REVISION对应最终文档提交、BINARY_SOURCE_REVISION对应eebc受测核心，SOURCE_SHA256/BINARY_SHA256及外部SHA用于核对。[安装](usage.md)

本地preview门槛和P10本轮已识别问题闭环完成。远端CI、GitHub发布、外部第三方审计和原生x86硬件未做；稳定版另需更广内核/发行版及长期压力。此前自动审批拒绝GitHub推送，理由是未明确批准目的地接收完整设计/源码/测试；未重试绕过。

## v0.1 历史验证（不计入v0.2）

日期：2026-11-06（Asia/Shanghai）。最终受测业务源码提交：`238c008`。本地源码与两台VM保存的逐文件SHA256清单完全一致；后续交付提交只补文档、证据与打包。原始记录在 [reports](../reports/README.md)。

## 实际平台与统计

| 环境 | 内核 / Landlock | 模式 | PASS | FAIL | BLOCKED |
|---|---|---|---:|---:|---:|
| 本地Lima jiuwen-lite，Ubuntu24.04，aarch64 | 6.8.0-147 / ABI4 | 兼容执行 + 严格拒绝启动 | 83 | 0 | 1 |
| 上述VM的Docker 29.1.3 | 同宿主 | 兼容执行 + 严格拒绝启动 | 83 | 0 | 1 |
| 新建Lima cincta-verify，Ubuntu26.04，aarch64 | 7.0.0-34 / ABI8 | 严格 + 兼容 | 154 | 0 | 0 |
| 新VM的Docker 29.1.3 | 同宿主 | 严格 + 兼容 | 154 | 0 | 0 |
| 合计 | 两种真实内核，四种运行环境 | 包含公共CLI/probe用例 | **474** | **0** | **2** |

旧内核的BLOCKED是严格执行套件，原因是ABI4不提供signal/abstract UNIX scopes；严格模式拒绝exec另计PASS。不会把拒绝启动当成严格执行通过。新内核的--compat仍安装其支持的scope，旧内核覆盖真正缺scope的分支。容器与VM分别实测，容器共享内核不算新的内核样本。

所有Docker测试使用非root `tester`（UID10001）、`--cap-drop ALL`、`--security-opt no-new-privileges`，保留默认builtin seccomp及docker-default AppArmor，无privileged/unconfined/user namespace要求。同一镜像ID `sha256:918c423d9d78621fd8386fd2808c741b91f51d094f715aa54afba068a07898b8` 在两台VM运行；配置证据分别保存在docker-*-security.json和daemon-security.json。

额外验证：最终静态二进制在scratch容器（无libc/动态链接器）作为PID1运行受限的自身 `--version`，旧内核加--compat、新内核严格执行均成功。GCC13静态构建、GCC15编译及Python/shell语法检查通过；通用Agent示例完成stdout/stderr/JSON闭环。musl、x86_64原生执行和CI远端运行**未执行**，不计PASS。本次只交付已验证的aarch64二进制。

## 覆盖和独立审查

覆盖读写/截断、默认拒绝、单文件和重叠授权、dotdot/symlink/link/rename、metadata修改、rw不可直接exec、禁止隐式shell、继承FD、no_new_privs、namespace/clone/setsid/setpgid/ptrace/bpf/io_uring、ioctl/异步FD信号、外部信号拒绝、none各socket family、host IPv4/IPv6/UDP、清空环境、cwd、内存/CPU/FD/进程限额、正常/非零/exec失败、超时、取消、后台子进程、exit_signal=0 clone、继承忽略/屏蔽信号、CLI与monitor单独SIGKILL、调用方进程退出和仅父线程退出、结果独占创建、并发重复。

故障注入实际通过外层BPF拒绝Landlock创建、add_rule及seccomp安装，验证业务哨兵未执行且结果不误报已生效保护。拒绝行为是cincta与外层策略的交集；未沙箱socket和metadata正例建立差异基线，不能把Docker中任意EPERM都单独归因cincta。

不同Agent独立承担设计审查、内核实现、测试发布，根Agent负责CLI/生命周期和实际验证。审查促成metadata/ioctl、FD委托、probe/结果误报、进程身份复用、fork清理竞态、clone等待、monitor故障、父线程取消等修复。完整审查见 [security-review.md](security-review.md)。开发轮次曾发现默认NPROC64小于现有同UID80线程，调整默认256；scratch实测发现PID1无可见父进程，已修复并复验。

## 性能原始样本

每行100次 `/bin/true` 沙箱执行、100次直接执行基线；最终静态二进制。时间为Python围绕subprocess.run测得的外部wall时间，包含spawn/setup/exec/cleanup。路径策略是显式runtime rx，网络none、默认资源限制。每条样本保留退出码、分阶段时间、保护确认和二进制SHA256。

| 环境 | 并发 | 沙箱中位ms | 沙箱p95 ms | 失败/样本 |
|---|---:|---:|---:|---:|
| Linux6.8 VM compat | 1 | 22.01 | 23.85 | 0/100 |
| Linux6.8 Docker compat | 1 | 22.09 | 23.99 | 0/100 |
| Linux7.0 VM strict | 1 | 22.14 | 23.34 | 0/100 |
| Linux7.0 Docker strict | 1 | 21.52 | 23.08 | 0/100 |
| Linux6.8 VM compat | 8 | 20.70 | 21.39 | 0/100 |
| Linux7.0 VM strict | 8 | 20.67 | 21.98 | 0/100 |

串行直接基线中位约0.20–0.24ms。内部阶段中位通常setup1ms、运行等待10ms、cleanup0ms（毫秒粒度）；外部约22ms包含CLI与monitor的10ms轮询等待，不代表内核限制本身需要22ms。满足当前暖启动p95≤50ms工程预算，不能推广为其他工作负载或所有平台性能保证。无长期压力、真实Agent构建负载或完整cold-cache结论。

## 复现与发布门槛

```sh
make check
python3 tests/integration.py --environment linux-vm --report reports/linux-vm.json
python3 scripts/benchmark.py --samples 100 --report reports/linux-vm-benchmark.json
python3 scripts/benchmark.py --samples 100 --concurrency 8 --report reports/linux-vm-concurrent.json
docker build --target test -t cincta-test .
docker run --name cincta-verify --cap-drop ALL --security-opt no-new-privileges \
  cincta-test python3 tests/integration.py --environment docker --report /tmp/report.json
docker cp cincta-verify:/tmp/report.json reports/docker.json
docker rm cincta-verify
make BUILD=build-static STATIC=1
sh scripts/package.sh build-static/cincta
```

旧内核benchmark显式加--compat。导出源码没有.git时打包需 `CINCTA_SOURCE_REVISION=<实际提交>`。本次aarch64预览交付门槛已满足：两台真实VM、默认容器、正反/故障/回收/并发、原始性能和校验包。稳定版仍需两种原生架构严格验证、外部审计、更广内核/发行版矩阵和长期压力；x86_64目前为待验证的源码目标，不提供已验证产物。

GitHub推送在自动审批中被拒：未明确确认远端为允许外发完整设计/源码/测试的目的地。分支和本地提交、源码包、二进制包均可审查，远端推送与发布等待用户明确批准；未宣称已在GitHub发布或CI已通过。

新建验证VM `cincta-verify` 独立于原有 `jiuwen-lite`，未升级原VM内核。验证结束后停止新VM以释放内存，保留磁盘方便复现；原VM和其已有服务保持运行。
