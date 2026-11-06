# 验证与预览交付记录

## v0.2 本地交付候选

日期：2026-11-06。版本：`0.2.0-preview.1`。产品源码冻结于 `4437fcbab6386d46c81c385927532f1fdf043bf3`，最终验收脚本冻结于 `f52601a061daaa1b594bfeae35d864bd5b69190b`；其间仅修订测试夹具及覆盖分类，src/include/Makefile字节相同。后续提交补文档、证据及打包元信息。P10用户追加的全新Agent代码审查将在本地候选包完成后执行，完成通知须等该轮闭环。

[机器汇总](../reports/v02-summary.json)、[独立证据审查](v02-acceptance-review.md)、[实现安全审查](v02-design-review.md)保留不同职责；多Agent互审不是外部第三方审计。

### 真实内核验收

| 环境 / 原始报告 | PASS | FAIL | BLOCKED |
|---|---:|---:|---:|
| [arm64-linux68-vm](../reports/v02-arm64-linux68-vm/summary.json) | 227 | 0 | 1 |
| [arm64-linux68-docker](../reports/v02-arm64-linux68-docker/summary.json) | 208 | 0 | 20 |
| [arm64-linux70-vm](../reports/v02-arm64-linux70-vm/summary.json) | 298 | 0 | 0 |
| [arm64-linux70-docker](../reports/v02-arm64-linux70-docker/summary.json) | 279 | 0 | 19 |
| [arm64-linux68-docker-delegated](../reports/v02-arm64-linux68-docker-delegated/resources.json) | 9 | 0 | 0 |
| [arm64-linux70-docker-delegated](../reports/v02-arm64-linux70-docker-delegated/resources.json) | 9 | 0 | 0 |
| [arm64-linux68-docker-alias](../reports/v02-arm64-linux68-docker-alias.json) | 12 | 0 | 0 |
| [arm64-linux70-docker-alias](../reports/v02-arm64-linux70-docker-alias.json) | 12 | 0 | 0 |
| [x86-kernel](../reports/v02-x86-kernel.json) | 34 | 0 | 0 |
| 合计（不同执行配置的检查次数） | 1088 | 0 | 40 |

两台本地Lima虚拟机分别为Ubuntu24.04 / Linux6.8.0-147 / Landlock ABI4及Ubuntu26.04 / Linux7.0.0-34 / ABI8。VM以UID501验证；Docker29.1.3内以UID10001验证，保留builtin seccomp、docker-default AppArmor、cap-drop ALL、NNP和私有cgroup namespace。两个默认Docker环境使用同一最终镜像，源、测试、二进制指纹及实际容器安全配置均在各报告目录。详细内核配置、LSM、Yama、编译器和委派记录见两VM的environment.json。

40项BLOCKED分解：旧内核的严格模式各1项（VM及Docker共2），默认Docker没有委派的资源正例各6（共12），没有宿主bind夹具的别名正例各12（共24），外层过滤使内层新系统调用审计观察不可证明各1（共2）。前两类部署正例已在显式委派/夹具配置下分别实际运行，表中独立9项资源和12项别名正例不回填默认配置的BLOCKED。两个审计观察BLOCKED保留，原生VM同入口必须有真实request/deny；默认Docker中静态拒绝仍逐入口证明EPERM。ABI不足不以compat冒充严格模式。

默认Docker正例额外配置：委派使用UID501、`--cgroupns=host`，仅bind专用已有cgroup子树及报告目录RW，controller/owner由宿主部署者预先准备；测试脚本不修改全局配置。别名验证只bind宿主专用fixture，保留相同安全profile；包含根bind、子目录反向bind、源parent/export别名、ro/rx及私有baseline暴露拒绝。具体命令见[资源指南](resources.md)及对应launcher/security.json。

x86是QEMU TCG全系统启动真实Linux6.18.60 / ABI7、UID501的34项smoke；不是qemu-user或原生x86硬件。实际自定义boot initramfs、内核、guest init、被测二进制和源码清单见[来源证明](../reports/v02-x86-provenance.json)。覆盖窄于完整aarch64发行版套件，不借此声称所有应用兼容或原生硬件性能。[x86指南](x86-validation.md)

### 重复、组合与交付产物验证

- 四主环境分别100次、并发8的组合任务，共400 PASS：每次执行工作区复制、真实文件打开/写入/chmod、TCP echo、syscall审计、导出及回收；核对源不变、审计完整且pending=0、内外临时容器都消失。原始数据见各stress.json，组合任务包含真实复制及密集通知成本，p95约112–415ms，不套用基本启动基准预算。
- 准备阶段故障独立连续验证：两VM各5轮、每轮11项，共110 PASS；另默认Docker11 PASS。原ESRCH竞态实际复现后仍要求接管标记、进程真正从proc消失及目录/源内容断言，不把僵尸当清理完成。[重复证据](../reports/v02-preparation-final-repeats/summary.json)
- 实际交付ARM64二进制在Linux6.8 VM完整受测，原样取到[Linux7.0 VM再完整298 PASS](../reports/v02-arm64-delivery-linux70-vm/summary.json)，并在[默认Docker完整208 PASS](../reports/v02-arm64-delivery-docker/summary.json)，指纹均为68a2d7f9…；不把其他工具链编译出的同源程序称为同一产物。
- 同一ARM产物在FROM scratch镜像中以UID10001完成probe和受限自执行，导出的/cincta字节一致，镜像没有动态loader/libc文件，共5 PASS。[原始证明](../reports/v02-delivery-scratch/summary.json)
- 包元信息、相对BINARY_SHA256、实施计划副本、来源清单和两个架构包自验证13 PASS。[打包证据](../reports/v02-package-metadata-selfcheck.json)

上述补充重复/产物检查均单列，不与主1088次功能检查重复相加。当前仅交付经过验证的GNU libc静态产物；musl未完成验证。静态glibc的域名/NSS配置及可能的匹配运行库需求仍按[依赖指南](dependencies.md)处理，scratch受限自执行不证明独立DNS/NSS场景。

### 基本启动性能

每组100次直接基线及100次沙箱样本，共主800次沙箱、800次基线，均无失败。边界是subprocess.run墙钟，包含创建进程、安装保护、执行、清理与结果fsync；不是内核单次调用成本。原始命令、源码/二进制指纹、内核、逐样本与phase_ms见报告。

| 环境 | 并发 | 中位ms | p95 ms | 失败/样本 |
|---|---|---:|---:|---:|
| arm64-linux68-vm | 串行 | 3.16 | 5.69 | 0/100 |
| arm64-linux68-vm | 并发8 | 2.48 | 3.95 | 0/100 |
| arm64-linux68-docker | 串行 | 1.31 | 1.73 | 0/100 |
| arm64-linux68-docker | 并发8 | 2.84 | 4.04 | 0/100 |
| arm64-linux70-vm | 串行 | 0.93 | 1.16 | 0/100 |
| arm64-linux70-vm | 并发8 | 3.86 | 6.01 | 0/100 |
| arm64-linux70-docker | 串行 | 1.35 | 2.34 | 0/100 |
| arm64-linux70-docker | 并发8 | 4.77 | 6.98 | 0/100 |

基本暖启动主样本满足p95≤50ms工程目标，不能推广到任意负载。额外保留旧VM与QEMU/镜像构建共用资源时的100次并发样本：p95=65.57ms、max=100.13ms、0失败，**该共享负载不满足50ms目标**，不计主800样本，也不删除或冒充独占性能。[共享负载原始数据](../reports/v02-arm64-linux68-vm/concurrent-shared-load.json)

### 缺陷与夹具历史

保留 `reports/v02-preflight-4437fcb/`：首次两VM完整验收分别226 PASS/1FAIL和295PASS/3FAIL；缺失授权根的旧测试误要求早期JSON，另有准备测试SIGCONT时guardian合法提前退出的竞态。修订测试前后产品源码未改变，两VM各5轮复现并验证清理证明后再完整运行。

保留 `reports/v02-preflight-e4c29f5/`：默认Docker各1个新入口动态审计预期错误；外层ERRNO优先于USER_NOTIF，不能把未观测记成功。最终记录逐NR errno/request_seen/deny_seen及外层Seccomp状态，完全无该入口事件且已有外层过滤时记BLOCKED；有请求无deny、错误返回或未建立审计仍FAIL。其他模块的开发缺陷复现及x86夹具修正记录同样保留并明确排除最终统计。

### 来源、交付与尚未执行的门槛

实际交付二进制SHA256：

```text
aarch64  68a2d7f9f5046512c28547c696857e4fe78c3b1f90fc30e26af21a1dbd97393a
x86_64   9ed861ec61e7a9d199262046448ca0d8f4283cf75efb6dc6d868b5c1912e87e7
```

Linux7.0本机构建另为b6728f9e…，两Docker镜像编译为046277b9…；完整64位指纹见各summary，工具链/路径不同而源码一致。两个交付包记录SOURCE_REVISION、BINARY_SOURCE_REVISION、SOURCE_SHA256、BINARY_SHA256、PACKAGE_INFO及外部压缩包SHA256；配套源码包包含设计、指南、原始计划、C源码、全部测试与证据。最终打包来源提交可能晚于受测核心提交，但源码清单核对必须一致。

远端CI和GitHub发布尚未执行。此前自动审批拒绝推送，理由是未明确批准GitHub目的地接收完整设计/源码/测试；未重试绕过。稳定版另需原生x86硬件、更广发行版/内核、长期压力和外部安全审计，当前只提供preview。P10新增代码审查的结论和后续修复验证将单独记录，不能用本轮实现审查替代。

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
