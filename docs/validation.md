# 验证与预览交付记录

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
