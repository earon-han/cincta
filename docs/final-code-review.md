# P10 独立源码审查

审查日期：2026-11-06。独立审查对象为干净候选提交
`c6a2ef525f4d32bd0c5ba33167cfb25b3f955d90`；以下行号均以该候选为准。
本轮只读审查产品与测试，只新增本报告。主审另启动两名全新、只读子审查者，
分别审查 broker/filebroker/network 和 workspace/resources；主审负责 main、
security、supervisor、preparation、result/json 及交叉核验。没有把既有审查报告
或历史 PASS 当作正确性证明，也没有将本轮针对性复现冒充全部环境的重新验收。

## 结论与覆盖

确认三个问题：一项 P1、两项 P2；没有确认 P0。均有真实 Linux 内核复现。
初轮结论为 **FAIL：需修复以下问题并重新验证后再冻结交付候选**。
这不是对所有潜在问题不存在的证明。

检查范围包括全部 `src/*.c`、`include/*.h`、相关测试及公开设计/使用契约；
重点检查 native ABI/BPF 跳转、引导 listener 撤销、通知 ID/mem/FD 固定、
metadata 路径授权、网络参数复制与 socket 身份、工作区复制/差异/导出、
cgroup 身份与配额读回、两层后代回收、准备交接、审计预算和结果真实性。
未把明确记录的 DNS 地址快照身份、GC 非原子可用性、O_PATH 原生回退、
已获准副作用不可回滚、准备/导出不计执行 timeout、稳定可信宿主布局、
采样峰值与 CPU 预算超量等边界算作缺陷。

本轮复现环境：jiuwen-lite，非 root UID501，Linux
`6.8.0-147-generic`，aarch64，Landlock ABI4，显式 `--compat`。
没有使用 cgroup 夹具、修改 Docker 安全 profile 或放宽内核策略。
冻结静态程序为 `/tmp/cincta-v02-final/build-static/cincta`，SHA256：
`68a2d7f9f5046512c28547c696857e4fe78c3b1f90fc30e26af21a1dbd97393a`。
本机候选与该 VM 下 `main.c`、`supervisor.c`、`workspace.c` 的 SHA256 一致。

## F1 / P1：准备期间原调用方退出后，CLI 仍会启动业务

- 位置：`src/supervisor.c:469`–474；相关调用位置 `src/main.c:455`–547，
  guardian 仅绑定 CLI 身份的位置 `src/preparation.c:256`–260。
- 原因：首次获取调用方 `getppid()` 和 pidfd 发生在 `supervise()` 内，晚于
  工作区复制、DNS 和 cgroup 准备。原调用方在准备期间退出后，CLI 已重父化；
  后续取得的是收养者身份，两次 `getppid()` 一致也无法发现原调用方已经死亡。
  guardian 只观察 CLI，所以也不会因原调用方消亡而取消准备。
- 触发：调用方启动带准备操作的 CLI，随后在准备完成前退出。正常服务管理器
  或 subreaper 可收养 CLI。无需突破沙箱或向 CLI 注入不可信代码。
- 影响：失去调用方生命周期绑定；原请求已消亡，业务仍可启动、获得配置的文件/
  网络权限并产生副作用。最终还能报告 `status=ok,cancelled=false`。
  这与文档已经说明的“准备时间不计 timeout”是两个独立问题。
- 建议：任何准备前固定原调用方 pidfd，并贯穿 guardian、CLI、monitor 的交接
  和启动屏障；不得在准备后重新定义调用方。准备取消清理前先确认 CLI 不会继续
  写入准备对象；D/ACK/G 各阶段处理 caller 已死的情况；纯 DNS、无 workspace/
  cgroup 的路径也必须拒绝在已死调用方之后启动。保留按整个调用进程而非创建
  线程判断死亡的语义；PID1 无可见调用方须显式处理。
- 回归要求：准备中自然 caller exit、固定准备窗口 caller exit、D/G 交接边界、
  无 guardian 的准备路径、调用线程退出但调用进程仍存活，以及既有正常运行、
  取消和 CLI/monitor 单独故障路径。

实核两次均确认：第一次用 SIGSTOP 固定准备窗口，原 caller 175874 退出，
CLI175875 被 reviewer175870 收养后恢复；CLI 退出0，实际 marker 为
`PAYLOAD_EXECUTED\n`，结果 `status=ok,cancelled=false,elapsed_ms=768`。
第二次完全不暂停 CLI，仅原调用方看到 guardian 后自然退出；当时 result
尚不存在，workspace tree 已开始建立。CLI176229 退出0，结果：

```json
{"early":{"pid":176229,"result_exists_when_caller_exits":false,"workspace_tree_exists":true},"wait_status":0,"status":"ok","cancelled":false,"marker":"PAYLOAD_EXECUTED\n","elapsed_ms":418}
```

两次临时大文件夹具已清理；原始输出保留于独立审查聊天的工具记录。下列完整
重现程序覆盖两种方式；`PAUSE=False` 对应无暂停复现，改为 True 固定准备窗口。
在上述 VM 内运行。子进程 stdio 使用 `/dev/null`，遵守 workspace 的 stdio 边界。

```python
import ctypes, json, os, pathlib, shutil, signal, subprocess, tempfile, time

PAUSE = False
binary = "/tmp/cincta-v02-final/build-static/cincta"
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0  # test-driver subreaper
area = pathlib.Path(tempfile.mkdtemp(prefix="cincta-review-caller-"))
(area / "source").mkdir()
(area / "scratch").mkdir()
with (area / "source" / "data").open("wb") as f:
    f.truncate(256 * 1024 * 1024)
r, w = os.pipe()
caller = os.fork()
if caller == 0:
    os.close(r)
    p = subprocess.Popen([
        binary, "run", "--compat", "--rx", "/usr/bin", "--rx", "/usr/lib",
        "--workspace", str(area / "source"),
        "--workspace-parent", str(area / "scratch"), "--workspace-keep",
        "--result", str(area / "result.json"), "--", "/bin/sh", "-c",
        "echo PAYLOAD_EXECUTED > marker",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
       stderr=subprocess.DEVNULL)
    for _ in range(10000):
        children = pathlib.Path(
            f"/proc/{p.pid}/task/{p.pid}/children").read_text().split()
        if children:
            if PAUSE:
                os.kill(p.pid, signal.SIGSTOP)
            os.write(w, json.dumps({
                "pid": p.pid,
                "result_exists_when_caller_exits": (area / "result.json").exists(),
                "workspace_tree_exists": bool(list((area / "scratch").glob(
                    "cincta-preparation-*/cincta-workspace-*/tree"))),
            }).encode())
            os._exit(0)
        time.sleep(.001)
    os._exit(2)
os.close(w)
early = json.loads(os.read(r, 4096))
os.close(r)
os.waitpid(caller, 0)
if PAUSE:
    os.kill(early["pid"], signal.SIGCONT)
_, status = os.waitpid(early["pid"], 0)
result = json.loads((area / "result.json").read_text())
tree = pathlib.Path(result["workspace"]["tree"])
print(json.dumps({"early": early, "wait_status": status,
    "status": result["status"], "cancelled": result["cancelled"],
    "marker": (tree / "marker").read_text(), "elapsed_ms": result["elapsed_ms"]}))
shutil.rmtree(area)
```

## F2 / P2：工作树根目录的变化没有进入 diff

- 位置：`src/workspace.c:528`，以及 `collect()` 的364–417行，特别是378行。
- 原因：manifest 只收集子条目，不加入 baseline/tree 根自身；比较结果和
  `workspace.changes` 都来自这两个 manifest。导出却会复制根的实际权限/时间。
- 触发：空源根0755；业务通过 `--metadata` 执行 `os.chmod(".", 0o700)`，
  同时请求 diff 和 export。
- 证据：真实任务退出0、`status=ok`，diff为 `count=0,changes=[]`，结果
  `workspace.changes=0`；`stat` 显示源根0755、导出根0700。
  根 mtime 同样不被 manifest 比较。
- 影响：依赖差异审查导出的调用方会把实际根权限变化判断为零变化。
  `docs/workspace.md` 的“变更与导出”承诺权限和目录mtime变化计入差异，
  并没有排除工作树根；copied_files 明确排除根只是复制量计量规则。
- 建议：比较根元数据，以相对路径 `.` 记录根变化，保留 copied_files 的原有
  计量语义。增加纯根 chmod、纯根 mtime、根未变化的回归验证。

原始证据保留于 VM `/tmp/cincta-review-workspace-uze0wpm0/`：
`result.json`、`diff.json`、`source`、`export`。复现命令（使用新的 `$d`）：

```sh
d=$(mktemp -d /tmp/cincta-review-root-diff.XXXXXX)
mkdir "$d/source"
chmod 755 "$d/source"
/tmp/cincta-v02-final/build-static/cincta run --compat --metadata \
  --rx /usr/bin --rx /usr/lib --workspace "$d/source" \
  --workspace-diff "$d/diff.json" --workspace-export "$d/export" \
  --result "$d/result.json" -- /usr/bin/python3 -c 'import os; os.chmod(".", 0o700)'
cat "$d/diff.json"
stat -c '%a %n' "$d/source" "$d/export"
```

## F3 / P2：4095字节 FD 路径让 metadata 操作与审计伪成功

- 位置：`src/broker.c:269`–270，错误传播353行，审计响应432–433行。
- 原因：`readlink(..., size-1)` 返回 `size-1` 时，`path_from_fd()` 直接
  返回-1但未设置 errno。`metadata_handle()` 随后按 `-errno` 生成响应；
  errno 为0时响应成为成功，实际对象操作没有执行。
- 触发：在 rw 根下通过相对 mkdir/chdir 构造最终 `/proc/self/fd/N` 目标
  恰为4095字节；对实际0600的普通文件调用 `fchmod(fd, 0644)`。
  超过4095时本环境内核 readlink 自身报 ENAMETOOLONG，精确边界才命中。
- 证据：真实业务输出 `pathlen=4095 chmod_rc=0 errno=0 mode=600`。
  审计仅有 start、request、`response(value=0,errno=0)`、finish(ok)，最终
  `status=ok,audit.complete=true,delivery_pending=0`，与未改变的实际权限矛盾。
- 影响：业务误以为 metadata 已成功修改；如果实际请求为收紧权限，会误判
  文件已经受到保护。当前复现不构成越权，但违反返回值和可信审计契约。
- 建议：截满分支明确设置 `errno=ENAMETOOLONG`；metadata 失败响应防御零
  errno。加入4094、4095及超过边界的真实功能测试，核对实际权限、返回 errno
  和审计 deny，不能只验证 CLI 退出或日志存在。

原始夹具保留于 VM `/tmp/cincta-review-meta.8gfSTF/`：`probe.c`、`probe`、
`audit.jsonl`、`audit-result.json`、`writable-audit`。
probe.c SHA256 `f72a7a5dd7e43f390fc8300f28c84d768f8b3b56e18719f3d34c6c3240525922`，
probe SHA256 `3124bc7d7e26cdbbc2e178abc82e21e027b3b1f881bda0362b6f8ba343eaa34e`。
probe根据argv目录长度逐级相对创建目录，因此可换新根复跑：

```sh
d=/tmp/cincta-review-meta.8gfSTF
mkdir "$d/writable-new"
/tmp/cincta-v02-final/build-static/cincta run --compat --metadata \
  --rw "$d/writable-new" --rx "$d/probe" --audit "$d/new-audit.jsonl" \
  --result "$d/new-result.json" -- "$d/probe" "$d/writable-new"
```

初轮发现已逐条交给主 Agent 核验。F1/F2 已获主 Agent 初步认可，F3 的实际源码、
probe和原始审计也经主审交叉读取；本报告初版尚不宣称任何问题已修复，后续须
逐条记录主 Agent 的核验结论、修复提交及功能验证。

## 修复源码与专项证据复核（2026-11-06）

主 Agent 已逐条认可 F1/F2/F3，无实质结论分歧；修复由主 Agent 及另外两名
实现 Agent 完成，原始审查者不修改产品代码。以下是对随后工作树差异的独立
复核，初轮候选的 FAIL 保留为历史，不表示修复后仍有同样问题。

- **F1 源码复核认可。** 新 caller 模块在 main 准备前固定原 TGID pidfd；
  guardian 保留并监视它，先通过固定 CLI pidfd SIGKILL 并确认 CLI 已终止，
  再清理准备对象。D 和 ACK 前均复核 caller；DNS-only 路径也有 guardian，
  无工作区的空容器在交接时清理。supervise 不再重取 getppid，CLI 自有 dup
  独立释放，monitor 保留原描述符供 G、payload gate 和运行阶段复核；
  payload 的 close_range 及 broker 的显式 close 防止身份 FD 进入业务/
  worker。已检查 helpers 的显式 -1 初始化和专用 caller_capture 路径。
  未发现需追加修复的 FD、交接或清理问题；功能及最终冻结指纹由统一验收闭环。
- **F2 专项可以关闭。** 原发现者与主审只读核对修复：根以 `.` 加入 manifest，
  通过原有目录比较逻辑检查权限和 mtime，不调用 account、不占复制或最终树
  配额；分配/释放没有新增悬垂引用或重复释放。当前 workspace.c SHA256
  `cc54ebad7b2bb4c21dbd8f709027c452421dc911d98395f57ed9aa20313f5cdf`，
  workspace_test.py SHA256
  `69361f2ef76e7e6400733da277fc245ffb228edc136077231174753fac357960`，
  与专项报告一致。`reports/v02-review-F2-module-vm.json` 和
  `reports/v02-review-F2-module-docker.json` 各21 PASS，
  `reports/v02-review-F2-cli-vm.json` 为3 PASS；覆盖纯根 chmod、mtime、
  未变化及实际子项占满配额时根不挤占预算，文档同步。
- **F3 专项可以关闭。** 认可 full-buffer readlink 支持合法4095路径，比
  一律拒绝边界路径更兼容；仅在 n<size 时写 NUL，满缓冲返回 ENAMETOOLONG，
  两条 metadata 失败路径均防御 errno0。原发现者复核业务 fstat、父进程
  逐级 dirfd/stat、完整目标字节长度与 audit deny 的双侧验证；4094/4095/4096
  边界在 VM 和默认 Docker 共6 PASS。专项 VM52 PASS，Docker51 PASS、
  1个既有外层过滤观察 BLOCKED。helper/test 指纹与
  `reports/v02-review-f3/provenance.json` 一致；当前 broker 去掉并行 F1 的
  caller FD close 行后与 F3 报告源码指纹精确一致，没有把隔离验证冒充
  综合候选验收。

最终交付结论仍须主 Agent 完成修复版统一冻结、真实多环境回归和交付包核验，
并在 `review-resolutions-v02.md` 记录最终提交及功能证据；本次源码复核没有
重新执行已经通过且无新疑点的专项测试。

## 补充：无可见父进程的 docker exec 兼容性

主 Agent 在修复提交 `46d4919` 后提出 caller_capture 的兼容性核对。
独立实核确认：Docker exec 创建的进程可以是当前 PID 命名空间内的非 PID1，
但 `getppid()==0`。在 jiuwen-lite 新建专用容器，以 UID65534、cap-drop ALL、
no-new-privileges、network none、默认 seccomp 和 AppArmor docker-default
运行，直接 docker exec Python 的原始观测为：

```json
{"exec_process":{"pid":7,"ppid":0,"uid":65534},"hostconfig":{"Privileged":false,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"NetworkMode":"none"},"apparmor":"docker-default"}
```

容器已停止并自动删除。`46d4919` 的 `src/caller.c:24` 只允许
`parent==0 && getpid()==1` 使用 unbound 模式，会误拒绝上述常用执行方式；
旧实现对任意 ppid0 都不绑定不可见父进程。认可主 Agent 的修正建议：任意
`getppid()==0` 返回 caller_fd=-1，仅对当前 PID 命名空间中可见的调用方固定
pidfd；将代码与文档的“PID1”表述改为“当前 PID 命名空间无可见调用方，
由 runtime 信号取消”。负值或其他真正的身份探测错误仍失败关闭。

应补真实 docker exec 正常执行及 runtime 发信号取消/后代回收验证，且保留
可见调用方退出和线程退出语义回归。本段记录的是修复过程中的兼容性回归，
尚不宣称其补丁或最终验收已经完成。

## 最终源码与功能证据闭环（2026-11-07）

**P10 独立审查闭环通过：F1、F2、F3 及兼容性补充 F4 均已修复，最终
冻结源码与对应真实功能验证通过；没有未解决的审查发现或结论分歧。**
初轮 FAIL 和缺陷复现保留为历史，不能用修复后的 PASS 抹去。

最终 runtime/test 冻结为 `eebc7700ea70a6586007b7e38c126a9af88d507f`；
三项修复提交为 `46d4919`，F4及能力报告补充提交为 `eebc770`。
独立复核已确认：任意 ppid0 的无可见调用方模式恢复正确兼容语义；
`protections.caller_bound` 和 unsupported 原因明确区分该边界，ABI不同
组合下JSON分隔正确；guardian 的 signal0 权限预检位于准备容器创建之前，
失败不创建对象。产品、头文件、测试和脚本在本次最终审计时均无偏离冻结版
的工作树修改。

| 项目 | 最终修复及功能证据 | 结论 |
|---|---|---|
| F1 / P1 | 四个主环境 preparation 各15 PASS，均含自然caller退出、stopped CLI、DNS-only及死亡优先buffered D；legacy 中运行期caller退出和创建线程退出但进程存活回归均 PASS | 关闭 |
| F2 / P2 | 四环境 workspace 模块各21 PASS，根 chmod、mtime、未变化及精确预算均通过；四环境CLI根元数据专项各3 PASS，diff与实际导出一致 | 关闭 |
| F3 / P2 | 四环境4094/4095/4096边界共12 PASS；helper与父进程双侧核对真实权限，审计目标字节与成功/拒绝结果一致，无伪成功 | 关闭 |
| F4 / 兼容性 | 最终 `v02-docker-exec-linux68.json`、`v02-docker-exec-linux70.json` 各3 PASS，同一交付产物直接exec成功、SIGTERM取消、实际payload消失，caller_bound=false及unsupported原因准确 | 关闭 |

### 来源与附件卫生

四个主环境执行完全相同的 ARM 静态产物，SHA256：
`e4a33692eefc944b4e500872df9963d5a2610c084b79e0bb65ad82f44a2a9180`。
已逐项核对四份主 summary 共140个源码/头文件/测试摘要，既与本地文件匹配，
也与 `git show eebc770:PATH` 匹配；专项测试摘要同步匹配。

最终四环境八套测试从全新空报告根完整执行，之后整体替换 primary。
独立交叉核对每环境45个附件 `result.json`，均与本轮 independent.json 中
嵌套原始结果逐对象完全一致，且都有最终新增的 caller_bound 字段，没有
发现旧结果混入；每环境32份JSONL均可逐行解析。旧候选报告保存在
`reports/v02-before-P10/`，首轮附件整理前的整合报告保存在
`reports/v02-initial-reviewed-run/`，均排除最终计数。

两主 Docker 的不可变镜像均为
`sha256:f3f32e31e6855feb0228e22c48d45428b06c2a5482db3790658600cc75e52092`，
来源见 `reports/v02-reviewed-image-provenance.json`：由冻结源码测试镜像派生，
仅将上述原静态产物 COPY 到 `/src/build/cincta`，保留非root tester、
cap-drop ALL、NNP、默认 AppArmor docker-default 与 daemon builtin seccomp，
主运行没有挂载或 privileged/unconfined 设置。

部分 suite（如 legacy、network）与独立资源报告本身不含 binary_sha256；
它们的来源通过统一 test_all 调度所用固定 binary 路径、主 summary 的源码/
产物指纹，以及资源启动器与不可变镜像身份链关联，不能声称每份原始报告
都独立自证二进制摘要。两份委派资源 security 的 image ID 均匹配上述镜像，
启动器固定从镜像 `/src` 执行 `build/cincta`；该链条与报告是否自带摘要
明确区分。模块审查者还在两台 VM 独立只读检查该不可变镜像的 WORKDIR=/src、
USER=tester，并在默认安全profile、cap-drop ALL、NNP的只读临时容器中
实际读取 `/src/build/cincta` 的 SHA256，两者均为上述 e4a 摘要。
F4最终两份报告均直接记录同一 e4a 产物；早期
`v02-review-namespace/docker-exec-check.json` 的9b09产物只保留为历史。

### 最终验证范围与计数

已从实际九个 functional report 重新累加，并核对每个主 summary 与其八套
原始suite计数一致：

| 配置 | PASS | FAIL | BLOCKED |
|---|---:|---:|---:|
| ARM / Linux6.8 VM | 241 | 0 | 1 |
| ARM / Linux7.0 VM | 312 | 0 | 0 |
| ARM / Linux6.8 默认 Docker | 222 | 0 | 20 |
| ARM / Linux7.0 默认 Docker | 293 | 0 | 19 |
| 两个最小委派 Docker 资源验证 | 18 | 0 | 0 |
| 两个显式bind别名夹具验证 | 24 | 0 | 0 |
| x86_64真实内核全系统 QEMU smoke | 34 | 0 | 0 |
| **合计** | **1144** | **0** | **40** |

这些是不同配置下的检查数，不是1144个互异逻辑功能。40个 BLOCKED 保留：
两份ABI4环境的严格模式不可用各1；两个默认Docker各12个需显式bind夹具、
6个需委派的正例及1个外层过滤阻止证明内层审计观察的入口。单独正例配置的
PASS 没有改写原配置的 BLOCKED。

x86产物 SHA256
`04638adbe2cd0a52dd0aaf966d45b03874f64d30138a46964d7c190fd434d461`；
已独立核对其22项冻结源码manifest和4个证据文件摘要。
真实 x86_64 Linux6.18.60 内核在 QEMU full-system TCG 中运行，UID501、
strict模式，34 PASS；它不是原生x86硬件，也不是qemu-user，覆盖窄于
ARM完整套件。来源见 `reports/v02-x86-provenance.json`。

另核对四环境共400个压力样本，均PASS；800个sandbox及800个direct原始
性能样本全部实际退出0，800个sandbox样本均 cleanup_complete=true，来源指纹
与冻结源码和同一 e4a 产物一致。scratch交付证明为5 PASS，context只有
Dockerfile及原产物，不重新编译；context、实际执行容器导出产物摘要
均为e4a，证据文件manifest逐项匹配。scratch不包含DNS/NSS能力证明。

最终汇总入口为 `reports/v02-summary.json`。审查者没有为此重复已无新疑点
的功能测试，而是独立核对原始结果、实际行为、附件、源码和产物来源。
P10关闭不代表外部安全审计或所有平台稳定认证；远端CI、GitHub推送和外部
审计均未完成，也未计为PASS。最终文档台账更新、重新打包及clean-source
安装/校验由主 Agent 随后完成，不在本次源码/功能证据审查中提前宣称完成。
