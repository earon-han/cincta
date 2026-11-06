# 整棵进程树资源限制

本模块使用真实 **cgroup v2**。原有 `--memory-mb`、`--cpu-seconds`、`--processes` 仍是逐进程/同UID的rlimit，不会冒充整棵树配额。

| 参数 | 内核/监管机制 | 含义 |
|---|---|---|
| `--cgroup-parent PATH` | 在已经委派的parent创建本次独占叶组 | 必须绝对路径；由部署者提供，cincta不改全局委派 |
| `--tree-memory-mb N` | `memory.max`、`memory.oom.group=1`，可用时`memory.swap.max=0` | payload整组accounted内存上限，OOM时整组终止 |
| `--tree-pids N` | `pids.max` | 整棵树任务数，包含线程 |
| `--tree-cpu-percent N` | `cpu.max`，周期100000µs | 带宽，100表示一个CPU，200表示两个CPU |
| `--tree-cpu-ms N` | 定期读取`cpu.stat usage_usec`并终止 | 本次整组累计CPU预算，受采样周期/调度影响可有超量 |

请求任意树级限制必须提供可用parent，否则在业务执行前125失败，绝不退回rlimit。只提供parent也会建立独占组，便于整组清理和统计。CPU百分比范围1–1000000；CPU预算不是墙钟时间，带宽限制不是累计预算。

## 委派与安全前提

需要 `CONFIG_CGROUPS`、cgroup v2挂载、对应cpu/memory/pids控制器，以及独占子树的创建、配置、迁移、删除权限。`resource_prepare`通过fstatfs验证cgroup2文件系统，普通目录里的同名文件无法伪造可用能力；配额写入后读回确认。模块不自动启用parent controller，不chown主机控制目录，也不要求全局root服务。

委派至少涉及parent目录、`cgroup.procs`和所需控制文件。父组必须已在`cgroup.subtree_control`启用所需controller；有进程的domain组通常不能同时承载启用的子controller，需要把管理进程放到manager子组。Linux迁移权限还检查源、目标的共同祖先`cgroup.procs`写权，cgroup namespace也约束迁移可见范围，因此**只chown一个目标目录不保证能把任意外部进程移进去**。典型部署是systemd的Delegate服务/作用域，cincta调用进程已经位于该委派子树内部。[内核cgroup v2委派规则](https://docs.kernel.org/admin-guide/cgroup-v2.html)

可信preparation guardian创建独占`cincta-PID-RANDOM`叶组并写入/核对所有请求的配额，PID是实际创建者的PID，不保证等于最外层CLI PID。业务子进程保持在exec屏障后，monitor写入`cgroup.procs`并确认成员后才允许执行用户代码；这样业务首次fork之前已经入组，后代自动继承。CLI、guardian、monitor、broker及其可信worker留在该叶组外，不被业务OOM/CPU/pids限制一并杀死。payload不得获得覆盖控制目录的rw授权，也不得继承控制FD。父路径必须可信，不允许业务替换；重开时核对cgroup2与目录dev/inode。

`memory.max`限制内核记账的内存，不等同单个RSS或虚拟地址空间。请求memory上限且 `faccessat(F_OK)` 检测到该组的 `memory.swap.max` 时，当前实现会把它写为0并读回核对，结果 `swap_disabled=true`；写入或核对失败时拒绝执行。若未检测到该文件，则不声称禁用了swap，结果为false，部署者须评估其外层swap策略。内核在某些场景可能临时超量，不能把采样峰值超过名义值直接判定逃逸。`memory.oom.group=1`使组OOM按组处理，实际回收仍需wait确认。[内存控制器说明](https://docs.kernel.org/admin-guide/cgroup-v2.html)

这些额度只计payload及其子孙，不包含可信监管成本。网络另有最多64个worker/512个保留socket、单次1MiB缓冲等上限；文件审计最多32个worker，审计日志另有字节/条数预算。这些是数量/缓冲上限，不是可信进程总和的cgroup硬配额。需要把业务与全部监管开销一起限制时，应把整套cincta部署在额外的外层服务cgroup/容器配额中。

## Docker验证条件

默认Docker通常把`/sys/fs/cgroup`只读挂载。该环境下应验证显式请求树配额得到明确失败；这不是测试通过树级限制正例。

正例需要运行时提供专用委派。可将容器放在专用parent下（`--cgroup-parent`）、只bind该委派子树RW、使用与委派owner匹配的非root UID，并保留默认seccomp/AppArmor、`--cap-drop ALL`和no-new-privileges。如果绑定的parent在容器私有cgroup namespace根之外，迁移会失败；该部署需显式`--cgroupns=host`，或由宿主在容器自身cgroup根内部建立委派并将管理进程放到manager子组。这是额外的部署条件，必须和完全默认容器的负例分开记录，不能隐式加privileged/unconfined绕过。

主机准备委派、controller启用和初始进程迁移属于部署管理动作，不由cincta静默执行。验证记录应包含parent挂载、owner、source cgroup、controller、namespace模式和实际命令。资源测试程序不配置controller或更改已有委派的owner。

已有委派可通过以下入口验证；在Linux Docker宿主机以root执行，镜像须已包含本仓库构建产物和测试程序，报告目录须为绝对路径且尚不存在：

```sh
sudo sh scripts/validate_delegated_docker.sh IMAGE EXISTING_PARENT NEW_REPORT_DIR
```

`EXISTING_PARENT`必须是已委派给非root UID/GID的cgroup v2目录，已有`manager`子组，并已启用cpu、memory、pids控制器；parent和`manager/cgroup.procs`须允许该委派UID迁移任务。脚本核对这些前提，不创建委派、不启用controller、不更改已有cgroup所有权。它以委派UID/GID启动独立容器，使用`--cgroupns=host`和仅该委派子树的RW挂载，把本次容器的宿主PID迁移到已有manager后才放行测试。容器保持内置seccomp、docker-default AppArmor、`--cap-drop ALL`和no-new-privileges；缺少这些策略时拒绝验证。

脚本只创建新的报告目录并为其设置委派UID/GID，结束时移除本次创建的容器，保存测试JSON、容器日志、实际安全配置、启动器哈希和退出码。开发验证已实际得到9 PASS、0 FAIL、0 BLOCKED，证据为[委派Docker资源报告](../reports/v02-delegated-docker-launcher-development/resources.json)及同目录部署记录；最终组合版本仍以统一验证报告为准。

## 统计与清理

当前结果resources对象报告enabled/path、removed/populated、memory_peak/pids_peak、memory_peak_supported/pids_peak_supported、cpu_usage_usec/cpu_nr_throttled、memory_oom_kill、pids_limit_hits、swap_disabled及cpu_budget_exhausted。名义配额来自调用参数，current值和kill_supported留在内部ctx，当前JSON不单独导出这些字段。旧内核缺`pids.peak`时以采样最大值作为下界并标记原生peak不可用，不能把它当精确内核峰值。CPU计量为微秒；CPU预算每50ms维护采样，可因采样和调度超量。

取消和资源预算触发时可写`cgroup.kill`补充终止整组；若内核没有该文件，内部ctx记为kill_supported=false，启动器仍需完成进程身份固定的kill/reap。`resource_finish`在实际后代回收后采最终stats，仅`cgroup.events populated=0`才删除本次叶组。目录删除、populated=0和发过SIGKILL都不能单独代替wait到ECHILD。清理失败必须体现在结果和退出码中。准备阶段创建/配置和最终统计/删除本身不在 `--timeout-ms` 的执行计时器预算内；准备取消由guardian处理，详情见[preparation.md](preparation.md)。

## 实核验收

```sh
# 默认/no-delegation：正例将列BLOCKED，负例必须PASS
python3 tests/resources_test.py --binary build/cincta \
  --environment linux-vm-no-delegation --report reports/resources-negative.json
# 启动器已位于委派子树之后运行：真实聚合pids/memory/CPU和清理
python3 tests/resources_test.py --binary build/cincta \
  --cgroup-parent /sys/fs/cgroup/DELEGATED \
  --environment linux-vm-delegated --report reports/resources-positive.json
```

脚本覆盖缺parent、伪造普通文件系统、无委派拒绝、入组/删组、聚合pids、聚合内存OOM、CPU带宽、累计CPU预算及取消清理；真实Linux VM与Docker分别运行。最终PASS/FAIL/BLOCKED和原始证据以统一验证报告为准，不以实现者编译或配置存在替代实核验收。
