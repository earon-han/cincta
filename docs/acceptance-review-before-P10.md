# P10之前候选的独立证据核验（历史）

本页保留2026-11-06候选c6a2ef5的核验记录；最终eebc修复版已取代它。旧primary报告原位已替换，阅读本页旧数据应使用reports/v02-before-P10快照或候选提交。

# v0.2 独立验收证据审查

日期：2026-11-06。本审查由独立Agent完成，不修改产品代码。本文检查证据内部一致性、冻结来源与交付身份，不把代码审查或开发期运行当成最终验收。

## 冻结基线与测试修订

产品源码冻结：`4437fcbab6386d46c81c385927532f1fdf043bf3`。准备夹具修订：`e4c29f50d24f6687302408b030705b988bbe9fb0`；最后外层过滤观察分类修订：`f52601a061daaa1b594bfeae35d864bd5b69190b`。已比较这些提交，`src/`、`include/`、`Makefile`、`scripts/`没有差异；工作区19个产品C/header文件的SHA256均与冻结一致。

测试修订没有降低安全预期：

- 缺失授权根仍要求125、业务哨兵未执行和明确stderr，同时要求不提前创建result，符合先验证输出身份再创建文件的契约。
- 缓冲D交接用例仅容许guardian在显式SIGCONT前已经退出的ESRCH；仍必须收到monitor确认自己持有有效快照并完成清理的专有标记，确认guardian/monitor消失、私有目录删除及源内容不变。
- 管道改用无缓冲字节读取，避免TextIO预读与communicate混用导致已经输出的确认标记丢失；没有跳过实际交接、进程或目录断言。
- 外层过滤观察分类仍要求467/469/472全部返回拒绝；静态分支必须全为EPERM。动态分支存在通知时必须同时有request、EPERM deny和实际EPERM；日志完整性仍检查。只有确认外层Seccomp=2且该编号完全没有通知时，才把内层审计观察列为BLOCKED；没有外层过滤而缺事件仍为FAIL，不把不可观察当作PASS。

最后一项符合内核过滤器优先级：ERRNO高于USER_NOTIF，两个ERRNO同优先级时最近安装的filter提供errno，因此静态EPERM与通知模式下的外层ENOSYS可以并存。单凭Seccomp=2不能精确反推出Docker的具体规则，证据只能说明拒绝已发生、内层观察无法证明。首轮容器失败按preflight保留，修订后重新运行，不修改产品或放宽容器profile。[内核seccomp优先级说明](https://docs.kernel.org/userspace-api/seccomp_filter.html)

## 已核对的补充证据

| 证据 | 逐条核对 | 来源与边界 |
|---|---|---|
| x86最终全系统测试 | 34条PASS，无FAIL/BLOCKED；原始summary与行数一致，名称不重复 | 真正x86_64 Linux6.18.60 / ABI7，ARM宿主QEMU全系统TCG；不是x86硬件原生或完整x86 Docker矩阵 |
| 准备阶段VM重复 | 两种内核各5轮、每轮11条，共110次PASS | 每轮19产品源文件SHA与freeze一致，测试SHA与e4c29f5一致；单列重复验证，不叠加进完整功能套件 |
| 额外默认Docker准备测试 | 11条PASS，无FAIL/BLOCKED | 非root UID10001、cap-drop ALL、no-new-privileges、docker-default；该轮是夹具修订的补充证据 |
| 实际交付ARM64默认Docker完整套件 | 208条PASS、0 FAIL、20 BLOCKED，8个suite均完整结束 | 本审查Agent独立执行，只读挂载dist对应的原文件；属于产物验证补充，不重复计入主四环境功能总数 |

已经逐行校验 `reports/v02-x86-source-sha256.txt` 的22个源码/测试/产物条目，清单SHA与provenance一致。x86受测二进制与当前dist文件的SHA256均为 `9ed861ec61e7a9d199262046448ca0d8f4283cf75efb6dc6d868b5c1912e87e7`。x86链接器的glibc静态DNS/NSS提示已保留，数值IP网络测试不能代表无NSS依赖的域名验证。

另以只读方式从本地Linux构建VM取得实际QEMU启动的 `validation-initramfs.gz` SHA256：`dbc54aba86147e4bf755ef8aadeee5ef21fd0bef32840e757b151bc1c16277b6`，及暂存root中的init/cincta/测试程序摘要，补入x86 provenance。原kernel报告的initramfs_sha256是原始Alpine归档摘要，已明确与这个实际自定义启动归档区分；未改受测脚本。

准备重复报告中的Linux6.8二进制为 `68a2d7f9f5046512c28547c696857e4fe78c3b1f90fc30e26af21a1dbd97393a`，与当前dist aarch64文件一致；Linux7.0和普通Docker构建SHA不同，不能仅凭同一产品源码就把不同构建产物混作相同二进制。

为闭合产物身份，本审查Agent在本地Linux6.8 VM独立创建容器，把这一文件只读挂到 `/tested/cincta`，完整执行f52601a的8个suite。容器所算binary SHA与dist逐字节相同；33份源码/测试清单与冻结一致。filtered security与daemon证据确认镜像 `sha256:a93f9539182e1f90d7c044962894134476057a29d1adf6cbdfb34f8fe6a84399`、UID10001、无CapAdd、CapDrop ALL、NNP、builtin seccomp、docker-default AppArmor、private cgroupns，容器退出0且证据取回后已清理。逐行计数和每suite的(mode,name)唯一性已独立核对；完整原始证据在 `reports/v02-arm64-delivery-docker/`。最终归档内容与sidecar仍待打包后核对。

## 计数规则

最终功能计数只从根Agent声明的最终报告集逐行重算，报告内summary不是额外用例。开发期失败复现、模块开发轮、预检失败、重复准备测试、性能样本和压力样本分别列出，不合并成一次不透明的PASS总数。

严格模式不支持、默认Docker缺cgroup委派或缺挂载夹具时，BLOCKED必须保留；同一能力的最小委派/真实bind夹具正例另有证据。默认容器拒绝启动的PASS不冒充该能力正例。预览版的平台、NSS和内核阻塞边界继续适用。

## 最终功能、压力与性能核对

最终四环境报告均记录f52601a，33份产品/测试文件摘要均与本地一致。八个suite逐行重算，summary只汇总一次；每suite按(mode,name)检查唯一性，同名的strict/compat是不同模式测试。报告中存在的binary SHA均与相应环境summary一致。

| 最终环境 / 部署条件 | PASS | FAIL | BLOCKED |
|---|---:|---:|---:|
| ARM64 Linux6.8 VM | 227 | 0 | 1 |
| ARM64 Linux7.0 VM | 298 | 0 | 0 |
| Linux6.8默认Docker | 208 | 0 | 20 |
| Linux7.0默认Docker | 279 | 0 | 19 |
| 两内核Docker最小cgroup委派，各9项 | 18 | 0 | 0 |
| 两内核Docker真实bind夹具，各12项 | 24 | 0 | 0 |
| x86_64全系统TCG | 34 | 0 | 0 |
| 功能/验收检查总计 | **1088** | **0** | **40** |

40项BLOCKED的来源可以完整解释：Linux6.8的VM及Docker各1项严格执行不可用；默认Docker各6项树配额正例缺委派、各12项bind夹具检查缺挂载；两个默认Docker各1项新syscall动态审计被外层过滤遮蔽。最小委派容器保留非root、CapDrop ALL、NNP、builtin seccomp与docker-default，只提供专用RW cgroup子树及显式host cgroup namespace，launcher记录不改已有controller/owner。它们的18项和别名夹具24项是不同部署条件下的独立检查，未把默认环境的BLOCKED改成PASS。

两个alias容器已分别核对独立的filtered security与实际运行命令：同一a93f镜像、tester用户、CapDrop ALL、无CapAdd、NNP、docker-default、private cgroupns，唯一额外挂载为预先由宿主准备的 `/fixtures` RW bind，均退出0。没有借用主容器的空mount列表证明另一个运行的安全配置。记录位于各自的 `v02-arm64-linux{68,70}-docker-alias-security.json` 与command文件。

四环境每组100条、8路并发的组合压力共 **400 PASS、0 FAIL**，逐条index、测试SHA、binary SHA均核对。每条测试实际检查文件打开/写入/chmod、TCP echo、可信审计收尾、workspace导出、原源不变及内外两层私有目录清理。

八份主要性能报告包含 **800条受限执行样本，另800条直接执行基线**，全部退出0。已从raw_samples重算样本数、失败数、中位数、p95和max，核对所有受限样本cleanup_complete及非负phase_ms，C/header/Makefile内容指纹均为 `9491f59aca64a551bcb10e7a98a9a34370598eb3c17ad5617c3136bb25267805`。

| 环境 | 串行p95 ms | 8路并发p95 ms |
|---|---:|---:|
| Linux6.8 VM | 5.69 | 3.95 |
| Linux7.0 VM | 1.16 | 6.01 |
| Linux6.8 Docker | 1.73 | 4.04 |
| Linux7.0 Docker | 2.34 | 6.98 |

额外共享宿主负载记录 `v02-arm64-linux68-vm/concurrent-shared-load.json` 保留100条受限样本和100条基线，全部退出0，但受限p95 **65.57ms**、max **100.13ms**。这份补充不并入上述800条主样本，也不能被隔离测量覆盖；当前结果不能支持“任意宿主共享负载下均满足50ms”的结论。内核、工具链与文件系统不同也不支持简单归因性能差异。

完整交付身份另有补充验证：同一ARM64 dist二进制在Linux7.0 VM完整套件298 PASS、0 FAIL，与本Agent执行的默认Docker208 PASS、0 FAIL相互对应，均不重复计入上表。P9元数据自检13 PASS和scratch产物检查5 PASS分别单列；scratch证明同一文件在无libc/loader镜像中运行及受限自身exec，不覆盖DNS/NSS场景。

开发期模块记录、`v02-preflight-4437fcb/`、`v02-preflight-e4c29f5/`、最初夹具失败与较早x86重复boot全部排除在最终功能计数外；准备阶段110次重复和额外Docker11次也仅作为补充。日志没有把早期失败改写成最终通过。

## 验收结论范围

**本轮冻结候选的运行验收证据审查通过，未发现剩余计数、来源或二进制身份阻断。** P9脚本变更仅增加原始计划、相对路径二进制校验和双revision元信息；其13项自检已核对。包源码revision与实际二进制编译revision可以不同，但必须明确分开记录，并用产品文件SHA证明4437fcb与后续测试/文档提交的运行代码相同，不能把旧构建悄悄当成新源码产物。

二进制归档须在P9打包后再核对实际文件、BINARY_SHA256、源码/二进制双revision及tar sidecar，元数据自检不冒充最终归档本身。用户随后要求的全新Agent代码审查属于下一阶段；若该阶段改变产品源码，须重新冻结并验证，不能把本轮旧指纹证据套用给新实现。本文为多Agent内部证据审查，不是外部第三方安全认证。
