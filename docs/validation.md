# 验证范围、历史结果与复现

## 历史验证快照

以下结果来自2026-11-07的`0.2.0-preview.1`，产品与测试冻结提交均为`eebc7700ea70a6586007b7e38c126a9af88d507f`。它们是明确版本的历史记录，不代表以后每次检出都已经运行。原始运行数据在本地保留，不再作为源码文件提交；公开[机器摘要](../reports/v02-summary.json)保留计数、环境、二进制指纹及原报告摘要。代码审查结论见[最终审查](final-code-review.md)和[修复台账](review-resolutions-v02.md)。内部多角色审查不等于外部安全认证。

| 配置 | PASS | FAIL | BLOCKED |
|---|---:|---:|---:|
| ARM64 Linux6.8 VM，ABI4 | 241 | 0 | 1 |
| ARM64 Linux6.8默认Docker | 222 | 0 | 20 |
| ARM64 Linux7.0 VM，ABI8 | 312 | 0 | 0 |
| ARM64 Linux7.0默认Docker | 293 | 0 | 19 |
| Linux6.8显式委派Docker | 9 | 0 | 0 |
| Linux7.0显式委派Docker | 9 | 0 | 0 |
| Linux6.8显式挂载夹具Docker | 12 | 0 | 0 |
| Linux7.0显式挂载夹具Docker | 12 | 0 | 0 |
| x86_64全系统QEMU，真实Linux6.18.60 | 34 | 0 | 0 |
| 合计（各配置中的检查次数） | 1144 | 0 | 40 |

40项BLOCKED分别为：旧ABI缺少严格模式能力2项；默认Docker无cgroup委派12项；无显式挂载夹具24项；外层seccomp阻止内层通知观察2项。需要额外权限的正例单独运行，不把默认环境的BLOCKED改成PASS。

两VM分别为Ubuntu24.04/Linux6.8.0-147与Ubuntu26.04/Linux7.0.0-34；Docker29.1.3，以普通UID、cap-drop ALL、no-new-privileges和默认seccomp/AppArmor验证。同一ARM64静态程序用于四个主环境及委派/别名补充。x86是TCG全系统仿真中的真实内核，覆盖较窄的34项smoke，不是原生x86硬件验收。

```text
ARM64 SHA256 e4a33692eefc944b4e500872df9963d5a2610c084b79e0bb65ad82f44a2a9180
x86_64 SHA256 04638adbe2cd0a52dd0aaf966d45b03874f64d30138a46964d7c190fd434d461
```

另有400次组合压力任务全部通过：工作区、文件修改、TCP echo、审计完整性、导出、源目录不变和资源回收。两内核Docker exec补充共6项通过，同一ARM64程序的scratch交付补充5项通过。这些不与主功能计数重复相加。GNU libc静态程序的scratch自执行不证明独立DNS/NSS能力；musl未验证。

## 历史基本启动性能

各行100次受限执行、100次直接基线，合计800+800次；全部退出0，受限执行清理完成。墙钟包括创建、安装限制、执行、回收和结果写入。

| 环境 | 并发 | 中位ms | p95 ms |
|---|---:|---:|---:|
| Linux6.8 VM | 1 | 5.14 | 22.43 |
| Linux6.8 VM | 8 | 4.89 | 10.94 |
| Linux6.8 Docker | 1 | 1.06 | 1.29 |
| Linux6.8 Docker | 8 | 2.34 | 3.57 |
| Linux7.0 VM | 1 | 1.01 | 1.79 |
| Linux7.0 VM | 8 | 7.82 | 12.83 |
| Linux7.0 Docker | 1 | 1.17 | 1.38 |
| Linux7.0 Docker | 8 | 4.10 | 5.91 |

这些暖启动样本满足p95≤50ms的工程目标，不保证任意负载。更早候选在共享构建负载下曾出现p95=65.57ms、max=100.13ms且无失败，该轮未满足50ms目标，不计入上述样本。

## 如何验证当前源码

在真实Linux VM中运行：

```sh
make check
make test-all TEST_LABEL=linux-vm
make BUILD=build-static STATIC=1 check
```

八套suite分别覆盖基础行为、工作区模块、准备期生命周期、输出边界、网络、跨模块对抗、文件审计和资源。完整报告是本地生成文件，保存方式见[reports说明](../reports/README.md)。不要将重跑前的旧JSON计入本次结果。

Docker单独运行并保存报告，不复用VM结论：

```sh
docker build --target test -t cincta-test .
docker run --name cincta-test-run --cap-drop ALL --security-opt no-new-privileges cincta-test
# 测试失败后仍应执行以下采集和清理操作
docker logs cincta-test-run > docker-test.log 2>&1
docker cp cincta-test-run:/src/reports/. reports/
docker rm cincta-test-run
```

cgroup委派部署及正例见[资源说明](resources.md)，x86全系统验证见[x86说明](x86-validation.md)。内核或外层策略缺少所请求能力时，拒绝运行并记录原因，不能用unconfined/privileged伪造通过。

## 交付边界

源码/二进制默认包只含公开代码、文档、示例、许可证与来源/校验信息，不包含本地计划、开发台账和原始运行报告。源码与二进制来源分别记录，未知二进制来源必须明确为unknown，不能由当前HEAD推定。已有Git工作树打包要求干净；导出树来源是调用方显式提供的声明，应结合文件清单核对。

远端CI和发布、外部第三方审计、原生x86硬件及更广发行版/长期压力矩阵未在上述本地记录中完成。当前版本仍为preview。
