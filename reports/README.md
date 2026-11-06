# v0.2 证据索引

[最终机器汇总](v02-summary.json)覆盖两本地Linux VM、两默认Docker、最小委派/挂载夹具正例和真实x86全系统内核。逐项计数、来源、二进制SHA、审计样本、性能原始样本及安全配置分别保留。统计只使用汇总显式列出的最终报告；preflight、development、reproduction、重复与产物验证不混加。[完整解释](../docs/validation.md)

P10已在候选完成后由全新Agent执行，F1–F4经逐项核实讨论、修复和独立复核，修复版eebc最终1144PASS/0FAIL/40条件BLOCKED；详见最终代码审查与修复台账。旧候选及首次集成附件独立归档，不混入最终统计。

## v0.1 历史索引

# 原始验证证据

2026-11-06本地实测，最终业务源码提交 `238c008`；两份 tested-*-source-sha256.txt 已与仓库逐文件校验一致。JSON及.log为实际运行输出，没有把跳过项目转换为通过。

- linux-vm / docker-compat：Lima jiuwen-lite，Ubuntu24.04，Linux6.8，aarch64，ABI4。
- linux-vm-strict / docker-strict：独立Lima cincta-verify，Ubuntu26.04，Linux7.0，aarch64，ABI8。
- 两台Docker均29.1.3，非root tester、cap_drop ALL、no-new-privileges、docker-default AppArmor及builtin seccomp；安全配置和daemon选项单独留档。
- scratch-*.log：静态二进制作为无libc scratch容器PID1执行受限的自身 --version，兼容/严格分别通过。
- benchmark/concurrent.json：每组100条sandbox样本、100条直接执行基线；保留外部wall时间、真实phase_ms、失败数、源码指纹和二进制SHA256。VM并发为8路。

无Git目录的导出源码构建以 CINCTA_SOURCE_REVISION 注入版本，因此日志可能包含git找不到仓库的诊断；该诊断不影响显式版本和内容指纹。最终静态包的SOURCE_SHA256提供来源清单。源码目录、二进制构建目录和镜像路径不同会导致debug信息/源码fingerprint不同；真实被测C源码已按清单核对。

具体范围、统计和发布限制见 ../docs/validation.md。未保存的开发轮次不计入最终统计；早期失败及修复背景在进度/审查文档中说明。
