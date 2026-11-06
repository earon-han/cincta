# 原始验证证据

2026-11-06本地实测，最终业务源码提交 `238c008`；两份 tested-*-source-sha256.txt 已与仓库逐文件校验一致。JSON及.log为实际运行输出，没有把跳过项目转换为通过。

- linux-vm / docker-compat：Lima jiuwen-lite，Ubuntu24.04，Linux6.8，aarch64，ABI4。
- linux-vm-strict / docker-strict：独立Lima cincta-verify，Ubuntu26.04，Linux7.0，aarch64，ABI8。
- 两台Docker均29.1.3，非root tester、cap_drop ALL、no-new-privileges、docker-default AppArmor及builtin seccomp；安全配置和daemon选项单独留档。
- scratch-*.log：静态二进制作为无libc scratch容器PID1执行受限的自身 --version，兼容/严格分别通过。
- benchmark/concurrent.json：每组100条sandbox样本、100条直接执行基线；保留外部wall时间、真实phase_ms、失败数、源码指纹和二进制SHA256。VM并发为8路。

无Git目录的导出源码构建以 CINCTA_SOURCE_REVISION 注入版本，因此日志可能包含git找不到仓库的诊断；该诊断不影响显式版本和内容指纹。最终静态包的SOURCE_SHA256提供来源清单。源码目录、二进制构建目录和镜像路径不同会导致debug信息/源码fingerprint不同；真实被测C源码已按清单核对。

具体范围、统计和发布限制见 ../docs/validation.md。未保存的开发轮次不计入最终统计；早期失败及修复背景在进度/审查文档中说明。
