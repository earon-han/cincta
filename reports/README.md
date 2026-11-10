# 验证报告

Git只保存本说明和经过整理的[v0.2历史验证摘要](v02-summary.json)。摘要记录2026-11-07受测源码、环境、计数、产物指纹和性能统计，不包含测试进程号、临时目录、原始业务输出或开发过程日志，也不等于对以后每次检出的重新验收。

原始报告与开发日志保留为本地文件，受`.gitignore`排除，不进入默认分发包。运行验证时生成新的报告目录：

```sh
sh scripts/validate.sh linux-vm
# 或者指定一个新的报告位置
CINCTA_REPORT_DIR=/tmp/cincta-report-new make test-all TEST_LABEL=linux-vm
```

需要复核时单独保存本次报告目录及其源码/二进制指纹。CI将运行报告作为独立工件上传；工作流文件存在不表示某次远端CI已经执行。共享报告前应检查命令、环境、路径和审计目标中是否包含敏感信息。

默认Docker的无委派负例、显式cgroup委派正例、挂载夹具正例与全系统QEMU应分开标注。只统计实际执行的PASS/FAIL/BLOCKED，具体条件见[验证说明](../docs/validation.md)。
