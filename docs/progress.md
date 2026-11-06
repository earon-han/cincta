# 实施任务台账

任务来源：[实施计划](../实施计划.txt)。首版范围按 design.md 冻结为静态策略 CLI，动态代理能力单列后续版本。状态仅使用待办、进行中、受阻、完成。

| ID | 状态 | 交付物 / 验证 | 关联提交 | 阻断 / 下一步 |
|---|---|---|---|---|
| B00 | 完成 | design.md 范围与排除项 | B00–B03设计提交 | 无 |
| B01 | 完成 | README、AGENTS、LICENSE、模板、Makefile、CI | B04–B08实现提交 | 无 |
| B02 | 完成 | research.md 固定Sandlock源码SHA/许可证、官方UAPI研究 | B00–B03设计提交 | 无 |
| B03 | 完成 | design/dependencies/security-review，独立审查并修正 | B00–B03设计提交 | 无 |
| B04 | 完成 | probe真实安装原语；Linux6.8 ABI4通过，严格拒绝执行 | B04–B08实现提交 | 新内核严格实测见报告 |
| B05 | 完成 | C17 CLI、参数/策略验证、版本、JSON、错误码 | B04–B08实现提交 | 无 |
| B06 | 完成 | Landlock+BPF安装后握手才exec；实际正反/故障注入 | B04–B08实现提交 | 无 |
| B07 | 完成 | none/host IP网络、IPC、权限、资源边界 | B04–B08实现提交 | 不包含动态代理 |
| B08 | 完成 | pidfd caller、双subreaper、timeout/cancel/异常回收、Agent示例 | B04–B08实现提交 | 两层同时强杀/内核D状态属边界 |
| B09 | 完成 | 预览aarch64：两内核/四环境474 PASS、0FAIL、2BLOCKED；故障与回收验证 | 238c008 + B09–B11证据提交 | x86原生和稳定版门槛另列，不冒充已验证 |
| B10 | 完成 | 6组原始benchmark共600次sandbox、8路并发、静态包、CI配置 | B09–B11证据提交 | CI尚未远端运行；p95约23–24ms，无失败 |
| B11 | 受阻 | 本地0.1.0-preview.1静态aarch64包、源码包、来源清单与SHA256 | B09–B11证据提交 | 自动审批拒绝推送；等待用户明确批准GitHub目的地 |

分工：根Agent负责整合、CLI/生命周期、Linux/Docker实测和交付；kernel_security负责内核实现及生命周期交叉审查；security_design负责独立设计、固定版本研究和安全审查；tests_release负责独立对抗测试、故障注入、构建/打包/CI。各自独占文件，发现跨模块问题后由所有者修复。

关联提交：设计699ac1d，内核/CLI/测试bfb6300，无隐式shell与导出打包018750f，PID1兼容238c008；证据提交可通过 `git log --grep B09-B11` 定位（避免文档自引用提交哈希）。

检查点：设计可实施已完成；CLI功能完整已完成；本地预览交付可审查，远端发布受阻。稳定版要求x86_64/aarch64原生严格验证、外部安全审计和更广内核矩阵，本次不提前宣称。
