# 实施任务台账

原始需求：[实施计划](../实施计划.txt)。扩展计划：[v0.2逐项实施计划](implementation-plan-v02.md)。状态只使用待办、进行中、受阻、完成；本页区分实现、自验证、独立验收和最终交付，不把旧证据当新版本通过。

## v0.2 当前进度

| ID | 状态 | 已有交付 / 验证 | 提交 / 证据 | 阻断与下一步 |
|---|---|---|---|---|
| P1 | 进行中 | 详细计划、CLI/结果扩展、独立威胁模型与审查；模块接口已落盘 | 0732842；v02-design-review.md | 最终组合源码复核和文档同步 |
| P2 | 进行中 | VM实际通知/ADDFD、定向Yama、cgroup委派机制已运行；x86全系统环境在建 | 各模块开发报告 | 完成默认Docker、最小委派Docker和最终x86镜像实测 |
| P3 | 进行中 | 独立broker、固定policy FD、metadata代执行、file-open worker和引导锁定已实现 | src/security.c、broker.c、filebroker.c | 最终组合回归与故障收尾复核 |
| P4 | 进行中 | TCP/UDP/CIDR/端口/DNS快照、复制后代执行及24项专门网络测试 | network.c；network_test.py | 最新投递审计补丁后重跑VM/Docker |
| P5 | 进行中 | 真实业务树cgroup配额和事件驱动monitor已实现，VM资源9项通过 | resources.c；resources_test.py | 最小委派Docker正例、默认Docker负例和最终统计 |
| P6 | 进行中 | 双副本、diff/export/discard、链接与别名限制已实现；独立模块17项通过 | workspace.c；workspace_test.py | 最终CLI/故障/容器复验，不把物理快照叫透明COW |
| P7 | 进行中 | 请求/实际结果/FD交付事件、额度/pending检测、新结果对象及Agent示例 | result.c；broker.c；audit.md | 审计覆盖/失败/上限与最终示例复验 |
| P8 | 进行中 | 独立跨模块36项、文件审计18项开发轮VM通过；legacy83项通过且旧ABI严格执行BLOCKED | reports/v02-*开发记录 | 最终同版本全套VM/Docker、压力/性能、x86全系统验证 |
| P9.1 | 进行中 | v0.2文档、统一测试/验证脚本、CI及打包入口已更新 | test_all.sh；Makefile；CI；各指南 | 按最终受测提交打包/校验并更新validation实际数字 |
| P9.2 | 受阻 | 本地分支/提交可审查 | codex/v02-full-sandbox | 此前自动审批拒绝GitHub外发；等待明确目的地批准，不重复尝试 |

上表模块开发结果只表示相应快照的自验证/独立测试。最终发行数字、受测源码指纹、镜像配置与重复样本统一在 [validation.md](validation.md)；代码更新后必须重跑相关套件，不能相加旧轮次来宣称全功能通过。x86的全系统TCG结果应与aarch64和硬件原生明确分开。

分工：根Agent负责公共契约、CLI/生命周期/审计整合、环境与最终交付；v02_design_review独立威胁模型及安全复审；v02_network网络实现/专测；v02_workspace_tests快照模块及后续独立跨模块验收；v02_cgroup资源实现/专测；v02_file_audit文件打开实际结果代理与专测；v02_x86_validation全系统目标内核验证；v02_docs_release文档、总验证入口和CI。各自独占文件并交叉复核，自测不替代独立验收。

验收门槛：请求保护不能建立即拒绝执行；VM和Docker分别保留PASS/FAIL/BLOCKED；默认无委派容器与委派正例分开；审计不把请求当完成；快照不自动写回；清理必须wait到无后代；未执行的远端CI、外部审计或硬件平台不计通过。

## v0.1 历史记录（不作为v0.2验收）


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
