# 实施任务台账

原始需求：[实施计划](../实施计划.txt)。扩展计划：[v0.2逐项实施计划](implementation-plan-v02.md)。状态只使用待办、进行中、受阻、完成；本页区分实现、自验证、独立验收和最终交付，不把旧证据当新版本通过。

## v0.2 当前进度

| ID | 状态 | 已有交付 / 验证 | 提交 / 证据 | 阻断与下一步 |
|---|---|---|---|---|
| P1 | 完成 | C17/CLI/结果协议、威胁模型及交叉审查 | eebc770；v02-design-review.md、final-code-review.md | 无已知源码冻结阻断 |
| P2 | 完成 | 两真实VM/两默认Docker、祖先mem RPC、ADDFD、cgroup最小委派、x86全系统 | reports/v02-*最终证据 | 明确区分部署条件与默认环境 |
| P3 | 完成 | broker、固定policy/内存FD、metadata、file-open代理、锁定与错误收尾 | eebc770；file-audit20项 | 范围与兼容拒绝已文档化 |
| P4 | 完成 | TCP/UDP、IPv4/IPv6、CIDR/端口/DNS快照；26项专测 | 四环境network.json | 域名是地址能力，不是应用层身份 |
| P5 | 完成 | 真实cgroup树配额、统计/清理与事件驱动生命周期 | VM及最小委派Docker各9项 | 默认无委派正例仍BLOCKED |
| P6 | 完成 | 物理双副本、diff/export/discard/keep、构建执行与别名隔离 | workspace17项、独立49项、别名12项 | 无自动写回/透明COW承诺 |
| P7 | 完成 | 审计结果/交付/预算/完整性、JSON与Agent示例 | broker/result、使用及审计指南 | 外层早拒绝不可观测如实BLOCKED |
| P8 | 完成 | 主1144 PASS/0FAIL/40条件BLOCKED；400组合、800启动样本 | reports/v02-summary.json；validation.md | 额外重复、artifact验证和共享负载单列 |
| P9.1 | 完成 | 两架构静态原件、元信息13项、scratch5项及文档齐备 | package.sh；两产物SHA | 两架构包/源码包与来源校验；候选完成后进入P10 |
| P9.2 | 受阻 | 本地分支与提交可审查 | codex/v02-full-sandbox | 自动审批拒绝GitHub目的地外发，未重复尝试 |
| P10 | 完成 | 新Agent审查F1–F4经主Agent确认/讨论、分工修复、独立复核及最终重验 | eebc770；final-code-review.md；修复台账 | 无未关闭意见；最终归档校验 |

上表模块开发结果只表示相应快照的自验证/独立测试。最终发行数字、受测源码指纹、镜像配置与重复样本统一在 [validation.md](validation.md)；代码更新后必须重跑相关套件，不能相加旧轮次来宣称全功能通过。x86的全系统TCG结果应与aarch64和硬件原生明确分开。

分工：根Agent负责公共契约、CLI/生命周期/审计整合、环境与最终交付；v02_design_review独立威胁模型及安全复审；final_code_review与两位全新子审查者执行P10、实现者分工修复；v02_network网络实现/专测；v02_workspace_tests快照模块及后续独立跨模块验收；v02_cgroup资源实现/专测；v02_file_audit文件打开实际结果代理与专测；v02_x86_validation全系统目标内核验证；v02_docs_release文档、总验证入口和CI。各自独占文件并交叉复核，自测不替代独立验收。

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
