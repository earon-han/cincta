# P10 最终代码审查与修复台账

用户要求：本地实现、文档、双环境验收及交付候选完成后，启动全新的代码审查Agent，主Agent逐条核验、讨论，认可问题后修复并验证。候选c6a2ef5的双架构包/源码包和校验完成后，已启动final_code_review及两位全新只读模块审查者；原始意见见[final-code-review.md](final-code-review.md)。初轮三项均被主Agent独立复现认可，没有以既有PASS否定新证据。

| 编号 | 证据与主Agent确认 | 讨论与最终修改结论 | 已实施修改 | 功能验证 |
|---|---|---|---|---|
| F1 / P1 | 主Agent用原候选复跑：原caller自然退出，CLI仍退出0、status=ok、实际写PAYLOAD_EXECUTED；419ms。[原始输出](../reports/v02-review-root-confirm/F1.json) | 认可生命周期缺陷，与准备不计timeout无关；与审查Agent讨论固定原TGID pidfd、guardian先停CLI再清理、D/ACK/G复核及DNS-only路径；双方一致采用pidfd而非按创建线程生效的PDEATHSIG | main准备前捕获原caller；guardian监视其死亡、固定CLI pidfd终止并等退出后清理；CLI/monitor/payload启动屏障及运行检查同一身份；broker/payload关闭FD；无WS/cgroup的DNS同样守护，空容器在D前清理 | 新增自然caller退出、stoppedCLI、DNS-only、caller死亡优先bufferedD；最终四环境preparation各15项、caller/thread及CLI/monitor生命周期全PASS；修复源码eebc，x8634项通过，F1关闭 |
| F2 / P2 | 主Agent复跑原候选：diff.count=0，源0755/导出0700。[原始输出](../reports/v02-review-root-confirm/F2.json) | 认可公开diff契约缺陷；以`.`记录根变化，复制量与预算仍排除根；独立审查者复核实现 | manifest收集根权限和mtime，统一差异比较；新增root chmod、mtime、不变及精确预算回归 | 模块21项分别VM/Docker通过，CLI3项通过，reports/v02-review-F2-*；最终四环境模块各21项、CLI根3项均通过，F2关闭 |
| F3 / P2 | 主Agent复跑原候选：pathlen4095、fchmod返回0、mode仍0600。[原始输出](../reports/v02-review-root-confirm/F3.txt) | 认可返回值与审计真实性缺陷；与实现/审查Agent讨论后选择完整buffer读取，支持合法4095字节而非简单拒绝；双方认可，截满明确ENAMETOOLONG且错误分支防御errno0 | readlink使用完整buffer、仅n<size补NUL；metadata失败零errno转EIO；新增4094/4095/4096边界，payload fstat与父driver dirfd stat双侧核验 | 隔离VM52PASS、默认Docker51PASS+1既有观察BLOCKED，F3专项两环境6PASS；reports/v02-review-f3；最终四环境12个边界全部通过，F3关闭 |
| F4 / 兼容性补充 | 主Agent检查46d后发现parent0仅限PID1可能误拒；独立审查者在默认安全Docker实测docker exec为PID7/PPID0；主Agent修复后实际exec与signal取消3PASS。[原始报告](../reports/v02-docker-exec-linux68.json) | 双方讨论确认PID namespace隐藏parent不限PID1，恢复旧版任意ppid0不绑定语义；其他身份错误仍fail closed | caller_capture接受任意parent0；结果新增protections.caller_bound与明确unsupported原因，文档按实际能力描述；新增host Docker exec功能回归 | 默认profile/nonroot/capdrop/NNP下直接exec成功、SIGTERM取消和实际payload回收3PASS；最终artifact两内核各3PASS，另一报告v02-docker-exec-linux70.json，F4关闭 |

没有尚未讨论的分歧。修复分工：主Agent处理F1和集成，fix_workspace_root处理F2，fix_metadata_path处理F3；final_code_review及原发现者独立复核，未由实现者自评替代。三项初始问题及兼容补充均已修复、独立复核及最终功能验证通过，无未解意见或分歧。最终冻结eebc770；1144 PASS/0FAIL/40条件BLOCKED，400组合与800基本执行无失败。归档按最终文档提交重新生成并校验。
