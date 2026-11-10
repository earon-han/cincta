# v0.2审查修复台账

候选`c6a2ef5`完成本地验收后进行了独立源码审查。初轮三项由集成人员独立复现认可；各项讨论、修复、交叉复核与功能验证分开完成，兼容补充F4同样复核。最终产品/测试冻结`eebc770`；以下结论针对该修复版。

| 编号 | 确认与讨论结论 | 修改位置 | 回归与状态 |
|---|---|---|---|
| F1 / P1 | 准备期原caller退出仍执行业务确属生命周期缺陷；固定原TGID pidfd贯穿准备和运行，guardian先终止CLI并等退出再清理；不使用线程语义的PDEATHSIG替代 | `src/caller.c`、`src/main.c`、`src/preparation.c`、`src/supervisor.c` | `tests/preparation_test.py`覆盖自然退出、暂停CLI、DNS-only和buffered D竞争；四主环境各15项准备测试通过，既有caller/thread回归通过。关闭 |
| F2 / P2 | 源根0755、导出0700而diff为0违反契约；以`.`记录根变化且不增加复制预算 | `src/workspace.c` | `tests/workspace_test.py`模块21项及`tests/v02_integration.py`根chmod/mtime/不变回归在最终四环境通过。关闭 |
| F3 / P2 | 4095字节fchmod返回成功但权限仍0600确属错误；合法边界应支持，截满及零errno失败应明确返回错误 | `src/broker.c` | `tests/metadata_path_boundary.c`与`tests/v02_integration.py`核对4094/4095成功及4096拒绝，同时验证实际权限与审计，最终四环境12个边界检查通过。关闭 |
| F4 / 兼容性 | 无可见parent不限PID1；兼容隐藏parent，但明确不能绑定其生命周期 | `src/caller.c`、`src/result.c` | `tests/docker_exec_test.py`在两内核默认安全Docker中各3项通过：正常exec、SIGTERM取消、实际payload回收。关闭 |

以上四项均已修复、独立复核和功能验证，无未解分歧。该冻结版整体1144 PASS / 0 FAIL / 40条件BLOCKED，统计与边界见[验证说明](validation.md)。完整内部开发记录保留本地；正式审查结论见[最终源码审查](final-code-review.md)。
