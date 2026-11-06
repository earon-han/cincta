# 工作区快照、变更查看与导出

`--workspace SOURCE` 把一个现有目录复制到私有工作区，业务的工作目录和可写授权指向该副本。原目录不作写入目标。该功能使用用户态物理快照，不要求 mount、overlayfs、user namespace、root 或外部文件工具；它提供隔离写入/丢弃语义，不宣称是按需分配的内核 overlay COW。

## 数据与生命周期

准备阶段由可信guardian在 `--workspace-parent DIR`（默认 `/tmp`）先创建并固定0700专属容器，再在其中创建工作区私有根，包含两棵**独立**文件树：

```text
cincta-preparation-XXXXXX/
    cincta-workspace-XXXXXX/
        baseline/  启动时快照，只供可信监管者计算差异
        tree/      业务cwd及rw授权，只在这里运行
```

完整复制两次可避免工作副本的写入通过共享 inode 污染 baseline。原有硬链接逐路径复制为独立普通文件，不保留硬链接身份关系。准备期间按文件大小及mtime/ctime检查源对象是否变化；这不是跨整个目录的原子文件系统快照。调用方应在准备期间保持源工作区静止，并为并发运行提供各自的快照。

默认每棵树最多100000个条目、普通文件总大小1GiB；可用 `--workspace-max-files`、`--workspace-max-bytes` 指定上限。目录、符号链接也计入条目数，源根本身不计数；copied_bytes为源普通文件大小之和，每条硬链接路径分别计数，copied_files为条目数，均只报告一棵启动快照的计量，不将baseline/tree两次复制相加。最大嵌套128层。完整快照及工作树约占两倍源数据，导出还需额外一份空间。该限制覆盖准备和最终检查/导出，不是业务运行中的磁盘配额；运行时磁盘硬限制需外层磁盘配额。

仅在业务及全部后代已真正回收后计算diff或导出。如果进程清理不完整，不得发布一个仍可被业务修改的导出结果。`--workspace-keep` 保留私有根及外层0700容器供审查，默认在成功完成diff/导出后丢弃并删除空容器。完成阶段出错时保留快照并报告 `retained=true`，便于检查和恢复，不自动覆盖原目录。调用方审查完keep快照后可删除其专属外层容器；不能只删inner根后把空容器误认成产品自动清理失败。

复制、DNS解析和cgroup准备不在 `--timeout-ms` 执行预算内；执行结束后的diff/export也不受该timer限制。准备耗时加入setup/elapsed统计，完成阶段耗时包含在elapsed中，当前phase_ms未单列diff/export时间。CLI在复制中取消/死亡时的回收与READY之前guardian自身故障的边界见[preparation.md](preparation.md)，不承诺底层阻塞I/O的端到端硬超时。

## 在快照中编译和运行

默认工作树只有rw，不能直接exec其中的二进制。显式 `--workspace-exec` 会给同一工作树再加rx，结果workspace.executable=true；未指定为false。运行解释器读取脚本仍属于显式runtime授权，因此默认禁止直接exec不是代码来源认证。

编译器、链接器、头文件和内部工具也必须显式授权。例如Ubuntu的非沙箱侧准备一个包含hello.c的SOURCE，再运行：

```sh
cincta run --workspace /absolute/SOURCE --workspace-exec --metadata \
  --rx /usr/bin --rx /usr/lib --ro /usr/include --env TMPDIR=. -- \
  /bin/sh -c 'cc hello.c -o hello && ./hello'
```

编译器若把cc1等程序安装在 `/usr/libexec`，还须显式加 `--rx /usr/libexec`；其他发行版按实际安装目录授权。`TMPDIR=.`让编译临时文件进入工作副本。`--metadata`用于允许快照内的安全chmod等操作，额外要求可用的 `fchmodat2(AT_EMPTY_PATH)`（Linux6.6起，仍以启动探测为准）；缺少能力时拒绝，不降低为路径检查后CONTINUE。

## 变更与导出

- `--workspace-diff PATH`：独占新建JSON差异文件，记录added/deleted/modified、相对路径、前后类型、大小、权限及符号链接目标；内容比较能发现大小和mtime未变的字节修改。目录mtime变化也计入差异。
- `--workspace-export DIR`：独占新建目录，复制**完整最终树**，适合后续检查或交给调用方处理；不是自动应用补丁。
- 不提供自动写回原目录；调用方审查导出后另行决定如何应用。默认discard就是回滚本次沙箱产生的工作区改动。
- diff及export的路径必须在原目录和私有快照之外，且最终组件不存在；不会覆盖任何已有文件/目录/符号链接。

同一次finish中的导出与diff不是跨目录原子事务：若导出已完成而随后diff写入失败，结果会保留导出和私有快照，并明确报告失败。调用方应以结果文件的完成状态判断，不以某个路径已经出现判断整个任务成功。

## 路径安全与兼容性

目录遍历和文件复制使用相对目录FD、`O_NOFOLLOW`、`fstat`身份校验，避免复制期间跟随被替换的符号链接。已存在的内部相对符号链接可保留；除了词法边界检查，还通过 `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` 对完整链接链解析，防止中间链接改变后续`..`的含义。绝对链接、越界链接、dangling链接、链接循环均拒绝。任务结束时再次验证链接，避免业务新建的外部链接被导出。

FIFO、socket、设备等特殊文件拒绝；不读取其内容以避免阻塞或向外部通道泄露数据。普通文件/目录只复制低9位权限和时间戳；不复制所有者、setuid/setgid/sticky、ACL、扩展属性、capabilities或特殊inode标志。文件名和链接目标须为有效UTF-8，以保证结构化差异是合法JSON。

workspace模式拒绝任何额外 `--rw`，只有生成的工作树可写；其他显式ro/rx也不能覆盖原目录或其祖先/后代，不能暴露私有baseline和外层快照。可写普通文件stdio同样拒绝，避免调用方的硬链接别名把写能力带回源目录；业务输出请使用pipe等流。`--workspace` 与自定义 `--cwd` 不能同时使用。结果、审计、diff、export等输出必须位于业务不可写的可信父目录，CLI对已固定授权根还核对祖先对象身份和mount边界，不只依赖路径字符串或realpath。

CLI在创建guardian容器前读取真实 `/proc/self/mountinfo`，拒绝SOURCE内部的子mount，避免源目录中的bind/mount别名把看似无关的导出父目录带回原目录视图。SOURCE根本身就是mount允许；workspace-parent如果经另一条bind路径实际落在源目录内，祖先device/inode检查同样拒绝。挂载元数据不可读或布局不能确认时失败关闭。其他可信主机进程在准备/执行期间主动改变mount布局不属于不可变授权前提。

清理不跟随业务留下的链接；只操作经device/inode核对的私有根。业务把自己创建的目录权限改为000时，可信清理器通过固定的O_PATH目录描述符恢复必要权限再删除，依赖真实 `/proc/self/fd`。这不会按攻击者提供的链接目标执行chmod。

## 外部依赖与结果

需要Linux普通文件系统、足够空间、真实可读procfs、Linux 5.6起的`openat2`和容器外层策略对该调用的允许；本项目最低支持内核已包含该接口。外层禁用openat2且输入含链接时准备失败，不会跳过链接检查。

执行结果的 `workspace` 对象包含enabled、source/tree/root、copied_files/copied_bytes、changes、retained、exported和executable。私有根可能在任务完成后已删除，路径用于说明实际执行位置和关联审计，不代表仍然存在。result文件在授权根身份与mount/布局安全检查通过后才创建，因此较早的布局/规则配置失败只有stderr和退出125，不能假设一定存在JSON。
