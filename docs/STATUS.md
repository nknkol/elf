# 当前进度与验收快照

核查日期：2026-10-28。最近完整核查基线：`105e8c2`，分支 `feat/proot-svc-bridge`。
完整核查补充 SIGSYS 扫描记录与运行时回归的逐项核对，并纠正文档的过期接入状态。
后续更新：绝对路径及已知目录 FD 相对 open 的挂载来源已接入实验 FD 表；
同源别名的嵌套挂载视图已测；cwd 已接 chdir/fchdir/getcwd 与相对 open，
fork/vfork 原生对照及 exec 降级通过。现有 PRoot 路径 handlers 也已接每次调用
上下文，rename/link 两端分别取来源。exec 目标/解释器与受限 BENEATH 也已接来源
观察值，七个执行标记用例通过。两套回归继续通过。
最新增量新增独立 [存储能力探测](STORAGE_CAPABILITIES.md)，实测三个 backing 并通过
19 项规划器/探测测试。2026-10-29 增量：规划器通过现有祖先的设备号/inode
检查私有 state 与暴露目录的大小写别名重叠，允许尚未创建的 state 尾路径，
检查失败则拒绝；本机 home 别名与大小写敏感目录对照均通过，共 22 项测试。
这只是规划时快照，不解决运行时路径竞争或所有 bind 别名。
没有修改 ELF 运行时，这两次增量未重复构建两套 ELF。
2026-10-29 后续增量：新增独立 C 权限判定核心，按挂载编号处理 deny/ro/rw、
未知来源拒绝、双路径修改与 EXDEV，并与真实 PRoot 挂载选择器联合测试通过。
已纳入 `make check`，但尚未链接 payload 或接入 syscall，不能算运行时隔离完成。
本次仅运行该核心测试、路径核心回归和 22 项 Python 测试，未重建 ELF。
环境为当前 HarmonyOS AArch64 终端沙盒；以下结果不能直接外推到其他系统。

**已可运行受限的 Linux rootfs 工作流；尚未具备 agent 文件访问隔离。**
主要缺口是挂载/FD 权限来源与执行策略，而不是文件内容的用户态实现。
路径映射、元数据与策略应保持轻量，内容读写、偏移和实际 FD 仍交给内核。

## 两个构建的区别

| 能力 | 默认 `elfloader-proot` | `elfloader-proot-fd-experiment` |
| --- | --- | --- |
| root/bind、路径翻译、动态 ELF/exec | 已接入并有回归 | 已接入并有回归 |
| FD 元数据 | 未启用 | 常用创建/dup/关闭、CLOEXEC、SCM_RIGHTS 已接入；最多 128 条 |
| fork/vfork/exec 的 FD 状态 | 不跟踪 FD 元数据 | 私有 fork、单层受限 vfork、exec 快照交接通过；普通线程/共享 VM 及嵌套 vfork 不支持 |
| 同线程嵌套慢调用 | 保留重入透传 | 返回 EDEADLK；非拥有者任务拒绝 |
| openat2 | HarmonyOS 返回 ENOSYS | 24 字节 how、O_PATH\|O_NOFOLLOW 子集；resolve=0 经 PRoot，BENEATH 仅单分量及受限尾斜杠 |
| 已确认危险 syscall | 公共 guard 返回 ENOSYS | 同一公共 guard 加实验拒绝项 |
| 挂载来源与只读/默认拒绝 | 未实现 | 绝对/已知目录 FD/cwd 相对 open 已记录 mount/可写配置标签；未知来源及 exec 恢复仍 UNKNOWN，无权限执行 |
| agent JSON 配置 | 只输出计划 | 同样未连接执行层 |

`src/elfloader` 是最后一次构建的产物，不能用它的名称判断启用了哪种能力。
应使用上述两个具名快照及各自 manifest；两种构建不能并发编译，共用中间产物。

## 本轮测试结果

| 入口 | 本轮结果 | 范围与限制 |
| --- | --- | --- |
| `make check` | 通过 | 路径、exec/auxv、模型与 clone、ABI/路由、重入、运行时 guard、配置/解包单测 |
| `make check-fd-runtime` | 通过 | 实际补丁 SVC、FD 生命周期、错误路径、shell 与文件工作流；不等于权限测试 |
| `python3 test/alpine/run.py ../alpine-minirootfs-3.24.3-aarch64.tar.gz` | 18/18 | 默认构建，离线验收 |
| `python3 test/ubuntu/run.py ../ubuntu-base-26.04.1-base-arm64.tar.gz` | 18/18 | 默认构建，离线验收；归档硬链接按副本展开 |
| FD 实验中的 rootfs 工作流 | 24 个文件用例、12 个 shell 用例通过 | 两套 rootfs；包含相对/绝对路径打包、gzip、符号链接、简单/嵌套解包 |
| 硬链接打包 fixture | 2 项明确 SKIP | 宿主原生创建硬链接被拒绝，不算成功 |
| 新增 census 核对 | 两种 loader 逐项核对已记录 SIGSYS 编号 | 扫描记录新增危险调用但运行时探针遗漏时，测试会失败 |

`make check` 不含 FD 实验工作流；两套都通过才能支持上表结论。
构建与离线验收报告位于忽略目录 `vendor/proot/svc/build/`；不提交二进制或 rootfs。
当前全量扫描记录是 98 个参数配方、13 个不同 SIGSYS 编号，不是所有 syscall 的证明。
共享慢路径 134 项表示“进入处理器”，不能作为“实现 134 项”的完成率。
固定危险调用回归另包含 fchmodat2，共 14 项；close_range 有单独的拒绝/回退测试。
原生配方、支持子集和错误路径都需分别看待，不能把 ENOSYS 算作功能实现。

## 尚未完成的验收门槛

1. **agent 权限执行**：配置只规划不运行；所有 bind 仍可写。绝对/已知目录 FD/cwd 相对打开已有
   mount/access 观察值，但未知 cwd/目录 FD、导入和 exec 恢复仍 UNKNOWN；尚无可信来源链、
   只读执行或默认拒绝。
2. **完整 FD/任务语义**：普通线程与共享 VM/FD、通用 clone、close_range 真正实现、
   更多 ioctl/辅助消息 FD 通道仍有缺口。不能把 128 条元数据表视作全部内核 FD。
3. **路径与挂载语义**：目录 FD 仍经 `/proc/self/fd` 反向路径映射；往返检查可拒绝
   一些覆盖歧义，但不等于保留完整挂载身份。重命名竞争、完整 `/proc`、多分量
   BENEATH、通用 xattr/ACL 等尚未完成，普通模式与实验模式的能力也未统一。
4. **恶意 guest 边界**：默认重入透传、raw 入口、可写代码/别名、用户指针读取、
   内部 FD 与可信 exec 交接等需要完整审计。封存快照只保证不可修改，不证明来源可信。
   现有回归不能替代对抗验收。
5. **完整应用兼容**：未完成包管理器联网安装、实际 agent/brew 工具链、通用线程程序
   与端到端性能基准。xz/bzip2 缺失是镜像依赖问题，不自动归因于 syscall。

## 下一步顺序与验收标准

1. **先落地最小挂载身份和只读来源模型**：绝对路径的解析来源已交给 FD 表，
   目录 FD/cwd、现有 PRoot 路径操作及 exec/BENEATH 已接观察值；下一步处理可信来源链、未知来源和只读配置边界。继承、SCM_RIGHTS
   和 exec 当前保守清除/保留 UNKNOWN。后续验证同一宿主文件
   经 ro/rw 两个 bind 打开时不会合并权限，并覆盖 dup、改名和 exec。
2. **再接入受限策略执行**：选择明确的单线程进程支持范围；同时覆盖路径写入、
   FD 写入、截断、共享可写映射、splice/copy 等写入通道。支持范围之外拒绝，不能
   只检查 open 的 O_WRONLY 就宣布只读完成；配置规划器在此之前仍标记 not-connected。
3. **随后扩展兼容与性能**：按实际 agent/brew 工作流处理 /proc、线程和缺失调用，
   对照原生测试；基准区分路径解析成本与普通 FD IO 成本，不将所有内容操作改成 VFS。

核查及后续来源接入均未启用只读权限。兼容性基线、来源观察值和危险调用回归，
不能替代权限执行及对抗验收。
