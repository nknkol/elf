# FD 身份与只读策略实施顺序

状态：FD 元数据核心已实现并独立测试，运行时接入及权限执行仍未实现。先解决对象身份，再连接策略；
当前 root/bind 只提供路径映射，agent JSON 只生成计划。

## 当前实现与缺口

`proot_bridge.c` 对目录 FD 使用宿主 `/proc/self/fd/N` 获取路径，再反向映射。
最近加入往返校验：反向得到的 guest 路径必须正向映射回原宿主路径，否则返回 EXDEV。
这阻止了目录移动到 bind 遮盖区域后误访问另一个目录，但不等价于 Linux 的挂载/FD 语义。

普通 read/write 和文件偏移由内核处理。fchmod/fchown/ftruncate 等也是直接作用于内核 FD。
当前没有保存 FD 的来源挂载、访问策略或继承状态，所以不能仅通过 openat 的写入标志
检查提供只读保证。不能将宿主路径或 dev/ino 单独当成挂载身份：同一文件可由不同权限的
bind 打开，已打开的 FD 也可能在重命名、删除后继续有效。

## 已完成：独立元数据核心

`src/payload/include/fd_table.h` 与 `src/payload/logic/fd_table.c` 提供由调用方持有的
稀疏 FD 表，不分配内存，不调用 syscall。容量限制元数据条目数，而不是 FD 编号大小。
保存来源挂载及访问标签、描述符 CLOEXEC、编号分配代次和打开描述身份。
不同 open 获得不同身份，dup 保留来源身份；未知来源覆盖目标时清除旧权限。
访问标签是策略来源信息，不代替内核 O_ACCMODE 或一次实际权限判定。

支持成功 open/dup/setfd/close/range 事件、复制表快照和 exec 的 CLOEXEC 清理。
容量不足返回 ENOSPC、代次溢出返回 EOVERFLOW，错误不修改原状态。
返回记录指针只在调用方保持独占访问且没有修改表时有效；代次只描述 FD 分配生命周期，
不替代同步。跨 fork 分支的身份编号不是全局唯一，不可合并独立表。
复制目标必须是初始化后未使用的独立存储；CLONE_FILES 必须共享同一张表，而不是复制。

`python3 test/fd_table/run.py` 测试模型边界，并实际运行内核 dup/dup3/fcntl、共享偏移、
fork 与 exec，与模型事件对照。它不是 loader/SVC 集成测试，尚未验证并发操作或
真实 close_range（仅有范围状态转换测试）。`make check` 已纳入这个测试入口。

核心暂不链接到 payload，不存在已启用的权限或 FD 跟踪开关。运行时接入的阻塞点是：
clone 当前在不碰栈的快速路径执行，没有复制/共享 FD 表通知；exec 元数据交接模块尚未连接到 loader；
内嵌 loader 和 payload 内部 FD 也需要区分。不能直接挂一张全局表或简单照搬重入表的
共享映射，否则 fork 独立 FD 表会相互污染。

## 已完成：exec 快照与传输模块

`fd_snapshot.c` 提供带版本、小端、无指针的快照，导出时排除 CLOEXEC 项，不修改原表。
导入时先检查完整长度、容量、FD/代次唯一性、来源标签和共享身份一致性，再发布记录。
失败不修改目标表；保留 serial 避免 exec 后重新使用旧代次。来源缓冲区需不可变且不与
表存储重叠，调用方需提供独占访问。校验采用有界表规模下的 O(n²) 扫描，无额外分配。

`fd_handoff.c` 将快照写入带 WRITE/GROW/SHRINK/SEAL seals 的 memfd，默认 CLOEXEC。
调用方需在计划中的 exec 前显式允许交接 FD 继承，并在失败时关闭它。读取使用有界
pread 和额外字节检测，处理 EINTR/部分传输；无需依赖 fstat。测试中本机 libc fstat
对继承的传输 memfd 返回 EACCES，而 pread 可用。恢复函数不接管 FD 所有权。

独立 harness 使用这两个生产模块完成真实 exec 传输，验证来源、dup 身份、未知来源、
CLOEXEC 排除、失败 exec 原表保持和传输 FD 清理。注入 write/seal/read 错误、EINTR
及短传输验证清理和重试路径。封存仅保证数据不可修改，不证明权限来源可信；不能把
任意 guest 提供的 memfd 当作授权信息。继承 FD 仍需在运行时核对存活性与身份。

这两个模块尚未链接到 loader/payload，CLI 没有新增可接受权限快照的选项。
实际 exec 链还需接入可信交接通道、内部 FD 管理、同步及所有错误出口清理；clone
复制/共享通知也仍待实现。测试通过不表示这些运行时环节已经接通。

## 下一阶段：运行时身份与生命周期接入

引入单独的描述符元数据模块，保存 guest 挂载 ID、访问权限、FD 代次与共享打开描述身份。
元数据不保存文件内容，不模拟文件偏移。来源无法确认的 FD 必须保持 unknown，不能
反向解析失败后默认放行。已有兼容模式保持现有行为；以后策略模式单独定义 unknown 处理。

需要一起覆盖的入口：

| 行为 | 需要维护的状态 | 验证场景 |
| --- | --- | --- |
| openat | 成功后记录所选挂载和权限；失败不发布记录 | 同一宿主目录通过两个 bind 打开 |
| dup/dup3、fcntl 复制 | 新 FD 共享打开描述身份，保留各自 CLOEXEC | 复制、替换目标 FD、编号复用 |
| close/close_range | 移除关闭的条目；区分 CLOEXEC 标记 | 关闭后立即复用、失败与部分范围 |
| fork/clone | 区分复制 FD 表与 CLONE_FILES 共享表 | 父子 close/dup 的可见性 |
| exec | 保留未 CLOEXEC 元数据，移除 CLOEXEC 项 | 链式 loader 交接与失败 exec |
| 启动继承、SCM_RIGHTS | 显式登记或限制未知来源 | stdio、管道、外部文件 FD |

不能持有一个非重入锁跨越任意宿主 syscall：信号回调、阻塞调用、fork 和线程退出都需要
明确协议。检查与操作之间的 close/dup 竞争必须纳入设计；仅在查表时加锁并不足够。
元数据分配失败应在公开新 FD 前回滚，避免返回一个不受策略管理的描述符。

目录 FD 的目标是相对操作继续指向原目录，同时保持 guest 绝对软链与 bind 语义。
不能简单将全部 dirfd 调用透传给宿主，否则绝对软链可能按宿主根解析。
对删除目录、跨挂载和遮盖场景，优先保留当前明确错误，直到相应身份模型通过测试。

## 第二阶段：将只读规则连接到执行层

配置必须在 loader、payload 和 exec 链上保持一致；不认识的策略或超出配置容量时拒绝启动。
按最长 guest 前缀决定挂载，软链解析后检查实际目标。rename/link 需检查两侧。

写权限不仅涉及 openat(O_WRONLY/O_RDWR/O_TRUNC/O_CREAT)，还包括：

- mkdir/unlink/rename/link/symlink/mknod 等目录项修改。
- chmod/chown/utimens/truncate，以及对应 FD 形式和扩展属性操作。
- write/pwrite/writev、sendfile/splice/copy_file_range 的输出 FD、fallocate。
- 可写 MAP_SHARED 映射及后续 mprotect 升权；MAP_PRIVATE 写入不修改后备文件。
- 已继承可写 FD、异步 I/O、ioctl 及未知修改入口的显式策略。

按实际 ABI 清点 syscall，并复用沙盒探测结果；未支持的入口应有明确拒绝规则。
不能重新把所有普通 syscall 无条件放进慢路径：仅在开启策略后扩充分流，保留现有
clone/rt_sigreturn 等入口约束，并对未知接口采用经过设计的策略。

验收必须验证宿主文件内容和元数据未改变，而非只检查 guest 返回的 errno。
加入并发 close/dup、可写继承 FD、两个权限不同的 bind 指向同一宿主文件、exec 后策略继承、
共享映射写入等测试。路径只读测试通过不能替代这些测试。

## 第三阶段：agent 文件视图

连接默认拒绝、只读 brew、可写 workspace 和私有 home/tmp/cache。
补齐为访问已暴露目录所需的祖先目录遍历、目录列表过滤和最小 guest `/proc`。
这些能力与 rootfs 兼容分别验收，不用 Ubuntu/Alpine 启动成功推导隔离完成。

## 性能与安全边界

优先让普通 FD 读操作保持内核直通；只对需要权限判断的操作查询元数据。
不可变挂载表不应每次重建，路径 scratch 可在线程/重入生命周期明确后复用。
先测路径操作与 FD 密集 I/O，再决定缓存，避免缓存失效破坏 rename/软链语义。

路径解析到最终宿主 syscall 仍有竞争窗口；raw syscall 直接入口和同线程重入绕过
仍未解决。完成上述策略功能也不自动解决这些问题。系统沙盒继续作为部署边界，
在绕过和竞争问题闭环前，不宣称可隔离恶意 guest。
