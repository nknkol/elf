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
复制目标必须是初始化后未使用的独立存储；实际共享内核 FD 表时应使用同一张表，而不是复制。
不能仅按 CLONE_FILES 推断本机行为，见下方 clone 实测。

`python3 test/fd_table/run.py` 测试模型边界，并实际运行内核 dup/dup3/fcntl、共享偏移、
fork 与 exec，与模型事件对照。它不是 loader/SVC 集成测试，尚未验证并发操作或
真实 close_range（仅有范围状态转换测试）。`make check` 已纳入这个测试入口。

核心暂不链接到 payload，不存在已启用的权限或 FD 跟踪开关。运行时接入的阻塞点是：
clone 专用通知入口已接通，但尚未连接 FD 快照/登记；exec 元数据交接模块尚未连接到 loader；
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
通知已运行，但复制/共享 FD 表登记仍待实现。测试通过不表示这些运行时环节已经接通。

## 本机 clone 语义实测（2026-10-25）

`test/fd_table/check_clone.py` 通过普通 SVC，分别直接运行和经 ELF loader 运行六种组合。
子线程/进程修改 FD 后通过共享内存和 futex 握手，在它退出之前检查关闭、F_SETFD 和
新增 FD 是否可见；同时检查共享打开描述的偏移、VM 标记和 PID。子任务使用独立栈，
线程用 exit 而不是 exit_group，并通过 CHILD_CLEARTID 等待退出。

| 请求 | 本机观察的 FD 表 | VM | 与 CLONE_FILES 预期一致 |
| --- | --- | --- | --- |
| 普通 fork 式 clone | 复制 | 复制 | 是 |
| CLONE_FILES，无 CLONE_VM/THREAD | 复制 | 复制 | 否 |
| CLONE_VM，无 CLONE_FILES/THREAD | 复制 | 共享 | 是 |
| CLONE_VM + CLONE_FILES，无 THREAD | 复制 | 共享 | 否 |
| CLONE_THREAD + VM + SIGHAND + FILES | 共享 | 共享 | 是 |
| CLONE_THREAD + VM + SIGHAND，无 FILES | 共享 | 共享 | 否 |

六种情况下 loader 均与 native 输出一致，且复制 FD 表时打开描述的文件偏移仍共享。
这仅描述当前终端沙盒上的实测，不将差异归因于某个尚未定位的内核/沙盒组件，也不能
推广为所有 HarmonyOS 或 Linux 系统的规则。没有因此修改 guest clone 标志。

默认测试检查 loader 与 native 一致，并将上述已知 host deviation 单独报告；
`python3 test/fd_table/check_clone.py --strict-linux` 会对三种语义差异返回非零。
`make check` 使用兼容性对照模式，不能把其成功解释为全部 Linux clone 语义通过。
完整即时输出写入忽略的 `vendor/proot/svc/build/clone-fd-results.json`。

运行时设计需调整：不能仅根据 CLONE_FILES 决定元数据表归属，也不能使用一个随
CLONE_VM 共享的全局指针。本机观察更接近按进程共享 FD 表，但仅按 PID 惰性复制也不
充分：父进程可能在子进程首次进入 hook 前修改表。仍需要 clone 前快照/登记、结果通知、
目标环境的明确能力策略及同步协议。对不支持的组合，未来权限模式应明确拒绝或完整适配，
不能让元数据共享关系与实际 FD 表不同。专用通知入口已实现，FD 状态交接尚未连接，不启用权限执行。

## 已完成：运行时 clone 通知入口

PRoot 的生成 stub 已接到 `clone_entry.S` / `clone_notify.c`，在 clone 前准备独立上下文，
恢复原始 SP 后执行 syscall，再由父子各自在自己的栈上执行 finish。回调提供 flags、
父 PID/TID、cookie 和内核结果，允许子进程先返回；内核失败只有父侧 finish。
当前默认回调为空，未改变 FD 表归属或权限。before 返回后 cookie 由事务持有，
before 拒绝时也由 cleanup 统一清理；finish 不得自行释放。未来 finish 必须使用
事前保留的资源，不依赖可失败的事后分配。before 内部非局部退出仍需单独处理。

载荷 ABI 升为 3；loader 在启动 guest 前拒绝版本不匹配的自定义 payload。
`check_notify.py` 验证真实 clone 通知、寄存器/栈恢复、失败清理和并发调用，
`check_payload_abi.py` 验证版本匹配与拒绝。六种原生/loader 对照与两套 rootfs 回归仍通过。
上下文改为继承共享的 64 槽池；容量不足时用 tgkill 的 ESRCH 结果回收已知死亡任务，
仍无槽位则返回 EAGAIN。未知子身份、初始化中退出及遗留回收 pin 仍可能占用槽位；
非局部跳转或 exec 后任务仍存活也不能据此回收。

`clone_observer_cleanup` 已提供共享资源退役协议：父子角色完成且所有回收 pin 释放后，
唯一 finalizer 调用 cleanup，返回后才复用槽位。回调接收准备拒绝、父/子遗弃标记；
正常完成与内核 clone 失败不标记遗弃。回收与正常 finish 竞争时只标记实际补齐的角色。
同一事务不会重复调用 cleanup；清理中死亡或跳出会保留槽位，不能盲目重试副作用。
未知子身份不触发提前清理。测试以预先映射的共享资源池验证正常、失败、异常退出、
并发回收、清理重入、清理暂停和清理者死亡，检查资源没有提前释放或重复释放。

cleanup 可在任意继承进程运行，因此 cookie 必须指向继承后仍有效的共享 arena 或稳定句柄。
不能将任意私有指针、fork 后才建立的映射或进程局部 FD 当成可由它统一释放的资源。
这完成了共享元数据的退役接口；FD 表快照的实际分配、登记和进程资源管理仍未接入。
详见 [syscall 经验](SYSCALL_ENGINE_LESSONS.md#dedicated-clone-notification-path-proot-payload-abi-3)。

## 已完成：clone 前 FD 快照与单事务身份发布

`fd_clone.c` 提供无分配的事务模块：prepare 在 clone 前按明确 COPY/SHARE 模式
复制元数据或引用同一张表；父子用同一子 TID 幂等发布，身份冲突返回 EEXIST，
未发布或身份不匹配的查找返回空。复制容量不足时不发布事务、不修改目的表。
它不根据 CLONE_FILES 猜测本机共享行为，也不提供全局 PID/TID 登记表。

`check_fd_clone.py` 将该模块、FD 表和生产 clone 通知汇编接在真实回调中测试。
六种本机 clone 组合各覆盖父先/子先登记：父在内核 clone 返回后修改 CLOEXEC，
子核对克隆前快照或共享表，并实际关闭 FD；父核对内核状态和元数据可见性。
准备拒绝、内核失败、身份冲突、容量不足和 cookie 清理后的已接管表也有覆盖。
线程 fixture 的 x29 清零预期由独立原生 SVC 探针先验证，不改变生产寄存器恢复逻辑。

模块尚未链接到默认 payload：这是实际 clone 回调中的集成验证，不是已启用的
FD syscall 跟踪。事务仅覆盖单次 clone，TID 不构成持久身份。共享 arena 容量/所有权和任务登记核心见下一节；仍需将其接入运行时，
处理退出/TID 复用、FD 操作同步和 exec 交接。
源码表在 prepare 复制时必须稳定；该测试用显式握手串行化操作，没有解决任意
并发 close/open 与 clone 的一致性。清理 cookie 不得释放已被子任务接管的表。

## 已完成：有界任务登记与共享表所有权核心

`fd_registry.c` 使用调用方提供的任务槽、表槽和连续记录存储，适合放入预先继承的
共享映射。create/clone 在内核 clone 前预留容量，COPY 创建独立快照，SHARE 增加
同一表的持有者计数；publish 不分配内存，重复身份发布幂等，活跃 TID 冲突拒绝。
未发布任务不可按 TID 查到，可取消；已发布任务只能由确认退出后的 retire 回收。

任务句柄包含槽位与递增代次；旧句柄在取消、退出和槽位/TID 复用后返回 ESTALE。
代次耗尽返回 EOVERFLOW。最后一个持有者退出后表槽可复用，复用前清空记录与代次，
避免旧权限残留；另一个线程退出不会清空仍有持有者的共享表。表内描述身份仍非全局 ID。

真实 clone harness 已接此登记模块：六种模式、两种通知顺序继续核对内核 FD，
等待实际任务退出后按句柄 retire；失败与拒绝由 cookie cleanup 取消预留。
独立测试补容量耗尽、最后持有者、共享者保活、旧句柄/TID 复用及代次溢出。

这是所有权核心，尚未链接默认 payload；不提供并发互斥、退出自动探测、PID namespace
或 exec 后恢复。调用方必须串行化登记操作及借用表访问，不能跨 clone 持有互斥。
不能仅凭观察到 TID 不存在就释放仍被通知/读者引用的槽位。未知死亡、被中断的预留、
信号重入和运行时并发 FD 事件仍需由接入层统一处理；没有新增权限执行开关。

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
