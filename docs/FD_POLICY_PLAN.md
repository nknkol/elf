# FD 身份与只读策略实施顺序

状态：独立实验构建已接入单任务 openat/dup/fcntl/close 跟踪；默认运行时与权限执行仍未启用。
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

## 已完成：元数据短临界区保护

`fd_guard.c` 为共享存储提供不等待的独占访问原语：实际 TID 加 32 位代次以单次
64 位 CAS 获取，自己的重入返回 EDEADLK，其他竞争返回 EAGAIN；获取失败不改 lease。
解锁必须匹配完整 lease，重复/过期解锁返回 ESTALE；代次耗尽返回 EOVERFLOW，不回绕。
它不调用 syscall、libc 或 TLS，不自旋、不分配；独立编译检查确认无外部符号依赖。

并发测试用四线程在保护下执行 8,000 次登记、FD 元数据修改与回收，验证结果及容量复用；
真实信号 handler 验证重入立即返回。fork 故障注入验证共享可见性和死亡持有者不会自动
解锁。死亡任务可能留下部分修改，不能仅凭 ESRCH 自动清锁并继续使用元数据。

该原语尚未接入默认 payload，不替换现有慢路径 reentry guard。它仅允许包围短小的
元数据操作，不能跨 syscall、clone、回调或分配持有。测试里的等待/重试属于测试协调，
不是生产策略。退出清理、信号非局部跳转和内核成功后的记账竞争仍未闭环：例如 close
已成功时，不能因更新表遇到 EAGAIN 就假装内核未执行，也不能直接放行。接入层需要
事前预留、操作身份和结果提交协议，才可连接 open/dup/close 等事件并启用权限执行。

## 已完成：close 延迟记账的代次校验

`fd_table_close_generation` 只删除匹配分配代次的记录；已不存在时幂等成功，
同编号已有新记录时返回 ESTALE 且保持新来源不变。之前未跟踪的 FD 用代次 0，
不能据此删除后来登记的记录。调用方仍需保护表访问并保证表实例未被回收重建。

真实 pthread 测试安排：主线程 close 成功，另一线程 dup3 复用编号并登记新来源，
然后主线程提交旧 close。验证新记录、CLOEXEC 来源信息和新内核 FD 仍保留；随后
匹配代次的关闭可以正常清理。核对使用实际 read，而非只验证元数据返回值。

ESTALE 是记账状态，不能覆盖已成功的内核返回值，也不能因此重试 close。
此接口不解决 syscall 前编号已被替换的竞争，不分类 EINTR/其他 close 错误，
不提供提交队列或互斥失败恢复。完整接入仍需操作预留/排序、错误语义和表生命周期
保活；默认 payload 的 close 尚未连接该模块，不能视作 FD 权限已启用。

## 已完成：close 预留与结果发布队列

`fd_close_queue.c` 使用调用方提供的有界共享槽位。prepare 在 syscall 前预留，
捕获 FD 分配代次并 pin 所属任务；pin 阻止 retire，因此待提交期间表不会被回收。
同表/同 FD 的重复预留返回 EBUSY，容量不足在执行 syscall 前返回 ENOSPC。
票据含槽位代次，旧票据不能发布新操作，代次溢出拒绝复用。

结果 publish 仅用一次无锁 CAS，无需获得元数据 guard；取得 guard 后 drain 再
做代次校验删除并解除 pin。明确没有关闭效果或执行前取消用 KEEP；已确认关闭用 REMOVE。
错误码到效果的完整分类尚未实现；已返回的不确定结果发布 UNKNOWN，尚未返回的操作
保持 RESERVED。未知/死亡操作不会自动取消。
KEEP/REMOVE 是记账效果，不是 guest 返回值，禁止因提交延迟重试内核 close。

真实测试让另一线程占有 guard，主线程 close 一次并发布结果，再由持锁线程 drain；
核对清理只发生一次、待处理期间不能 retire、同表共享者冲突、容量/代次耗尽和过期票据。
新增模块独立编译无 libc 依赖；完整共享任务/clone 测试仍纳入 make check。

准备、查询和 drain 仍需调用方互斥；只有 publish 可并发且不需要 guard。接入所有
相关 FD 操作及 clone/exec/range 时必须查询 pending 并确定排序，否则它不是完整的
FD 竞争防护。drain 中断后不能自行清锁重试部分修改；沿用死亡 guard 不自动恢复的限制。
模块尚未链接默认 payload，没有自动 close 拦截，也没有完成 close 错误语义和信号退出恢复。

## 已完成：可执行 close 适配流程

`fd_close_execute` 已将现有模块串为单次内核关闭流程：取得实际 TID，验证其登记句柄，
在 guard 下 drain/预留，释放 guard 后执行 raw close，再无锁发布并尽力 drain。
内核执行后的返回值始终保留，额外 bookkeeping 状态表示延迟提交或需要协调；
调用方不得把它覆盖为 guest errno，更不能因它失败而再次执行 close。
负 FD 直接返回 EBADF，身份不符、容量或前置互斥错误均不执行内核 close。

目前只处理返回 0 和 EBADF 的确定效果：二者均允许移除匹配旧代次的记录，
EBADF 说明内核调用时描述符不存在，不能保留对应的旧来源授权。其他结果统一
保留预留并标记 EINPROGRESS。后续同 FD 操作会被 pending 拒绝，不猜测错误效果。

实际内核测试覆盖成功、已关闭 FD 的 EBADF、旧记录协调；注入提交阶段竞争验证
原始成功值保持、下次入口 drain 不重复执行旧 close。注入 gettid 失败、EINTR、
EACCES、EIO 验证前置拒绝或保留不确定操作；这些注入不构成本机实际错误语义证据。

适配流程仍仅在集成 harness 中启用，默认 dispatcher 尚未接它。全局登记初始化、
其他 FD 入口的 pending 排序、exec/clone 生命周期和未知结果恢复未完成前，不能
只接 close 就宣称 FD 跟踪或权限完整。真实信号退出及罕见 close 错误仍需后续验证。

## 已完成：待提交状态阻止 clone 准备

登记核心现在直接检查父表所有持有者的 pending 计数，任一持有者仍被操作 pin 时，
COPY 和 SHARE 准备都返回 EBUSY，且不消耗槽位、不修改输出句柄。检查以表为单位，
避免从共享该表的另一线程绕过；独立复制表上的操作不受影响。解除 pin 后可正常准备。
这修复了之前仅依赖接入层主动查询 pending 的遗漏，但仍未接入默认 clone 回调。

close 执行测试还验证了元数据表满时关闭未知来源的真实 FD：关闭预留只需要队列槽，
不需要新增来源记录，旧记录保持不变。不确定 close 结果保留 pin 时，同时拒绝同 FD
重复关闭、队列耗尽后的新操作、任务 retire 以及 clone 准备；没有自动透传分支。

## 已完成：不确定 close 结果的显式来源撤销

队列现在区分 RESERVED（尚无返回结果）与 UNKNOWN（内核已返回但效果未知）。
执行适配器发布 UNKNOWN 后仍返回原始内核错误，并保留表 pin；普通 drain 不处理它。
`fd_close_forget_unknown` 可在互斥下显式把 UNKNOWN 转成撤销旧来源的完成事件，
随后 drain 按代次移除旧记录并释放 pin。仍在执行的 RESERVED 返回 EINPROGRESS，
不会提前释放；重复协调或已完成事件也不会重复解 pin。

这个恢复策略不猜测 FD 是否仍存在，也不再执行 close 或其他探测 syscall：无论实际
关闭还是存活，都撤销旧来源信息。若 FD 仍在，后续必须按 unknown 处理，不能据此
授予权限；它也不能用于恢复未发布结果的死亡调用方。表中已有较新代次时沿用保护规则。
票据增加 UNKNOWN 状态，槽位代次现为 61 位；无持久化格式或默认 payload ABI 改动。

故障注入分别模拟“返回错误但 FD 仍在”和“实际 close 后返回错误”，核对内核 FD
状态、旧来源移除、pin/队列容量恢复和 syscall 次数不增加。这不证明本机实际 EINTR/EIO
的效果，只验证协调不依赖该假设。默认运行时仍未启用跟踪或自动调用该恢复策略。

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


## 首条运行时闭环（FD_EXPERIMENT）

`make check-fd-runtime` 构建独立 `elfloader-proot-fd-experiment`。真实 dispatcher
现在可初始化单任务登记、跟踪 openat/dup/dup3/fcntl 和调用已有 close 执行流程；
所有来源仍标记 UNKNOWN，不执行只读或默认拒绝策略。普通构建不启用这些入口。

实验模式拒绝 clone/exec/close_range 等生命周期变更，额外分流 pipe/socket 等部分
原本快路径的创建接口后拒绝；同线程嵌套慢调用返回 EDEADLK，不再旁路执行。
端到端 guest 通过专用诊断 prctl 核对真实 payload 的记录、复制身份、CLOEXEC、关闭、
失败保持及 128 条容量边界。已有 Alpine BusyBox 和 Ubuntu cat 均完成文件读取烟测。

这替代了“只有独立 harness”的状态，但不是多任务完整跟踪，更不是权限隔离完成。
使用方式、拒绝范围、诊断接口和共享构建目录限制见 ../test/fd_runtime/README.md。
前文各独立模块阶段的“未接入默认 payload”仍然成立；实验构建按明确限制先形成闭环。


## 实验运行时扩展：memfd 与 eventfd

实验 dispatcher 已接入 memfd_create/eventfd2，不再拒绝这两个创建入口。两者沿用
单任务容量预检、分配代次与描述身份记录，以及已有 dup/close 链。分别正确处理
MFD_CLOEXEC 的 bit 0 和 eventfd 的 O_CLOEXEC；来源仍为 UNKNOWN。

真实 guest 验证匿名文件写读、dup 后关闭原 FD、eventfd 非阻塞计数器读写，
用原生 F_GETFD 对照记录标志，并验证无 CLOEXEC、非法 flags 和容量耗尽路径。
没有新增模型层；普通构建仍保持原行为，实验模式的 clone/exec 限制没有放开。


## 实验运行时扩展：内核事件循环

新增 epoll_create1 和 timerfd_create 的单 FD 创建跟踪，沿用 128 条容量预检、
UNKNOWN 来源以及已有关闭链。CLOEXEC 分别读取 epoll 的第一个参数和 timerfd
的第二个参数，不改变事件注册、等待和定时器设置的内核实现。

真实 guest 将 eventfd、timerfd 注册到 epoll，核对事件携带数据、计数消费、
非就绪返回和最后 FD 关闭后的清理。另覆盖无 CLOEXEC、非法参数及容量耗尽。
实验模式仍为单任务，clone/exec 未放开，文件访问权限策略仍未启用。

### 实验运行时扩展：pipe2 双 FD 创建

pipe2 创建前预检两个空槽及两个序号的余量，再由内核创建管道。
成功后双端各自建立 UNKNOWN 来源记录，dup 只共享对应端的 description。
真实 guest 验证数据传输、非阻塞、EOF、CLOEXEC、错误参数及容量边界。
仍限单任务实验模式：内核成功后读取 guest FD 数组，不提供并发用户内存快照，
不启用权限隔离；socketpair、SCM_RIGHTS 与多任务生命周期尚未接入。

### 实验运行时扩展：socket / socketpair

socket 接入单 FD 创建，socketpair 复用双槽及双 generation 预检，成功后
从第 4 个参数取得双端 FD；二者的 CLOEXEC 均来自第 2 个参数。
AF_UNIX 实测覆盖双向读写、dup 后原端关闭、EOF、flags、失败及容量边界。
原生探测发现本机 socketpair 接受 0x80000000/0x40000000 未知 type 位，
但 socket 拒绝；不在适配层改写此行为，非法类型回归使用 type=15（EINVAL）。
accept/accept4、SCM_RIGHTS 接收及多任务生命周期仍未接入，来源仍为 UNKNOWN。

### 实验运行时扩展：accept / accept4

两种接收调用接入单 FD 创建预检；accept 的 CLOEXEC 为 0，accept4 来自
第 4 个参数。抽象 UNIX socket 实测地址回填、双向 IO、关闭及 EOF、空队列、
非法参数；满表拒绝后释放一个槽仍能接收原排队连接，验证拒绝发生于内核调用前。
本机原生 accept/accept4(flags=0) 会继承监听端 O_NONBLOCK；测试运行器先获取
原生参考值，再对照 guest，适配层不改写该宿主行为。CLOEXEC 仍按调用标志跟踪。
recvmsg/recvmmsg 的 SCM_RIGHTS 接收及多任务生命周期仍未接入，来源仍为 UNKNOWN。

### 实验运行时扩展：recvmsg / SCM_RIGHTS

新增独立接收适配器：用 self process_vm_readv 安全读取 msghdr，在内部有界
控制缓冲区接收，再用 process_vm_writev 回填控制区及输出字段。进入内核前
按控制长度计算 FD 数量上界，预检槽位和 generation；不静默缩小控制空间。
当前上限为 128 个 FD，过大的控制区或保守预检容量不足会返回 ENOSPC，
即使实际排队消息只有少量 FD。普通 read/write 不受此复制开销影响。

收到的 FD 来源 UNKNOWN、description=0，不推断发送者权限或与本地 FD 的别名关系。
输出回填失败会关闭收到的 FD，消息可能已经消耗或部分输出已写入。
真实 guest 覆盖双 FD、CLOEXEC、peek、截断、0/1/2 空槽、只读控制区和只读消息头
的回滚、满表无控制区的数据接收；同时检查元数据和内核 FD 号复用以检测泄漏。
本机原生重复 MSG_PEEK 仅第一次返回 SCM_RIGHTS，后续只返回数据；测试按原生参考对照。
recvmmsg、其他携带 FD 的辅助消息类型及多任务生命周期仍未覆盖，不代表完整隔离。

本轮普通回归曾在 clone_notify_test.c 的 orphan 子进程退出断言失败一次；
该测试单独重跑通过，保留为待调查的已有生命周期测试不稳定性，不修改断言掩盖。

### 实验运行时扩展：recvmmsg 有界批量接收

recvmsg 与 recvmmsg 复用头部快照、容量上界检查、控制消息解析、输出回填、
UNKNOWN 导入及失败清理。recvmmsg 每批最多 8 条（超出 E2BIG），整批 FD
上界最多 128；先快照全部输入头并检查总容量，然后一次调用原生 recvmmsg。
使用内部消息头、控制区和 timeout，避免内核完成后因用户输出指针故障丢失
已接收消息数量。等待、MSG_WAITFORONE 和内核部分成功由原生调用处理。

回填失败保留已公布前缀，关闭失败项和后续项所有未公布 FD；返回前缀数量，
前缀为空则返回错误。timeout 回填失败关闭全部接收 FD 并返回错误。
后续消息可能已消耗，后项输入头无效也会提前拒绝整批；这不是完整 Linux
故障/部分进度语义兼容。整批容量按控制空间保守预估，不静默缩小缓冲区。

真实 guest 覆盖双消息四 FD、CLOEXEC、部分成功、阻塞 socket 的 WAITFORONE、
整批容量拒绝后原消息仍可接收、首项/次项控制区只读、msg_len 单独只读、
timeout 输入/输出故障及 FD 号复用检查；原生对照验证完整和部分 datagram 批次。
仍为单任务实验模式，其他携带 FD 的辅助消息类型与多任务生命周期未完成。

### 实验运行时扩展：inotify / signalfd

inotify_init1 和 signalfd4(fd=-1) 接入创建预检及 UNKNOWN 来源记录。
signalfd4 更新已有 FD 直接保留内核语义，不分配新记录，不改变 generation、
description、CLOEXEC；因此满表也可更新，继承的未跟踪 FD 不因更新被错误认领。
真实 guest 覆盖文件修改/关闭事件、信号接收、满表更新信号掩码、通过 dup
副本接收更新后的信号、创建 flags 与更新 flags 的区别、非法参数与容量失败。

本轮只完成 FD 生命周期覆盖，inotify_add_watch 的路径仍未转换到 guest 视图，
测试使用 compat 模式相对路径。watch 路径转换和权限检查必须后续接入，
不能据此宣称文件事件接口已隔离。pidfd_getfd、io_uring 创建及多任务/exec 仍待处理。

### 路径语义补齐：inotify_add_watch

将 inotify_add_watch 加入共享慢路径和 PRoot 路径适配，普通及 FD 实验构建均启用。
保留原 FD 和事件 mask，以 guest cwd 解析相对路径，按 root/bind 转换绝对路径；
默认跟随末端符号链接，IN_DONT_FOLLOW 则保留末端链接交给内核处理。
实际事件测试覆盖根目录文件、相对路径、外部绑定目录、跨绑定绝对符号链接和目录；
原生对照覆盖 ONLYDIR、缺失/空路径、空指针，以及宿主对 nofollow 链接 watch 的 EACCES。
额外验证直接传入存在的宿主绑定源路径不能绕过 guest 路径解析（ENOENT）。
本机拒绝监视符号链接，不能将该用例计为链接 watch 成功；路径竞争窗口和权限策略仍未完成。

### close_range：宿主致命调用防护，尚非范围关闭实现

原生隔离子进程实测 flags=0/CLOEXEC/UNSHARE/二者组合/非法标志均触发 SIGSYS；
即使范围内没有 FD 也会被杀。普通 HarmonyOS 构建现明确返回 ENOSYS，
FD 实验模式继续保持原有 ENOSYS；其他平台普通构建保留内核透传。
真实 guest 用继承且未跟踪的 FD、创建和 dup 的 FD 验证调用不改变 flags/记录，
再验证调用方逐个 F_SETFD/close 的回退。普通和实验构建均纳入回归。

未实现 close_range 批量语义。不能仅遍历跟踪表而遗漏继承 FD；后续实现需覆盖
完整宿主 FD 集合、loader 自有 FD、并发和 UNSHARE 的表所有权，不可假成功。

### 实验运行时扩展：pidfd_open / pidfd_getfd

隔离原生探测确认 pidfd_open(自身 PID) 与 pidfd_getfd(自身 FD) 可用，返回 FD
均有 CLOEXEC。pidfd_open 原先虽已进入慢路径但未登记元数据，现接入创建预检；
pidfd_getfd 接入同样预检并以 UNKNOWN 来源、description=0 导入，不推断别名权限。
真实 guest 验证共享文件偏移、关闭原 FD 后仍可读取、dup pidfd 后仍能导入、
错误参数和满表/释放槽后重试，普通路径不受实验开关之外的行为修改。

io_uring_setup 原生可成功，但 enter/register 已知受宿主限制；实验模式继续拒绝
setup，不以创建成功冒充异步 FD 生命周期已覆盖。跨进程导入权限、多任务、exec
与 close_range 完整语义仍未完成。

### 实验模式直接 FD 创建入口审计

发现 fanotify_init、userfaultfd、perf_event_open、bpf、mq_open 等可能走透传，
而 fsopen/fsmount/fspick/open_tree 虽已在共享慢路径中，也并未登记返回 FD。
新增实验专用拒绝清单，同一清单同时驱动汇编路由和 C 层 ENOSYS，避免只分流
但未实现跟踪。清单还包括 open_by_handle_at、seccomp 和原已拒绝的 io_uring_setup。
landlock_create_ruleset / memfd_secret 在目标头文件提供编号时条件启用；当前
头文件未提供这两项，不能计为本机已测。普通构建路由和行为保持原样。

真实 guest 独立枚举当前可用的 12 项，验证零参数/非法参数均返回 ENOSYS，
元数据不变，正常 memfd/dup/read/write/close 仍可用。拒绝原因是适配器缺失，
不是宿主能力判定；bpf/seccomp 包括不创建 FD 的命令也暂时拒绝，属于兼容性限制。
FD-producing ioctl、其他携带 FD 的辅助消息、原始入口及多任务生命周期仍未覆盖，
不能将该清单描述为完整的 syscall 安全边界。

### ioctl：CLOEXEC 状态同步与 TIOCGPTPEER 拒绝

FIOCLEX/FIONCLEX 原先直接透传，会令内核 CLOEXEC 与跟踪记录不一致。
现复用 F_SETFD 的预检和发布路径：成功后同步 CLOEXEC，不改变已有 generation
和 description；继承未跟踪 FD 需要先确保可登记，失败不执行内核修改。
实际 guest 验证副本标志独立、满表已知 FD 更新、未知继承 FD 的 ENOSPC 与释放槽后
重试、EBADF，以及 FIONBIO 仍由内核处理并共享状态标志。

本机原生 /dev/ptmx 的 TIOCSPTLCK 解锁成功，但 TIOCGPTPEER(O_RDWR|O_NOCTTY|
O_CLOEXEC|O_NONBLOCK) 返回 EACCES；实验模式显式返回 ENOSYS，避免其成功时产生
未登记 FD。本轮没有实现该请求成功路径，也没有完成所有 FD-producing ioctl 审计。
普通构建行为不变，权限隔离和多任务/exec 仍待完成。

### 实际接入单任务 exec 交接

实验模式现在允许 execve/execveat 经现有 PRoot exec 链进入同一实验 loader。
目标预检后导出密封 memfd 快照，仅包含非 CLOEXEC 记录；执行前解除传输 FD 的
CLOEXEC，失败返回时关闭传输 FD，不更改原表。loader 通过内部 --fd-state 参数
传递 FD，下一 payload 首次慢调用恢复 generation/description，核对 F_GETFD，
关闭传输 FD；恢复失败保存错误，不静默回到空表。来源一律降为 UNKNOWN。
内部参数只在实验构建提供并要求 --child-loader，密封不构成认证或权限授权。

真实 guest 在私有 loader 副本被临时移走后触发快照创建后的内核 exec ENOENT，
验证原记录、CLOEXEC 和 FD 号复用；随后连续 execve/execveat，核对保留项、
CLOEXEC 删除（含 ioctl 设置）、共享偏移及 root/bind 视图。另测未密封快照的
持续拒绝。Alpine busybox sh 与 Ubuntu dash 的 exec builtin -> cat 实测通过。
clone/线程仍拒绝，通用 shell 创建子进程和权限隔离尚未实现；既有 exec 路径预检、
单层 shebang、有界 argv、AT_EMPTY_PATH 等限制不因本次接入而消失。

### exec 恢复边界与序号耗尽修复

新增真实 guest 恢复用例：密封快照引用失效 FD、将传输 FD 本身列为继承项、
携带非法 CLOEXEC 记录，分别持续返回 ESTALE/EINVAL，不回退到空表继续运行。
另用合法密封快照将 serial 置为 UINT64_MAX，复现已知 FD 的 F_SETFD 被误拒绝。
修正创建预检：仅需要新 generation 的操作受序号耗尽限制；已有 FD 的标志更新
不改 generation/description，F_SETFD/FIOCLEX/FIONCLEX 及 close 仍允许，
新建/复制仍拒绝 EOVERFLOW。测试先在修复前失败，再验证修复后的行为。
这些人工快照只测试协议/元数据边界，不构成认证或权限隔离证明。

### 实际接入独立地址空间 fork

实验模式的生成 clone gate 现在接受 SIGCHLD，以及可选 CHILD_SETTID/CHILD_CLEARTID。
共享 VM、CLONE_FILES、线程、vfork 和其他组合继续 ENOSYS；直接普通慢入口的 clone
仍拒绝，必须走保留原栈的通知入口。before 获取父任务 reentry 活跃调用槽，初始化
元数据、drain 完成 close 并拒绝 pending；不持有元数据互斥锁跨 clone。
父返回才释放共享活跃调用槽；子进程不释放父槽，而在自己的私有映射副本中将
单任务 registry 绑定到实际子 TID，保留记录/序号。父进程在返回前死亡可能遗留
活跃调用槽，目前不自动回收；该限制不因 clone transaction reaper 而消失。

真实 guest 验证首次受控调用就是 fork、child_tid 输出、父改 CLOEXEC 后子仍为原值、
子 close 不影响父 FD，以及子进程再 exec 后的状态恢复。这里使用私有 VM 的真实复制，
不启用共享 registry 的线程方案，也不按宿主有偏差的 CLONE_FILES 标志推断共享。
权限隔离、共享 VM/线程和通用 shell/vfork 兼容仍未完成。

### 真实 shell 工作流验证与下一处阻塞

新增 `test/fd_runtime/shell.py` 并接入实验运行时套件。Alpine 和 Ubuntu 各通过
外部 cat 管道、子 shell、后台任务退出码/wait、命令替换和跨 fork FD 重定向；
Alpine 额外通过外部命令后继续执行 builtin，共 11 个成功场景。
测试显式绑定 `/dev/null`，避免 minirootfs 缺少设备导致后台任务退出 2 的干扰。

Ubuntu dash 普通外部命令后接 builtin 仍报 Cannot fork，单独标记 KNOWN LIMIT。
该 rootfs libc 的 vfork 反汇编显示 clone flags=16657（0x4111），即
CLONE_VM|CLONE_VFORK|SIGCHLD，当前门禁明确拒绝。现有 pipeline/subshell 的成功
不能推出普通 shell 命令已完整兼容。下一步应处理 vfork 的共享 VM 生命周期、
父任务挂起期间的元数据所有权、子 exec/exit 后父状态恢复，不能直接放开标志或
把 fork 替代当作完整 vfork 语义。本轮只增加实际工作流回归和诊断，不改变门禁。

### 接入受限 vfork，解除 Ubuntu dash 普通外部命令阻塞

本机原生探针确认 0x4111 的共享内存、父挂起、独立 FD 标志及退出行为。
实验 clone gate 现接受精确 CLONE_VM|CLONE_VFORK|SIGCHLD；保留真实内核语义。
父 clone 前复制独立子 metadata arena 并修复内部指针；按 TID 选择父/子记录，
不让子 close/dup/CLOEXEC 改写父记录。父从内核返回后丢弃子状态，同时释放成功
exec 在旧 VM 中留下的 scratch 和活跃调用槽。失败 exec 走正常清理和重试。

新增 native/loader 双跑 vfork guest：首次调用初始化、共享内存和父挂起、FD 标志
独立、子 close/dup、exit、慢路径外 SIGKILL、失败 exec 后重试、40 次 exec 循环。
Alpine/Ubuntu 共 12 个 shell 工作流现在全部通过，Ubuntu 普通外部命令不再作为
KNOWN LIMIT。仍拒绝嵌套 clone、额外 vfork flags、CLONE_FILES 和普通共享 VM 线程。
这只完成受限 FD 生命周期接入；其他旧后端全局状态及任意共享 VM 操作未全面审计。
子在其他慢调用中死亡仍可能遗留活跃槽/临时映射；父提前死亡也未自动回收。

### 回收 vfork 子在阻塞慢调用中遗留的活跃槽

先新增原生/loader 对照：连续 40 次 vfork，子在空 socketpair 的 recvmsg 中阻塞，
由默认 SIGALRM 终止，父验证信号退出、FD 记录不变且后续慢调用可用。
旧版本原生通过、实验后端失败，证明仅回收成功 exec 的槽还不够。

现在子从 clone 回调开始使用私有 payload 内的独立 reentry 槽；正常返回照常释放，
父在内核 vfork 返回确认子离开共享 VM 后统一清空，包括 acquire/epilogue 中被杀
的窗口。不按 TID 扫描并回收公共槽，避免误清 fork 兄弟任务可复用的槽。
原有 exec 专用槽记录删除；exec scratch 回收保持。满公共池测试验证专用槽回收
不改变 32 个既有 owner，真实 recvmsg 中断循环已通过。

本步解决 vfork 子活跃槽泄漏；其他慢调用的临时 mmap、父提前死亡以及普通 fork
子进程遗留公共槽仍需后续处理，不声称完成通用进程退出回收。

### 为 vfork 预留路径/exec scratch，回收阻塞路径调用遗留映射

Bridge 与 ExecScratch 统一使用 scratch 分配接口；普通构建及非 vfork 调用仍按原样
mmap/munmap。父在进入内核 vfork 前按两个结构实际大小预留映射，失败时回收已分配
部分再返回错误。子按最小可容纳槽借用并清零，释放只归还槽；父内核返回后统一
munmap，包括 clone 失败。这避免子在 mmap 成功但尚未登记、或释放前后被杀的窗口。
分配必须选择最小合适槽，否则较小的 exec scratch 会占用 Bridge 槽，导致嵌套解析
无可用槽；exec 失败重试和多轮成功 exec 已覆盖该组合。

新增 native/loader 对照：32 次 vfork 子在 FIFO openat 中阻塞，由 SIGALRM 终止，
父每轮读 /proc/<数字 PID>/statm，验证虚拟页数不增长和 FD generation/CLOEXEC 不变。
工作目录不允许 FIFO，fixture 在允许创建及删除的应用 cache 中建立，并用工作目录
软链接访问；退出清理。现有 40 次 recvmsg 中断、40 次 exec 和 shell 工作流继续通过。
本步覆盖路径/exec 两类 scratch，不包括其他内部 mmap、父提前死亡和普通 fork 回收。

### 普通 fork 子改用私有活跃槽

新增 40 次普通 fork 子在 recvmsg 中被 SIGALRM 终止的回归，旧实验后端失败：子进程
退出留下的公共活跃槽会累积耗尽。现在仅在确认独立 VM 的 child clone 回调中绑定
私有 payload 槽；子死亡/exec 时旧 VM 由内核回收，不再消耗祖先的共享槽容量。
嵌套 fork 只重置子 VM 中复制的槽，父槽仍由父返回释放；vfork 专用槽保持优先。
普通构建及一般共享 VM/thread 的公共 guard 未切换，不能外推为线程支持。

真实 guest 新增嵌套 fork、40 次子 exec、40 次阻塞 recvmsg 中断，逐轮检查父 FD
记录/CLOEXEC。guard 测试在持槽状态 fork，子绑定并带着活跃槽退出，父仍检测到
递归且正常释放后可复用。clone cookie 文档明确父专用私有引用禁止子和 cleanup
解引用；本适配器遵守此约束。初始任务共享槽、未完成 clone transaction 和任意
父提前死亡的处理仍未完成；本步不做基于 TID 的死亡猜测与回收。

### 初始实验任务也使用私有活跃槽；真实孤儿链回归

实验后端首次 entry 在获取 lease 前绑定私有槽，不再初始化公共 guard 表；普通构建
保留原实现。未知同 VM TID 返回 EOPNOTSUPP，已绑定 vfork 子走自己的专用槽。
绑定不能延迟到 dispatch，否则信号重入可能绕过外层已持有的另一槽。初始进程
退出/exec 时，活跃槽随旧 VM 一并消失；不再产生共享 guard 遗留引用。
专用测试禁止 mmap，验证首次获取、递归拒绝、未知 TID 拒绝和父持槽时 vfork 回收。

新增真实 orphan guest：80 代父进程创建下一代后立即退出不等待，后代逐代验证
FD generation 并继续 fork；监督进程作为 subreaper 接收最后完成标记并回收全部
81 个进程。累计超过通知池 64 槽，验证正常 clone 返回后的父退出不会阻塞后代。
本次没有放宽 clone_notify 的死亡判定；未知 child、INIT 中死亡、遗留 reaper pin
和 finalizer 中死亡仍不能据此声称已解决，也未完成一般资源回收或权限隔离。

### 消除 clone 身份查询阶段的 INIT 槽泄漏窗口

原实现先 reserve INIT 槽，再调用 getpid/gettid。任务若在身份查询中非局部退出，
槽尚不可被 reaper 检查，累计会耗尽 64 槽。现在先完成 PID/TID 查询和有效性检查，
再创建通知池、占槽和调用 observer；查询失败不会分配池或留下 INIT 槽。

新增故障注入在两个 raw 身份查询中分别 pthread_exit，各连续 67 次；旧版失败，
修复后没有 observer/池分配，完整容量检查通过。另验证 EINTR 原样返回、零身份
返回 EIO，原有 observer 中死亡、并发回收、finalizer 保留测试继续通过。
这消除的是占槽前可完成的身份查询窗口；占槽之后的初始化、before 回调中途死亡、
未知 child、reaper pin 和 finalizer 遗留仍需不同的生命周期协议，不能推断可回收。

### 区分已发布 BEFORE 阶段，回收回调中死亡的通知槽

父身份和返回上下文写好后，原子发布 ACTIVE|BEFORE，再调用 observer。该阶段
能证明 prepare 尚未返回、内核 clone 尚未执行。reaper 固定住槽后仅在 tgkill
确认 ESRCH 且 CAS 再次确认 BEFORE 未变时，标记父完成及“无子”并回收通知槽。
此时 cookie 尚未移交，不能调用完整 cleanup；observer 自己负责未移交资源。
回调返回结果原子发布后才转交 cookie，拒绝分支也通过正常 reader-pin/finalizer
流程保证 cleanup 一次执行，不在有 reader 时直接清空槽。

竞态测试让 reaper 先读到 BEFORE，再在死亡查询期间推进回调返回并让调用方退出；
它必须保留未知子状态，下一轮最多完成父角色，不能按旧阶段误判无子。
另测试活回调不可回收、EPERM 不表示死亡，以及 cookie 分配前后各 67 次退出。
通知槽恢复全部容量；分配后的 partial cookie 由测试中的 observer 责任方显式释放，
验证 core 从未误调用 cleanup。原并发回收、回调死亡、拒绝和 finalizer 保留测试通过。
仍保留占槽到 BEFORE 发布之间的 INIT 窗口，以及未知子、遗留 pin/finalizer 的限制。
这不是通用资源回收；BEFORE 前后的未移交资源仍可能需要 observer 专属清理。

### 实际文件工作流与 fchmodat2 漏拦修复

转向 rootfs 实际操作检查：Alpine/Ubuntu 的 ls、cp/mv、readlink/-f、find、tar
创建及列表均通过，Alpine 解包也通过，共 13 个成功场景。Ubuntu GNU tar 解包
要求 openat2 RESOLVE_BENEATH，仍作为 KNOWN LIMIT，不能降低其目录边界要求。
过程中还发现宿主旧头文件缺少 fchmodat2(452)，导致 Ubuntu libc 调用走快路径
被系统 SIGSYS 杀死。原生三个 flags 组合独立探针均验证该行为，现补 AArch64
条件编号和共享慢路径拦截，HarmonyOS 明确返回 ENOSYS。GNU tar 现在稳定返回
错误 2，不再因该调用被杀；这不表示支持 fchmodat2 或 openat2。
普通/实验运行时都验证 452 不会进入原生危险调用，工作流测试接入 FD 套件。
后续兼容重点是有明确路径边界语义的 openat2 支持，不应继续扩展无条件降级。

### openat2 的单分量 BENEATH 子集

FD 实验后端现在接受 24 字节 open_how、resolve=RESOLVE_BENEATH、mode=0，
flags 必须包含 O_PATH|O_NOFOLLOW，且只能另外包含 O_DIRECTORY/O_CLOEXEC。
仅支持非空单个相对路径分量；绝对路径及 `..` 返回 EXDEV，多级路径返回
EOPNOTSUPP。其它 how/resolve/flags 组合不降级，普通后端仍保持原 ENOSYS。

实际打开使用原目录 FD 的内核 openat；AT_FDCWD 先打开 `.` 固定目录身份，
完成后关闭内部锚点。检查 guest mount identity，跨配置 bind 的目标拒绝。
O_PATH|O_NOFOLLOW 可以返回符号链接自身，不能把链接作为目录跟随；打开结果
接入 FD 容量预检、generation/description 和 CLOEXEC 登记。名称与 how 在使用前
复制，但仍沿用现有单任务用户指针访问假设，不增加通用 EFAULT 安全复制能力。

新增实际 SVC 测试覆盖目录 FD/AT_FDCWD、绝对路径/父目录/多级路径拒绝、空名、
缺失文件、非目录、符号链接自身身份、跨 bind 拒绝、FD 数量及 CLOEXEC。
Ubuntu GNU tar 解包仍超出此子集并返回 EOPNOTSUPP（退出 2），保留 KNOWN LIMIT。
本增量不实现通用 BENEATH、不解决外部并发改名下的完整挂载视图一致性，也不启用
FD 访问权限策略；多级路径不能用“字符串归一化后绝对路径打开”直接扩展。

### 尾部目录分隔符与 Ubuntu tar 解包

实际参数跟踪确认前一轮简单归档的失败路径是 `a/`，而非多级路径；临时跟踪已移除。
现对显式 O_DIRECTORY 的单分量名称允许尾部重复 `/`，去掉分隔符后仍以原目录 FD
执行 O_PATH|O_NOFOLLOW|O_DIRECTORY 打开。`../` 拒绝，内部 `/`、跨 bind 和尾部
符号链接仍不支持。尾部分隔符下的内核 ENOTDIR 返回 EOPNOTSUPP，明确保留未实现
的链接跟随/非目录错误细分；不把尾部斜杠当作允许跟随符号链接的理由。

Alpine 和 Ubuntu 的原归档以及新增 `a/sub/deep` 多层归档现在均解包成功，退出 0，
宿主检查解出的内容一致。文件工作流共 16 个成功场景，撤销先前 GNU tar 解包的
KNOWN LIMIT。归档多层目录可用不等于单次 openat2 多分量解析可用，后者仍拒绝。
实际 SVC 测试覆盖目录 FD/AT_FDCWD 的尾部斜杠、重复斜杠、CLOEXEC/O_DIRECTORY
保留，以及缺少 O_DIRECTORY、普通文件、`../`、中间分隔符、跨 bind、链接目录拒绝。

### 无额外解析约束的 openat2 与打包回归

FD 实验对相同受限 O_PATH flags 新增 resolve=0 分支，经 PRoot openat 解析支持
绝对路径、多分量及 bind 视图；resolve=8 仍保持单分量 BENEATH 限制，其它 resolve
位明确拒绝。直接 SVC 覆盖 resolve=0 FD/CLOEXEC 和相对多分量，并验证 resolve=16/9
不会被忽略。Ubuntu 绝对源路径 tar 打包纳入回归，归档由宿主独立验证。
公共 namespace/mount/kcmp SIGSYS 拒绝也已补齐，见 SYSCALL_ENGINE_LESSONS.md。
