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
已纳入 `make check`；后续已链接 FD payload 的诊断入口，尚未执行文件权限检查。
本次仅运行该核心测试、路径核心回归和 22 项 Python 测试，未重建 ELF。
2026-10-29 配置传递增量：FD 实验版新增 `--observe-mount-access` 观察参数，
root/bind 权限向量经 loader→payload→两次 exec 保留，非法配置拒绝，
未指定时保持旧行为。当时实验 payload ABI 升至 4，普通 PRoot 仍为 3。
真实 SVC 诊断与旧 ABI 拒绝测试、完整 FD 回归、普通版 `make check` 通过。
此参数不限制实际读写，也不改变 FD 来源标签；传递未经身份认证，JSON 尚未接启动。
2026-10-29 路径修改增量：新增独立 `--guard-path-mutations` 开关，将权限核心
接到 PRoot 写方式 open、创建/删除、rename/link 双端、路径截断和元数据修改。
真实 guest 测试覆盖软链接最终目标、嵌套覆盖、cwd/dirfd 与 exec 未知来源拒绝，
并核对宿主文件及目录没有被拒绝调用修改；观察模式保持原行为。
配置布局使实验 ABI 升至 5（普通版仍为 3）。传递/路径测试、完整 FD 回归和
普通版 `make check` 通过。此开关不限制读取、FD 写入/mmap、FD 元数据或未迁移
handler，不具备完整只读或默认拒绝隔离；路径竞争和未认证 exec 仍待解决。
2026-10-29 FD 修改增量：`--guard-file-mutations` 包含路径保护，并检查 write/
pwrite/向量写、truncate/fallocate、FD 元数据及数据转移的目标 FD。
只读来源拒绝、可写来源原生 IO、dup/fork/槽位复用、exec 导入降为未知均已实测；
未知 stdio/pipe 也拒绝写入，所以此模式尚不能用于通用 agent 启动。
实验 ABI 升至 6，拒绝把新模式解释成只有路径保护的旧 payload。
新增 FD 与既有路径/传递测试、完整 FD 回归及普通版 `make check` 通过。
mmap/mprotect、任意 ioctl、异步 IO、读取可见性和可信执行交接仍未完成。
2026-10-29 映射修改增量：文件修改模式要求文件共享 mmap 的来源可写，即使
初始只读；private/COW 和匿名映射仍可用。新增最多 128 个地址区间的准入表，
mprotect 加写/执行及 MADV_REMOVE 要求完整覆盖；munmap 成功后更新，失败保留。
private fork 复制记录；mremap 成功暂清空记录，vfork 共享 VM 窗口拒绝相关操作。
实验 ABI 升至 7，pkey_mprotect 在此模式返回 ENOSYS。区间模型、真实映射回归、
完整 `make check-fd-runtime` 与普通版 `make check` 通过。
初始映射不会自动获得准入、已有权限不撤销；标准 IO 授权和完整隔离仍待完成。
2026-10-29 标准输出增量：新增显式 `--allow-stdio-output`，仅在文件修改模式
初始化时授权可写 pipe/FIFO 或通过 TCGETS 的终端 stdout/stderr，限 write/writev。
授权跟随本地 description ID，dup/fork 保留，编号替换/复用不继承；exec 后重新
验证 fd 1/2，其他继承别名仍未知。普通文件、socket、非终端设备不会获得此授权。
实验 ABI 升至 8。真实 pipe/PTY 与生命周期测试、Alpine/Ubuntu 受保护 shell
read/printf/exec→cat、原有权限测试、完整 FD 回归和普通版 `make check` 通过。
新建管道/复杂流水线和可信执行交接仍未完成，不能据此宣称完整 agent 隔离。
2026-10-29 新建管道增量：独立 `--allow-pipe-output` 授权成功 pipe2 的写端，
限数据输出，读端/socket/文件不获准；dup/fork 保留本地 capability，替换/复用清除，
快照不序列化且 exec 清除。配合 stdio 重新验证，Alpine/Ubuntu 的三级流水线、
命令替换和子 shell 输出已通过。真实管道传输、模型生命周期/快照降级、既有权限
测试、完整 FD 回归及普通版 `make check` 通过；实验 ABI 为 9。
当时跨 exec 的普通文件输出重定向仍丢失来源。
2026-10-29 普通文件重新验证增量：新增显式 `--revalidate-file-fds`，仅用于文件
修改模式的快照恢复。通过实际 FD 的类型、路径、设备号/inode 与当前挂载表重新
确定唯一有效视图，不信任快照中的挂载/权限标签；只读和拒绝策略仍分别拒绝写入。
歧义别名（包括全部可写）、已删除/替换、视图外文件继续未知，不接管初始继承 FD。
实验 ABI 升至 10。连续两次 exec、伪造封印快照、拒绝边界及 Alpine/Ubuntu 的
真实重定向和追加写入测试通过；既有权限测试、完整 FD 回归与普通版回归通过。
这是当前策略下的重新授权，不是原始来源证明；执行配置尚未认证，路径检查仍有
竞态，默认拒绝读取等缺口未完成，尚未具备完整 agent 隔离。
2026-10-29 xattr 路径增量：set/get/list/remove xattr 及 l* 共八个路径入口接入
PRoot 解析；l* 不跟随最终 symlink，其余遵循最终目标。路径/文件修改模式对 set/remove
检查目标挂载权限，未知 cwd 拒绝，已知 cwd 与嵌套挂载按实际视图执行。FD 形式继续
使用现有内核 FD 与修改检查。真实探针覆盖读值/列表、创建/替换/删除、短缓冲、断链、
跨权限 symlink、相对 cwd、嵌套 bind，以及宿主属性/ctime 无变化检查；两种保护模式、
观察模式和无策略模式均验证；完整 FD 运行时回归与默认 `make check` 通过。
ABI 布局不变（实验 10，普通 3）。
这只补齐扩展属性的路径映射与修改入口，读取仍未默认拒绝，ACL/安全属性由宿主裁决，
未解决路径竞争或新式 xattrat ABI，不代表完整规范 FILE-09 已通过。
2026-10-29 ioctl 增量：文件修改模式改为按命令和对象类型准入；普通 FD 控制保留，
GETFLAGS/GETVERSION/FSGETXATTR 仅用于文件/目录，三种对应 setter 先检查挂载写权限。
FIONREAD 限文件/pipe/socket/经 TCGETS 验证的终端，有限终端查询限已验证字符设备。
未知命令、clone/dedupe、终端注入和设置均返回 EOPNOTSUPP；TIOCGPTPEER 仍 ENOSYS。
真实原生对照包含可写文件 NODUMP 修改/恢复、只读/deny/未知来源拒绝、dup 与编号替换、
pipe/CLOEXEC 及 PTY 查询；既有权限测试、完整 FD 回归与默认 `make check` 均通过。
观察/路径保护/无策略模式保持原行为；ABI 布局未变。
这仍不包含默认拒绝读取、完整终端设置、fcntl 命令审计或通用设备模型。
2026-10-29 fcntl 增量：在实验版中先按内核 unsigned 32 位 ABI 规范化命令号，
修复高位非零 DUPFD/DUPFD_CLOEXEC/SETFD 已在内核生效但未进入正确 FD 记账的缺口。
文件修改模式增加命令准入：保留普通 FD/pipe 控制和有限查询；锁要求已知非 deny 来源，
write hint 设置要求可写来源；owner/signal/lease/notify/seal 设置、O_ASYNC 和未知命令拒绝。
真实高位参数测试核对来源/description/CLOEXEC；原生对照覆盖宿主持锁下 POSIX/OFD 冲突、
只读读锁、共享状态 flags、pipe 容量及 seal 拒绝后状态不变。新增测试、既有权限测试、
完整 FD 回归与默认 `make check` 通过。当前宿主 hint 设置为 EOPNOTSUPP，不算成功支持。
ABI 布局不变；无额外路径查找或用户 flock 解引用。默认拒绝读取、完整 memfd 能力、
跨进程锁隔离和共享 FD 竞争仍未完成。
2026-10-29 madvise 参数宽度修复：复现高位非零 MADV_REMOVE 绕过映射准入检查，
在 mremap 清除记录后仍实际清零共享可写测试文件。现于分流前按内核 int ABI 规范化
advice；普通、bit 32 非零、高 32 位全一均执行同一检查。五种模式共 15 组真实用例
核对原生清零与保护模式 EACCES/宿主内容和时间戳不变，并检查 NORMAL/负 advice。
新增用例、既有权限测试、完整 FD 回归和默认 `make check` 均通过。
这是已证实的映射检查旁路修复，不是已证实的只读挂载逃逸；原有映射生命周期和
动态代码边界限制仍在。ABI 布局、慢路径清单及普通 IO 成本均不变。
2026-10-29 异步 IO 增量：复现保护模式下继承可写 FD 的普通 write 被 EACCES 拒绝，
但 io_submit(PWRITE) 仍改写只读 bind 对应宿主测试文件。文件修改模式现对六个 Linux
AIO 和三个 io_uring 入口统一 ENOSYS，在请求结构读取和原生调用之前拒绝；没有实现
异步请求权限与生命周期，也不撤销外部已提交 IO。原生和三种兼容模式的实际 AIO
写入对照通过；保护模式九入口的有效/无效参数均拒绝，宿主内容和时间戳不变。
新增测试、既有权限测试、完整 FD 回归和默认 `make check` 均通过。
ABI 与慢路径数量不变，路由测试固定九项覆盖；恶意代码与其他权限缺口仍待处理。
2026-10-29 写权限预检增量：faccessat/faccessat2 的 W_OK 路径查询按最终挂载执行
现有修改策略；文件修改模式的 AT_EMPTY_PATH 查询另按 FD/cwd 来源检查。mode/flags
按内核 32 位 ABI 解释，无效位先拒绝。读取/存在性查询没有因此变成默认拒绝。
四种实验模式与默认构建的真实用例覆盖 symlink、嵌套 bind、cwd/dirfd、继承 FD 与
宿主状态不变。当前 fixture backing 原生 NOFOLLOW 写查询返回 EACCES，空路径返回
EINVAL；保留宿主限制，不尝试绕过系统沙盒，也不把该项记为成功兼容。
本轮新增测试、权限核心、路径/FD 修改保护、xattr 回归，以及默认版 82 项路径和
20 项元数据检查通过。使用自建临时文件进行沙盒开发验证，未运行网络相关探针；
未重跑完整套件，ABI 未变。
2026-10-30 默认拒绝读取与目录可见性增量：新增 `--guard-file-access`，在文件修改模式之上
检查读取与可见性。权限核心新增纯词法可见性判定：非 deny 挂载可见；deny 路径若是有效
非 deny bind 的严格祖先则仅可遍历，否则隐藏。PRoot 解析在每个分量、相对基准和 symlink
目标交给宿主前判定，隐藏名统一 EACCES，不因存在与否、symlink 路由或 `..` 而不同；
祖先目录只允许 stat/statx/statfs、非写 access、chdir/fchdir、O_DIRECTORY 只读或 O_PATH
打开及枚举。getdents64 先读入 payload 私有缓冲，只把可见记录复制给 guest，隐藏名
不会出现在 guest 内存中（返回长度之后的字节和读取期间均不出现）；整批隐藏时继续读取，
不会提前返回 0。inotify 不能监听祖先或隐藏目录；可见目录若有隐藏的直接子 bind，
其事件会带出该名称，因此此类监听返回 EACCES（尚未实现按 wd 过滤事件）。FD 读取覆盖 read/readv/pread/preadv(2)、sendfile/splice/tee/
copy_file_range 的来源、fd 型 xattr 读取、空路径 readlinkat 和全部文件 mmap（含 private）。
已知来源按挂载判定；本地创建的 pipe/socketpair/socket/accept/eventfd/timerfd/signalfd/
epoll/inotify/memfd 带本地 stream 授权，随 dup/fork 保留，exec 清除且不进快照。
未知（继承/导入/exec 恢复）FD 默认拒绝；显式 `--allow-stream-input` 时仅放行 fstat 为
pipe/socket 或通过 TCGETS 的终端，无效 FD 仍先返回 EBADF。name_to_handle_at 未桥接，
此模式返回 ENOSYS。实验 ABI 升至 11。
验证环境不是 HarmonyOS：Android 14 AArch64 真机（内核 5.10，root）上的 Alpine 工具链
chroot。新增 reads 用例覆盖隐藏/祖先/嵌套 deny 再暴露、symlink 与 `..`、cwd/dirfd、
小缓冲枚举、继承 FD 各读取入口、stream 开关、exec 后策略保持及非法参数组合；
Alpine 3.24.3 与 Ubuntu 26.04.1 的受保护 shell 只读系统树、管道、命令替换、重定向和
`ls /` 隐藏通过。全部 fs_policy 运行时用例、shell 工作流与默认构建 port/dispatch/guard
测试通过。check_fd_clone、test_inotify、check_runtime 及 fd_runtime/run 在该设备上
对未修改的 HEAD 同样失败，属环境差异，未计为通过。该设备的 Linux 不按低地址 mmap 提示
放置 SVC stub，静态探针改用自重定位 static-pie 链接；这只是设备测试环境调整，未入库。
guest 内 exec 链的 PT_INTERP 现由 payload 读取，用 guest symlink 语义和读取策略解析，
解析出的宿主路径经 `--exec-interp` 交给子 loader 直接加载；隐藏或仅可遍历的解释器使 exec
失败。文件访问模式的子 loader 遇到 PT_INTERP 而无该参数时拒绝，不回退到词法宿主映射。
merged-usr 系统的 `/lib` 等是根目录中的 symlink，配置须显式暴露解释器所在路径。
2026-10-30 agent 启动增量：新增 `tools/agent_sandbox/launch.py`，把 profile 计划接到文件访问模式。
私有 home/tmp/cache 以 0700 创建；`<state>/root` 只含挂载点占位，作为 deny 根，祖先目录 stat
看到占位而非宿主目录，每次启动重建，缺少标记的已有目录拒绝且不删除。全部挂载按 ro/rw 生成
访问向量，并启用 stdio/pipe 输出、stream 输入和 FD 重新验证；环境只含 HOME/PATH/USER 等固定项、
TERM 和显式 `--env`。首个程序是随 FD 构建生成、哈希记入 manifest 的静态 exec 助手：确认 payload
已拦截后 chdir 到工作目录并经 payload exec 命令，因此命令、shebang 与 PT_INTERP 都按策略解析。
挂载数、环境数、路径长度等后端上限在启动前拒绝。同时修复：exec 后 cwd 不带来源，相对路径
打开的文件读取被拒；现在 `--revalidate-file-fds` 在启动时按唯一可见视图重新验证 cwd（读取模式
下隐藏别名不参与竞争，两个可见别名仍为未知）。末尾 `/.` 或 `/` 的规范路径此前被当作隐藏子项，
现按目录本身判定。Android 真机上的 agent_launch 用例覆盖 Alpine shell 的工作目录、干净环境、
私有状态持久化、根目录列表、brew shebang 工具、只读/隐藏路径、管道及参数拒绝；全部 fs_policy、
shell 与默认构建回归通过。
2026-10-30 UNIX socket 路径增量：bind/connect/sendto/sendmsg 的 pathname AF_UNIX 地址此前以原始
guest 路径交给宿主，可在视图外创建 socket 文件或连接宿主 socket。现由 PRoot 桥接在私有副本中
按 guest 语义翻译：bind 不跟随最终 symlink 并按创建执行修改策略，connect/sendto/sendmsg 跟随
symlink 并按读取可见性判定；宿主路径超过 sun_path 时经父目录 O_PATH FD 的 /proc/self/fd 名称
访问。抽象与非 UNIX 地址、内核将拒绝的长度原样透传；sendmmsg 带 pathname 目标时在受控模式下
返回 EOPNOTSUPP。sendto 加入共享慢路径（135 项），两种构建均翻译。真机用例覆盖 stream/dgram、
相对路径、超长宿主路径、symlink、抽象名、ro/deny 与宿主 socket 拒绝，以及默认构建；旧代码在首个
bind 即失败。文件修改模式仍拒绝对 socket 使用 write/writev（来源未知），send/recv 不受影响；
getsockname/getpeername/accept/recvfrom 返回的地址仍是宿主路径，尚未反向映射。
2026-10-30 HarmonyOS 真机核查（`f23d91a`，HongMeng Kernel 1.13.0 AArch64）：`make check` 212 项
PASS、`make check-fd-runtime` 158 项 PASS（仅既有的 2 项硬链接夹具 SKIP），Alpine/Ubuntu 离线验收
各 18/18。核查发现并修复：鸿蒙目录记录比 ext4 大，私有 getdents 批次此前沿用 guest 的 count，
隐藏的大记录会让小缓冲返回 EINVAL；现读取完整私有批次，仅复制放得下的可见记录并把目录游标
退回首个未返回记录，首个可见记录放不下时才 EINVAL 且不移动游标。/storage/Users 与 /tmp 拒绝
创建 socket inode，socket 用例改为探测可用目录（应用 TMPDIR）。
2026-10-30 本地对象输出增量：文件修改模式此前拒绝对 guest 自建 socket/eventfd/memfd 的 write、
memfd ftruncate 与共享可写映射（来源未知），事件循环唤醒、socket write 和 memfd 用法因此失败。
新增显式 `--allow-local-output`：仅授权本进程映像中由 socket/socketpair/accept/accept4/eventfd2/
memfd_create 创建的对象，随 dup/fork 保留、exec 清除且不进快照；memfd 可共享映射（PROT_EXEC 共享
映射仍拒绝）。pipe 仍只由 `--allow-pipe-output` 授权，继承/导入对象仍拒绝。实验 ABI 升至 12，
launch.py 默认启用。HarmonyOS 真机 local_output 用例覆盖开启/关闭、dup/fork/exec、sendfile、继承
socket 与 pipe 契约。HarmonyOS 上经 launch.py 运行 harmonybrew python3（暴露 brew、/system、/lib、
/etc）成功读写工作区且根目录只见暴露项；libc 的 hilog socket 不在视图内，连接被拒并在 stderr 输出
告警，需要在 profile 中显式暴露，而 8 个挂载上限已用满。
2026-10-30 挂载上限与 HarmonyOS profile 增量：CONFIG_MAX_BINDS 由 8 提高到 16（默认 ABI 4，实验 ABI 13），
exec 链参数容量按挂载数计算，launch.py 上限同步。新增 `profiles/harmonyos-agent.json`：brew 前缀、
/system、/lib（/system/lib）、/etc 只读，工作区与 /dev/null 可写，并单独暴露 hilog 输入 socket，
消除 libc 的 HiLogBase 连接告警；私有 home/tmp/cache。规划器对路径规范但 resolve 得到 EACCES 的
显式来源（该 socket 及其目录对用户不可 stat 但可连接）保留原拼写并标记 `unresolved`，只做词法重叠
检查。HarmonyOS 真机新增 agent_brew 用例：harmonybrew python3 经 subprocess 运行 git init/add/commit/log，
cwd/HOME、根与 /dev 列表、宿主项目目录不可见、/system 写入 EROFS 均核对。容器模式 getuid 报告 0 而
stat 返回真实属主，git 的所有权检查需 `safe.directory`；这是既有 uid 模拟的语义差异。
2026-10-30 线程增量：FD 实验版此前拒绝一切非 vfork 的共享 VM clone，所有权限保护模式（含 launch.py）
都无法运行多线程程序。现接受 pthread 标志组合（VM|FS|FILES|SIGHAND|THREAD，可带 SYSVSEM/SETTLS/
PARENT_SETTID/CHILD_CLEARTID/CHILD_SETTID 及 musl 的 DETACHED），同进程线程共享 FD 表、cwd 与映射
准入。重入租约：首个任务仍用私有槽，其他线程使用每进程私有映射的 64 槽表，私有 fork 子进程清空副本。
元数据由 futex 互斥保护，只覆盖表/cwd/映射/预留更新与非阻塞查询（fstat、TCGETS），可能阻塞的 guest
调用（读写、accept、FIFO open、recvmsg）不持锁；mmap 系列连同准入记录在锁内完成；fork 持锁取得一致
快照，子进程重置。close 改为锁内记录 generation、内核关闭、按 generation 撤销，结果原样返回，不再因
租约竞争返回 EAGAIN；不确定的关闭结果撤销来源与授权。FD 号复用竞争按失败关闭处理：没有记录或其记录
已在关闭中的号码被关闭（含 dup3 目标）时登记到 64 项环，创建期间该号码被登记则记录为未知且无授权；
已记录且无人关闭的对象占用号码，无法被并发创建取得，其关闭不登记。创建前在锁内预留记录槽，recvmsg
导入同样预留。HarmonyOS 真机 threads 用例：8 个 Python 线程各 150 轮 open/write/mmap 共享映射/dup/
关闭/只读拒绝/socketpair，同时另一线程 fork+exec 子进程，连续多次通过；只读文件内容与时间戳不变。
harmonybrew python3/git 用例与全部既有回归通过。已知限制：检查与内核使用之间，另一线程可把继承的
未知对象 dup3 到同一号码（仅涉及启动时继承的对象）；信号处理器以 siglongjmp 离开钩子会遗留锁与租约。
2026-10-30 性能基准增量：新增 `make bench`（test/bench，原生与默认/实验/修改保护/完整访问保护
五种配置的中位 ns/op，见 [BENCHMARKS](BENCHMARKS.md)）。首次测量发现 payload 以 -O0 编译，保护模式的
匿名 mmap 为原生 27.9 倍、路径 stat 为 6 倍以上。改为 -O2 后暴露 loader 从不应用 payload 的
R_AARCH64_RELATIVE 重定位（-O0 payload 也带两个未重定位 GOT 项）；loader 现于全部段可写时应用 RELATIVE
并拒绝其他动态重定位类型。路径调用改用每进程 4 个复用 scratch（vfork 子进程仍用预留区），并跳过不改变
解析结果的宿主 lstat（根与 bind 挂载点、不跟随的最终名）。HarmonyOS 结果：stat 3.1 倍、open+close 2.5 倍、
保护模式目录读取 1.5 倍、mmap 2.0 倍，FD 读写 1.4-1.8 倍；全部回归与 rootfs 验收通过。
2026-10-30 /proc 增量：此前经过 /proc/self 的任何路径都返回 EOPNOTSUPP。现按 PRoot readlink_proc 语义
（无 PID 命名空间）：self/thread-self 规范化为真实 pid/tid；exe 为 guest 程序（脚本为解释器，经
`--exec-exe` 传递，其他 loader 进程从其 cmdline 解析）；cwd 反向映射，root 为 "/"；fd 项作为最终分量
保持魔术链接，读取保护下文件目标按 guest 路径解析以受策略约束；readlink 返回 guest 路径，视图外目标
在无保护时原样、读取保护下拒绝。loader 以 exec 名设置 comm；loader 运行进程的 /proc/<pid>/cmdline 由
memfd 提供 guest argv，不再暴露 loader 参数与宿主路径。默认 ABI 5、实验 ABI 14。HarmonyOS proc_links
用例三种配置通过，全部回归通过。
仍未完成：直接调用 loader 时首个目标仍由 loader 词法映射加载解释器（launch.py 经助手规避）；祖先目录的 stat 仍是宿主元数据，
bind 目标在宿主中缺少挂载点目录时枚举不合成 glue 项；返回给 guest 的 socket 地址、新式 xattrat
入口和路径竞争未处理；读取模式不检查未知 cwd 的来源，仅依赖反向映射往返后的词法判定。
环境为当前 HarmonyOS AArch64 终端沙盒；以下结果不能直接外推到其他系统。

**已可运行受限的 Linux rootfs 工作流；尚未具备 agent 文件访问隔离。**
主要缺口是挂载/FD 权限来源与执行策略，而不是文件内容的用户态实现。
路径映射、元数据与策略应保持轻量，内容读写、偏移和实际 FD 仍交给内核。

## 两个构建的区别

| 能力 | 默认 `elfloader-proot` | `elfloader-proot-fd-experiment` |
| --- | --- | --- |
| root/bind、路径翻译、动态 ELF/exec | 已接入并有回归 | 已接入并有回归 |
| FD 元数据 | 未启用 | 常用创建/dup/关闭、CLOEXEC、SCM_RIGHTS 已接入；最多 128 条 |
| fork/vfork/exec 的 FD 状态 | 不跟踪 FD 元数据 | 私有 fork、单层受限 vfork、exec 快照交接、pthread 线程（共享 FD 表）通过；其他共享 VM 组合及嵌套 vfork 不支持 |
| 同线程嵌套慢调用 | 保留重入透传 | 返回 EDEADLK；同进程其他线程使用每进程 64 槽租约表 |
| openat2 | HarmonyOS 返回 ENOSYS | 24 字节 how、O_PATH\|O_NOFOLLOW 子集；resolve=0 经 PRoot，BENEATH 仅单分量及受限尾斜杠 |
| 已确认危险 syscall | 公共 guard 返回 ENOSYS | 同一公共 guard 加实验拒绝项 |
| 挂载来源与只读/默认拒绝 | 未实现 | 绝对/已知目录 FD/cwd 相对 open 已记录 mount/可写配置标签；未知来源及 exec 恢复仍 UNKNOWN；可选路径/FD 修改保护，`--guard-file-access` 增加默认拒绝读取与目录可见性；仍非完整隔离 |
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
共享慢路径 135 项表示“进入处理器”，不能作为“实现 135 项”的完成率。
固定危险调用回归另包含 fchmodat2，共 14 项；close_range 有单独的拒绝/回退测试。
原生配方、支持子集和错误路径都需分别看待，不能把 ENOSYS 算作功能实现。

## 尚未完成的验收门槛

1. **agent 权限执行**：配置只规划不运行；所有 bind 仍可写。绝对/已知目录 FD/cwd 相对打开已有
   mount/access 观察值，但未知 cwd/目录 FD、导入和 exec 恢复仍 UNKNOWN；尚无可信来源链。
   实验版的只读修改保护与默认拒绝读取已可选启用，但首个目标的 PT_INTERP、返回的 socket 地址和竞争仍有缺口。
   `tools/agent_sandbox/launch.py` 已把 profile 接到实验版文件访问模式，但 brew 实际程序与平台库
   尚未在 HarmonyOS 沙盒中验证。
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
