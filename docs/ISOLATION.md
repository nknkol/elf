# 隔离模式（`--isolate`）设计

## 目标与威胁模型

进程内拦截（默认与 guarded 构建）对恶意代码不是边界：guest 与 loader/payload 同处一个地址空间，
可以跳进 payload 的系统调用指令，或改写 payload 的配置与策略（见 [STATUS](STATUS.md) 2026-10-31）。

隔离模式把**文件访问的最终授权**移到 guest 碰不到的进程：

- guest 进程（含其中的 loader/payload）装 seccomp 过滤器：所有按路径访问文件、以及能绕开 broker
  的系统调用一律返回 EPERM，**不论从哪个地址发出**。真机实测没有能绕过过滤器的内存类型
  （RWX 匿名页的系统调用根本不执行），seccomp 用户通知不可用，所以采用代理进程模型。
- broker 进程（loader 在启动 guest 前 fork 出来，不在过滤器下）持有允许访问的宿主目录树及其
  访问权限，代为执行每一次带路径的操作，FD 经 `SCM_RIGHTS` 交给 guest。
- payload 继续负责全部 PRoot 语义（root/bind 翻译、符号链接按 guest 视图解析、身份伪造），
  只是把“发给宿主的带路径系统调用”改为 broker 请求。payload 被篡改的后果，仅限于发出任意请求；
  broker 不信任请求中的任何内容。

不在本模式范围内（见文末“剩余风险”）：内核漏洞、资源耗尽、侧信道、网络与系统服务。

## broker 的策略

- **目录树**：root（container 模式）与每个 bind 的宿主源目录，各带权限 `d`/`r`/`w`
  （guarded 构建取 `--guard-*` 的权限向量；否则全部为 `w`）。另有 glue 目录（`w`）、
  loader 二进制（`r`，用于 exec）。broker 启动时打开每棵树的根目录并记录其 (dev, ino)。
- **安全解析**：宿主路径必须是绝对路径。从最长匹配的树根 FD 起逐级 `O_NOFOLLOW` 打开目录；
  每打开一级都比较 (dev, ino)：若等于另一棵树的根（嵌套 bind、大小写别名、同一目录多处挂载），
  就切换到那棵树的权限。`..` 不能越过树根。最后一级用 `*at` 加不跟随符号链接的方式操作；
  需要跟随时由 broker 读链接、拼出新路径并从头重新检查（最多 40 次）。
- **权限**：读类（stat、readlink、access 不含写、getxattr/listxattr、只读 open、O_PATH、statfs、
  chdir、inotify 监视）要求 `r` 或 `w`；写类（创建、删除、改名、链接、chmod/chown/utimes、
  截断、写方式 open、O_TMPFILE、setxattr/removexattr、bind 套接字文件）要求 `w`；
  `d` 一律 ENOENT（不可见）。两路径操作（rename、link）两端都要 `w`，因此不能把只读文件
  硬链接到可写区。
- **`/proc`**：仅当配置了 `/proc` bind 时可读；`/proc/self`、`/proc/thread-self` 改写为请求者
  的 pid（来自通道的 `SO_PEERCRED`）；`/proc/<pid>/…` 只允许请求者自己的 pid。
- **按 FD 的操作**（fchmod、fchown、fsetxattr、fremovexattr、utimensat(fd, NULL)、
  `/proc/self/fd/N` 的 readlink 与重新打开）：guest 把 FD 发给 broker，broker 由其副本的
  `/proc/self/fd/<n>` 得到宿主路径，按上面的规则检查后对 FD 本身操作。

## 协议

- 每个 guest 线程一条私有通道：payload 首次需要时建 socketpair（`SOCK_SEQPACKET`），经继承的
  控制套接字把一端交给 broker；broker 为每条通道 fork 一个处理进程（阻塞操作互不影响）。处理进程先建一个
  memfd 作为通道的共享区（封印为不可截短、不可扩大，guest 无法让 broker 读到 SIGBUS），作为第一条消息发给
  payload。之后请求与应答经共享区传递：payload 写请求并递增序号，broker 先把请求整体拷到私有缓冲区再解析
  （guest 可能同时改写共享区），写应答后置应答序号。双方先自旋等待（payload 等应答 300 µs，broker 应答后等下一
  请求 150 µs，用 cntvct_el0 计时），超时才置“睡眠”标志并阻塞在套接字的 recvmsg 上，另一方见到标志就发一个唤醒
  字节。套接字仍是通道本身：FD 以 SCM_RIGHTS 随请求或应答先行，对端退出时 recvmsg 读到 EOF（payload 失败即
  拒绝，broker 处理进程退出）；broker 在自旋中接到请求时用零超时 ppoll 检查套接字是否已挂断，guest 关掉自己
  那一端后共享区也不再应答。memfd 建不成时退回到套接字消息。
- 请求：系统调用号、6 个参数、按参数表复制的字符串与输入缓冲区、至多两个 FD
  （目录 FD 或操作对象）。响应：返回值、输出缓冲区、至多一个 FD。
- 参数表（`broker_proto.h`，loader 与 payload 共用）逐个系统调用描述哪个参数是目录 FD、
  路径、输入/输出缓冲区及其长度、读写类别、是否返回 FD；表外的调用 broker 一律拒绝。

## guest 过滤器

**拒绝（EPERM）**：
- 按路径访问文件：openat、openat2、open_by_handle_at、name_to_handle_at、newfstatat、statx、
  faccessat(2)、readlinkat、mkdirat、mknodat、unlinkat、symlinkat、linkat、renameat(2)、fchmodat(2)、
  fchownat、utimensat（路径非空时）、truncate、statfs、chdir、chroot、所有 xattr 调用、
  inotify_add_watch、fanotify_mark、execve；
- 按 FD 改元数据：fchmod、fchown、fsetxattr、fremovexattr；
- 能绕开 broker 或攻击其他进程：io_uring_*、process_vm_readv/writev、pidfd_getfd、ptrace、
  kcmp、bpf、perf_event_open、mount 一族与新挂载 API、`socket(AF_UNIX)`、`socketpair(…, SOCK_DGRAM)`、
  针对其他进程的 prlimit64、FS_IOC_SET* 类 ioctl、Linux 6.13+ 的 *xattrat/file_*attr。

**放行**：其余调用。exec 只能是 `execveat(898, E, …, AT_EMPTY_PATH)`：FD 898 是 loader 自身，`E` 是 loader
常量页里的空串（过滤器比较指针，路径内容因此确定为空）。这条执行可信链在所有 `--isolate` 进程里成立，
不依赖 `--isolate-device`，见下节。

### 执行可信链（2026-11-01 起所有 `--isolate` 通用）

过滤器读不到路径字符串，只能比较指针。所以 execveat 只放行 `fd == 898`、`pathname == E`（常量页里空串的
固定地址）、带 `AT_EMPTY_PATH`，于是每个受过滤进程运行的都是 loader 映像（归纳）。为了让这条链不被改写：
FD 898 不可关闭或替换（过滤器拒绝 close(898)、覆盖它的 close_range、以它为目标的 dup3、fcntl(F_SETFD)、
ioctl(FIOCLEX)）；常量页不可解除映射、改保护或被覆盖（与之相交的 munmap/mprotect/pkey_mprotect/madvise/
remap_file_pages、MAP_FIXED 的 mmap、mremap、SHM_REMAP 的 shmat 都拒绝，userfaultfd 整体拒绝）；常量页
内容不可改（broker 拒绝写 loader 文件，按 dev/ino 识别，含大小写别名与硬链接，打开后再核对；拒绝写
`/proc/<pid>/mem`）；unshare、setns 也拒绝。初始 loader 启动时 FD 898 被占用则拒绝启动。这些规则原先只在
`--isolate-device` 下生效（见“GPU 设备”中的不变量 1–3），现在是基础隔离模式的一部分；设备模式只在此之上
放行选中设备路径常量的 openat。验收：`test/isolation/device.py` 的过滤器、exec、broker 三组检查在
`--isolate` 与 `--isolate --isolate-device` 下都跑。

过滤器装在 loader 跳到程序之前，跨 exec 继承；与 `--seccomp-backstop` 可同时使用（TRAP 优先于
ERRNO：未改写的调用先交给 payload，再经 broker 执行）。

## exec 流程

payload 的 exec（proot_exec）：
1. 经 broker 打开目标程序（读权限），解释器（PT_INTERP、脚本解释器）同样经 broker 打开；
2. 以 `execveat(loader_fd, "", …, AT_EMPTY_PATH)` 重新执行 loader，`--exec-fd`、`--exec-interp-fd`
   传入这两个 FD，`--isolate-fd` 传入控制套接字；loader_fd 是初始 loader 在装过滤器前打开的、
   不带 close-on-exec 的自身 FD。
3. 子 loader 不做任何按路径的调用：用 fstat 代替 newfstatat，程序与解释器只从 FD 读取，
   loader 路径与大小写别名标记从参数继承。

## 第二阶段的实现要点

- **子 loader 的参数**：`--exec-fd`（要加载的 ELF，脚本时为最终解释器）、`--exec-interp-fd`（PT_INTERP）、
  `--loader-fd`（初始 loader 装过滤器前打开的自身，FD 898）、`--loader-path`、`--case-folds`（各 bind 的
  大小写别名标记）、`--isolate-fd`（控制套接字，FD 899）。子 loader 只用 fstat/pread/mmap 读这两个 FD。
- **PT_INTERP**：隔离模式下两个构建都由 payload 读出 PT_INTERP，按 guest 视图（符号链接、bind）解析后
  经 broker 打开；程序与解释器先打开、再对 FD 做 fstat 检查，避免检查与使用之间被替换。
- **按 FD 的元数据**：`newfstatat(fd, "", AT_EMPTY_PATH)`（glibc 的 fstat）在 payload 内改为 fstat；
  `statx` 的空路径与 `/proc/self/fd/N` 由 broker 直接对收到的 FD 执行（读取已持有对象的元数据，无需检查）；
  fchmod、fchown、fsetxattr、fremovexattr、utimensat(fd, NULL) 由 broker 按对象所在树检查。
- **`/proc/self/fd/N` 重新打开**：对象在某棵树内时按该树权限；不在任何树内（终端、继承的设备）时，
  至多保持原 FD 的访问方式，O_PATH FD 不能重开，也不能带 O_CREAT/O_TMPFILE。
- **套接字**：`socket(AF_UNIX)` 由 broker 创建（只给流与顺序包）；bind/connect 一律经 broker，UNIX 路径
  按树检查（bind 要求父目录 `w`，connect 要求可见），broker 在目标目录内用相对名完成，因此不受 `sun_path`
  长度限制；其他地址族与抽象名原样执行。数据报 socketpair 改为顺序包（保留消息边界）；sendto/sendmsg
  带 UNIX 路径名返回 EPERM（guest 没有可命名的数据报套接字）。
- **glue 目录**：glue 基目录是宿主的 TMPDIR（或 PROOT_TMP_DIR、/tmp），broker 只开放其中
  `proot-glue-*` 名下的内容（可写），基目录本身与其中其他名字一律不可达。最初整棵 TMPDIR 都是可写树，
  伪造请求可以读写其中任意文件，这是验收时发现的缺陷（见 ISOLATION_RESULTS.md）。
- **保留 FD**：控制套接字、loader FD 与各线程通道不允许被 guest 破坏：close 假装成功，作为 dup3 目标返回
  EBUSY，F_SETFD/FIOCLEX 被忽略；close_range 由 payload 代办：跳过保留 FD、其余照常关闭（或设 close-on-exec）并返回成功。HarmonyOS 不提供该调用，打开的 FD 从 broker 打开的 /proc/self/fd 列出。不能返回 ENOSYS：glibc 的 closefrom 退回路径每轮关过 FD 就从头重读 /proc/self/fd，假装关闭成功的保留 FD 会让它永远循环（posix_spawn、Python subprocess 因此卡住）。procfs 的 FD 列表（`/proc/*/fd`、`fdinfo`）去掉保留 FD，guest 只看到自己的。容器的挂载表与属主数据库（FD 901、902，[OCI](OCI.md) R4、R5）也是保留 FD，不加 `--isolate` 时同样受保护；它们不是安全边界，broker 不读它们。写时复制的根（`--lower`，[OCI](OCI.md) R6）的下层由 broker 登记为只读树：payload 的合并视图被绕过时也写不到下层。
- **通道生命周期**：每个线程一个通道（FD 900 起）。槽位用满时回收已退出线程的槽位（tgkill 返回 ESRCH）。fork 子进程在 clone 返回时关掉继承的通道副本并清空自己那份槽位表；vfork 子进程与父进程共享内存，不动父进程的槽位，另取一个，父进程在 vfork 返回后释放它。
- **过滤器补充**（相对上表）：bind、connect、acct、swapon/swapoff、quotactl、process_madvise 也被拒绝；
  `prlimit64` 只允许 pid 0（payload 把自身 pid 改写为 0）。

验收目标与判定标准见 [ISOLATION_TESTING.md](ISOLATION_TESTING.md)。

## 分阶段实施

1. **broker 与请求路由（不装过滤器）**（已完成）：broker 进程、协议与参数表、目录树策略与安全解析；
   payload 的宿主路径调用改走 broker。功能回归应全部通过，证明路由完整。
2. **过滤器与 exec**（已完成，见上节）：装过滤器；按 FD 的元数据操作、`/proc/self/fd` 与 exec 流程改造；
   AF_UNIX 套接字按上表处理。对抗测试：跳进 payload 的 `svc` 打开隐藏文件、改写 payload 配置
   后访问只读区、硬链接只读文件、大小写别名、`/proc/<其他 pid>`、`process_vm_writev` 写 broker，
   均必须失败。
3. **性能**（两轮已完成，见 BENCHMARKS.md）：第二轮把通道改为共享区加自旋（见上文“通道”），一次空请求往返
   从 25–40 µs 降到 1–2 µs，broker lstat 6–7 µs，带回 FD 的 open 21–25 µs（FD 仍经套接字）。第一轮：路径解析的每一级查找原本都是一次往返。现为乐观解析：
   payload 按字面映射，最终请求带 `BROKER_STRICT`；broker 走查时遇到任何符号链接（需要跟随的末级也算）
   即返回 ELOOP、不执行操作，并在应答中报告该链接的宿主路径与目标；payload 带着已知链接重试，仍按乐观方式，
   至多 8 个链接，之后或链接目标在名字之后含 ".." 时改为完整解析。含 ".." 的路径、`/proc`、嵌套挂载点的祖先
   目录不走乐观模式。broker 逐级走查时先 lstat 判断类型，打开目录后核对 dev/ino，不依赖打开标志（本平台上
   `O_NOFOLLOW|O_DIRECTORY` 曾打开符号链接本身）。

## GPU 设备（2026-11-01 实现，见文末“实现”）

目标：显式授权后（`--isolate-device`，默认关闭），guest 进程能使用 GPU 设备节点（HarmonyOS 为
`/dev/hvgr0`），同时过滤器仍是唯一边界：授权之外的文件访问照旧全部经 broker，且不引入依赖 guest
可写内存的放行条件。

### 实测事实（2026-10-31，HarmonyOS 真机，原生运行，`test/isolation/gpu_bind_probe.c`）

驱动在 Vulkan 建逻辑设备时自己打开两次 `/dev/hvgr0`。用进程内 seccomp TRAP 换掉这两次 openat 的结果：

| 交给驱动的 FD | vkCreateDevice |
|---|---|
| 驱动自己打开 | 成功 |
| 另一进程打开、经 SCM_RIGHTS 传入（现在 broker 的做法） | -1 |
| fork 前父进程打开、子进程继承 | -1 |
| 本进程事先打开一个，两次都 dup 它 | -1 |
| 本进程事先打开多个，每次给一个新的 | 成功（建设备、分配并映射显存、写入） |
| 本进程打开后 exec 自身（同 pid，新地址空间） | -1 |

结论：上下文绑定到**打开者的地址空间**，每次 open 一个上下文，打开的时间无关。所以 broker 代开永远不行，
必须由使用它的 guest 进程（同一地址空间）自己执行 open。

宿主应用沙箱自带的 seccomp 对 Landlock、mseal、unshare（user/mount namespace）一律 SIGSYS，用户通知也不可用：
没有“内核持有的路径白名单”或“不可改写的内存”可借用，只能靠我们自己的过滤器。

### 方案：过滤器按“固定地址的常量路径”放行

过滤器读不到路径字符串，但能比较指针。放行条件：

- `openat(任意, P_i, flags)`：`P_i` 是 loader 映像只读段中第 i 个设备路径常量的地址（loader 为静态非 PIE，
  地址链接时固定）；只放行 `--isolate-device` 选中的那几个 i；`flags` 只允许 `O_ACCMODE`、`O_CLOEXEC`、
  `O_NONBLOCK`、`O_LARGEFILE`、`O_NOCTTY`（无 O_CREAT、O_PATH、O_TMPFILE、O_TRUNC、O_DIRECTORY）。
  路径是绝对的，dirfd 不参与解析。
- 设备路径表编译进 loader（如 `/dev/hvgr0`、`/dev/mali0`、`/dev/kgsl-3d0`、`/dev/dri/renderD128`），放在单独
  按页对齐的只读节；运行时只能选，不能填，因为内容必须来自 loader 文件本身。
- payload：guest 路径经 PRoot 翻译后的宿主路径等于选中的设备时，直接以 `P_i` 发 openat，不经 broker。

该条件安全，当且仅当**每个受过滤进程里 `P_i` 处都是 loader 映像中的那个常量**。需要以下不变量，全部由过滤器
或 broker 强制，不依赖 payload：

1. **受过滤进程都在运行 loader 映像**（归纳）：初始 loader 装过滤器；之后 `execveat` 只放行
   `fd == 898`（loader FD）且 `pathname == E`（同一只读节中的空串常量）且带 `AT_EMPTY_PATH`。
   FD 898 不可替换：过滤器拒绝 `close(898)`、覆盖 898 的 `close_range`、`dup3/dup2` 以 898 为目标、
   `fcntl(898, F_SETFD)`、`ioctl(898, FIOCLEX)`（payload 现已对这些“假装成功”，这里改由过滤器兜底）。
   `F_DUPFD` 取不到已占用的 898。副作用：现有剩余风险“`execveat` 带非空路径可执行任意文件”随之消除。
2. **常量页不可替换**：过滤器拒绝与该只读节区间 `[G0, G1)` 相交的 `munmap`、`mprotect`、`pkey_mprotect`、
   `madvise`、`mremap`（旧区间相交，或 `MREMAP_FIXED` 的新地址相交）、带 `MAP_FIXED` 的 `mmap`、
   带 `SHM_REMAP` 的 `shmat`、`remap_file_pages`；`userfaultfd` 整体拒绝。不带 MAP_FIXED 的提示地址与
   `MAP_FIXED_NOREPLACE` 不会覆盖已有映射，无需拦。区间检查在 BPF 里用 32 位两半与进位比较实现；只守这一节
   （一两页），loader 其余部分、payload 与 stub 岛不受影响。
3. **常量页的内容不可改**：
   - 它是 loader 文件的 MAP_PRIVATE 只读映射，未写过的页随文件内容变化：broker 启动时记录 loader 文件
     (dev, ino)，拒绝对它的写方式打开、截断、改元数据；loader 文件位于可写树内时拒绝启用 `--isolate-device`。
   - 绕过页保护的写入：`/proc/<pid>/mem`（FOLL_FORCE）由 broker 拒绝打开；ptrace、process_vm_writev 已拒绝。
4. **路径解析不受 guest 影响**：chroot、mount 一族已拒绝，unshare 被宿主沙箱拦截；启动时检查设备路径的各级
   祖先都不在任何可写树内、末级是字符设备，否则拒绝启用。

授予的能力仅是“打开选中的设备节点”；驱动 ioctl 面（内核驱动漏洞）是用户显式接受的剩余风险，写入
“剩余风险”一节。不加 `--isolate-device` 时过滤器与现在逐条相同。

### 否决的方案

- broker 代开 / SCM_RIGHTS / fork 前预开：见上表，上下文属于打开者。
- 初始 loader 装过滤器前预开一池 FD：只对初始进程有效（fork、exec 后的进程用不了），每建一个设备耗两个，
  池用完即止。若方案的区间检查与平台冲突，可作退路。
- 进程内不受过滤的辅助线程代开：与 guest 共享内存，可被劫持成不受过滤的线程。
- seccomp 用户通知 + CONTINUE：本平台不可用，且内核文档明确 CONTINUE 不能用于安全决策（检查后路径可被改写）。

### 验收标准（实现时）

- 正向：`--isolate --isolate-device /dev/hvgr0` 下 gpu_bind_probe 的 self 流程在初始进程、fork 子进程、
  exec 之后的进程、多线程中都成功；四套回归与 check-isolation 在加该选项后仍通过。
- 反向（均须 EPERM，broker 的情形为拒绝）：其他指针的 openat；`P_i` 但带 O_CREAT/O_PATH/O_TRUNC/O_DIRECTORY；
  未选中的 `P_j`；与常量节相交的每一种内存调用；`userfaultfd`；`execveat` 的 fd ≠ 898 或 pathname ≠ E；
  `close(898)`、`dup3(x, 898)`、`fcntl(898, F_SETFD)`、`close_range` 覆盖 898；写方式打开 loader 文件
  （含经硬链接、大小写别名）；打开 `/proc/self/mem`。
- 不加选项时：过滤器程序与现在逐条一致（单元比较）。

### 实现（2026-11-01）

用法：`--isolate --isolate-device /dev/hvgr0`（可重复，只能选表中的路径；不加 `--isolate` 时拒绝启动）。
guest 视图里的设备路径必须翻译成同一宿主路径：compat 模式，或 container 模式下 `-v /dev/hvgr0:/dev/hvgr0`
（或 `-v /dev:/dev`）。

- **常量页**：`src/loader/devices.c` 的 `g_isolate_page`，单独占 `.rodata` 里按页对齐的一页（当前构建为
  `0x3f00003000`）：16 字节标记 `elf-isolate-pg1`（供探针定位）、空串 `E`、四个设备路径各 64 字节。
  `--guest-filter-dump [--isolate-device …]` 打印过滤器程序与该页地址后退出（测试用）。
- **过滤器**（`guest_filter.c`）：在调用号判断之前插入跳转（`JEQ` + `JA`），各规则段放在基础程序之后、
  自带返回（经典 BPF 只能前跳，条件跳转不超过 255 条）。2026-11-01 起除 openat 段外都不再依赖选项
  （执行可信链）；加选项时多出 openat 段（选中的 `P_i`，标志只允许上表五类）。其余规则段：execveat（fd 898、`E`、`AT_EMPTY_PATH`）、close/close_range/dup3/fcntl(F_SETFD)/
  ioctl(FIOCLEX) 对 898、与常量页相交的 munmap/mprotect/pkey_mprotect/madvise/remap_file_pages、
  `MAP_FIXED` 的 mmap、mremap（旧区间或 `MREMAP_FIXED` 新区间）、`SHM_REMAP` 的 shmat、userfaultfd，
  另加 unshare、setns（宿主沙箱也拦截，这里不依赖它）。区间相交用 32 位两半比较，`g0 - a` 存在 BPF 草稿
  内存 M[0]/M[1]。FD 参数只比较低 32 位，与内核按 unsigned int 截断一致。约 500 条指令。
- **loader**：选中设备时 loader FD 必须恰好是 898（被占用则拒绝启动），并核对它就是启动检查过的 loader 文件；
  payload 配置新增 `device_mask`、各设备路径与 `E` 的地址（payload ABI 21），子 loader 经
  `--isolate-devices <掩码>` 继承选择。
- **payload**（`broker_client.c` 的 `host_syscall`）：翻译后的宿主路径等于选中的设备、标志在允许集合内时，
  直接以 `P_i` 发 openat；bridge 的延迟打开会加 `O_NOFOLLOW`，对设备去掉它（末级在启动时确认是字符设备，
  其名字由 broker 保护）。exec 用 `E` 作 execveat 的路径。
- **broker**（`broker.c`），与上面的设计有两处不同：
  1. 不再“loader 文件在可写树内时拒绝启用”：compat 模式的根 `/` 是可写树，这样选项在 compat 下无法使用。
     改为按对象拒绝：启动时记录 loader 文件的 (dev, ino)，`check()` 对写类操作检查对象，写方式 openat 与
     truncate 在打开之后再对 FD 做 fstat（名字可能在检查后被换掉），fchmod/fchown/fsetxattr/fremovexattr
     检查收到的 FD。经硬链接、大小写别名或 `/proc/self/fd/N` 都是同一对象。（broker 原本就按 dev/ino 把
     loader 文件识别为只读树，这里是不依赖解析路径、无竞争的第二层。）
  2. 不再“设备路径的祖先在可写树内时拒绝启用”（同样排除了 compat 模式）。改为：启动时逐级 lstat 设备路径，
     每级必须是目录（不是链接）、末级是字符设备，记录各级目录的 (dev, ino)；之后 broker 拒绝在这些目录中
     unlinkat 与 renameat（两端），所以设备路径的各级名字不能被删除或替换（创建新名字不影响已有名字）。
  另外拒绝 `/proc/<pid>/…/mem`（含 task 下）。本机上宿主本来就不让 broker 打开 guest 的 mem
  （EACCES），这一条不依赖它。
- **线程**：本机 Vulkan 在任何非主线程里建设备都会崩溃（原生也一样：从 ld-musl 跳到非代码地址），所以
  “多线程”验收为主线程建设备时另一线程反复经 payload 打开设备。

### 验收结果（2026-11-01，HarmonyOS 真机）

`test/isolation/device.py`（并入 `make check-isolation`），两种构建：

- 不加选项时过滤器与之前逐条相同；加选项后多出设备规则。
- 拒绝启动：不带 `--isolate`、表外路径、本机不存在的 `/dev/mali0` 等。
- 正向：Vulkan 在初始进程、fork 子进程、exec 之后、多线程（见上）中建设备、分配并映射 1 MiB 显存、写入后
  读回，均成功；对照：只加 `--isolate` 时 createDevice 失败。
- 反向（从 payload 自身的 svc 发出）：其他指针（同内容副本、高 32 位不同、常量中间）、O_CREAT/O_PATH/
  O_TRUNC/O_DIRECTORY/O_TMPFILE/O_NOFOLLOW/O_APPEND、未选中的三个常量、与常量页相交的每一种内存调用
  （含从下方跨入、MAP_FIXED 覆盖、mremap 移入）、userfaultfd、execveat 的其他 FD / 自带空串 / 缺
  AT_EMPTY_PATH / 按路径、execve、close/dup3/fcntl/ioctl/close_range 对 898（含高位）均 EPERM，或被宿主
  沙箱以 SIGSYS 终止（pkey_mprotect、remap_file_pages、shmat、unshare、setns、close_range）。相邻页的
  mprotect、自己的 MAP_FIXED、提示地址 mmap 正常；`execveat(898, E, …, AT_EMPTY_PATH)` 确实运行 loader。
- broker：loader 文件本名与大小写别名以 O_RDWR/O_WRONLY/O_TRUNC 打开、truncate、`/proc/self/fd/898`
  写方式重开均失败，只读打开正常，文件哈希与权限不变；硬链接本机宿主不允许创建（SKIP）。
  `/proc/self/mem`、`/proc/<pid>/mem`、`/proc/<pid>/task/<tid>/mem` 失败、`/proc/self/status` 正常；
  `/dev/hvgr0` 的改名与删除失败。
- 回归：见 ISOLATION_RESULTS.md。

## 剩余风险（本模式也不能消除）

- 内核漏洞（guest 仍直接使用 read/write/mmap 等）；
- 资源耗尽与拒绝服务（无 cgroup；guest 可以杀掉 broker，结果是失败即关闭）；
- 侧信道；
- 与宿主应用同一 uid：kill 其他同 uid 进程、网络、经 binder 等访问系统服务；
- （已消除，2026-11-01）原先不加 `--isolate-device` 时 `execveat` 带非空路径可执行任意文件；现在执行可信链对
  所有 `--isolate` 生效；
- 加 `--isolate-device` 时：所选设备驱动的 ioctl 面（内核驱动漏洞），由用户显式接受；
- 宿主上已有的跨区硬链接（同一 inode 在只读与可写区都可见）；
- 从宿主继承来的数据报 UNIX 套接字（可向任意路径名发送）。
