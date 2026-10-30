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

- 每个 guest 线程一条私有通道（`SOCK_SEQPACKET`）：payload 首次需要时建 socketpair，经继承的
  控制套接字把一端交给 broker；broker 为每条通道 fork 一个处理进程（阻塞操作互不影响）。
  fork 后的子进程按 pid 发现通道不属于自己，重新建立。
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

**放行**：其余调用。exec 只能用 `execveat(fd, "", …, AT_EMPTY_PATH)`（过滤器检查标志位；
过滤器无法检查路径内容，带非空路径时内核仍会按路径执行，但新程序继承过滤器，打不开任何文件，
最多泄露可执行文件本身的内容，记为剩余风险）。

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

## 分阶段实施

1. **broker 与请求路由（不装过滤器）**：broker 进程、协议与参数表、目录树策略与安全解析；
   payload 的宿主路径调用改走 broker。功能回归应全部通过，证明路由完整。
2. **过滤器与 exec**：装过滤器；按 FD 的元数据操作、`/proc/self/fd` 与 exec 流程改造；
   AF_UNIX 套接字按上表处理。对抗测试：跳进 payload 的 `svc` 打开隐藏文件、改写 payload 配置
   后访问只读区、硬链接只读文件、大小写别名、`/proc/<其他 pid>`、`process_vm_writev` 写 broker，
   均必须失败。
3. **性能**：路径解析的每一级查找都是一次往返（约 20 µs），需要测量并优化（批量查找、
   broker 侧解析缓存）。

## 剩余风险（本模式也不能消除）

- 内核漏洞（guest 仍直接使用 read/write/mmap 等）；
- 资源耗尽与拒绝服务（无 cgroup；guest 可以杀掉 broker，结果是失败即关闭）；
- 侧信道；
- 与宿主应用同一 uid：kill 其他同 uid 进程、网络、经 binder 等访问系统服务；
- `execveat` 带非空路径时可执行任意可执行文件（不能读写文件，但可读取其映像内容）；
- 宿主上已有的跨区硬链接（同一 inode 在只读与可写区都可见）。
