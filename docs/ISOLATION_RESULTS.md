# 隔离模式验收结果

按 [ISOLATION_TESTING.md](ISOLATION_TESTING.md) 执行；用例在 `test/isolation/`（`make check-isolation`）。

## 2026-10-31，第一轮

- 设备：HarmonyOS 终端沙盒，HongMeng Kernel 1.13.0，AArch64；经 SSH 在设备上原生构建与运行。
- 构建：`build/elfloader`、`build/elfloader-guarded`，均带 `--isolate`。
- 布局：宿主测试目录位于应用临时目录（`/data/storage/el2/base/haps/entry/temp/iso-accept-*`）：
  `outside/`（不在任何树内，含哨兵、程序与监听中的 UNIX 套接字）、`ro/`→`/ro`、`hidden/`→`/hidden`、
  `rw/`→`/rw`；guarded 构建的权限向量 `wrdwwr`（root w、/ro r、/hidden d、/rw w、/dev/null w、/proc r）。
  plain 构建中所有树都可写，因此 B、C、K 与 D/E/I/L 中涉及只读的部分只在 guarded 构建上判定。
- 方法：每项操作分别经 payload 正常路径与从 payload 自身 `svc` 直接发出；对照组证明不隔离时直接调用能读到
  树外哨兵。前后对 `outside/`、`ro/`、`hidden/` 做内容哈希与元数据比较；任何输出中出现树外或 `d` 树哨兵
  即失败。

| 目标 | plain | guarded | 说明 |
|---|---|---|---|
| A 树外不可达 | PASS | PASS | 直接调用 stat/statx/readlink/access/statfs/chdir/xattr/inotify/open/列目录/exec 均 EPERM；rootfs 中指向宿主的绝对、相对符号链接不逃逸 |
| B `d` 树不可见 | — | PASS | 正常路径 ENOENT，直接调用 EPERM |
| C `r` 树只读 | — | PASS | 写方式打开、O_TRUNC、O_CREAT、O_TMPFILE、删除、chmod/chown/utime、truncate、xattr、mkdir/mknod/rmdir、符号链接、两向改名、bind 均失败；读、列目录正常 |
| D 跨树 | PASS | PASS | 只读/隐藏文件不能硬链接或改名到可写区；可写区指向只读文件的链接不能用于写；新建指向宿主的符号链接不能打开 |
| E 篡改 payload 配置 | PASS | PASS | 改 root、权限向量、guard 级别后仍不能访问树外或写只读区；关掉 isolate 标志后直接调用 EPERM |
| F guest 过滤器 | PASS | PASS | 表中 74 个调用号从 payload 的 svc 发出均 EPERM（或被宿主沙盒以 SIGSYS 终止）；execveat 规则、AF_UNIX/数据报规则、prlimit64、FS_IOC_SETFLAGS、x8 高位均符合；经 shell exec 后仍生效；`Seccomp: 2` |
| G 进程边界 | PASS | PASS | /proc 其他 pid（status、mem、1/environ）EACCES；process_vm_readv/writev、ptrace、pidfd_getfd 拒绝 |
| H 失败即关闭 | PASS | PASS | 从 svc 关闭通道与控制套接字后访问失败（含子进程）；从宿主侧杀死 broker 进程后访问返回 ECONNREFUSED/EACCES |
| I 伪造请求 | **FAIL→PASS** | PASS | 见下文缺陷 1；修复后：树外路径、`..`、只读写开、只读硬链接、无 FD 的魔链接标志、越界长度、未终止字符串、未知调用号、截断消息、FD 数不符、连接树外套接字（两种形式）均被拒，之后合法请求仍正常 |
| J exec | PASS | PASS | 可读程序可 execve 与 fexecve；隐藏程序不能执行；直接 execveat 按路径 EPERM |
| K `/proc/self/fd` 与按 FD 操作 | — | PASS | 只读对象不能以写方式重开；fchmod/fchown/futimens/fsetxattr/ftruncate/write 失败（直接调用 EPERM）；fstat、statx(fd) 正常 |
| L UNIX 套接字 | PASS | PASS | 可写区 bind 成功；直接 bind/connect EPERM |
| 哨兵 | PASS | PASS | `outside/`、`ro/`、`hidden/` 内容与元数据前后一致 |

合计 107 项 PASS，0 FAIL（修复缺陷 1 之后）。

### 缺陷 1：glue 基目录整棵可写（已修复）

broker 把 glue 基目录（宿主 TMPDIR，HarmonyOS 上为应用临时目录）作为可写树。guest 经 payload 正常路径
无法命名其中的文件，但伪造的 broker 请求可以：plain 构建中，对测试目录下 `outside/secret`（恰在
TMPDIR 内）的伪造 openat 返回了 FD 并读出哨兵内容。修复：glue 树改为只开放 `proot-glue-*` 名下的内容，
基目录本身与其他名字不可达（`src/loader/broker.c`，访问类别 `g`）。修复后 I 通过，回归不变。

### 测试工具本身的问题（不是隔离缺陷）

- 不隔离的对照组读到哨兵是预期结果，最初被计为泄露；
- guest 无法从套接字的对端凭据得知 broker 的 pid（socketpair 由初始 loader 在 fork 前创建，凭据是 guest 自己）；
  改由测试在宿主侧按进程组杀死 broker；
- guarded 构建在 `--guard-file-access` 下需要 `--allow-stream-input` 才能读 stdin 的同步行。

### 未覆盖

- 大小写别名（测试目录在大小写敏感的存储上；第四轮已补）；
- 继承自宿主的数据报 UNIX 套接字、`execveat` 带非空路径（已列为剩余风险）；
- N（实际工作负载在隔离下的完整对比与耗时）只做了抽查：Ubuntu rootfs 中 python subprocess 与 gcc 正常。

## 2026-10-31，第二轮（第三阶段性能改动之后）

同一设备与方法。新增用例：可写树中指向树外目录的目录链接（经正常路径与伪造请求访问其下文件都必须失败）、
树内相对目录链接（必须可用，覆盖乐观解析的重试）。两种构建共 115 项全部通过；四套回归在常规与 `--isolate`
下均通过。

性能改动过程中发现：broker 逐级走查时用 `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)` 打开中间分量，本平台在 broker
进程中对符号链接返回了成功（打开的是链接本身，之后的查找以 ENOTDIR 失败，因此是失败即关闭，未越界）。
broker 现在先 lstat 判断类型、打开后核对 dev/ino。此前 payload 总是先自己解析符号链接，broker 很少走到这条路径。

## 2026-10-31，第三轮（实际工作负载，目标 N）

`python3 test/isolation/workloads.py /data/storage/el2/base/files/apt-root [--loader elfloader-guarded]`：
Ubuntu rootfs，每项在常规与 `--isolate` 下各跑一次（`--runs 1`），只写绑定的 /w。

| 工作负载 | elfloader 常规 s | `--isolate` s | 比值 | elfloader-guarded 常规 s | `--isolate` s | 比值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gcc+make（9 个文件，-j4） | 0.83 | 0.96 | 1.16 | 0.78 | 0.97 | 1.25 |
| git init/add/commit/log | 0.80 | 1.03 | 1.29 | 0.68 | 0.99 | 1.44 |
| python 标准库导入 | 0.25 | 0.25 | 0.98 | 0.20 | 0.28 | 1.39 |
| python venv + pip list | 4.31 | 4.77 | 1.11 | 4.08 | 4.72 | 1.16 |
| node + npm | 1.78 | 1.97 | 1.10 | 1.41 | 1.92 | 1.36 |
| tar czf /usr/include | 1.14 | 1.55 | 1.36 | 0.94 | 1.42 | 1.51 |
| find（python 库） | 0.11 | 0.12 | 1.09 | 0.09 | 0.14 | 1.52 |
| dpkg-query | 0.05 | 0.07 | 1.36 | 0.06 | 0.10 | 1.68 |

所有输出与常规模式一致。设备负载均值约 20，单次计时只作量级参考。

### 缺陷 2：posix_spawn/closefrom 在隔离模式下永远循环（已修复）

`python3 -m venv`（ensurepip 启动子进程）卡住。Python 3.14 用 glibc posix_spawn 加 closefrom(3)；payload 对
close_range 返回 ENOSYS，glibc 退回逐个关闭：列 /proc/self/fd，每轮只要关过 FD 就从头重读。保留 FD close 时假装
成功但仍然打开，所以每轮都“关”它们，循环不会结束。现在 close_range 由 payload 代办并返回成功。新增验收 K
closerange：close_range(3, ~0) 成功，普通 FD 已关闭，之后路径调用仍然可用。两种构建共 117 项通过。

### 缺陷 3：线程通道槽位不回收（已修复）

排查缺陷 2 时发现：每个线程的通道槽位（64 个）在线程退出后一直占着，进程累计创建第 64 个线程起，所有路径调用
都返回 EACCES（Python 先后起 100 个线程即可复现）。另外 vfork 子进程会清掉共享内存里父进程的槽位（父进程之后
重开通道，碰巧可用）。现在槽位用满时回收已退出线程的槽位，fork/vfork 由 clone 通知处理；procfs FD 列表不再显示
保留 FD。新增验收 K channels：200 个先后创建的线程全部成功、vfork 子进程用过 broker 后父进程仍可用、
/proc/self/fd 列表中没有保留 FD。两种构建共 119 项通过；四套回归在常规与 `--isolate` 下均通过。

## 2026-10-31，第四轮（大小写别名、apt、数据报套接字）

**大小写别名**（`test/isolation/case_alias.py`，`make check-isolation` 的一部分；没有大小写不敏感的存储时 SKIP）。
在 /storage/Users（hmdfs，大小写不敏感）上：work 绑定到 /work（可写），work/Secret 绑定到 /work/Secret（guarded 下隐藏），
work/Ro 绑定到 /work/Ro（只读）。guarded 构建中 Secret 的四种拼写的 open/stat/list 全部失败，Ro 的三种拼写可读、
不可写（open 写、chmod、unlink、rename、link 全部失败）；把 work/secret/key、work/SECRET/key 和 work/ro/file 等
宿主路径直接伪造给 broker，同样被拒绝。对照：伪造请求读可写树中的 work/FILE 成功，说明拒绝来自树的权限而不是拼写。
普通构建（全部可写）每种拼写都能读到。共 38 项通过，未发现缺陷。

**apt**（`test/isolation/apt_install.py ../ubuntu-base-26.04.1-base-arm64.tar.gz [--loader elfloader-guarded]`）：全新解压的
Ubuntu base 中 apt-get update、安装 tree 与 jq 并运行、卸载 jq、列出包状态。两种构建在 `--isolate` 下输出与常规模式
一致。耗时差异来自镜像：镜像断开连接（“Remote end closed connection”）时 apt 按指数退避重试，等待期间主循环以零超时
反复 select 并 stat 正在下载的文件（apt 的行为，常规模式同样发生，一次 update 可达数万到上百万次）；隔离模式下每次
stat 是一次 broker 往返，只多耗 CPU。常规与隔离同时运行五对：14.3/9.5、14.9/8.2、85.3/191.5、14.1/9.8、34.6/16.1 秒。

**数据报 UNIX 套接字**（评估，未改）：

| 用法 | 常规 | `--isolate` |
| --- | --- | --- |
| glibc syslog()、Python SysLogHandler('/dev/log')、logger（rootfs 中无 /dev/log） | 成功（静默丢弃） | 相同 |
| socketpair(AF_UNIX, SOCK_DGRAM) 收发 | 成功 | 成功（改为顺序包） |
| socket(AF_UNIX, SOCK_DGRAM)；树内命名或抽象名的 bind + sendto | 成功 | EPERM |
| UDP | 成功 | 成功 |

只有直接使用命名或抽象名数据报套接字的程序受影响。guest 持有的数据报套接字可以用 sendmsg 的 msg_name 向任意路径
发送，过滤器检查不到内存中的地址，因此安全的支持只能是 broker 代理收发（guest 拿顺序包的一端，broker 持有真正的
数据报套接字并按树检查目标）。出现具体需求前不做。
