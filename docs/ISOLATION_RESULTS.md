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

- 大小写别名（测试目录在大小写敏感的存储上）；
- 继承自宿主的数据报 UNIX 套接字、`execveat` 带非空路径（已列为剩余风险）；
- N（实际工作负载在隔离下的完整对比与耗时）只做了抽查：Ubuntu rootfs 中 python subprocess 与 gcc 正常。
