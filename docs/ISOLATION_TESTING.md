# 隔离模式验收（`--isolate`）

本文给出隔离模式的**验收目标、运行方式与判定标准**，供另一位执行者编写并运行具体用例。
隔离模式是本项目应用沙箱框架的一部分：在 HarmonyOS 应用沙箱内，为 agent 提供受控的文件视图，
文件访问的最终授权放在 guest 碰不到的 broker 进程里（设计见 [ISOLATION.md](ISOLATION.md)）。
验收的目的是确认这条边界按设计成立；本文不规定具体用例或实现手法。

## 被测对象

- 构建：`make build` 生成 `build/elfloader` 与 `build/elfloader-guarded`（两者都支持 `--isolate`）。
- 基本形式：

  ```
  build/elfloader --isolate --mode container --root <rootfs> -v <宿主目录>:<guest 路径> ... -- <程序> [参数]
  build/elfloader-guarded --isolate --guard-file-access <向量> --root <rootfs> -v ... -- <程序>
  ```

  `<向量>` 每个字符对应 root 与依次每个 `-v` 的权限：`d` 不可见、`r` 只读、`w` 读写
  （长度 = bind 数 + 1）。plain 构建与不带向量的 guarded 构建中所有树都是 `w`。
- broker 只认这些目录树：root、每个 bind 的宿主源目录、glue 目录（`PROOT_TMP_DIR`/`TMPDIR`/`/tmp`，`w`）、
  loader 二进制（`r`）。`/proc` 仅在配置了 `-v /proc:/proc` 时可见，且只能访问请求者自己的 pid。

## 能力假设（测试应按此给 guest 建模）

被测 guest 程序被视为不可信，具备以下能力；验收结论必须在这些能力下成立：

1. 在自身地址空间内任意读写内存，包括 loader/payload 的代码、数据与配置块；
2. 从任意地址发出任意系统调用，包括跳到 payload 自己的 `svc` 指令；
3. 使用继承到的所有 FD（控制套接字、loader FD、通道 FD），向它们写任意字节；
4. fork、exec、多线程，以及关闭或替换任何 FD。

探针可以用 `test/lib.py` 的 `build_probe`（静态、自由环境、入口 `_start`）或设备上的
`clang -static` 编译，放进 rootfs 或一个 bind 目录后在 guest 里运行。现有参考：
`test/fs_policy/isolate.py` 与 `isolate_probe.c`（从 payload 的 `svc` 发出 openat）。

## 运行方式

设备：HarmonyOS（HongMeng 内核）AArch64 终端沙盒，是唯一有效的验收平台；Android 或 qemu
上的结果不算数。rootfs 用 `make check-alpine` / `make check-ubuntu` 解出的
`build/alpine-test-root`、`build/ubuntu-test-root`。宿主测试目录放在大小写敏感、允许 UNIX 套接字的位置
（如 `/data/storage/el2/base/files/...`），不要放在 `/storage/Users` 下。

1. **功能回归**（必须先通过）：

   ```
   make check && make check-guarded
   ELF_LOADER_OPTIONS=--isolate make check
   ELF_LOADER_OPTIONS=--isolate make check-guarded
   ELF_LOADER_OPTIONS=--isolate make check-alpine ALPINE_ARCHIVE=...
   ELF_LOADER_OPTIONS=--isolate make check-ubuntu UBUNTU_ARCHIVE=...
   ```

   `ELF_LOADER_OPTIONS` 只作用于经 `test/lib.py` 启动 loader 的测试。
2. **验收用例**：建议放在 `test/isolation/`，每个目标一个脚本，两个构建各跑一遍，逐条输出
   `PASS:`/`FAIL:` 与原因；入口脚本汇总并以非零退出码表示失败。
3. **哨兵**：每轮在以下位置放入随机内容的哨兵文件与目录，并在前后记录内容哈希与 `stat`
   （大小、权限、属主、mtime/ctime、inode、链接数）：
   - 任何树之外的宿主目录（例如与 rootfs 并列的目录）；
   - `d` 树与 `r` 树内部；
   - 一个 `w` 树作为对照（应当可以改变）。

## 验收目标

每项目标都要在两个构建上、分别经 **payload 的正常路径**（普通 libc 调用）与
**绕过 payload 的直接调用**（能力假设 2）各验证一次，除非另有说明。

| 编号 | 目标 | 判定 |
|---|---|---|
| A | 树外的宿主路径不可达：打开、stat/statx、readlink、access、列目录、chdir、exec、xattr、inotify 都失败 | 返回错误；guest 输出中不含任何树外哨兵的内容或元数据 |
| B | `d` 树不可见 | 所有访问 ENOENT（或 EPERM，直接调用时）；父目录中看不到它的名字以外的信息 |
| C | `r` 树只读：写方式打开、O_TRUNC、O_TMPFILE、创建、删除、改名、硬链接、符号链接、mkdir/mknod、chmod/chown/utimes、truncate、setxattr/removexattr、bind 套接字都失败；读、stat、列目录、exec 正常 | 只读哨兵前后哈希与 `stat` 完全一致 |
| D | 跨树操作不能扩大权限：rename/link 两端都要 `w`；只读文件不能获得可写的名字；绝对、相对、`..` 与多级符号链接不能离开树，也不能把 `r` 对象变成 `w`；嵌套 bind、同一目录多处 bind、大小写别名按其对象所在树的权限处理 | 同 A–C |
| E | 篡改 payload 无效：改写 payload 配置（root、bind、权限向量、loader 路径等）或策略状态后，A–D 的结论不变 | 同 A–C；只有 broker 侧的配置起作用 |
| F | guest 过滤器：ISOLATION.md“guest 过滤器”表中的每个调用，从 guest 代码与 payload 代码地址发出都返回 EPERM；`execveat` 只有带 AT_EMPTY_PATH 时放行；`socket(AF_UNIX)` 与 `socketpair(AF_UNIX, SOCK_DGRAM)` 被拒；`prlimit64` 只允许 pid 0 | 逐号核对返回值；表外的普通调用（read/write/mmap/clone 等）不受影响；过滤器在 fork、exec 与新线程中都在（`/proc/self/status` 的 `Seccomp` 字段，需 `/proc` bind） |
| G | 进程边界：不能读写 broker 或其他 guest 进程的内存与 FD（process_vm_*、ptrace、pidfd_getfd、`/proc/<其他 pid>/…`）；broker 不是任何 guest 进程的子进程 | 全部失败；broker 内存与状态不变 |
| H | 失败即关闭：broker 不可用时（被终止、通道被关闭、控制套接字被替换），guest 的文件访问失败，不会退回到直接访问 | 返回 EACCES 等错误；哨兵不变 |
| I | 请求不被信任：向控制套接字或通道发送畸形请求（截断、长度越界、未知调用号、缺少或多余 FD、FD 类型不符、伪造的 `/proc/self/fd` 标志、超长路径）不能越权，也不能让 broker 崩溃或停止为其他线程/进程服务 | 越权一律失败；之后正常请求仍成功 |
| J | exec：程序、脚本解释器（含多级）与 PT_INTERP 都经 broker 按权限打开；`d` 树与树外的程序不能执行；子 loader 不做按路径的调用 | `r`/`w` 树内的程序正常执行；其余失败且不泄露内容 |
| K | `/proc/self/fd` 与按 FD 的操作：经 `/proc/self/fd/N` 重新打开不能提升访问（`r` 树对象不能以写方式重开；树外对象至多保持原 FD 的访问方式，O_PATH FD 不能重开）；fchmod、fchown、fsetxattr、fremovexattr、futimens 对 `r` 树和树外对象失败；fstat、fstatfs、read、readlink 正常 | 哨兵不变；功能调用结果与非隔离模式一致 |
| L | UNIX 套接字：只能经 broker 得到流或顺序包套接字；bind 到 `r`/`d` 树或树外失败，bind 到 `w` 树成功；connect 到树外或 `d` 树的套接字失败；数据报 socketpair 以顺序包代替；抽象命名空间与 AF_INET 不受限（属网络范围） | 按左列逐项核对 |
| M | 保留 FD：guest 关闭、dup 覆盖或设 close-on-exec 于控制套接字、loader FD 与通道 FD，不影响后续访问与 exec；即便真的失去它们，也只导致自身访问失败（H） | 后续访问与 exec 正常，或按 H 失败 |
| N | 实际工作负载：在 `--isolate` 下运行 apt、gcc/make、git、python venv+pip、node/npm（见 STATUS.md 已验证的工作流） | 记录成功与否及与非隔离模式的耗时比；性能属第三阶段，只记录不判定 |

## 判定标准

- **PASS**：操作返回预期的失败（记录实际 errno；可接受集合为 EPERM、EACCES、ENOENT、EROFS、
  ENOTDIR、ELOOP，具体以用例说明为准），宿主哨兵前后一致，broker 仍在运行（H 除外），
  guest 输出中没有树外或 `d` 树的内容。
- **FAIL（安全缺陷）**：任何一次读到树外或 `d` 树哨兵的内容或元数据、改变了 `r` 树或树外的任何
  状态、在 `d` 树中看到名字、读写了其他进程的内存，或 broker 因请求崩溃。FAIL 需附最小复现
  （命令行、构建、探针源码、输出）。
- **功能 FAIL**：回归或工作负载在 `--isolate` 下失败而非隔离模式成功。与安全缺陷分开记录。
- **不判 FAIL 的已知剩余风险**（ISOLATION.md“剩余风险”）：内核漏洞、资源耗尽、侧信道、同 uid 的
  信号/网络/系统服务、`execveat` 带非空路径执行任意可执行文件（新进程仍打不开文件）、宿主上已有的
  跨区硬链接、继承自宿主的数据报 UNIX 套接字。发现时记录，不计入失败。

## 结果记录

结果写入 `docs/ISOLATION_RESULTS.md`：日期、提交号、设备与内核版本、每个目标在两个构建上的
PASS/FAIL、实际返回值与备注；FAIL 附复现。汇总一行同时写入 `docs/STATUS.md`。
