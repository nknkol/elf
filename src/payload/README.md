## Payload/Hook 说明（proot 类场景）

- 目标：通过内存打补丁的方式高性能 hook（如 openat 等），实现类似 proot 的路径重写/隔离。`elfloader` 本身不依赖宿主 libc；payload 当前以 `-nostdlib` 构建的极简运行时（裸 syscall + 私有 TLS/栈），不链接 musl（后续如需更多 libc 能力可切换静态 musl）。
- 避免递归/重入：在 hook 内不要调用宿主 libc 的同名封装，否则可能再次触发 hook 或进入宿主 libc 锁。推荐直接用 `syscall(SYS_xxx, …)`/低级 `write` 输出日志，或在 TLS 里做递归保护位。
- 路径改写：把宿主传入的指针复制到 payload 自己的堆/栈上再改写，修改后直接发内核 `syscall`。不要用宿主的 `openat/printf` 等，以免重入。
- 资源隔离：payload 不依赖宿主 libc/TLS/栈/堆；当前构建没有宿主 malloc 依赖，使用私有 TLS/栈，避免注册全局信号处理/atexit 到宿主。
- Stub 分配：优先在目标附近 mmap 一页（不依赖 NOREPLACE），保持单条分支可达；如果跨距过大再考虑双层跳转。

## 面向 proot 类容器的方案/现状

- 目标：用内存补丁（stub + payload）在 syscall 层做路径虚拟化/隔离，性能和兼容性优于 ptrace 类 proot，尽量不干扰宿主进程。
- 架构：`elfloader` 自举 + 静态 PIE payload（当前 `-nostdlib` 极简运行时，私有 TLS/栈；如需更多 libc 功能可改为静态 musl）。在目标 ELF 的 `svc` 前插入跳转，进入 payload 做逻辑处理，返回前恢复寄存器状态。
- Hook 范围（规划）：`open/openat/stat/fstatat/access/execve/chdir/getcwd/mkdir/mknod/unlink/rename/link/symlink/readlink/socket/bind/connect` 等路径/网络相关 syscall，按环境变量开关。
- 路径虚拟化：把宿主传入路径复制到 payload 自己的内存，按根替换/bind 映射表重写后直接 `syscall`，不调用宿主 libc，避免重入。
- 默认 loader 绑定：无需手动 PROOT_BIND，自动把 guest `/elfloader` 映射到 `CONFIG_DEFAULT_LOADER_DST`。
- loader 自动定位（当前实现）：只依赖 `/elfloader` 绑定路径；`HOOK_LOADER_PATH`/`HOOK_LOADER_NAME` 尚未实现，后续作为 TODO。
- 重入与日志：TLS 中放递归保护标记，hook 内只用裸 `syscall(SYS_write,…)` 输出日志，避免再次触发 hook 或宿主 libc 锁。
- Stub 策略：优先在目标附近 hint mmap 一页可执行，保证单条分支可达；如遇距离问题，再设计中间跳板（短跳到跳板，再长跳到远 stub）。
- 状态：当前代码回到稳定的原始方案（`-nostdlib` 极简运行时 + 私有 TLS/栈，简单 hint mmap stub），tiny_target/payload_demo 跑通；复杂 proot 功能未实现。
- 开发路径：
  1) 按规划实现路径映射表与 openat/readlink 等基本 hook，增加 TLS 递归保护。
  2) 补充配置入口：环境变量设置 root/bind 映射、log 级别、hook 范围。
  3) 设计并集成中间跳板作为距离兜底；完善 stub 分配日志。
  4) 自检初始化：如后续切到 musl，可在 payload 入口可选调用 `__libc_start_init`，确保 musl 运行时就绪。
  5) 测试矩阵：最小 SVC（tiny_target）、payload_demo、实际路径重写场景；如有 CI，qemu aarch64 自测。
- 注意事项：
  - 只用 payload 自己的 libc/malloc/TLS/栈，不触碰宿主 TLS/栈/brk。
  - 避免在 hook 内调用宿主 libc 包装，避免递归；必要时在 TLS 里做 reentrancy guard。
  - 不注册宿主范围的全局信号/atexit 回调；谨慎修改宿主的全局资源（fd/env）。
  - 日志和调试默认走裸 syscall，减少依赖。

## 开发注意事项（近期踩坑）

- 桩/入口不要额外破坏调用方认为“保持不变”的寄存器。曾因入口快速过滤先改写 x9、桩复用 x16/x17/x30 未保存，导致返回时上下文损坏触发 SIGSEGV。修复：快速过滤直接比较 x8；stub 先保存/恢复 x16/x17，恢复 x30 后用立即分支返回原 SVC+4。新增指令/寄存器时务必一并保存或更新调用约定。
- 内联 `svc` 的调用方通常不会把 x9/x16/x17 写进 clobber，依赖 hook 保持 ABI；尽量在 hook 端保持寄存器无副作用，避免逼调用方改汇编。
- 共享配置 memfd 踩坑：强行让子 loader 通过共享内存拿配置，在平台不支持 memfd 或 fd 被关闭时会 mmap 失败甚至段错误。应先区分主/子 loader（参数或标志位），共享内存传递要做 magic/version/size 校验，不可用时回退配置文件，不要在校验失败时继续解引用。
- PATH/软链接/脚本执行踩坑：`execve` 不能只看 `argv[0]`，必须使用真实 pathname (`args[0]`) 去重写路径、展开软链接；否则 `PATH` 解析出的 `/bin/ls` 会因 argv[0]="ls" 被当成当前目录文件而报 ENOENT。软链接展开后若指向 ELF 走 loader；指向脚本则提前解析 shebang，把解释器作为 exec 目标并把脚本作为参数传入，避免交给内核直接解析导致解释器逃逸 root/bind。

## Hook 列表与状态

标记说明：✔ 完成、□ 部分完成、✘ 未 hook。

| 状态 | 命令 | 为什么 hook | hook 了什么（子项同样标记） |
| ---- | ---- | ----------- | -------------------------- |
| ✔ | getcwd | 返回路径需要映射到虚拟根/绑定 | ✔ 回填 guest 路径到调用方缓冲区；✔ 调整返回长度 |
| ✔ | chdir | 进程 cwd 需受虚拟根/绑定限制 | ✔ 重写路径后直接 syscall |
| ✔ | mkdirat | 目录创建应落在虚拟根/绑定 | ✔ 重写路径；✔ 保留原权限参数 |
| ✔ | mknodat | 特殊文件/管道创建需落在虚拟根/绑定 | ✔ 重写路径；✔ 透传 mode/dev |
| ✔ | unlinkat | 删除/移除应作用于虚拟根/绑定 | ✔ 重写路径；✔ 支持 AT_REMOVEDIR 透明透传 |
| ✔ | linkat | 硬链接两端路径需映射，避免跨根/绑定 | ✔ 重写 oldpath；✔ 重写 newpath；✔ 透传 flags |
| ✔ | renameat | 重命名需要两端路径都映射，避免跨根混乱 | ✔ 重写 oldpath；✔ 重写 newpath |
| ✔ | openat | 打开文件需走路径映射 | ✔ 重写路径；✔ 其他参数原样透传 |
| ✔ | faccessat | 权限检查应基于映射后的路径 | ✔ 重写路径；✔ 其他参数原样透传 |
| ✔ | readlinkat | 读取链接需映射输入路径并回填输出为 guest 路径 | ✔ 重写输入路径；✔ 将内核返回的宿主路径翻译为 guest 路径后写回 |
| ✔ | newfstatat | stat 目标需走映射 | ✔ 重写路径；✔ 其他参数透传 |
| ✔ | symlinkat | 链接目标与链接名都需映射 | ✔ 重写 target；✔ 重写 link 名 |
| ✔ | execve | 程序路径需映射且子进程应继续走 loader/hook | ✔ 重写 argv[0]/所有 argv 路径；✔ 复制 argv/envp 到 payload 栈避免改 caller；✔ PATH/LD_LIBRARY_PATH/LD_PRELOAD 等列表重写；✔ PWD/HOME/TMPDIR 等绝对路径 env 重写；✔ 强制通过 /elfloader 重启目标（找不到 loader 则 ENOENT）；✔ 溢出回退透传 |
| ✘ | socket/bind/connect 等 | 网络虚拟化需求 | ✘ 未实现 |

## TODO 列表

| 状态 | 任务 | 说明 |
| ---- | ---- | ---- |
| ✘ | 路径处理统一/规范化 | 区分主/子 loader 的路径处理：主 loader 打开目标时保持原始路径和符号链接，不做绑定/根替换；子 loader 必须按 `PROOT_ROOT`/bind 重写，符号链接指向绝对路径时先标准化（去掉 `//`、`.`、`..`）再拼接根，保证不泄漏宿主路径且避免拼接错误。拆项：a) 统一 `join_paths`/规范化逻辑供 loader/payload 共用；b) 处理 execve 相对路径拼接（目前 syscall_hooks.c 手动 `getcwd`+`/`）；c) 路径列表重写规范化（PATH/LD_LIBRARY_PATH 在 execve_utils.c）；d) loader 打开目标时的 `rewrite_exec_path` 逻辑对符号链接/根拼接一致化。 |
| ✘ | 共享配置传递安全化 | 区分主 loader/子 loader：主 loader 解析配置后用参数标记子 loader，安全传递配置（共享内存/参数），校验 magic/version/size，平台不支持或句柄失效时回退文件路径，避免子 loader mmap 失效段导致段错误。 |
| ✔ | ld.so 库加载 hook | 通过拦截 mmap/mprotect 可执行映射后即时调用 `install_hook`，对新加载共享库的 text 段补钩，覆盖后续加载的 libc/libm 等共享库里的 `svc`，彻底阻断动态库逃逸。 |
| ✘ | CLI/Init/配置扩展 | 实现类 docker CLI（run/bind/env/workdir/log/init 等选项），容器内 init（僵尸回收、信号转发、环境清理、可选降权），容器外初始化（验证/创建 root/bind、预热 payload/loader、准备必需文件/临时目录），最终写入 payload 配置并由子进程继承。 |

## 最小 proot 功能的实现步骤

1) 固定入口/防重入：在 payload TLS 中加递归标记（每线程可见），hook 入口先检查/置位，出口清除，防止递归进入同类 hook（无论调用来自可执行文件还是宿主共享库、动态拼接的命令）。hook 内避免调用宿主 libc 封装（如 open/printf），改用裸 `syscall(SYS_xxx, …)` 和 `syscall(SYS_write, …)` 输出日志；如必须重入，可用标记短路直接 `svc`。动态生成的命令/execve 同样先重写路径后用裸 syscall 发起。
2) 配置解析：改为只读配置文件（默认编译期路径，可用 `-c` 覆盖），不再信任容器内环境变量。
3) 路径重写引擎：将宿主路径复制到 payload 自己的缓冲区，应用根替换/绑定表后返回新路径。
4) 基础 hook 集：拦截 `open/openat/execve/readlink/chdir/getcwd`（如需删除/创建再加 `unlink/mkdir/rename`），流程：检查递归标记→重写路径→直接 `syscall` 调用内核，不走宿主 libc。
5) （可选）白名单/屏蔽：记录上层删除标记（whiteout），查找时先看上层标记再决定落到下层。
6) 测试矩阵：用 tiny_target 验证上下文恢复、payload_demo 验证 libc，再用路径重写用例验证 open/exec/chdir/getcwd。
- 测试提示：`payload_demo` 中的 `execve_missing` 是故意不存在的路径，用来触发 ENOENT；现在放在独立子进程里，不会打断其他用例。链式执行会先尝试 `/home/tiny_target`，不存在仍会返回 ENOENT，可按需放置可执行文件验证成功链路。

## 当前进度与实现要点

- 链式 execve 强制开启：任何 execve 都会尝试通过 `/elfloader` 重新进入 loader，找不到 loader 直接返回 ENOENT，不再回退裸 exec；当前未实现 `HOOK_LOADER_PATH`/`HOOK_LOADER_NAME`，仅依赖 `/elfloader` 绑定。
- 默认绑定：即使未设置 PROOT_BIND 也会自动把 guest `/elfloader` 映射到 `CONFIG_DEFAULT_LOADER_DST`，确保鸿蒙场景下始终有 loader。
- 解释器路径重写：加载 ELF 时会把 PT_INTERP 指向的解释器路径按配置的 root/bind 改写，优先使用容器内路径，避免直接访问宿主 `/lib/…` 造成逃逸。
- 根目录强制：配置 `PROOT_ROOT` 后主 loader 启动即 `chdir` 到该根，拒绝绝对路径目标；子 loader 通过 `--child-loader` 标记保留调用方 cwd，但解析时会把相对/软链路径落在 root/bind 内。
- 路径改写稳定：修复了 bind 目标长于源时的自覆盖拼接问题；`rewrite_path_from_host` 同步修正。
- 日志与调试：`HOOK_LOG=1` 打印关键 syscall（含 execve 链路路径），便于确认是否正确链式/重写。
- 仍未实现/待办：网络相关 hook（socket/bind/connect）、环境变量白名单、`HOOK_LOADER_PATH`/`HOOK_LOADER_NAME`/`ENV_` 扩展、后台/日志重定向、白障（whiteout）覆盖逻辑、链式自检和错误回退策略。
- 动态库逃逸防范（方案）：最彻底的做法是直接在 ld.so 内挂钩其库加载路径（如 `_dl_map_object`/`load_library` 等），在每个新映射的可执行段完成 mmap/mprotect 后立即调用 `install_hook` 扫描并补丁 text，这样 libc/libm 等后续加载的共享库也会被改写 `svc`，避免 printf 等经由未改写的 stub 逃逸。可在 loader 阶段对 ld.so 目标函数打跳转到包装函数，包装里先走原逻辑再补丁新段；比单纯 syscall 拦截更精准、更彻底。

## CLI / Init 设计草案（规划中，未实现）

- CLI（类 docker 风格）：`elfloader run [OPTIONS] -- <cmd> [args]`。典型选项：`--config/-c` 指定配置文件；`--root` 设置 PROOT_ROOT；`--bind src:dst` 可多次；`--workdir` 设置容器内 cwd；`--env KEY=VAL`/`--env-file` 控制注入的环境；`--clear-env`/`--keep-env KEY` 选择性继承；`--log[=level]`；`--init` 打开容器内 init；`--entrypoint` 覆盖目标；`--payload` 覆盖 payload 路径。所有选项最终写入 payload 配置，子进程继承，不依赖宿主环境。
- 容器内 init（PID1/shim）：在 `--init` 开启时，主 loader 先启动一个最小 init 作为 PID1：设置 `prctl(PR_SET_CHILD_SUBREAPER)`，安装 SIGCHLD 处理回收僵尸；将非 SIGKILL/STOP 信号转发给前台子进程组；重置可疑信号处理器；清理环境变量（去掉 LD_* 等），按 root/bind 重写 PATH/LD_LIBRARY_PATH/HOME/TMPDIR；可选降权（setuid/setgid/setgroups、drop capabilities）；初始化 umask、fd 关闭策略。init 再 exec 目标或 `--entrypoint`。
- 容器外初始化（启动前环境准备）：主 loader 在进入 target 前完成：验证/创建 root 目录、bind 目标存在性；预先构建路径映射表；预热 payload/loader 映射（确保可访问，必要时提前 mmap）；可选生成临时目录、绑定 `/etc/resolv.conf`/`/etc/hosts`；在未开启 namespace 的场景下，使用 chdir+bind 模式模拟隔离并记录失败降级策略。
- 已实现的 CLI 解析（功能尚未全部生效）：`-c/--config`、`--root`、`-v/--volume host:container`（转成 bind）、`-e/--env KEY=VAL`（会注入/重写环境，覆盖同名键）、`-w/--workdir`（记录）、`--init`、`-d/--detach`、`--log`（记录）。目前除 config/root/bind/env 重写外其他选项仅解析存储，后台/日志重定向尚未实现行为；`--init` 会切换为嵌入的 tiny-init 启动模式（内存 memfd 直接执行，无需容器内文件，名义路径为相对的 `tiny-init` 仅作占位）。

## 配置文件

- 默认配置路径由编译期宏 `CONFIG_DEFAULT_CONFIG_PATH` 定义（当前 `/data/service/hnp/horpkg-base.org/horpkg-base_1.0/etc/loader.conf`），运行时可用 `elfloader -c /path/to/conf <target>` 覆盖。
- 配置文件格式为 `KEY=VAL`，支持 `HOOK_LOG=1`、`PROOT_ROOT=/rootfs`、`PROOT_BIND=/a:/b,/c:/d`、`PAYLOAD_PATH=/path/to/payload.elf` 等；`#` 开头为注释，空行和空白行会被忽略。`PAYLOAD_PATH` 若未设置默认取 `CONFIG_DEFAULT_PAYLOAD_PATH`（当前 `./payload.elf`）。
- 加载顺序：仅读取配置文件，随后自动补上 `/elfloader` 绑定，不再信任容器内环境变量，避免被覆写导致逃逸。
- 编译期可通过 `make DEFAULT_CONFIG_PATH=/your/path` 覆盖默认配置路径；可用 `SAMPLE_CONFIG_PATH=/your/sample` 在构建时自动复制 `loader.conf.sample` 到指定位置（可与默认配置路径不同）。
- 环境传递：loader 不再透传宿主环境，默认空环境；仅注入 CLI `-e/--env` 指定的键。启用 `--init` 时，内嵌 tiny-init 会在空环境基础上填充 PATH/HOME/TERM/USER 等默认值后再 exec 用户命令（tiny-init 作为资源打包到 elfloader，运行时写入 memfd 直接 exec，名义路径为相对的 `tiny-init`）。
