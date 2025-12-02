## Payload/Hook 说明（proot 类场景）

- 目标：通过内存打补丁的方式高性能 hook（如 openat 等），实现类似 proot 的路径重写/隔离。`elfloader` 本身不依赖宿主 libc，payload 静态 PIE 链接 musl，使用私有 TLS/栈，尽量不影响宿主进程。
- 避免递归/重入：在 hook 内不要调用宿主 libc 的同名封装，否则可能再次触发 hook 或进入宿主 libc 锁。推荐直接用 `syscall(SYS_xxx, …)`/低级 `write` 输出日志，或在 TLS 里做递归保护位。
- 路径改写：把宿主传入的指针复制到 payload 自己的堆/栈上再改写，修改后直接发内核 `syscall`。不要用宿主的 `openat/printf` 等，以免重入。
- 资源隔离：payload 的 malloc/sbrk 来自静态 musl，自有堆，不会动宿主 brk；TLS/栈独立，不触碰宿主 TLS/栈。避免注册全局信号处理/atexit 到宿主。
- Stub 分配：优先在目标附近 mmap 一页（不依赖 NOREPLACE），保持单条分支可达；如果跨距过大再考虑双层跳转。

## 面向 proot 类容器的方案/现状

- 目标：用内存补丁（stub + payload）在 syscall 层做路径虚拟化/隔离，性能和兼容性优于 ptrace 类 proot，尽量不干扰宿主进程。
- 架构：`elfloader` 自举 + 静态 PIE payload（musl，私有 TLS/栈/堆）。在目标 ELF 的 `svc` 前插入跳转，进入 payload 做逻辑处理，返回前恢复寄存器状态。
- Hook 范围（规划）：`open/openat/stat/fstatat/access/execve/chdir/getcwd/mkdir/mknod/unlink/rename/link/symlink/readlink/socket/bind/connect` 等路径/网络相关 syscall，按环境变量开关。
- 路径虚拟化：把宿主传入路径复制到 payload 自己的内存，按根替换/bind 映射表重写后直接 `syscall`，不调用宿主 libc，避免重入。
- 默认 loader 绑定：无需手动 PROOT_BIND，自动把 guest `/elfloader` 映射到 `CONFIG_DEFAULT_LOADER_DST`。
- loader 自动定位：优先用 `HOOK_LOADER_PATH` 覆盖，其次 `/elfloader` 绑定，最后按 PATH 搜索 `elfloader`（可用 `HOOK_LOADER_NAME` 指定文件名），找不到直接 ENOENT，不会回退裸 exec。
- 重入与日志：TLS 中放递归保护标记，hook 内只用裸 `syscall(SYS_write,…)` 输出日志，避免再次触发 hook 或宿主 libc 锁。
- Stub 策略：优先在目标附近 hint mmap 一页可执行，保证单条分支可达；如遇距离问题，再设计中间跳板（短跳到跳板，再长跳到远 stub）。
- 状态：当前代码回到稳定的原始方案（静态 musl + TLS/私有栈，简单 hint mmap stub），tiny_target/payload_demo 跑通；复杂 proot 功能未实现。
- 开发路径：
  1) 按规划实现路径映射表与 openat/readlink 等基本 hook，增加 TLS 递归保护。
  2) 补充配置入口：环境变量设置 root/bind 映射、log 级别、hook 范围。
  3) 设计并集成中间跳板作为距离兜底；完善 stub 分配日志。
  4) 自检初始化：在 payload 入口可选调用 `__libc_start_init`，确保 musl 运行时就绪。
  5) 测试矩阵：最小 SVC（tiny_target）、payload_demo、实际路径重写场景；如有 CI，qemu aarch64 自测。
- 注意事项：
  - 只用 payload 自己的 libc/malloc/TLS/栈，不触碰宿主 TLS/栈/brk。
  - 避免在 hook 内调用宿主 libc 包装，避免递归；必要时在 TLS 里做 reentrancy guard。
  - 不注册宿主范围的全局信号/atexit 回调；谨慎修改宿主的全局资源（fd/env）。
  - 日志和调试默认走裸 syscall，减少依赖。

## 开发注意事项（近期踩坑）

- 桩/入口不要额外破坏调用方认为“保持不变”的寄存器。曾因入口快速过滤先改写 x9、桩复用 x16/x17/x30 未保存，导致返回时上下文损坏触发 SIGSEGV。修复：快速过滤直接比较 x8；stub 先保存/恢复 x16/x17，恢复 x30 后用立即分支返回原 SVC+4。新增指令/寄存器时务必一并保存或更新调用约定。
- 内联 `svc` 的调用方通常不会把 x9/x16/x17 写进 clobber，依赖 hook 保持 ABI；尽量在 hook 端保持寄存器无副作用，避免逼调用方改汇编。

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
| ✘ | ld.so 库加载 hook | 在 ld.so 的库加载路径（如 `_dl_map_object`/`load_library`）插入包装，调用原逻辑后立刻对新映射的可执行段执行 `install_hook`，覆盖后续加载的 libc/libm 等共享库里的 `svc`，彻底阻断动态库逃逸。 |
| ✘ | 初始化/配置扩展 | 引入“微型 init”或扩展配置，启动时统一做容器内初始化：`chdir` 到容器根/工作目录，构造/覆盖 PATH/LD_LIBRARY_PATH 等关键环境（按 root/bind 改写），清理高危变量，预绑定必需目录，行为类似 Dockerfile init/proot 配置脚本。 |

## 最小 proot 功能的实现步骤

1) 固定入口/防重入：在 payload TLS 中加递归标记（每线程可见），hook 入口先检查/置位，出口清除，防止递归进入同类 hook（无论调用来自可执行文件还是宿主共享库、动态拼接的命令）。hook 内避免调用宿主 libc 封装（如 open/printf），改用裸 `syscall(SYS_xxx, …)` 和 `syscall(SYS_write, …)` 输出日志；如必须重入，可用标记短路直接 `svc`。动态生成的命令/execve 同样先重写路径后用裸 syscall 发起。
2) 配置解析：改为只读配置文件（默认编译期路径，可用 `-c` 覆盖），不再信任容器内环境变量。
3) 路径重写引擎：将宿主路径复制到 payload 自己的缓冲区，应用根替换/绑定表后返回新路径。
4) 基础 hook 集：拦截 `open/openat/execve/readlink/chdir/getcwd`（如需删除/创建再加 `unlink/mkdir/rename`），流程：检查递归标记→重写路径→直接 `syscall` 调用内核，不走宿主 libc。
5) （可选）白名单/屏蔽：记录上层删除标记（whiteout），查找时先看上层标记再决定落到下层。
6) 测试矩阵：用 tiny_target 验证上下文恢复、payload_demo 验证 libc，再用路径重写用例验证 open/exec/chdir/getcwd。
- 测试提示：`payload_demo` 中的 `execve_missing` 是故意不存在的路径，用来触发 ENOENT；现在放在独立子进程里，不会打断其他用例。链式执行会先尝试 `/home/tiny_target`，不存在仍会返回 ENOENT，可按需放置可执行文件验证成功链路。

## 当前进度与实现要点

- 链式 execve 强制开启：任何 execve 都会尝试通过 `/elfloader` 重新进入 loader，找不到 loader 直接返回 ENOENT，不再回退裸 exec；支持 `HOOK_LOADER_PATH` 指定完整路径，`HOOK_LOADER_NAME` 指定可执行名，PATH 内自动搜索。
- 默认绑定：即使未设置 PROOT_BIND 也会自动把 guest `/elfloader` 映射到 `CONFIG_DEFAULT_LOADER_DST`，确保鸿蒙场景下始终有 loader。
- 解释器路径重写：加载 ELF 时会把 PT_INTERP 指向的解释器路径按配置的 root/bind 改写，优先使用容器内路径，避免直接访问宿主 `/lib/…` 造成逃逸。
- 根目录强制：配置 `PROOT_ROOT` 后 loader 启动即 `chdir` 到该根，目标路径必须用相对路径，禁止宿主绝对路径透传，避免从宿主 cwd 逃逸。
- 路径改写稳定：修复了 bind 目标长于源时的自覆盖拼接问题；`rewrite_path_from_host` 同步修正。
- 日志与调试：`HOOK_LOG=1` 打印关键 syscall（含 execve 链路路径），便于确认是否正确链式/重写。
- 仍未实现/待办：网络相关 hook（socket/bind/connect）、环境变量白名单、白障（whiteout）覆盖逻辑、链式自检和错误回退策略。
- 动态库逃逸防范（方案）：最彻底的做法是直接在 ld.so 内挂钩其库加载路径（如 `_dl_map_object`/`load_library` 等），在每个新映射的可执行段完成 mmap/mprotect 后立即调用 `install_hook` 扫描并补丁 text，这样 libc/libm 等后续加载的共享库也会被改写 `svc`，避免 printf 等经由未改写的 stub 逃逸。可在 loader 阶段对 ld.so 目标函数打跳转到包装函数，包装里先走原逻辑再补丁新段；比单纯 syscall 拦截更精准、更彻底。

## 配置文件

- 默认配置路径由编译期宏 `CONFIG_DEFAULT_CONFIG_PATH` 定义（当前 `/data/service/hnp/horpkg-base.org/horpkg-base_1.0/etc/loader.conf`），运行时可用 `elfloader -c /path/to/conf <target>` 覆盖。
- 配置文件格式为 `KEY=VAL`，支持 `HOOK_LOG=1`、`PROOT_ROOT=/rootfs`、`PROOT_BIND=/a:/b,/c:/d` 等；`#` 开头为注释，空行和空白行会被忽略。
- 加载顺序：仅读取配置文件，随后自动补上 `/elfloader` 绑定，不再信任容器内环境变量，避免被覆写导致逃逸。
- 编译期可通过 `make DEFAULT_CONFIG_PATH=/your/path` 覆盖默认配置路径；可用 `SAMPLE_CONFIG_PATH=/your/sample` 在构建时自动复制 `loader.conf.sample` 到指定位置（可与默认配置路径不同）。
