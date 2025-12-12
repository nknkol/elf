# ELF loader / payload

自举 ELF loader + 静态 PIE payload，用于在目标程序内做 syscall 级 hook（路径重写/链式 loader 等）。loader 不依赖宿主 libc，直接走 `z_syscall.c`。

## 设计约束
- 面向受限设备：假设无法启用 namespace/`chroot`/`pivot_root` 等内核特性，也不依赖容器运行时。
- 纯用户态方案：通过内存 hook + syscall 拦截模拟 PROOT 行为（路径改写、绑定覆盖、链式 loader），不改变内核全局状态。
- 兼容只读/noexec 挂载：payload/loader 内嵌，执行时从内存 memfd 映射，避免对宿主文件系统的可执行依赖。

## 容器/兼容模式拆分与 Hook 层次（实现方案）
- 模式定义与开关
  - 兼容模式：面向“在宿主机跑得更顺滑”，保留宿主身份/权限，开放 bind 映射与 env 追加，仍保留 execve 链式、mmap/mprotect hook 以维持受控环境。
  - 容器模式：面向隔离，启用 root/bind 虚拟化 + fakeroot 身份伪装，默认最小化对宿主可见信息。
  - 配置入口：CLI/配置文件暴露 `--mode container|compat` 或 `RUN_MODE=container|compat`，未显式指定时“存在 PROOT_ROOT → container，否则 compat”。`g_payload_config` 增加 `mode` 与 `hook_mask` 位图（BASE/COMPAT/ISOLATION）。
- Hook 三层职责
  - 地基 Hook（BASE，始终开启，两模式共用）：execve 链式 loader（含 argv/env 复制、PATH/LD_LIBRARY_PATH 列表重写、shebang 解析）、PT_INTERP 重写、路径改写（root/bind + 软链展开）覆盖 openat/faccessat/fstatat/readlinkat/symlinkat/linkat/renameat/mkdirat/mknodat/chdir/getcwd/unlinkat、mmap/mprotect 执行段 hook（用于后续动态库补钩与 noexec 绕过）。
  - 兼容性补全（COMPAT，两模式均可开，兼容模式默认开、容器模式可选）：bind 映射表/环境变量追加、readlink 回填 guest 路径、argv/env 里绝对路径替换、PATH 拼接工作目录、宿主 cwd 透传等，保证“非隔离”场景下也能跑起来。
  - 隔离/Fakeroot Hook（ISOLATION，仅容器模式）：getuid/geteuid/getgid/getegid/getgroups 返回 0/空组，set*uid/gid/setgroups/clearenv 等伪成功、屏蔽泄露；auxv 中 AT_UID/AT_GID 归零；必要时拦截 prctl/seccomp 替换/拒绝敏感操作；后续可在此层挂载元数据虚拟化（stat uid/gid/ctime 伪装）。
- 运行时流程拆分
  1) loader 解析 CLI/配置 → 生成 `mode` 与 `hook_mask`，写入 payload_config；链式 exec 进入子进程时继承该配置。
  2) payload 安装 hook 时根据 `hook_mask` 决定是否 patch 对应 syscall（BASE 无条件，COMPAT/ISOLATION 按位判断）；单个 hook 内也可用掩码做早退，避免无谓开销。
  3) execve 路径：先做 argv/env 路径重写 → 确保跳转到 `/elfloader` 链式 → 重新写入目标 argv/env（兼容层插入额外 env/bind），容器模式下附带身份伪装。
  4) mmap/mprotect 路径：拦截可执行映射后立即调用 install_hook 对新段补钩，确保动态库同样受 BASE/COMPAT/ISOLATION 控制。
  5) get*uid/gid/grouplist 等在容器模式返回伪造值，兼容模式透传原始结果；set* 系列容器模式直接返回 0（或记录日志），兼容模式透传。
  6) readlink/stat 系列返回宿主路径时，兼容层负责回填 guest 路径，容器层可附加权限/uid/gid 伪装；路径重写始终走 BASE。

## 目录结构
- `src/`: loader 通用代码（`loader.c`、`utils/` 等），架构相关的启动/辅助在 `src/arch/<arch>/`。
- `src/payload/`: payload 通用逻辑在 `logic/`，架构特定实现（入口、raw_syscall、mini_libc、reentry_guard、syscall_disp）在 `arch/<arch>/`，头文件集中在 `include/`。
- `test/payload_demo`: 复用 payload 逻辑的最小示例/单元测试。

## 构建
- 默认架构：`make`（默认为 `ARCH=aarch64`）。
- 指定架构：`make ARCH=amd64` 或 `make ARCH=i386`（需有对应 arch 源）。
- 精简模式：`make SMALL=1`（去掉 printf/err）。
- 默认 payload 路径可在构建时覆盖：`make DEFAULT_PAYLOAD_PATH=/path/to/payload.bin`。

payload 会在顶层构建时自动生成：`src/payload/payload.bin`（并嵌入到 elfloader）。

## 运行
- 基本用法：`./elfloader [OPTIONS] -- <target> [args]`
- 配置文件（可选）：`-c /path/to/loader.rc`（分层样式，样板见 `src/config/loader.rc.sample`）；若不指定则不读配置文件。
- 启用内嵌 init：`--init`（会用嵌入的 tiny-init，Guest 配置通过 `INIT_CONFIG_FD` 传递）。
- 环境注入：`-e KEY=VAL` 多次；默认不透传宿主环境。
- 主要选项速览：
  - `-c/--config <path>`：指定 loader.rc 配置。
  - `--root <path>`：容器根（Host 层）。
  - `-v/--volume host:guest`：绑定挂载，可多次。
  - `-e/--env KEY=VAL`：注入 env，可多次。
  - `-w/--workdir <path>`：容器内工作目录（记录）。
  - `--init`：使用内嵌 tiny-init（需配合配置或目标，至少其一存在）。
  - `--hook-range min-max`：控制目标的 SVC 扫描范围。
  - `--hook-range-interp min-max`：控制解释器（如 musl）的 SVC 扫描范围，便于调试崩点。
  - `-d/--detach`、`--log <path>`：仅解析，行为待实现。

## 测试
- payload_demo 测试：`cd elf/test/payload_demo && make ARCH=aarch64`

## 维护提示
- 架构新增：在 `src/arch/<arch>/` 放置汇编启动/辅助，在 `src/payload/arch/<arch>/` 放 `entry.S`、`raw_syscall.S`、`syscall_nums.h`、`syscall_disp.c`、`mini_libc.c`、`reentry_guard.c`。
