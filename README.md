# ELF / PRoot 文件系统运行后端

在系统沙盒内，通过 AArch64 ELF 加载与 SVC 拦截接入 PRoot 路径语义。
不依赖 ptrace、namespace 或 bubblewrap 运行时。主要目标是给 agent 提供系统/brew
文件视图与访问控制，其次是运行 Linux rootfs。

**当前是可运行的兼容性后端，尚未完成 agent 文件隔离。** root/bind、动态 ELF、
链式 exec 已有测试；只读绑定、默认拒绝、完整 FD 生命周期和 `/proc` 尚未完成。
默认构建仍有 raw syscall 入口及同线程重入透传风险；实验构建拒绝同线程嵌套慢调用，
但也尚未完成恶意代码隔离验收。
`container` 模式名称也不代表这些隔离能力已完成。

## 从哪里开始

此目录是独立 Git 仓库 `nknkol/elf`，开发分支为 `feat/proot-svc-bridge`。
如果外层目录叫 `bubblewrap`，请先进入 `opt/elf`；外层源码不参与当前后端构建。

```sh
make help
make build
make check
```

当前构建和运行验证环境为 HarmonyOS AArch64 终端沙盒。需要 Python 3、GNU make、
Clang、ld.lld、llvm-objcopy、llvm-ar、llvm-nm 及本地 Linux ABI 头文件；构建会使用
`/bin/sh`。未验证其他架构，也不自动安装依赖。

当前 PRoot payload ABI 为 3，自定义 payload 必须与 loader 匹配，否则启动时拒绝。
构建入口强制重编译 loader/payload，通过临时文件替换可执行文件，生成：

- `vendor/proot/svc/build/elfloader-proot`：运行工具。
- `vendor/proot/svc/build/elf-build.json`：用于测试校验的构建摘要。
- `vendor/proot/svc/build/elf-build.log`：编译日志。

`make check` 先构建，再运行路径核心、SVC 文件操作、exec、auxv、路由、重入保护、
运行时 syscall、FD 元数据核心和配置/解包测试。测试失败会使 make 返回非零。
clone 对照会单独报告本机三种 FD 共享语义差异；默认成功表示 loader 与 native 一致，
不表示完整 Linux clone 语义通过。详情见 [FD 计划](docs/FD_POLICY_PLAN.md)。
不要同时在不同终端构建两种后端，它们共用 `src/` 下的中间产物。

## 运行已有 rootfs

以下路径需替换为已解包 rootfs 和真实工作目录；所有 `-v` 当前均为可写映射。
首个目标使用 rootfs 内的相对路径，后续 guest exec 可以使用绝对路径。

```sh
vendor/proot/svc/build/elfloader-proot \
  --mode container --root /absolute/path/to/alpine-rootfs \
  -v /absolute/path/to/workspace:/workspace \
  -v /dev/null:/dev/null -- ./bin/busybox sh
```

Ubuntu 对应入口可用 `./usr/bin/dash`。已验证两套镜像各 18 项离线用例，
不包含联网安装、完整容器或安全隔离验收。可用自备压缩包重跑：

```sh
make check-alpine ALPINE_ARCHIVE=../alpine-minirootfs-3.24.3-aarch64.tar.gz
make check-ubuntu UBUNTU_ARCHIVE=../ubuntu-base-26.04.1-base-arm64.tar.gz
```

测试临时解包后清理；Ubuntu 硬链接因宿主限制被复制成独立文件，不代表硬链接语义通过。
镜像和构建产物不提交 Git。

## 代码地图

| 位置 | 职责 |
| --- | --- |
| `src/loader.c` | ELF 加载、配置、guest 启动栈 |
| `src/payload/arch/aarch64/` | SVC 补丁、分流、重入保护和 clone 专用通知入口 |
| `src/payload/logic/proot_bridge.c` | syscall 参数适配、路径和目录 FD 解析 |
| `src/payload/logic/proot_exec.c` | 保留配置的 exec 链 |
| `src/payload/logic/proot_auxv.c` | guest PR_GET_AUXV |
| `src/payload/logic/fd_table.c` | FD 元数据核心，已接入独立实验运行时 |
| `src/payload/logic/fd_snapshot.c`、`fd_handoff.c` | exec 元数据快照与封存 memfd 传输，已接入实验 loader |
| `test/fd_table/` | 元数据模型、exec 交接、native/loader clone 共享行为对照 |
| `vendor/proot/src/path/` | 从原版 PRoot 提取的共享路径核心 |
| `vendor/proot/port-tests/` | 核心与 ELF 集成回归 |
| `test/syscalls/` | 沙盒 syscall 行为、分流和重入验证 |
| `test/alpine/`、`test/ubuntu/` | rootfs 离线验收 |
| `tools/agent_sandbox/`、`profiles/` | agent 策略规划原型，尚未连接执行层 |

## 实现状态与下一步

先看 [当前进度与验收快照](docs/STATUS.md)，其中区分默认/实验构建及本轮测试；
FD 计划后半部分保留历史增量记录，不应把早期“未接入”描述当作当前状态。

- [底层约束和历史经验](docs/SYSCALL_ENGINE_LESSONS.md)
- [FD 身份与只读策略实施顺序](docs/FD_POLICY_PLAN.md)
- [PRoot 移植记录](vendor/proot/SVC_PORT.md)
- [agent 配置规划器](tools/agent_sandbox/README.md)
- [backing 存储能力与实测](docs/STORAGE_CAPABILITIES.md)
- [Ubuntu auxv 故障与修复](test/ubuntu/AUXV_DIAGNOSIS.md)
- [旧后端设计记录](docs/LEGACY_BACKEND.md)：历史材料，不是当前能力说明。

保持路径翻译与访问策略轻量化；文件内容、FD 读写和文件偏移继续由内核管理，
不构造一套完整的用户态 VFS。


单线程进程的 FD 跟踪实验：`make check-fd-runtime` 构建独立的
`vendor/proot/svc/build/elfloader-proot-fd-experiment`，覆盖常用 FD 创建、复制、
标志修改、关闭和 SCM_RIGHTS 接收，并支持私有地址空间 fork 与 exec 状态交接。
支持单层 `CLONE_VM|CLONE_VFORK|SIGCHLD` 的 vfork，父子分别保存 FD 元数据；
普通共享 VM/线程及嵌套 clone 仍拒绝，不提供权限隔离。
详见 [实验使用说明](test/fd_runtime/README.md)。普通构建保持原行为。
