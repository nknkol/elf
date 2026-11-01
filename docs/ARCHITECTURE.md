# 架构说明

当前版本的总览（2026-11-01，payload ABI 27）。各子系统的设计与验收在专门文档里：隔离模式
[ISOLATION.md](ISOLATION.md)、Docker/OCI [OCI.md](OCI.md)、agent 启动器 `tools/agent_sandbox/README.md`，
当前状态与已知限制 [STATUS.md](STATUS.md) 开头的“当前版本”一节。

## 进程模型

```
build/elfloader[-guarded] [选项] -- 程序 参数
  ├─ 装载 payload（内嵌，固定地址 0x3f80000000）
  ├─ 装载程序与解释器：可执行段复制为匿名页，svc 改写为跳到桩岛，再设为可执行
  ├─ 把配置（root、bind、下层、身份、策略、挂载表、网络、guest auxv、保护区）写入 payload
  ├─ --isolate：先 fork 出 broker（不受过滤），再打开自身为 FD 898，装 guest 过滤器
  └─ 重建初始栈，跳到程序入口
guest 的每次 exec → payload 以 --child-loader 重新执行同一个 loader
                    （--isolate 下只能是 execveat(898, 常量页空串, AT_EMPTY_PATH)）

          ┌──────────── guest 进程（同一地址空间）────────────┐
          │ 程序 ──svc──▶ 桩 ──▶ payload（PRoot 语义、视图）   │
          │                        │ 直接系统调用（默认/guarded）│
          │                        │ 按路径与改元数据的调用      │
          │                        ▼ （--isolate：过滤器强制）   │
          └────────────── 私有 SOCK_SEQPACKET 通道 ─────────────┘
                                   │
                         broker 进程（不受过滤）：按 root/bind/下层的
                         deny/ro/rw 打开、检查、执行，回传结果或 FD
```

三种强度：
- **默认构建**：PRoot 语义的视图（root、bind、身份、挂载表、写时复制、网络），不是边界。
- **guarded 构建**：payload 内按挂载的 deny/ro/rw 检查（`--guard-*`），对合作程序有效，与 guest 同一地址
  空间，不是对抗边界。
- **`--isolate`**：guest 过滤器拒绝所有按路径访问文件与改元数据的调用，payload 只能请 broker 代办；
  执行可信链保证每个受过滤进程都在运行 loader 映像。剩余风险见 ISOLATION.md。agent 启动器默认用它。

loader 是静态、非 PIE 的二进制，固定在 0x3f00000000；guest 进程里没有宿主动态链接器。
loader 与 payload 地址固定，seccomp 兜底与 guest 过滤器才能按地址比较（常量页、自身系统调用）。

宿主侧工具（Python，见 STATUS.md“当前版本”）：`tools/oci/`（Docker 兼容命令、compose、build、Engine API）
在容器运行期间以监视进程、端口转发器常驻；`tools/agent_sandbox/` 生成启动参数后 exec 到 loader，不常驻。

## 一次系统调用的路径

```
guest svc → 桩（stub.c 模板，按 w8 判断 rt_sigreturn/clone）
  → entry.S（保存寄存器，w8 规范化，快路径透传）
  → syscall_disp.c: syscall_dispatcher
       1. integrity_check   自身完整性：保护区封印、兜底下的 W^X 与 SIGSYS
       2. guarded 构建: fd_runtime_dispatch（FD 来源记录与访问策略）
       3. dispatch_syscall  PRoot 语义（proot_bridge/proot_exec/proot_auxv）、
                            fake_ids、可执行内存补钩、平台不支持的调用、透传
       4. 结果加工          stat 属主、uname、socket 名
```

## 目录与模块

| 模块 | 内容 |
| --- | --- |
| `src/loader/main.c` | 编排：选项 → payload → 程序/解释器 → 配置 → 启动栈 → 跳转 |
| `src/loader/options.c` | 命令行与 child-loader 协议（`config.h` 的 `CONFIG_CHILD_*`） |
| `src/loader/elf_load.c` | ELF 整体校验、装载与补钩、payload 装载与重定位 |
| `src/loader/paths.c` | 宿主路径规范化、大小写别名标记、PT_INTERP 解析 |
| `src/loader/hook.c` | 桩岛的 loader 端实现（共用 `stub_island.h`） |
| `src/loader/backstop.c`、`signals.c` | seccomp 兜底；信号工具与崩溃转储 |
| `src/loader/broker.c` | `--isolate` 的 broker：树表（root/bind/下层/glue/scratch）与访问检查、按 FD 授权、执行可信链的文件保护 |
| `src/loader/guest_filter.c`、`devices.c` | guest 过滤器（经典 BPF 生成）；常量页（空串与设备路径） |
| `src/loader/lazy_layer.c` | 层镜像（erofs）按需展开，loader 侧（broker 代办 `BROKER_LAZY_MOUNT`） |
| `src/payload/include/elf_abi.h` | loader、payload、测试共用的固定数字（ABI 版本、固定地址、私有 prctl） |
| `src/payload/include/integrity.h` | 自身完整性规则（loader 与 payload 共用 W^X 判定） |
| `src/payload/logic/dispatch.c` | 通用分发（见上） |
| `src/payload/logic/proot_*.c` | PRoot 路径语义、exec 链、auxv |
| `src/payload/logic/fd_*.c`、`fs_policy.c`、`vm_write_guard.c` | guarded 构建的 FD 运行时与策略 |
| `src/payload/logic/broker_client.c` | `--isolate` 下按路径的调用改由 broker 执行（协议 `broker_proto.h`） |
| `src/payload/logic/container_state.c` | 共享挂载表（FD 901）、属主库（FD 902）、loop 设备槽 |
| `src/payload/logic/union_view.c`、`lazy_layer.c` | 写时复制的合并视图；层镜像缓存的按需展开与填充 |
| `src/payload/logic/net_view.c` | 容器网络：回环地址池、端口映射、peers |
| `tools/oci/` | Docker 兼容工具（宿主侧 Python）：`union.py`/`guestfs.py` 在宿主侧读写同一合并视图，`erofs.py` 写读层镜像 |
| `tools/agent_sandbox/` | agent 配置校验（`plan.py`）与启动器（`launch.py`，默认 `--isolate`） |
| `vendor/proot/src/path/` | PRoot 路径核心（canonicalize、绑定表、解析） |

## 约定

- **构建变体**：只有 `GUARDED` 一个编译开关（`make build` 产出 `elfloader` 与 `elfloader-guarded`）。
  配置结构在两种构建中布局相同，只有一个 `PAYLOAD_ABI_VERSION`；改动 `payload_config_t`
  或桩约定时必须递增它。
- **系统调用号**：一律用内核的 `__NR_*`，判断时按 32 位（内核以 int 解释 w8）。
- **错误**：payload 函数返回 `-errno`；loader 内部函数返回 0/-1，致命错误统一 `z_errx`
  （失败即退出，绝不留下未改写的系统调用指令）。
- **日志**：loader 用 `z_printf`，仅在 `--log` 非零时输出，默认对 guest 完全静默；payload 不打印。
- **常量**：私有 prctl、固定地址、陷阱标记只定义在 `elf_abi.h`（Python 侧经 `tools/elf_abi.py` 读取）；
  不写裸数字。
- **注释**：代码注释用英文，文档用中文。
- **测试**：用 `test/lib.py`（`lib.loader()`、`lib.loaders()`、`lib.build_probe()`、`lib.guest()`）；
  修复必须附带在修复前构建上会失败的用例。

## 同一语义的多套实现

运行环境不同，以下几处各有两套实现，不能简单合并；改动其中一处必须同时改另一处，并由共享的验收用例
覆盖：

| 语义 | 实现 | 共享的验收 |
| --- | --- | --- |
| 写时复制合并视图（whiteout、opaque、复制上来） | payload `union_view.c`；宿主 `tools/oci/union.py`、`guestfs.py` | `test/oci/run.py` 的 `--cow` 与层镜像用例（同一容器内外对照） |
| 层镜像（erofs）读取与按需展开 | loader/payload `lazy_layer.c`；宿主 `tools/oci/erofs.py` | `test/oci/erofs_check.py`、`test/proot/test_loop.py`、`test_union.py` |
| 路径到权限的解析 | payload `proot_bridge.c` + `fs_policy.c`；broker `broker.c` 树表 | guarded 与 `--isolate` 跑同一组用例（`test/fs_policy/agent_launch.py` 比较两种后端输出一致） |
