# 架构说明

## 进程模型

```
build/elfloader [选项] -- 程序 参数
  ├─ 装载 payload（内嵌，固定地址 0x3f80000000）
  ├─ 装载程序与解释器：可执行段复制为匿名页，svc 改写为跳到桩岛，再设为可执行
  ├─ 把配置（root、bind、身份、策略、guest auxv、保护区）写入 payload
  └─ 重建初始栈，跳到程序入口
guest 的每次 exec → payload 以 --child-loader 重新执行同一个 loader
```

loader 是静态、非 PIE 的二进制，固定在 0x3f00000000；guest 进程里没有宿主动态链接器。
loader 与 payload 地址固定，seccomp 兜底才能按地址放行它们自身的系统调用。

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
| `src/payload/include/elf_abi.h` | loader、payload、测试共用的固定数字（ABI 版本、固定地址、私有 prctl） |
| `src/payload/include/integrity.h` | 自身完整性规则（loader 与 payload 共用 W^X 判定） |
| `src/payload/logic/dispatch.c` | 通用分发（见上） |
| `src/payload/logic/proot_*.c` | PRoot 路径语义、exec 链、auxv |
| `src/payload/logic/fd_*.c`、`fs_policy.c`、`vm_write_guard.c` | guarded 构建的 FD 运行时与策略 |
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
