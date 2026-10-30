# ELF / PRoot 文件系统运行后端

在 HarmonyOS 系统沙盒内，用 AArch64 ELF 加载与 SVC 指令改写接入 PRoot 的路径语义：
guest 程序的每条系统调用跳到 payload，按 root/bind 视图翻译路径、伪造身份后再交给内核。
不依赖 ptrace、namespace 或 bubblewrap（真机上都不可用）。主要用途是给 agent 提供
文件视图与访问控制，其次是运行 Linux rootfs（Alpine、Ubuntu、apt、gcc、pip、node、cargo 已验证）。

**这是兼容性后端，不是安全边界。** 进程内拦截无法阻止 guest 跳进 loader/payload 自身的
系统调用指令；保护模式（guarded 构建）只约束正常程序的文件访问，尚未完成对抗验收。

## 构建与测试

需要 Python 3、GNU make、Clang、ld.lld、llvm-objcopy 及 AArch64 Linux ABI 头文件。

```sh
make build            # build/elfloader 与 build/elfloader-guarded
make check            # 核心回归（两种构建）
make check-guarded    # 保护模式回归
make check-alpine ALPINE_ARCHIVE=../alpine-minirootfs-3.24.3-aarch64.tar.gz
make check-ubuntu UBUNTU_ARCHIVE=../ubuntu-base-26.04.1-base-arm64.tar.gz
make bench            # 原生与 loader 的系统调用开销对比
```

每个二进制旁有 `build/<名字>.json` 记录哈希，测试拒绝不是最近一次构建的二进制。
镜像与构建产物不提交 Git。

## 运行

```sh
build/elfloader --mode container --root /absolute/path/to/rootfs \
  -v /absolute/path/to/workspace:/workspace -- ./bin/busybox sh
```

| 选项 | 作用 |
| --- | --- |
| `--root DIR` | guest 根目录（隐含 container 模式）；首个程序用相对 root 的路径 |
| `-v HOST:GUEST` | bind（最多 16 个） |
| `--mode compat\|container` | compat 保留宿主环境与身份；container 清空环境并伪装 root（同 PRoot -0） |
| `-e KEY=VALUE` | 设置 guest 环境变量 |
| `--link-copy` | 存储拒绝硬链接时改为复制（dpkg/apt 需要） |
| `--kernel-release R`、`--kernel-sysname S` | 改写 uname（同 PRoot -k） |
| `--seccomp-backstop` | seccomp 兜底：截获未改写的系统调用；每次调用约多 2 µs，拒绝 W+X 内存 |
| `--log LEVEL` | loader 诊断输出（0-4）；非零时崩溃会打印寄存器转储 |
| `--payload FILE` | 改用外部 payload（测试用；ABI 必须一致） |

guarded 构建另有 `--guard-path-mutations`、`--guard-file-mutations`、`--guard-file-access`
等访问策略选项，见 [保护模式说明](test/fd_runtime/README.md) 与
[agent 启动器](tools/agent_sandbox/README.md)。

## 代码地图

见 [架构说明](docs/ARCHITECTURE.md)。

| 位置 | 职责 |
| --- | --- |
| `src/loader/` | 选项、ELF 装载与校验、桩岛、seccomp 兜底、启动栈 |
| `src/payload/arch/aarch64/` | 入口、桩模板、分发、重入保护、clone 门 |
| `src/payload/logic/` | 完整性检查、PRoot 语义（bridge/exec/auxv）、身份伪造、运行期补钩、guarded FD 运行时 |
| `vendor/proot/src/path/` | 从 PRoot 提取的路径核心（来源见 `vendor/proot/UPSTREAM.md`） |
| `tools/` | 构建脚本、agent 启动器 |
| `test/` | 回归测试；公共辅助在 `test/lib.py` |

## 文档

- [当前进度与验收](docs/STATUS.md)
- [架构说明](docs/ARCHITECTURE.md)
- [PRoot 移植记录](docs/SVC_PORT.md)
- [性能数据](docs/BENCHMARKS.md)
- [FD 身份与只读策略](docs/FD_POLICY_PLAN.md)
- [底层约束和经验](docs/SYSCALL_ENGINE_LESSONS.md)
- [完整形态测试规范](docs/FULL_SYSTEM_TEST_PLAN.md)（目标清单）
- [存储能力实测](docs/STORAGE_CAPABILITIES.md)
