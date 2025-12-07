# ELF loader / payload

自举 ELF loader + 静态 PIE payload，用于在目标程序内做 syscall 级 hook（路径重写/链式 loader 等）。loader 不依赖宿主 libc，直接走 `z_syscall.c`。

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
