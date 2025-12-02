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

payload 会在顶层构建时自动生成：`src/payload/payload.bin`。

## 运行/测试
- 加载可执行文件：`./elfloader <target>`
- payload_demo 测试：`cd elf/test/payload_demo && make ARCH=aarch64`

## 维护提示
- 架构新增：在 `src/arch/<arch>/` 放置汇编启动/辅助，在 `src/payload/arch/<arch>/` 放 `entry.S`、`raw_syscall.S`、`syscall_nums.h`、`syscall_disp.c`、`mini_libc.c`、`reentry_guard.c`。
