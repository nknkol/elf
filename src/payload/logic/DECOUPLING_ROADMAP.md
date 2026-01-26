### **`syscall_hooks.c` 解耦与 VFS 核心重构路线图**

**1. 目标**

本文档旨在指导 `syscall_hooks.c` 的重构工作，将其从一个多功能混合体解耦为一个清晰的、可维护的结构，主要分为 **VFS 适配层** 和 **VFS 核心层**，并为后续实现 OverlayFS 打下基础。

**2. 解耦流程**

**第一阶段：分离通用代码，为重构做准备**

*   **步骤 1.1: 分离通用工具函数 (起点)**
    *   **动作**: 创建新文件 `utils.c` 和 `utils.h`。
    *   **迁移内容**: 将 `syscall_hooks.c` 中与业务逻辑无关的纯工具函数迁移过去。
        *   候选函数: `sys_streq`, `small_copy`, `format_range`, `format_int`, `path_exists`, `dir_len`, `join_paths`, `path_basename`, `format_fd_path`, `zero_region`。
    *   **结果**: `syscall_hooks.c` 体积初步减小，通用能力被集中管理和复用。
    *   **状态**: 已完成。

*   **步骤 1.2: 分离日志与调试函数**
    *   **动作**: 创建新文件 `log.c` 和 `log.h` (如果现有 `log.h` 功能不全)。
    *   **迁移内容**: 将 `log_debug_enabled`, `log_path`, `log_path_pair`, `log_errno_value` 等所有日志相关的功能统一管理。
    *   **结果**: 日志系统独立，方便统一控制日志级别和输出。
    *   **状态**: 已完成。

**第二阶段：抽象 VFS 核心层接口**

*   **步骤 2.1: 创建 VFS 核心层接口文件**
    *   **动作**: 创建 `vfs_core.h`。
    *   **内容**: 定义 VFS 核心的数据结构（如 `vfs_config_t`）和对外暴露的 API。初期 API 可以只是现有功能的简单封装。
        *   `vfs_core_init(config)`
        *   `vfs_resolve(virt_path, sys_no, args)` -> 返回真实路径
        *   `vfs_getuid()`, `vfs_getgid()` -> 返回伪造的ID
        *   `vfs_fake_success()` -> 返回 0
        *   `vfs_reverse_path(host_path)` -> 反向映射，用于 `getcwd/readlinkat`
        *   `vfs_rewrite_noresolve(virt_path)` -> 仅重写，不做 symlink 解析
    *   **结果**: VFS 的能力边界被清晰定义。
    *   **状态**: 已完成。

*   **步骤 2.2: 创建 VFS 核心层实现文件**
    *   **动作**: 创建 `vfs_core.c`。
    *   **迁移内容**: 将 `syscall_hooks.c` 中实现**路径翻译**和**身份/权限伪造**的逻辑及相关辅助函数 (`rewrite_path`, `resolve_symlink_chain`) 迁移至此，并实现 `vfs_core.h` 中定义的接口。
    *   **结果**: VFS 的核心逻辑被封装在独立的模块中。
    *   **状态**: 已完成。

**第三阶段：重构 `syscall_hooks.c` 为适配层**

*   **步骤 3.1: 改造 `syscall_handle_common`**
    *   **动作**: 修改 `syscall_hooks.c` 中的 `switch` 语句。
    *   **内容**: 对于文件和身份相关的 `case`，移除原有的复杂逻辑，改为调用 `vfs_core.h` 中的 API。
    *   **结果**: `syscall_hooks.c` 中的 `case` 变得非常简洁，只负责参数解析和 API 调用，职责单一。
    *   **状态**: 已完成（`getcwd/readlinkat/symlinkat` 路径处理也已下沉到 VFS）。

*   **步骤 3.2: 分离执行流处理逻辑 (可选但推荐)**
    *   **动作**: 创建 `exec_handler.c` 和 `exec_handler.h`。
    *   **迁移内容**: 将 `handle_execve_like` 及其辅助函数 (`execve_scratch_alloc` 等) 迁移过去。
    *   **结果**: `syscall_hooks.c` 进一步简化，`execve` 的复杂逻辑被独立封装。`exec_handler` 会依赖 `vfs_core` 来解析路径。
    *   **状态**: 已完成。

**第四阶段：实现 OverlayFS**

*   **步骤 4.1: 升级 VFS 核心**
    *   **动作**: 在 `vfs_core.c` 中用 `Radix Tree` + `Lnode` 的设计替换掉旧的 `rewrite_path` 逻辑。
    *   **内容**: 实现 `Lookup`, `Copy-Up`, `Whiteout` 等核心策略。
    *   **结果**: 底层 VFS 模型被替换，但由于接口不变，上层 `syscall_hooks.c` 无需改动。

*   **步骤 4.2: 实现缺失的 syscall hook**
    *   **动作**: 在 `entry.S` 和 `syscall_hooks.c` 中添加对 `getdents64` 的钩子。
    *   **内容**: `syscall_hooks.c` 的 `getdents64` case 调用 `vfs_core.c` 中新实现的目录合并 API。
    *   **结果**: OverlayFS 功能完整。
