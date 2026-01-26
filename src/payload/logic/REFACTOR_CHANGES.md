# `syscall_hooks.c` 重构修改记录

本文档记录了 `syscall_hooks.c` 在 VFS 核心层解耦过程中的主要修改。

## 1. 身份伪造 (Fakeroot)

### `set*id` 系列

**原始代码:**
```c
        /* Fakeroot Phase1/2: 身份切换调用全部假成功 */
        case SYS_setuid:
        case SYS_setgid:
        case SYS_setreuid:
        case SYS_setregid:
        case SYS_setresuid:
        case SYS_setresgid:
        case SYS_setfsuid:
        case SYS_setfsgid:
        case SYS_setgroups:
            DEBUG_LOG("[Payload] fakeroot set* uid/gid -> fake 0\n");
            ret = 0;
            break;
```

**重构后代码:**
```c
        /* Fakeroot Phase1/2: Identity faking via VFS core */
        case SYS_setuid:
        case SYS_setgid:
        case SYS_setreuid:
        case SYS_setregid:
        case SYS_setresuid:
        case SYS_setresgid:
        case SYS_setfsuid:
        case SYS_setfsgid:
        case SYS_setgroups:
            DEBUG_LOG("[Payload] fakeroot set* uid/gid -> VFS\n");
            ret = vfs_fake_success();
            break;
```

---

### `get*id` 系列 (简单)

**原始代码:**
```c
        /* Fakeroot Phase2: 信息查询伪造 */
        case SYS_getuid:
        case SYS_geteuid:
        case SYS_getgid:
        case SYS_getegid:
            DEBUG_LOG("[Payload] fakeroot get[u/g]id -> 0\n");
            ret = 0;
            break;
```

**重构后代码:**
```c
        /* Fakeroot Phase2: Information faking via VFS core */
        case SYS_getuid:
            DEBUG_LOG("[Payload] fakeroot getuid -> VFS\n");
            ret = vfs_getuid();
            break;
        case SYS_geteuid:
            DEBUG_LOG("[Payload] fakeroot geteuid -> VFS\n");
            ret = vfs_geteuid();
            break;
        case SYS_getgid:
            DEBUG_LOG("[Payload] fakeroot getgid -> VFS\n");
            ret = vfs_getgid();
            break;
        case SYS_getegid:
            DEBUG_LOG("[Payload] fakeroot getegid -> VFS\n");
            ret = vfs_getegid();
            break;
```

---

### `getres*id` 系列 (带指针参数)

**原始代码:**
```c
        case SYS_getresuid: {
            DEBUG_LOG("[Payload] fakeroot getresuid\n");
            int *ruid = (int *)args[0];
            int *euid = (int *)args[1];
            int *suid = (int *)args[2];
            if (ruid) *ruid = 0;
            if (euid) *euid = 0;
            if (suid) *suid = 0;
            ret = 0;
            break;
        }
        case SYS_getresgid: {
            DEBUG_LOG("[Payload] fakeroot getresgid\n");
            int *rgid = (int *)args[0];
            int *egid = (int *)args[1];
            int *sgid = (int *)args[2];
            if (rgid) *rgid = 0;
            if (egid) *egid = 0;
            if (sgid) *sgid = 0;
            ret = 0;
            break;
        }
```

**重构后代码:**
```c
        case SYS_getresuid: {
            DEBUG_LOG("[Payload] fakeroot getresuid -> VFS\n");
            ret = vfs_getresuid((int *)args[0], (int *)args[1], (int *)args[2]);
            break;
        }
        case SYS_getresgid: {
            DEBUG_LOG("[Payload] fakeroot getresgid -> VFS\n");
            ret = vfs_getresgid((int *)args[0], (int *)args[1], (int *)args[2]);
            break;
        }
```

---

### `getgroups`

**原始代码:**
```c
        case SYS_getgroups: {
            DEBUG_LOG("[Payload] fakeroot getgroups\n");
            int size = (int)args[0];
            int *list = (int *)args[1];
            if (list && size > 0) {
                list[0] = 0; /* root group */
            }
            ret = (size > 0) ? 1 : 0;
            break;
        }
```

**重构后代码:**
```c
        case SYS_getgroups: {
            DEBUG_LOG("[Payload] fakeroot getgroups -> VFS\n");
            ret = vfs_getgroups((int)args[0], (int *)args[1]);
            break;
        }
```

---

## 2. 路径处理

**重构后代码:**
```c
        case SYS_chdir: {
            DEBUG_LOG("[Payload] chdir -> VFS\n");
            const char *virt_path = (const char *)args[0];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, 0);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] chdir path ", virt_path, res.path);
                args[0] = (long)res.path;
            }
            ret = do_syscall(sys_no, args);
            break;
        }
```

---

### 路径读写/查询类 ( `openat`, `faccessat`, `newfstatat` 等)

**原始代码:**
```c
        case SYS_mkdirat:
        case SYS_mknodat:
        case SYS_unlinkat:
        case SYS_renameat:
        case SYS_openat:
        case SYS_faccessat:
        case SYS_readlinkat:
        case SYS_newfstatat:
            if ((const char *)args[1]) {
                const char *orig = (const char *)args[1];
                const char *rw = rewrite_path(orig,
                                              scratch->new_path,
                                              sizeof(scratch->new_path));
                int need_resolve = 1;
                if (sys_no == SYS_unlinkat || sys_no == SYS_readlinkat || sys_no == SYS_renameat) {
                    need_resolve = 0;
                } else if (sys_no == SYS_openat) {
                    int flags = (int)args[2];
                    if (flags & O_NOFOLLOW)
                        need_resolve = 0;
                } else if (sys_no == SYS_newfstatat || sys_no == SYS_faccessat) {
                    int flags = (int)args[3];
                    if (flags & AT_SYMLINK_NOFOLLOW) {
                        need_resolve = 0;
                    }
                }
                if (need_resolve) {
                    if (resolve_symlink_chain(rw,
                                              scratch->resolved,
                                              sizeof(scratch->resolved))) {
                        rw = scratch->resolved;
                    }
                }
                log_path_pair("[Payload] path arg1 ", orig, rw);
                args[1] = (long)rw;
            }

            /* ... specific handling for renameat and readlinkat ... */
```

**重构后代码:**
```c
        case SYS_mkdirat:
        case SYS_mknodat:
        case SYS_unlinkat:
        case SYS_renameat:
        case SYS_openat:
        case SYS_faccessat:
        case SYS_readlinkat:
        case SYS_newfstatat: {
            const char *virt_path = (const char *)args[1];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] path arg1 ", virt_path, res.path);
                args[1] = (long)res.path;
            }

            /* Handle syscalls with a second path argument (e.g., renameat) */
            if (sys_no == SYS_renameat) {
                const char *virt_path2 = (const char *)args[3];
                if (virt_path2) {
                    /* For rename's destination, we generally don't follow symlinks.
                     * We pass SYS_unlinkat as a hint to vfs_resolve to prevent resolution. */
                    vfs_path_result_t res2 = vfs_resolve(virt_path2, SYS_unlinkat, args);
                     if (res2.error) {
                        ret = res2.error;
                        break;
                    }
                    log_path_pair("[Payload] path arg3 ", virt_path2, res2.path);
                    args[3] = (long)res2.path;
                }
            }

            /* Handle syscalls that write a path back to the user */
            if (sys_no == SYS_readlinkat && args[2]) {
                char *user_buf = (char *)args[2];
                long user_len = args[3];
                long count = user_len < sizeof(scratch->bounce) ? user_len : sizeof(scratch->bounce) - 1;

                args[2] = (long)scratch->bounce;
                args[3] = count;
                ret = do_syscall(sys_no, args);

                if (ret > 0) {
                    scratch->bounce[ret] = '\0';
                    const char *guest_path = rewrite_path_from_host(scratch->bounce,
                                                                   scratch->new_path,
                                                                   sizeof(scratch->new_path));
                    size_t guest_len = sys_strlen(guest_path);
                    if (guest_len < (size_t)user_len) {
                        safe_cpy(user_buf, guest_path);
                        ret = guest_len;
                    } else {
                        // Path doesn't fit, what's the right errno? ENAMETOOLONG?
                        // For now, just return the truncated length.
                        safe_cpy(user_buf, guest_path, user_len -1);
                        user_buf[user_len-1] = '\0';
                        ret = user_len;
                    }
                }
                // Restore original args, just in case.
                args[2] = (long)user_buf;
                args[3] = user_len;
            } else {
                ret = do_syscall(sys_no, args);
            }
            break;
        }
```

---

### `SYS_statfs`

**原始代码:**
```c
        case SYS_statfs: {
            const char *path = (const char *)args[0];
            if (path) {
                const char *rw = rewrite_path(path,
                                              scratch->new_path,
                                              sizeof(scratch->new_path));
                if (resolve_symlink_chain(rw,
                                          scratch->resolved,
                                          sizeof(scratch->resolved))) {
                    rw = scratch->resolved;
                }
                log_path_pair("[Payload] statfs path ", path, rw);
                args[0] = (long)rw;
            }
            ret = do_syscall(sys_no, args);
            break;
        }
```

**重构后代码:**
```c
        case SYS_statfs: {
            DEBUG_LOG("[Payload] statfs -> VFS\n");
            const char *virt_path = (const char *)args[0];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, 0);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] statfs path ", virt_path, res.path);
                args[0] = (long)res.path;
            }
            ret = do_syscall(sys_no, args);
            break;
        }
```

---

### `getcwd` / `readlinkat` 反向路径回写

**重构后代码:**
```c
const char *guest_path = vfs_reverse_path(host_path,
                                          scratch->out_path,
                                          sizeof(scratch->out_path));
```

---

### `symlinkat` target 仅重写不解析

**重构后代码:**
```c
vfs_path_result_t res = vfs_rewrite_noresolve(target_path,
                                             scratch->new_path,
                                             sizeof(scratch->new_path));
args[0] = (long)res.path;
```

## 3. 权限伪造

### `fchmod`, `fchown`, `utimensat` 等

**原始代码:**
```c
        case SYS_fchmodat: {
            // ... path rewrite logic ...
            ret = 0;
            break;
        }

        case SYS_fchownat: {
            // ... path rewrite logic ...
            ret = 0;
            break;
        }

        case SYS_utimensat:
            // ... path rewrite logic ...
            ret = 0;
            break;

        case SYS_fchmod:
            DEBUG_LOG("[Payload] fchmod\n");
            ret = 0;
            break;

        case SYS_fchown:
            DEBUG_LOG("[Payload] fchown\n");
            ret = 0;
            break;
```
**重构后代码:**
```c
        case SYS_fchmodat: {
            DEBUG_LOG("[Payload] fchmodat -> VFS\n");
            const char *virt_path = (const char *)args[1];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] fchmodat path ", virt_path, res.path);
                args[1] = (long)res.path;
            }
            ret = vfs_fake_success();
            break;
        }

        case SYS_fchownat: {
            DEBUG_LOG("[Payload] fchownat -> VFS\n");
            if ((const char *)args[1]) {
                const char *virt_path = (const char *)args[1];
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] fchownat path ", virt_path, res.path);
                args[1] = (long)res.path;
            }
            ret = vfs_fake_success();
            break;
        }

        case SYS_utimensat:
            DEBUG_LOG("[Payload] utimensat -> VFS\n");
            if ((const char *)args[1]) {
                const char *virt_path = (const char *)args[1];
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] utimensat path ", virt_path, res.path);
                args[1] = (long)res.path;
            }
            ret = vfs_fake_success();
            break;

        case SYS_fchmod:
            DEBUG_LOG("[Payload] fchmod -> VFS\n");
            ret = vfs_fake_success();
            break;

        case SYS_fchown:
            DEBUG_LOG("[Payload] fchown -> VFS\n");
            ret = vfs_fake_success();
            break;
```

---

## 4. 执行流处理拆分

`handle_execve_like` 及其辅助函数已从 `syscall_hooks.c` 迁移至 `exec_handler.c/.h`，`syscall_hooks.c` 仅保留调用入口。

**重构后代码:**
```c
        case SYS_execve:
            ret = handle_execve_like(sys_no, args, 0);
            break;

        case SYS_execveat:
            ret = handle_execve_like(sys_no, args, 1);
            break;
```
