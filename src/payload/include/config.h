#ifndef PAYLOAD_CONFIG_H
#define PAYLOAD_CONFIG_H

#include <stdint.h>

#define LOG_LEVEL_NONE   0
#define LOG_LEVEL_ERROR  1
#define LOG_LEVEL_WARN   2
#define LOG_LEVEL_INFO   3
#define LOG_LEVEL_DEBUG  4

#define CONFIG_MAGIC        0x484f4f4b /* "HOOK" */
#define CONFIG_VERSION      1

/* compat keeps the host environment and identity; container starts from a
 * clean environment and fake root (PRoot -0). */
#define CONFIG_MODE_COMPAT     0
#define CONFIG_MODE_CONTAINER  1

#define CONFIG_MAX_PATH     256
#define CONFIG_AUXV_PAIRS   64
#define CONFIG_MAX_BINDS    16
#define CONFIG_CHILD_LOADER_ARG "--child-loader"
#define CONFIG_CHILD_EXEC_TARGET "--exec-target"
#define CONFIG_CHILD_EXEC_PATH "--exec-path"
/* Payload-resolved host path of the target PT_INTERP (file access mode). */
#define CONFIG_CHILD_EXEC_INTERP "--exec-interp"
/* Guest path of the executed binary (/proc/self/exe). */
#define CONFIG_CHILD_EXEC_EXE "--exec-exe"
/* Basename of the path as passed to execve, for the kernel comm. */
#define CONFIG_CHILD_EXEC_NAME "--exec-name"
/* Base directory of the glue tree, fixed by the initial loader. */
#define CONFIG_CHILD_GLUE_DIR "--glue-dir"
/* Guest credentials r:e:s:fs uid then gid (PRoot fake_id0), when not root. */
#define CONFIG_CHILD_FAKE_IDS "--fake-ids"
/* Supplementary groups, comma separated ("-" for none). */
#define CONFIG_CHILD_FAKE_GROUPS "--fake-groups"
/* fexecve: a descriptor of the program itself; the loader opens it through
 * /proc/self/fd and closes it. */
#define CONFIG_CHILD_EXEC_FD "--exec-fd"

struct bind_entry {
    char src[CONFIG_MAX_PATH];
    char dst[CONFIG_MAX_PATH];
    /* Set by the loader when host names below the parent mount match this
     * mountpoint regardless of case: 1 + length of the parent's guest
     * prefix (matched exactly); the rest matches ignoring ASCII case. */
    uint32_t fold;
};

/* Guarded build: what the mount access policy enforces (each level
 * includes the previous ones). Not isolation. */
enum guard_level {
    GUARD_OBSERVE, /* --observe-mount-access: record origins only */
    GUARD_PATHS,   /* --guard-path-mutations: path-based changes */
    GUARD_FILES,   /* --guard-file-mutations: and FD-based changes */
    GUARD_READS,   /* --guard-file-access: and reads, listings, exec */
};

/* Written by the loader into the payload before the guest runs; the same
 * layout in both builds (PAYLOAD_ABI_VERSION). */
typedef struct payload_config {
    int32_t log_level;       /* LOG_LEVEL_* */
    int32_t mode;            /* CONFIG_MODE_* */
    int32_t bind_count;
    char root[CONFIG_MAX_PATH];
    struct bind_entry binds[CONFIG_MAX_BINDS];
    /* Host path of the loader binary, re-executed for every guest exec. */
    char loader_path[CONFIG_MAX_PATH];
    /* Guest path of the running executable (interpreter for scripts), for
     * /proc/<pid>/exe. The kernel link names the loader instead. */
    char exec_exe[CONFIG_MAX_PATH];
    /* Glue tree base: PROOT_TMP_DIR, TMPDIR or /tmp of the initial loader. */
    char glue_dir[CONFIG_MAX_PATH];
    uint32_t fake_ids[8]; /* Guest r/e/s/fs uid then gid; all 0 initially. */
    /* --link-copy: a hard link the storage refuses becomes a copy. */
    int32_t link_copy;
    /* --seccomp-backstop: unhooked syscalls trap to the payload. */
    int32_t seccomp_backstop;
    /* Loader image and the stub islands the loader created: guest memory
     * calls may not unmap, remap or reprotect them. */
    uint32_t protected_count;
    uint64_t protected_ranges[64][2];
    /* Supplementary groups (PRoot fake_id0); fake_group_count < 0: {0}. */
    int32_t fake_group_count;
    uint32_t fake_groups[32];
    /* uname overrides (PRoot -k for the release); empty keeps the kernel's. */
    char kernel_release[65];
    char kernel_sysname[65];
    /* Guarded build only (zero otherwise). */
    int32_t fd_state; /* Internal sealed exec handoff, -1 if absent. */
    /* Root then bind order, d/r/w; empty=legacy, guard selects partial enforcement. */
    char mount_access_observe[CONFIG_MAX_BINDS + 2];
    int32_t revalidate_file_fds; /* Re-derive regular-file origins, never trust snapshot tags. */
    int32_t allow_pipe_output; /* Newly created pipe2 write ends only. */
    int32_t allow_stdio_output; /* Revalidate pipe/TTY stdout+stderr, write/writev only. */
    int32_t guard; /* enum guard_level; meaningful with mount_access_observe. */
    int32_t allow_stream_input; /* Inherited pipe/socket/verified TTY reads in read guard mode. */
    int32_t allow_local_output; /* Writes to locally created sockets/eventfd/memfd. */
    uint64_t guest_auxv_bytes;
    uint64_t guest_auxv[CONFIG_AUXV_PAIRS * 2];
} payload_config_t;

extern payload_config_t g_payload_config;

#endif /* PAYLOAD_CONFIG_H */
