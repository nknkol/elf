#ifndef PAYLOAD_CONFIG_H
#define PAYLOAD_CONFIG_H

#include <stdint.h>

#define CONFIG_MAGIC        0x484f4f4b /* "HOOK" */
#define CONFIG_VERSION      1

#define CONFIG_MAX_PATH     256
#define CONFIG_MAX_BINDS    8
#define CONFIG_MAX_ENVS     16
#define CONFIG_DEFAULT_LOADER_DST "/data/service/hnp/horpkg-base.org/horpkg-base_1.0/bin/elfloader"
#ifndef CONFIG_DEFAULT_INIT_PATH
#define CONFIG_DEFAULT_INIT_PATH "tiny-init" /* 名义路径，仅用于 argv/AT_EXECFN，占位相对路径 */
#endif
#ifndef CONFIG_DEFAULT_CONFIG_PATH
#define CONFIG_DEFAULT_CONFIG_PATH "/data/service/hnp/horpkg-base.org/horpkg-base_1.0/etc/loader.conf"
#endif
#ifndef CONFIG_DEFAULT_PAYLOAD_PATH
#define CONFIG_DEFAULT_PAYLOAD_PATH "./payload.elf"
#endif
#define CONFIG_CHILD_LOADER_ARG "--child-loader"

struct bind_entry {
    char src[CONFIG_MAX_PATH];
    char dst[CONFIG_MAX_PATH];
};

typedef struct payload_config {
    int32_t log_enabled;
    int32_t bind_count;
    int32_t env_count;
    int32_t use_init;
    int32_t detach;
    char root[CONFIG_MAX_PATH];
    struct bind_entry binds[CONFIG_MAX_BINDS];
    char workdir[CONFIG_MAX_PATH];
    char log_path[CONFIG_MAX_PATH];
    char config_path[CONFIG_MAX_PATH];
    char payload_path[CONFIG_MAX_PATH];
    char envs[CONFIG_MAX_ENVS][CONFIG_MAX_PATH];
} payload_config_t;

extern payload_config_t g_payload_config;
int config_log_enabled(void);

#endif /* PAYLOAD_CONFIG_H */
