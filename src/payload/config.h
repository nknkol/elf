#ifndef PAYLOAD_CONFIG_H
#define PAYLOAD_CONFIG_H

#include <stdint.h>

#define CONFIG_MAGIC        0x484f4f4b /* "HOOK" */
#define CONFIG_VERSION      1

#define CONFIG_MAX_PATH     256
#define CONFIG_MAX_BINDS    8

struct bind_entry {
    char src[CONFIG_MAX_PATH];
    char dst[CONFIG_MAX_PATH];
};

typedef struct payload_config {
    int32_t log_enabled;
    int32_t bind_count;
    char root[CONFIG_MAX_PATH];
    struct bind_entry binds[CONFIG_MAX_BINDS];
} payload_config_t;

extern payload_config_t g_payload_config;
int config_log_enabled(void);

#endif /* PAYLOAD_CONFIG_H */
