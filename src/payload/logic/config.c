#include "config.h"

payload_config_t g_payload_config;

int config_log_level(void)
{
    int level = g_payload_config.log_level;
    if (level < LOG_LEVEL_NONE)
        level = LOG_LEVEL_NONE;
    if (level > LOG_LEVEL_DEBUG)
        level = LOG_LEVEL_DEBUG;
    return level;
}

int config_log_enabled(void)
{
    return config_log_level() > LOG_LEVEL_NONE;
}

int config_mode(void)
{
    return g_payload_config.mode;
}

int hook_layer_enabled(int layer_mask)
{
    return (g_payload_config.hook_mask & layer_mask) != 0;
}
