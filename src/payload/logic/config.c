#include "config.h"

payload_config_t g_payload_config;

int config_log_enabled(void)
{
    return g_payload_config.log_enabled != 0;
}

int config_mode(void)
{
    return g_payload_config.mode;
}

int hook_layer_enabled(int layer_mask)
{
    return (g_payload_config.hook_mask & layer_mask) != 0;
}
