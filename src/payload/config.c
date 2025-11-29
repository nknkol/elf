#include "config.h"

payload_config_t g_payload_config;

int config_log_enabled(void)
{
    return g_payload_config.log_enabled != 0;
}
