#include "log.h"
#include "mini_libc.h"

int log_level_enabled(int level)
{
    if (level <= LOG_LEVEL_NONE)
        return 0;
    int current = config_log_level();
    return current >= level;
}

void log_write(int level, const char *buf, unsigned long len)
{
    if (!buf || len == 0)
        return;
    if (!log_level_enabled(level))
        return;
    /* write logs to stderr to avoid polluting stdout pipelines */
    long r = sys_write(2, buf, len);
    (void)r; /* best-effort: ignore failures to avoid disturbing target */
}

void log_message(int level, const char *msg)
{
    if (!msg)
        return;
    log_write(level, msg, sys_strlen(msg));
}
