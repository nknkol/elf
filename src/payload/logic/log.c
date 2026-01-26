#include "log.h"
#include "mini_libc.h"
#include "utils.h"

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

int log_debug_enabled(void)
{
    return log_level_enabled(LOG_LEVEL_DEBUG);
}

void log_path(const char *tag, const char *path)
{
    if (!log_debug_enabled() || !tag || !path)
        return;
    sys_write(2, tag, sys_strlen(tag));
    sys_write(2, path, sys_strlen(path));
    sys_write(2, "\n", 1);
}

void log_path_pair(const char *tag, const char *p1, const char *p2)
{
    if (!log_debug_enabled() || !tag)
        return;
    sys_write(2, tag, sys_strlen(tag));
    if (p1) sys_write(2, p1, sys_strlen(p1));
    if (p2) {
        sys_write(2, " -> ", 4);
        sys_write(2, p2, sys_strlen(p2));
    }
    sys_write(2, "\n", 1);
}

void log_errno_value(const char *tag, long err)
{
    if (!log_debug_enabled() || !tag)
        return;
    char buf[32];
    format_int(err, buf, sizeof(buf));
    sys_write(2, tag, sys_strlen(tag));
    sys_write(2, buf, sys_strlen(buf));
    sys_write(2, "\n", 1);
}