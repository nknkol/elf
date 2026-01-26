#ifndef PAYLOAD_LOG_H
#define PAYLOAD_LOG_H

#include "config.h"

int log_level_enabled(int level);
void log_write(int level, const char *buf, unsigned long len);
void log_message(int level, const char *msg);

#define LOG_CONST(level, literal)                \
    do {                                         \
        static const char _log_buf[] = literal;  \
        log_write(level, _log_buf, sizeof(_log_buf) - 1); \
    } while (0)

#define LOG_DEBUG(literal) LOG_CONST(LOG_LEVEL_DEBUG, literal)

int log_debug_enabled(void);
void log_path(const char *tag, const char *path);
void log_path_pair(const char *tag, const char *p1, const char *p2);
void log_errno_value(const char *tag, long err);

#endif /* PAYLOAD_LOG_H */
