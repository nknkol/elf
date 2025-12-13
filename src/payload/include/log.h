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

#endif /* PAYLOAD_LOG_H */
