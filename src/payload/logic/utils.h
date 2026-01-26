#ifndef PAYLOAD_UTILS_H
#define PAYLOAD_UTILS_H

#include <stddef.h> // For size_t

int sys_streq(const char *a, const char *b);
int is_harmonyos(void);
void small_copy(char *dst, const char *src);
void format_range(int min, int max, char *buf, size_t buf_sz);
void format_int(long v, char *buf, size_t buf_sz);
int path_exists(const char *path);
size_t dir_len(const char *path);
void join_paths(char *out, size_t out_sz, const char *base, size_t base_len, const char *suffix);
const char *path_basename(const char *path);
int format_fd_path(char *out, size_t out_sz, int fd);
void zero_region(void *addr, unsigned long len);

#endif /* PAYLOAD_UTILS_H */
