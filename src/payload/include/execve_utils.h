#ifndef EXECVE_UTILS_H
#define EXECVE_UTILS_H

#include <stddef.h>
#include "config.h"

size_t safe_cpy(char *dst, size_t dst_sz, const char *src);
void rewrite_path_list(const char *val, char *out, size_t out_sz);
void rewrite_env_entry(const char *in, char *out, size_t out_sz);
int build_exec_env(const char *const *in, char **out,
                   char buf[][CONFIG_MAX_PATH], size_t max_items);

#endif /* EXECVE_UTILS_H */
