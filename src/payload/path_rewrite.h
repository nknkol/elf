#ifndef PATH_REWRITE_H
#define PATH_REWRITE_H

#include <stddef.h>

/* Guest->host: rewrite path into payload-owned buffer with root/bind mapping. */
const char *rewrite_path(const char *in, char *out, size_t out_sz);

/* Host->guest: rewrite kernel-returned path back into guest view. */
const char *rewrite_path_from_host(const char *in, char *out, size_t out_sz);

#endif /* PATH_REWRITE_H */
