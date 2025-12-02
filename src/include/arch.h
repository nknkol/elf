#ifndef ARCH_H
#define ARCH_H

#include <stddef.h>

/* Architecture-specific helpers used by the loader. */
void arch_flush_cache(void *addr, size_t len);

#endif /* ARCH_H */
