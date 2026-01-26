#ifndef RADIX_TREE_H
#define RADIX_TREE_H

#include "config.h"

#define RADIX_MAX_ENTRIES 512

typedef struct radix_entry {
    char key[CONFIG_MAX_PATH];
    void *value;
} radix_entry_t;

typedef struct radix_tree {
    radix_entry_t entries[RADIX_MAX_ENTRIES];
    int count;
} radix_tree_t;

void radix_tree_init(radix_tree_t *tree);
void *radix_tree_lookup(radix_tree_t *tree, const char *key);
int radix_tree_insert(radix_tree_t *tree, const char *key, void *value);

#endif /* RADIX_TREE_H */
