#include "radix_tree.h"
#include "execve_utils.h"
#include "utils.h"

void radix_tree_init(radix_tree_t *tree)
{
    if (!tree)
        return;
    tree->count = 0;
}

void *radix_tree_lookup(radix_tree_t *tree, const char *key)
{
    if (!tree || !key)
        return NULL;
    for (int i = 0; i < tree->count; i++) {
        if (sys_streq(tree->entries[i].key, key))
            return tree->entries[i].value;
    }
    return NULL;
}

int radix_tree_insert(radix_tree_t *tree, const char *key, void *value)
{
    if (!tree || !key)
        return 0;
    for (int i = 0; i < tree->count; i++) {
        if (sys_streq(tree->entries[i].key, key)) {
            tree->entries[i].value = value;
            return 1;
        }
    }
    if (tree->count >= RADIX_MAX_ENTRIES)
        return 0;
    safe_cpy(tree->entries[tree->count].key,
             sizeof(tree->entries[tree->count].key),
             key);
    tree->entries[tree->count].value = value;
    tree->count++;
    return 1;
}
