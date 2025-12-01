#include <stdio.h>
#include <string.h>

#include "../../elf/src/payload/execve_utils.h"
#include "../../elf/src/payload/path_rewrite.h"
#include "../../elf/src/payload/config.h"

extern payload_config_t g_payload_config;

static int g_failures = 0;

static void expect_str(const char *name, const char *actual, const char *expected)
{
    if (strcmp(actual, expected) != 0) {
        printf("[test][FAIL] %s\n  expected: %s\n  actual  : %s\n",
               name, expected, actual);
        g_failures++;
    } else {
        printf("[test][OK] %s -> %s\n", name, actual);
    }
}

static void reset_config(void)
{
    memset(&g_payload_config, 0, sizeof(g_payload_config));
}

static void setup_basic_mapping(void)
{
    reset_config();
    safe_cpy(g_payload_config.root, CONFIG_MAX_PATH, "/rootfs");
    safe_cpy(g_payload_config.binds[0].src, CONFIG_MAX_PATH, "/bind");
    safe_cpy(g_payload_config.binds[0].dst, CONFIG_MAX_PATH, "/real/bind");
    g_payload_config.bind_count = 1;
}

static void test_path_list_rewrite(void)
{
    setup_basic_mapping();
    char out[CONFIG_MAX_PATH];

    rewrite_env_entry("PATH=/bin:/bind/app:rel/bin", out, sizeof(out));
    expect_str("PATH rewrite", out, "PATH=/rootfs/bin:/real/bind/app:rel/bin");

    rewrite_env_entry("LD_LIBRARY_PATH=/bind/lib:/usr/lib", out, sizeof(out));
    expect_str("LD_LIBRARY_PATH rewrite",
               out,
               "LD_LIBRARY_PATH=/real/bind/lib:/rootfs/usr/lib");

    rewrite_env_entry("LD_PRELOAD=/bind/libfoo.so:/usr/lib/libbar.so:rel.so",
                      out, sizeof(out));
    expect_str("LD_PRELOAD rewrite",
               out,
               "LD_PRELOAD=/real/bind/libfoo.so:/rootfs/usr/lib/libbar.so:rel.so");
}

static void test_absolute_envs(void)
{
    setup_basic_mapping();
    char out[CONFIG_MAX_PATH];

    rewrite_env_entry("PWD=/bind/work", out, sizeof(out));
    expect_str("PWD rewrite", out, "PWD=/real/bind/work");

    rewrite_env_entry("HOME=relative", out, sizeof(out));
    expect_str("HOME relative untouched", out, "HOME=relative");

    rewrite_env_entry("TMPDIR=/usr/tmp", out, sizeof(out));
    expect_str("TMPDIR rewrite", out, "TMPDIR=/rootfs/usr/tmp");
}

int main(void)
{
    test_path_list_rewrite();
    test_absolute_envs();
    return g_failures ? 1 : 0;
}
