/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The loader: runs a guest program (and every program it executes, through
 * re-execution with --child-loader) with the payload installed. */
#ifndef LOADER_H
#define LOADER_H

#include <stddef.h>
#include <stdint.h>
#include <signal.h>

#include "config.h"
#include "z_asm.h"
#include "z_elf.h"
#include "z_syscalls.h"
#include "z_utils.h"

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0x20000
#endif
#define MAP_FIXED_NOREPLACE_ 0x100000

#define PAGE_SIZE   4096ul
#define ROUND_PG(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))

#define LOADER_MAX_ENVS 16

/* Command line: the user's options, and the child-loader protocol the
 * payload uses to re-execute the loader for a guest exec. */
struct loader_options {
	int child;              /* --child-loader */
	int target;             /* argv index of the program and its arguments */
	const char *payload;    /* --payload: a payload file, not the embedded one */
	const char *envs[LOADER_MAX_ENVS]; /* -e KEY=VALUE */
	int env_count;
	/* Child protocol (config.h CONFIG_CHILD_*). */
	const char *exec_target; /* host path the payload resolved */
	const char *exec_path;   /* the path the guest passed (AT_EXECFN) */
	const char *exec_interp; /* payload-resolved PT_INTERP (file access guard) */
	const char *exec_exe;    /* guest path of the program (/proc/self/exe) */
	const char *exec_name;   /* basename for the kernel comm */
	int exec_fd;             /* fexecve: a copy of the program's descriptor */
	int isolate;             /* --isolate: start the broker (initial loader) */
	int exec_interp_fd;      /* isolation: the interpreter, opened by the broker */
	const char *case_folds;  /* isolation: bind fold marks, comma separated */
};

/* options.c */
void options_parse(int argc, char **argv, payload_config_t *cfg, struct loader_options *opt);

/* paths.c: host paths and the guest view the loader itself needs. */
void copy_cstr(char *dst, size_t cap, const char *src);
void copy_substr(char *dst, size_t cap, const char *src, size_t len);
int has_prefix(const char *path, const char *prefix);
size_t join_paths(char *out, size_t cap, const char *left, size_t left_len, const char *right);
void normalize_host_path(char *path, size_t cap);
void mark_case_aliases(payload_config_t *cfg);
int resolve_self_path(char *out, size_t cap);
const char *resolve_interp_path(const payload_config_t *cfg, const char *in, char *out, size_t cap);
int is_elf_file_at(int dirfd, const char *path);

/* elf_load.c */
#define ELF_MAX_PHNUM 256
extern unsigned long g_payload_lo, g_payload_hi;
void elf_read_headers(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr, const char *file);
unsigned long elf_load_image(int fd, const Elf_Ehdr *ehdr, const Elf_Phdr *phdr,
			     unsigned long payload_entry, const char *file);
unsigned long payload_load(const char *path);
payload_config_t *payload_config_of(unsigned long entry);

/* hook.c */
void hook_set_section_scan(int enabled);
long install_hook_file(void *target_base, size_t target_size, void *payload_entry, int prot,
		       int fd, unsigned long file_off);
extern uint64_t g_loader_islands[64][2];
extern unsigned g_loader_island_count;

/* signals.c */
typedef void (*signal_handler_t)(int, siginfo_t *, void *);
int signal_install(int sig, signal_handler_t handler, unsigned long flags);
void die_of_signal(int sig);
void debugger_install(void);

/* broker.c (isolation mode) */
void broker_start(payload_config_t *cfg);
void guest_filter_install(void);

/* backstop.c */
void backstop_install(unsigned long payload_entry, int with_filter);

int platform_is_harmonyos(void);
int mprotect_exec(void *addr, size_t len, int prot);

#endif /* LOADER_H */
