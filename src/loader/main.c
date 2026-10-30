/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Loader entry: load the payload and the program (with its interpreter),
 * hand the payload its configuration, rebuild the initial stack for the
 * program and jump to it. The same binary runs every guest exec again
 * (--child-loader, arguments from the payload). */
#include <asm/unistd.h>
#include "loader.h"
#include "elf_abi.h"

static void z_fini(void)
{
}

/* The program's environment: the host's in compat mode and for every guest
 * exec (the guest passed it), only -e entries for a fresh container; -e
 * entries replace variables of the same name. */
static char **environment(const payload_config_t *cfg, const struct loader_options *opt,
			  char **host, int *count)
{
	int n = 0, keep = cfg->mode == CONFIG_MODE_COMPAT || opt->child;
	while (keep && host[n])
		n++;
	size_t bytes = (size_t)(n + opt->env_count + 1) * sizeof(char *);
	char **env = z_mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (env == (void *)-1)
		z_errx(1, "out of memory");
	for (int i = 0; i < n; i++)
		env[i] = host[i];
	for (int i = 0; i < opt->env_count; i++) {
		const char *kv = opt->envs[i];
		size_t key = (size_t)(z_strchr(kv, '=') - kv) + 1;
		int j = 0;
		while (j < n && z_strncmp(env[j], kv, key))
			j++;
		env[j] = (char *)kv;
		if (j == n)
			n++;
	}
	env[n] = NULL;
	*count = n;
	return env;
}

/* PRoot's glue lives in PROOT_TMP_DIR, else TMPDIR, else /tmp; the exec
 * chain keeps the initial choice whatever the guest environment. */
static void choose_glue_dir(payload_config_t *cfg, char **env)
{
	static const char *const keys[] = {"PROOT_TMP_DIR=", "TMPDIR="};
	for (int k = 0; k < 2; k++) {
		size_t len = z_strlen(keys[k]);
		for (char **e = env; *e; e++)
			if (!z_strncmp(*e, keys[k], len) && (*e)[len] == '/' &&
			    z_strlen(*e + len) < CONFIG_MAX_PATH) {
				copy_cstr(cfg->glue_dir, CONFIG_MAX_PATH, *e + len);
				return;
			}
	}
	copy_cstr(cfg->glue_dir, CONFIG_MAX_PATH, "/tmp");
}

/* /proc/self/exe in guest terms: named by the exec chain, else the initial
 * target (relative to the root, or to the cwd without one). */
static void choose_exec_exe(payload_config_t *cfg, const struct loader_options *opt,
			    const char *file)
{
	const char *named = opt->exec_exe ? opt->exec_exe : opt->exec_path;
	if (named) {
		copy_cstr(cfg->exec_exe, CONFIG_MAX_PATH, named);
		return;
	}
	while (file[0] == '.' && file[1] == '/')
		for (file += 2; *file == '/'; file++)
			;
	if (file[0] == '/') {
		copy_cstr(cfg->exec_exe, CONFIG_MAX_PATH, file);
	} else if (cfg->root[0]) {
		cfg->exec_exe[0] = '/';
		copy_cstr(cfg->exec_exe + 1, CONFIG_MAX_PATH - 1, file);
	} else if (z_getcwd(cfg->exec_exe, CONFIG_MAX_PATH)) {
		join_paths(cfg->exec_exe, CONFIG_MAX_PATH, cfg->exec_exe,
			   z_strlen(cfg->exec_exe), file);
	}
}

/* Address of the program headers in the loaded image (AT_PHDR), computed
 * as the kernel does: PT_PHDR, else relative to the first PT_LOAD. */
static unsigned long phdr_address(const Elf_Ehdr *ehdr, const Elf_Phdr *phdr, unsigned long bias)
{
	for (int i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_PHDR)
			return bias + phdr[i].p_vaddr;
	for (int i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_LOAD)
			return bias + phdr[i].p_vaddr - phdr[i].p_offset + ehdr->e_phoff;
	return 0;
}

struct image {
	Elf_Ehdr ehdr;
	Elf_Phdr phdr[ELF_MAX_PHNUM];
	unsigned long bias, entry;
};

static void load(struct image *img, const char *path, unsigned long payload_entry)
{
	int fd = z_openat(AT_FDCWD, path, O_RDONLY);
	if (fd < 0)
		z_errx(1, "can't open %s", path);
	elf_read_headers(fd, &img->ehdr, img->phdr, path);
	img->bias = elf_load_image(fd, &img->ehdr, img->phdr, payload_entry, path);
	img->entry = img->bias + img->ehdr.e_entry;
	z_close(fd);
}

/* PT_INTERP of the program, as a host path: the payload resolved it for a
 * guarded child (read policy, guest symlinks); otherwise it is resolved
 * through the root and binds here. NULL for a static program. */
static const char *interpreter(const struct image *prog, const char *file,
			       const payload_config_t *cfg, const struct loader_options *opt,
			       char *out, size_t cap)
{
	for (int i = 0; i < prog->ehdr.e_phnum; i++) {
		const Elf_Phdr *p = &prog->phdr[i];
		if (p->p_type != PT_INTERP)
			continue;
		if (opt->exec_interp)
			return opt->exec_interp;
#ifdef GUARDED
		/* A target swapped after the payload's check must not fall back to
		 * lexical mapping and bypass the read policy. */
		if (opt->child && cfg->guard == GUARD_READS)
			z_errx(1, "interpreter not authorized by payload");
#endif
		char name[CONFIG_MAX_PATH + 1];
		int fd = z_openat(AT_FDCWD, file, O_RDONLY);
		if (fd < 0 || z_lseek(fd, (off_t)p->p_offset, SEEK_SET) < 0 ||
		    z_read(fd, name, p->p_filesz) != (ssize_t)p->p_filesz ||
		    name[p->p_filesz - 1] != '\0')
			z_errx(1, "bogus interp segment %s", file);
		z_close(fd);
		const char *host = resolve_interp_path(cfg, name, out, cap);
		z_printf("[loader] interp \"%s\" -> \"%s\"\n", name, host);
		return host;
	}
	return NULL;
}

/* The program's auxv: its own headers, entry and interpreter base. */
static void set_auxv(Elf_auxv_t *av, const struct image *prog, const struct image *interp,
		     const char *execfn)
{
	for (; av->a_type != AT_NULL; av++) {
		switch (av->a_type) {
		case AT_PHDR: av->a_un.a_val = phdr_address(&prog->ehdr, prog->phdr, prog->bias); break;
		case AT_PHNUM: av->a_un.a_val = prog->ehdr.e_phnum; break;
		case AT_PHENT: av->a_un.a_val = prog->ehdr.e_phentsize; break;
		case AT_ENTRY: av->a_un.a_val = prog->entry; break;
		case AT_BASE: av->a_un.a_val = interp ? interp->bias : 0; break;
		case AT_EXECFN: av->a_un.a_val = (unsigned long)execfn; break;
		}
	}
}

/* What the payload needs beyond the options: the guest auxv (for
 * PR_GET_AUXV and /proc/self/auxv) and the ranges to protect. */
static void configure_payload(unsigned long payload_entry, const payload_config_t *cfg,
			      const Elf_auxv_t *auxv)
{
	extern char __ehdr_start[], _end[];
	payload_config_t *dst = payload_config_of(payload_entry);
	z_memcpy(dst, cfg, sizeof(*dst));
	size_t pairs = 1;
	while (auxv[pairs - 1].a_type != AT_NULL)
		pairs++;
	if (pairs > CONFIG_AUXV_PAIRS)
		z_errx(1, "guest auxv exceeds payload capacity");
	z_memcpy(dst->guest_auxv, auxv, pairs * sizeof(*auxv));
	dst->guest_auxv_bytes = pairs * sizeof(*auxv);
	unsigned n = 0;
	dst->protected_ranges[n][0] = (uint64_t)__ehdr_start;
	dst->protected_ranges[n++][1] = ROUND_PG((uint64_t)_end);
	for (unsigned i = 0; i < g_loader_island_count && n < 64; i++, n++) {
		dst->protected_ranges[n][0] = g_loader_islands[i][0];
		dst->protected_ranges[n][1] = g_loader_islands[i][1];
	}
	dst->protected_count = n;
}

/* argv, envp and auxv are rewritten in place: the program's arguments
 * (argv[target..]) move down over the loader's own, so everything fits. */
static void rebuild_stack(unsigned long *sp, char **argv, int argc, int target,
			  char **env, int envc, const Elf_auxv_t *auxv)
{
	int new_argc = target < argc ? argc - target : 0;
	char **dst = (char **)(sp + 1);
	for (int i = 0; i < new_argc; i++)
		dst[i] = argv[target + i];
	dst[new_argc] = NULL;
	char **dst_env = dst + new_argc + 1;
	Elf_auxv_t *dst_aux = (Elf_auxv_t *)(dst_env + envc + 1);
	if ((const void *)dst_aux > (const void *)auxv)
		z_errx(1, "environment does not fit the initial stack");
	for (int i = 0; i < envc; i++)
		dst_env[i] = env[i];
	dst_env[envc] = NULL;
	int i = 0;
	do
		dst_aux[i] = auxv[i];
	while (auxv[i++].a_type != AT_NULL);
	*sp = (unsigned long)new_argc;
}

void z_entry(unsigned long *sp, void (*fini)(void))
{
	static payload_config_t cfg;
	static struct image prog, interp;
	static char interp_buf[CONFIG_MAX_PATH];
	struct loader_options opt;
	(void)fini;

	z_printf_enabled = 0;
	int argc = (int)*sp;
	char **argv = (char **)(sp + 1), **host_env = &argv[argc + 1], **p = host_env;
	while (*p++)
		;
	Elf_auxv_t *auxv = (Elf_auxv_t *)p;

	options_parse(argc, argv, &cfg, &opt);
	z_printf_enabled = cfg.log_level != LOG_LEVEL_NONE;
	hook_set_section_scan(cfg.seccomp_backstop);
	g_deny_wx = cfg.seccomp_backstop;
	normalize_host_path(cfg.root, CONFIG_MAX_PATH);
	for (int i = 0; i < cfg.bind_count; i++)
		normalize_host_path(cfg.binds[i].dst, CONFIG_MAX_PATH);
	mark_case_aliases(&cfg);
	resolve_self_path(cfg.loader_path, CONFIG_MAX_PATH);

	/* A guest exec names the program with --exec-target (its argv may be
	 * empty); otherwise the program is the first argument. */
	if (!opt.exec_target && opt.target >= argc)
		z_errx(1, "no program to run");
	const char *file = opt.exec_target ? opt.exec_target : argv[opt.target];
	if (!opt.child) {
		/* The initial program is named relative to the root. */
		if (cfg.root[0] && file[0] == '/')
			z_errx(1, "absolute path not allowed with --root; use a path relative to it");
		if (cfg.root[0] && z_chdir(cfg.root) < 0)
			z_errx(1, "chdir to root %s failed", cfg.root);
		if (!cfg.glue_dir[0])
			choose_glue_dir(&cfg, host_env);
	} else if (!is_elf_file_at(AT_FDCWD, file)) {
		z_errx(1, "target is not ELF: %s", file);
	}
	choose_exec_exe(&cfg, &opt, file);
	int envc;
	char **env = environment(&cfg, &opt, host_env, &envc);

	unsigned long payload_entry = payload_load(opt.payload);
	load(&prog, file, payload_entry);
	const char *interp_path = interpreter(&prog, file, &cfg, &opt, interp_buf, sizeof(interp_buf));
	if (interp_path)
		load(&interp, interp_path, payload_entry);
	/* fexecve: the program is loaded; this descriptor copy is not the guest's. */
	if (opt.exec_fd > 2)
		z_close(opt.exec_fd);

	set_auxv(auxv, &prog, interp_path ? &interp : NULL,
		 opt.exec_path ? opt.exec_path : opt.target < argc ? argv[opt.target] : file);
	configure_payload(payload_entry, &cfg, auxv);
	rebuild_stack(sp, argv, argc, opt.target, env, envc, auxv);

	if (cfg.log_level != LOG_LEVEL_NONE)
		debugger_install();
	if (cfg.seccomp_backstop)
		backstop_install(payload_entry, !opt.child);
	/* /proc/<pid>/{comm,stat,status} name the guest program, not the loader. */
	const char *name = opt.exec_name ? opt.exec_name : cfg.exec_exe;
	for (const char *c = name; *c; c++)
		if (*c == '/' && c[1])
			name = c + 1;
	if (*name)
		z_prctl(15 /* PR_SET_NAME */, (unsigned long)name, 0);
	z_trampo((void (*)(void))(interp_path ? interp.entry : prog.entry), sp, z_fini);
	z_exit(0);
}
