#include <stdint.h>

#include "z_asm.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "z_elf.h"
#include "hook.h"
#include "payload/config.h"

#define PAGE_SIZE	4096
#define ALIGN		(PAGE_SIZE - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR	((unsigned long)-1)

static int z_strncmp(const char *s1, const char *s2, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (s1[i] != s2[i])
			return s1[i] - s2[i];
		if (s1[i] == '\0')
			return 0;
	}
	return 0;
}

static int z_atoi(const char *s)
{
	int res = 0;
	while (*s >= '0' && *s <= '9')
		res = res * 10 + (*s++ - '0');
	return res;
}

static char *z_strchr(const char *s, int c)
{
	while (*s != (char)c) {
		if (!*s++)
			return 0;
	}
	return (char *)s;
}

static void z_fini(void)
{
	/* No-op placeholder for atexit style hook */
}

static size_t z_strlen(const char *s)
{
	size_t n = 0;
	while (s && s[n])
		n++;
	return n;
}

static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
	    	e_ident[EI_CLASS] != ELFCLASS ||
		e_ident[EI_VERSION] != EV_CURRENT ||
		(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)) ? 0 : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr, void *payload_addr, size_t payload_sz)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	typedef struct {
		void *start;
		size_t size;
	} exec_seg_t;
	exec_seg_t *exec_segs = z_alloca(ehdr->e_phnum * sizeof(exec_seg_t));
	int exec_cnt = 0;

	minva = (unsigned long)-1;
	maxva = 0;
	
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;
	z_munmap(base, maxva - minva);

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = z_mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
		if (p == (void *)-1)
			goto err;
		if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
			goto err;
		if (z_read(fd, p + off, iter->p_filesz) !=
				(ssize_t)iter->p_filesz)
			goto err;
		
		int prot = PFLAGS(iter->p_flags);

		if ((prot & PROT_EXEC) && payload_addr) {
			exec_segs[exec_cnt].start = (void *)((unsigned long)p + off);
			exec_segs[exec_cnt].size = iter->p_filesz;
			exec_cnt++;
		}

		if (prot & PROT_EXEC) {
			z_prctl(0x6a6974, 0, 0);
		}
		z_mprotect(p, sz, prot);
		if (prot & PROT_EXEC) {
			z_prctl(0x6a6974, 0, 1);
		}
	}

	/* Install hooks after mappings complete to keep stub pages intact */
	for (int i = 0; i < exec_cnt; i++) {
		install_hook(exec_segs[i].start, exec_segs[i].size, payload_addr, payload_sz);
	}

	return (unsigned long)base;
err:
	z_munmap(base, maxva - minva);
	return LOAD_ERR;
}

#define Z_PROG		0
#define Z_INTERP	1

static void z_flush_cache(void *addr, size_t len)
{
	uintptr_t start = (uintptr_t)addr;
	uintptr_t end = start + len;
	uintptr_t p;

	for (p = start; p < end; p += 4)
		__asm__ volatile ("dc cvau, %0" : : "r"(p) : "memory");
	if (p < end + 4)
		__asm__ volatile ("dc cvau, %0" : : "r"(end - 1) : "memory");
	__asm__ volatile ("dsb ish");

	for (p = start; p < end; p += 4)
		__asm__ volatile ("ic ivau, %0" : : "r"(p) : "memory");
	if (p < end + 4)
		__asm__ volatile ("ic ivau, %0" : : "r"(end - 1) : "memory");
	__asm__ volatile ("dsb ish");
	__asm__ volatile ("isb");
}

static void *load_elf_payload(const char *path, size_t *entry_point_out)
{
	int fd = z_open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	Elf_Ehdr ehdr;
	if (z_read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		z_close(fd);
		return NULL;
	}

	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		z_close(fd);
		return NULL;
	}

	size_t ph_size = ehdr.e_phnum * sizeof(Elf_Phdr);
	Elf_Phdr *phdr = z_alloca(ph_size);
	if (z_lseek(fd, ehdr.e_phoff, SEEK_SET) < 0 ||
	    z_read(fd, phdr, ph_size) != (ssize_t)ph_size) {
		z_close(fd);
		return NULL;
	}

	unsigned long minva = (unsigned long)-1;
	unsigned long maxva = 0;
	for (int i = 0; i < ehdr.e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;
		if (phdr[i].p_vaddr < minva)
			minva = phdr[i].p_vaddr;
		if (phdr[i].p_vaddr + phdr[i].p_memsz > maxva)
			maxva = phdr[i].p_vaddr + phdr[i].p_memsz;
	}
	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);
	size_t total_size = maxva - minva;

	void *base = z_mmap(NULL, total_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == (void *)-1) {
		z_close(fd);
		return NULL;
	}

	for (int i = 0; i < ehdr.e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;

		unsigned long off = phdr[i].p_vaddr & ALIGN;
		unsigned long seg_start = (unsigned long)base + TRUNC_PG(phdr[i].p_vaddr);
		size_t seg_sz = ROUND_PG(phdr[i].p_memsz + off);
		int prot = PFLAGS(phdr[i].p_flags);

		void *p = z_mmap((void *)seg_start, seg_sz, PROT_WRITE,
				 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == (void *)-1) {
			z_munmap(base, total_size);
			z_close(fd);
			return NULL;
		}

		if (z_lseek(fd, phdr[i].p_offset, SEEK_SET) < 0) {
			z_munmap(base, total_size);
			z_close(fd);
			return NULL;
		}

		z_read(fd, (void *)((unsigned long)p + off), phdr[i].p_filesz);
		z_mprotect(p, seg_sz, prot);

		if (prot & PROT_EXEC)
			z_flush_cache(p, seg_sz);
	}

	z_close(fd);

	if (entry_point_out)
		*entry_point_out = (size_t)base + ehdr.e_entry;

	return base;
}

static void parse_hook_range(char **env)
{
	(void)env;
}

typedef struct {
	uint32_t magic;
	uint32_t config_off;
	uint32_t version;
} payload_header_t;

static payload_config_t *locate_payload_config(void *payload_entry)
{
	if (!payload_entry)
		return NULL;

	uint8_t *base = (uint8_t *)payload_entry;
	payload_header_t *hdr = (payload_header_t *)(base + 4); /* skip branch */
	if (hdr->magic != CONFIG_MAGIC || hdr->config_off == 0)
		return NULL;
	return (payload_config_t *)(base + hdr->config_off);
}

static void copy_substr(char *dst, size_t dst_sz, const char *src, size_t len)
{
	if (!dst || dst_sz == 0)
		return;
	size_t i = 0;
	while (i + 1 < dst_sz && i < len && src[i]) {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
}

static void copy_cstr(char *dst, size_t dst_sz, const char *src)
{
	if (!src)
		return;
	copy_substr(dst, dst_sz, src, z_strlen(src));
}

static void parse_bind_list(payload_config_t *cfg, const char *val)
{
	if (!cfg || !val)
		return;

	const char *p = val;
	while (*p && cfg->bind_count < CONFIG_MAX_BINDS) {
		const char *comma = z_strchr(p, ',');
		const char *colon = z_strchr(p, ':');
		const char *end = comma ? comma : p + z_strlen(p);

		if (colon && colon < end) {
			copy_substr(cfg->binds[cfg->bind_count].src,
				    CONFIG_MAX_PATH, p, (size_t)(colon - p));
			copy_substr(cfg->binds[cfg->bind_count].dst,
				    CONFIG_MAX_PATH, colon + 1, (size_t)(end - colon - 1));
			cfg->bind_count++;
		}

		if (!comma)
			break;
		p = comma + 1;
	}
}

static void init_payload_config(payload_config_t *cfg)
{
	if (cfg)
		z_memset(cfg, 0, sizeof(*cfg));
}

static void apply_config_entry(payload_config_t *cfg, const char *entry, char *payload_path_out)
{
	if (!cfg || !entry)
		return;
	if (z_strncmp(entry, "HOOK_LOG=", 9) == 0) {
		const char *val = entry + 9;
		cfg->log_enabled = (val[0] != '\0' && val[0] != '0') ? 1 : 0;
	} else if (z_strncmp(entry, "PROOT_ROOT=", 11) == 0) {
		copy_cstr(cfg->root, CONFIG_MAX_PATH, entry + 11);
	} else if (z_strncmp(entry, "PROOT_BIND=", 11) == 0) {
		parse_bind_list(cfg, entry + 11);
	} else if (z_strncmp(entry, "PAYLOAD_PATH=", 13) == 0) {
		const char *p = entry + 13;
		if (payload_path_out)
			copy_cstr(payload_path_out, CONFIG_MAX_PATH, p);
		copy_cstr(cfg->payload_path, CONFIG_MAX_PATH, p);
	}
}

static void parse_payload_config(payload_config_t *cfg, char **env)
{
	if (!cfg)
		return;

	while (env && *env) {
		apply_config_entry(cfg, *env, NULL);
		env++;
	}
}

static void load_config_file(payload_config_t *cfg, const char *path, char *payload_path_out)
{
	if (!cfg || !path || !path[0])
		return;
	copy_cstr(cfg->config_path, CONFIG_MAX_PATH, path);
	int fd = z_open(path, O_RDONLY);
	if (fd < 0)
		return;

	char buf[2048];
	ssize_t n = z_read(fd, buf, sizeof(buf));
	z_close(fd);
	if (n <= 0)
		return;

	size_t len = (size_t)n;
	size_t pos = 0;
	while (pos < len) {
		size_t end = pos;
		while (end < len && buf[end] != '\n')
			end++;
		size_t start = pos;
		while (start < end && (buf[start] == ' ' || buf[start] == '\t'))
			start++;
		if (start < end && buf[start] != '#') {
			size_t copy_len = end - start;
			char line[CONFIG_MAX_PATH * 2];
			if (copy_len >= sizeof(line))
				copy_len = sizeof(line) - 1;
			for (size_t i = 0; i < copy_len; i++)
				line[i] = buf[start + i];
			line[copy_len] = '\0';
			while (copy_len > 0 && (line[copy_len - 1] == ' ' ||
						line[copy_len - 1] == '\t' ||
						line[copy_len - 1] == '\r')) {
				line[--copy_len] = '\0';
			}
			if (line[0] != '\0')
				apply_config_entry(cfg, line, payload_path_out);
		}
		pos = end + 1;
	}
}

static int has_loader_bind(payload_config_t *cfg)
{
	if (!cfg)
		return 0;
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		if (z_strncmp(cfg->binds[i].src, "/elfloader", CONFIG_MAX_PATH) == 0)
			return 1;
	}
	return 0;
}

static void ensure_loader_bind(payload_config_t *cfg)
{
	if (!cfg)
		return;
	if (has_loader_bind(cfg))
		return;
	if (cfg->bind_count >= CONFIG_MAX_BINDS)
		return;
	copy_cstr(cfg->binds[cfg->bind_count].src, CONFIG_MAX_PATH, "/elfloader");
	copy_cstr(cfg->binds[cfg->bind_count].dst, CONFIG_MAX_PATH, CONFIG_DEFAULT_LOADER_DST);
	cfg->bind_count++;
}

void z_entry(unsigned long *sp, void (*fini)(void))
{
	Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
	Elf_Phdr *phdr, *iter;
	Elf_auxv_t *av;
	char **argv, **env, **p, *elf_interp = NULL;
	unsigned long base[2], entry[2];
	const char *file;
	ssize_t sz;
	int argc, fd, i;

	void *payload_base = NULL;
	size_t payload_entry_addr = 0;
	payload_config_t *payload_cfg = NULL;

	(void)fini;

	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	env = p = (char **)&argv[argc + 1];

	parse_hook_range(env);

	while (*p++ != NULL)
		;
	av = (void *)p;

	(void)env;
	const char *config_path = CONFIG_DEFAULT_CONFIG_PATH;
	char payload_path_override[CONFIG_MAX_PATH];
	z_memset(payload_path_override, 0, sizeof(payload_path_override));
	payload_config_t bootstrap_cfg;
	init_payload_config(&bootstrap_cfg);
	int argi = 1;
	if (argc > 2 && z_strncmp(argv[argi], "-c", 3) == 0) {
		config_path = argv[argi + 1];
		argi += 2;
	}
	load_config_file(&bootstrap_cfg, config_path, payload_path_override);
	if (argc <= argi)
		z_errx(1, "no input file");
	file = argv[argi];
	char **target_argv = &argv[argi];

	z_printf("[Loader] Loading payload.elf...\n");
	const char *payload_path = payload_path_override[0] ? payload_path_override : CONFIG_DEFAULT_PAYLOAD_PATH;
	payload_base = load_elf_payload(payload_path, &payload_entry_addr);

	if (!payload_base) {
		z_printf("[Loader] Warning: payload.elf not found or invalid.\n");
	} else {
		z_printf("[Loader] Payload loaded. Base: %p, Entry: %p\n",
			 payload_base, (void *)payload_entry_addr);
		payload_cfg = locate_payload_config((void *)payload_entry_addr);
		if (payload_cfg) {
			init_payload_config(payload_cfg);
			z_memcpy(payload_cfg, &bootstrap_cfg, sizeof(*payload_cfg));
			ensure_loader_bind(payload_cfg);
		} else {
			z_printf("[Loader] Warning: payload config block not found.\n");
		}
	}

	for (i = 0;; i++, ehdr++) {
		if ((fd = z_open(file, O_RDONLY)) < 0)
			z_errx(1, "can't open %s", file);
		if (z_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
			z_errx(1, "can't read ELF header %s", file);
		if (!check_ehdr(ehdr))
			z_errx(1, "bogus ELF header %s", file);

		sz = ehdr->e_phnum * sizeof(Elf_Phdr);
		phdr = z_alloca(sz);
		if (z_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
			z_errx(1, "can't lseek to program header %s", file);
		if (z_read(fd, phdr, sz) != sz)
			z_errx(1, "can't read program header %s", file);

		if ((base[i] = loadelf_anon(fd, ehdr, phdr, (void *)payload_entry_addr, 0)) == LOAD_ERR)
			z_errx(1, "can't load ELF %s", file);

		entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
		if (file == elf_interp) {
			z_close(fd);
			break;
		}

		for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
			if (iter->p_type != PT_INTERP)
				continue;
			elf_interp = z_alloca(iter->p_filesz);
			if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
				z_errx(1, "can't lseek interp segment");
			if (z_read(fd, elf_interp, iter->p_filesz) !=
					(ssize_t)iter->p_filesz)
				z_errx(1, "can't read interp segment");
			if (elf_interp[iter->p_filesz - 1] != '\0')
				z_errx(1, "bogus interp path");
			file = elf_interp;
		}

		z_close(fd);
		if (elf_interp == NULL)
			break;
	}

#define AVSET(t, v, expr) case (t): (v)->a_un.a_val = (expr); break
	while (av->a_type != AT_NULL) {
		switch (av->a_type) {
		AVSET(AT_PHDR, av, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
		AVSET(AT_PHNUM, av, ehdrs[Z_PROG].e_phnum);
		AVSET(AT_PHENT, av, ehdrs[Z_PROG].e_phentsize);
		AVSET(AT_ENTRY, av, entry[Z_PROG]);
		AVSET(AT_EXECFN, av, (unsigned long)target_argv[0]);
		AVSET(AT_BASE, av, elf_interp ?
				base[Z_INTERP] : av->a_un.a_val);
		}
		++av;
	}
#undef AVSET
	++av;

	z_memcpy(&argv[0], &argv[argi],
		 (unsigned long)av - (unsigned long)&argv[argi]);
	(*sp) -= argi;

	z_trampo((void (*)(void))(elf_interp ?
			entry[Z_INTERP] : entry[Z_PROG]), sp, z_fini);
	z_exit(0);
}
