#include "z_asm.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "z_elf.h"
#include "hook.h"

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
	while (*env) {
		if (z_strncmp(*env, "HOOK_RANGE=", 11) == 0) {
			char *val = *env + 11;
			char *dash = z_strchr(val, '-');
			if (dash) {
				int min = z_atoi(val);
				int max = z_atoi(dash + 1);
				set_hook_range(min, max);
			}
		}
		env++;
	}
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

	(void)fini;

	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	env = p = (char **)&argv[argc + 1];

	parse_hook_range(env);

	while (*p++ != NULL)
		;
	av = (void *)p;

	(void)env;
	if (argc < 2)
		z_errx(1, "no input file");
	file = argv[1];

	z_printf("[Loader] Loading payload.elf...\n");
	payload_base = load_elf_payload("./payload.elf", &payload_entry_addr);

	if (!payload_base) {
		z_printf("[Loader] Warning: payload.elf not found or invalid.\n");
	} else {
		z_printf("[Loader] Payload loaded. Base: %p, Entry: %p\n",
			 payload_base, (void *)payload_entry_addr);
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
		AVSET(AT_EXECFN, av, (unsigned long)argv[1]);
		AVSET(AT_BASE, av, elf_interp ?
				base[Z_INTERP] : av->a_un.a_val);
		}
		++av;
	}
#undef AVSET
	++av;

	z_memcpy(&argv[0], &argv[1],
		 (unsigned long)av - (unsigned long)&argv[1]);
	(*sp)--;

	z_trampo((void (*)(void))(elf_interp ?
			entry[Z_INTERP] : entry[Z_PROG]), sp, z_fini);
	z_exit(0);
}
