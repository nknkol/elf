/* SPDX-License-Identifier: GPL-2.0-or-later */
/* ELF images: the guest program and its interpreter (copied, hooked, then
 * made executable), and the payload (embedded, or --payload). */
#include <asm/unistd.h>
#include "loader.h"
#include "elf_abi.h"
#include "integrity.h"
#include "arch.h"

#define PFLAGS(x) ((((x) & PF_R) ? PROT_READ : 0) | \
		   (((x) & PF_W) ? PROT_WRITE : 0) | \
		   (((x) & PF_X) ? PROT_EXEC : 0))

extern unsigned char _binary_payload_payload_bin_start[];
extern unsigned char _binary_payload_payload_bin_end[];

int platform_is_harmonyos(void)
{
	static int cached = -1;
	if (cached < 0) {
		char u[6][65];
		cached = z_syscall(__NR_uname, u) >= 0 &&
			z_strncmp(u[0], "HarmonyOS", sizeof("HarmonyOS")) == 0;
	}
	return cached;
}

/* HarmonyOS lets mprotect make anonymous memory executable only inside its
 * JIT window. */
int mprotect_exec(void *addr, size_t len, int prot)
{
	int jit = (prot & PROT_EXEC) && platform_is_harmonyos();
	if (jit)
		z_prctl(PR_HM_JIT, 0, 0);
	int rc = z_mprotect(addr, len, prot);
	if (jit)
		z_prctl(PR_HM_JIT, 0, 1);
	return rc;
}

int g_deny_wx;
unsigned long g_payload_lo, g_payload_hi;

/* The whole layout is checked before anything is mapped: header and
 * program table within the file, each loadable segment's file range within
 * the file and no larger than its memory, no address overflow, a fixed
 * image above the null guard, and a bounded PT_INTERP. */
#define ELF_MAX_VA (1ul << 47)
static unsigned long file_size(int fd, const char *file)
{
	struct stat st;
	if (z_newfstatat(fd, "", &st, AT_EMPTY_PATH) < 0)
		z_errx(1, "can't stat %s", file);
	return (unsigned long)st.st_size;
}

void elf_read_headers(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr, const char *file)
{
	const unsigned char *id = ehdr->e_ident;
	if (z_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
		z_errx(1, "can't read ELF header %s", file);
	if (id[EI_MAG0] != ELFMAG0 || id[EI_MAG1] != ELFMAG1 || id[EI_MAG2] != ELFMAG2 ||
	    id[EI_MAG3] != ELFMAG3 || id[EI_CLASS] != ELFCLASS || id[EI_VERSION] != EV_CURRENT ||
	    (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
		z_errx(1, "bogus ELF header %s", file);
	unsigned long size = file_size(fd, file);
	if (ehdr->e_phentsize != sizeof(Elf_Phdr) || !ehdr->e_phnum ||
	    ehdr->e_phnum > ELF_MAX_PHNUM || ehdr->e_phoff > size ||
	    size - ehdr->e_phoff < (unsigned long)ehdr->e_phnum * sizeof(Elf_Phdr))
		z_errx(1, "bogus program header table %s", file);
	ssize_t len = (ssize_t)(ehdr->e_phnum * sizeof(Elf_Phdr));
	if (z_lseek(fd, (off_t)ehdr->e_phoff, SEEK_SET) < 0 || z_read(fd, phdr, (size_t)len) != len)
		z_errx(1, "can't read program header %s", file);
	unsigned long minva = ELF_MAX_VA;
	int loads = 0;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		const Elf_Phdr *p = &phdr[i];
		if (p->p_type != PT_LOAD && p->p_type != PT_INTERP)
			continue;
		if (p->p_offset > size || p->p_filesz > size - p->p_offset)
			z_errx(1, "segment outside the file %s", file);
		if (p->p_type == PT_INTERP) {
			if (!p->p_filesz || p->p_filesz > CONFIG_MAX_PATH)
				z_errx(1, "bogus interp segment %s", file);
			continue;
		}
		if (p->p_filesz > p->p_memsz || p->p_vaddr >= ELF_MAX_VA ||
		    p->p_memsz > ELF_MAX_VA - p->p_vaddr)
			z_errx(1, "bogus loadable segment %s", file);
		if (p->p_vaddr < minva)
			minva = p->p_vaddr;
		loads++;
	}
	if (!loads)
		z_errx(1, "no loadable segment %s", file);
	if (ehdr->e_type == ET_EXEC && TRUNC_PG(minva) < 0x10000)
		z_errx(1, "fixed image below the null guard %s", file);
}

/* Maps a validated image and returns its load bias (0 for a fixed image).
 * Executable segments are anonymous copies (code
 * signing refuses executable file pages), hooked while still writable and
 * made executable once; read-only data is mapped from the file. Fails
 * closed: no unhooked syscall instruction is ever left executable. */
unsigned long elf_load_image(int fd, const Elf_Ehdr *ehdr, const Elf_Phdr *phdr,
			     unsigned long payload_entry, const char *file)
{
	int dyn = ehdr->e_type == ET_DYN;
	unsigned long minva = (unsigned long)-1, maxva = 0;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;
		if (phdr[i].p_vaddr < minva)
			minva = phdr[i].p_vaddr;
		if (phdr[i].p_vaddr + phdr[i].p_memsz > maxva)
			maxva = phdr[i].p_vaddr + phdr[i].p_memsz;
	}
	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);
	/* A fixed image never replaces anything already mapped (the loader,
	 * the payload, their islands, the stack): it lands where asked on free
	 * space, or loading fails. */
	void *hint = dyn ? NULL : (void *)minva;
	unsigned char *base = z_mmap(hint, maxva - minva, PROT_NONE,
				     (dyn ? 0 : MAP_FIXED_NOREPLACE_) | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == (void *)-1 || (!dyn && base != hint))
		z_errx(1, "can't load ELF %s: address range unavailable", file);
	unsigned long bias = dyn ? (unsigned long)base - minva : 0;

	for (int i = 0; i < ehdr->e_phnum; i++) {
		const Elf_Phdr *ph = &phdr[i];
		if (ph->p_type != PT_LOAD)
			continue;
		unsigned long off = ph->p_vaddr & (PAGE_SIZE - 1);
		void *start = (void *)(bias + TRUNC_PG(ph->p_vaddr));
		size_t size = ROUND_PG(ph->p_memsz + off);
		int prot = PFLAGS(ph->p_flags);
		if (g_deny_wx && integrity_wx(prot))
			z_errx(1, "seccomp backstop: writable and executable segment refused");
		if (prot == PROT_READ && ph->p_filesz == ph->p_memsz &&
		    (ph->p_offset & (PAGE_SIZE - 1)) == off &&
		    z_mmap(start, size, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd,
			   (off_t)TRUNC_PG(ph->p_offset)) != (void *)-1)
			continue;
		unsigned char *p = z_mmap(start, size, PROT_READ | PROT_WRITE,
					  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == (void *)-1 || z_lseek(fd, (off_t)ph->p_offset, SEEK_SET) < 0 ||
		    z_read(fd, p + off, ph->p_filesz) != (ssize_t)ph->p_filesz)
			z_errx(1, "can't load ELF %s", file);
		if ((prot & PROT_EXEC) &&
		    install_hook_file(p + off, ph->p_filesz, (void *)payload_entry,
				      PROT_READ | PROT_WRITE, fd, ph->p_offset) < 0)
			z_errx(1, "cannot place syscall stubs within branch range");
		if (mprotect_exec(p, size, prot) < 0)
			z_errx(1, "can't protect a segment of %s", file);
	}
	return bias;
}

#ifndef DT_RELR
#define DT_RELR 36
#endif
/* Payload segments are mapped at base + p_vaddr (first PT_LOAD at 0). */
static int apply_payload_relocations(void *base, const Elf_Ehdr *ehdr, const Elf_Phdr *phdr)
{
	unsigned long b = (unsigned long)base, rela = 0, size = 0, entry = sizeof(Elf64_Rela);
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_DYNAMIC)
			continue;
		for (const Elf64_Dyn *d = (const Elf64_Dyn *)(b + phdr[i].p_vaddr); d->d_tag != DT_NULL; d++) {
			if (d->d_tag == DT_RELA) rela = d->d_un.d_ptr;
			else if (d->d_tag == DT_RELASZ) size = d->d_un.d_val;
			else if (d->d_tag == DT_RELAENT) entry = d->d_un.d_val;
			else if ((d->d_tag == DT_JMPREL || d->d_tag == DT_PLTRELSZ ||
				  d->d_tag == DT_RELR || d->d_tag == DT_REL) && d->d_un.d_val)
				return -1;
		}
	}
	if (!size)
		return 0;
	if (!rela || entry != sizeof(Elf64_Rela) || size % entry)
		return -1;
	for (const Elf64_Rela *r = (const Elf64_Rela *)(b + rela);
	     (unsigned long)r < b + rela + size; r++) {
		if (ELF64_R_TYPE(r->r_info) != R_AARCH64_RELATIVE)
			return -1;
		*(unsigned long *)(b + r->r_offset) = b + r->r_addend;
	}
	return 0;
}

/* The payload is mapped at its fixed address (the seccomp backstop allows
 * its syscalls by address across exec), relocated and protected. */
static void *map_payload(const unsigned char *blob, size_t blob_size, unsigned long *entry)
{
	const Elf_Ehdr *ehdr = (const Elf_Ehdr *)blob;
	if (blob_size < sizeof(*ehdr) || ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 || ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3 || ehdr->e_phentsize != sizeof(Elf_Phdr) ||
	    ehdr->e_phoff > blob_size ||
	    blob_size - ehdr->e_phoff < ehdr->e_phnum * sizeof(Elf_Phdr))
		return NULL;
	const Elf_Phdr *phdr = (const Elf_Phdr *)(blob + ehdr->e_phoff);
	unsigned long maxva = 0;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;
		if (phdr[i].p_offset > blob_size || phdr[i].p_filesz > blob_size - phdr[i].p_offset)
			return NULL;
		if (phdr[i].p_vaddr + phdr[i].p_memsz > maxva)
			maxva = phdr[i].p_vaddr + phdr[i].p_memsz;
	}
	size_t total = ROUND_PG(maxva);
	unsigned char *base = z_mmap((void *)PAYLOAD_FIXED_BASE, total, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE_, -1, 0);
	if (base == (void *)-1)
		return NULL;
	if (base != (void *)PAYLOAD_FIXED_BASE) {
		z_munmap(base, total);
		return NULL;
	}
	g_payload_lo = (unsigned long)base;
	g_payload_hi = (unsigned long)base + total;
	for (int i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_LOAD)
			z_memcpy(base + phdr[i].p_vaddr, blob + phdr[i].p_offset, phdr[i].p_filesz);
	/* Position independent, but compilers may still emit RELATIVE
	 * relocations; any other dynamic relocation is refused. */
	if (apply_payload_relocations(base, ehdr, phdr) < 0) {
		z_munmap(base, total);
		return NULL;
	}
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;
		unsigned long off = phdr[i].p_vaddr & (PAGE_SIZE - 1);
		void *p = base + TRUNC_PG(phdr[i].p_vaddr);
		size_t size = ROUND_PG(phdr[i].p_memsz + off);
		z_mprotect(p, size, PFLAGS(phdr[i].p_flags));
		if (phdr[i].p_flags & PF_X)
			arch_flush_cache(p, size);
	}
	*entry = (unsigned long)base + ehdr->e_entry;
	return base;
}

/* The embedded payload, or a payload file (--payload; tests). */
unsigned long payload_load(const char *path)
{
	unsigned long entry = 0;
	if (!path) {
		if (!map_payload(_binary_payload_payload_bin_start,
				 (size_t)(_binary_payload_payload_bin_end -
					  _binary_payload_payload_bin_start), &entry))
			z_errx(1, "can't load the embedded payload");
		return entry;
	}
	int fd = z_openat(AT_FDCWD, path, O_RDONLY);
	if (fd < 0)
		z_errx(1, "can't open payload %s", path);
	size_t size = (size_t)file_size(fd, path);
	unsigned char *copy = z_mmap(NULL, size ? size : 1, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (copy == (void *)-1 || z_read(fd, copy, size) != (ssize_t)size)
		z_errx(1, "can't read payload %s", path);
	z_close(fd);
	if (!map_payload(copy, size, &entry))
		z_errx(1, "can't load payload %s", path);
	z_munmap(copy, size ? size : 1);
	return entry;
}

/* The payload header after its first branch: magic, config offset, ABI. */
payload_config_t *payload_config_of(unsigned long entry)
{
	const uint32_t *hdr = (const uint32_t *)(entry + 4);
	if (hdr[0] != CONFIG_MAGIC || !hdr[1])
		z_errx(1, "payload config block not found");
	if (hdr[2] != PAYLOAD_ABI_VERSION)
		z_errx(1, "payload ABI mismatch; rebuild loader and payload together");
	return (payload_config_t *)(entry + hdr[1]);
}
