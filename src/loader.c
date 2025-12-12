#include <stdint.h>
#include <errno.h>

#include "z_asm.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "z_elf.h"
#include "arch.h"
#include "hook.h"
#include "config.h"

#define PAGE_SIZE	4096
#define ALIGN		(PAGE_SIZE - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR	((unsigned long)-1)
#define SYMLINK_MAX_DEPTH 4

static int g_hook_min_default = 0;
static int g_hook_max_default = 0x7fffffff;
static int g_hook_min_interp = 0;
static int g_hook_max_interp = 0x7fffffff;

static void z_fini(void)
{
	/* No-op placeholder for atexit style hook */
}

extern unsigned char _binary_tiny_init_tiny_init_start[];
extern unsigned char _binary_tiny_init_tiny_init_end[];
extern unsigned char _binary_payload_payload_bin_start[];
extern unsigned char _binary_payload_payload_bin_end[];
extern unsigned char _binary_shell_dash_start[];
extern unsigned char _binary_shell_dash_end[];

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

static void *load_elf_payload_fd(int fd, size_t *entry_point_out)
{
	if (fd < 0)
		return NULL;

	if (z_lseek(fd, 0, SEEK_SET) < 0)
		return NULL;

	Elf_Ehdr ehdr;
	if (z_read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		return NULL;
	}

	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		return NULL;
	}

	size_t ph_size = ehdr.e_phnum * sizeof(Elf_Phdr);
	Elf_Phdr *phdr = z_alloca(ph_size);
	if (z_lseek(fd, ehdr.e_phoff, SEEK_SET) < 0 ||
	    z_read(fd, phdr, ph_size) != (ssize_t)ph_size) {
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
			return NULL;
		}

		if (z_lseek(fd, phdr[i].p_offset, SEEK_SET) < 0) {
			z_munmap(base, total_size);
			return NULL;
		}

		z_read(fd, (void *)((unsigned long)p + off), phdr[i].p_filesz);
		z_mprotect(p, seg_sz, prot);

		if (prot & PROT_EXEC)
			arch_flush_cache(p, seg_sz);
	}

	if (entry_point_out)
		*entry_point_out = (size_t)base + ehdr.e_entry;

	return base;
}

static void *load_elf_payload_path(const char *path, size_t *entry_point_out)
{
	if (!path || !path[0])
		return NULL;
	int fd = z_open(path, O_RDONLY);
	if (fd < 0)
		return NULL;
	void *res = load_elf_payload_fd(fd, entry_point_out);
	z_close(fd);
	return res;
}

static int write_all(int fd, const unsigned char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = z_write(fd, buf + off, len - off);
		if (n <= 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static int create_tiny_init_memfd(void)
{
	size_t sz = (size_t)(_binary_tiny_init_tiny_init_end -
			     _binary_tiny_init_tiny_init_start);
	int fd = z_memfd_create("tiny-init", 0);
	if (fd < 0) {
		z_printf("[Loader] tiny-init memfd_create failed errno=%d\n", z_errno);
		return -1;
	}
	if (write_all(fd, _binary_tiny_init_tiny_init_start, sz) < 0)
		goto err;
	if (z_lseek(fd, 0, SEEK_SET) < 0)
		goto err;
	z_printf("[Loader] tiny-init memfd prepared (fd=%d, size=%lu)\n",
		 fd, (unsigned long)sz);
	return fd;
err:
	z_close(fd);
	return -1;
}

static int create_payload_memfd(void)
{
	size_t sz = (size_t)(_binary_payload_payload_bin_end -
			     _binary_payload_payload_bin_start);
	int fd = z_memfd_create("payload.bin", 0);
	if (fd < 0) {
		z_printf("[Loader] payload memfd_create failed errno=%d\n", z_errno);
		return -1;
	}
	if (write_all(fd, _binary_payload_payload_bin_start, sz) < 0)
		goto err;
	if (z_lseek(fd, 0, SEEK_SET) < 0)
		goto err;
	z_printf("[Loader] Embedded payload prepared (fd=%d, size=%lu)\n",
		 fd, (unsigned long)sz);
	return fd;
err:
	z_close(fd);
	return -1;
}

static int create_shell_memfd(void)
{
	size_t sz = (size_t)(_binary_shell_dash_end -
			     _binary_shell_dash_start);
	int fd = z_memfd_create("compat-shell", 0);
	if (fd < 0) {
		z_printf("[Loader] compat-shell memfd_create failed errno=%d\n", z_errno);
		return -1;
	}
	if (write_all(fd, _binary_shell_dash_start, sz) < 0)
		goto err;
	if (z_lseek(fd, 0, SEEK_SET) < 0)
		goto err;
	z_printf("[Loader] compat-shell memfd prepared (fd=%d, size=%lu)\n",
		 fd, (unsigned long)sz);
	return fd;
err:
	z_close(fd);
	return -1;
}

/* Parse hook range string "A-B" */
static int parse_range_str(const char *s, int *min_out, int *max_out)
{
	if (!s || !min_out || !max_out)
		return 0;
	int a = 0, b = 0x7fffffff;
	const char *dash = z_strchr(s, '-');
	if (dash) {
		a = z_atoi(s);
		b = z_atoi(dash + 1);
	} else {
		a = z_atoi(s);
	}
	if (a < 0)
		a = 0;
	if (b < a)
		b = a;
	*min_out = a;
	*max_out = b;
	return 1;
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
			if (cfg->bind_count < CONFIG_MAX_BINDS) {
				copy_substr(cfg->binds[cfg->bind_count].src,
					    CONFIG_MAX_PATH, p, (size_t)(colon - p));
				copy_substr(cfg->binds[cfg->bind_count].dst,
					    CONFIG_MAX_PATH, colon + 1, (size_t)(end - colon - 1));
				cfg->bind_count++;
			}
		}

		if (!comma)
			break;
		p = comma + 1;
	}
}

static int parse_mode_value(const char *s)
{
	if (!s)
		return -1;
	if (z_strncmp(s, "container", 10) == 0 && (s[9] == '\0' || s[9] == '\n'))
		return CONFIG_MODE_CONTAINER;
	if (z_strncmp(s, "compat", 7) == 0 && (s[6] == '\0' || s[6] == '\n'))
		return CONFIG_MODE_COMPAT;
	return -1;
}

static void apply_mode(payload_config_t *cfg, int mode, int explicit_flag)
{
	if (!cfg)
		return;
	cfg->mode = mode;
	cfg->hook_mask = HOOK_LAYER_BASE | HOOK_LAYER_COMPAT;
	if (mode == CONFIG_MODE_CONTAINER)
		cfg->hook_mask |= HOOK_LAYER_ISOLATION;
	if (explicit_flag)
		cfg->mode_explicit = 1;
}

static void maybe_set_container_mode(payload_config_t *cfg)
{
	if (!cfg)
		return;
	if (cfg->mode_explicit)
		return;
	if (cfg->mode != CONFIG_MODE_CONTAINER)
		apply_mode(cfg, CONFIG_MODE_CONTAINER, 0);
}

static void init_payload_config(payload_config_t *cfg)
{
	if (cfg)
		z_memset(cfg, 0, sizeof(*cfg));
	if (cfg) {
		cfg->hook_min = 0;
		cfg->hook_max = 0x7fffffff;
		cfg->hook_min_interp = 0;
		cfg->hook_max_interp = 0x7fffffff;
		apply_mode(cfg, CONFIG_MODE_COMPAT, 0);
	}
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
		maybe_set_container_mode(cfg);
	} else if (z_strncmp(entry, "PROOT_BIND=", 11) == 0) {
		parse_bind_list(cfg, entry + 11);
	} else if (z_strncmp(entry, "PAYLOAD_PATH=", 13) == 0) {
		const char *p = entry + 13;
		if (payload_path_out)
			copy_cstr(payload_path_out, CONFIG_MAX_PATH, p);
		copy_cstr(cfg->payload_path, CONFIG_MAX_PATH, p);
	} else if (z_strncmp(entry, "RUN_MODE=", 9) == 0) {
		int mode = parse_mode_value(entry + 9);
		if (mode >= 0)
			apply_mode(cfg, mode, 1);
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

static int add_bind_entry(payload_config_t *cfg, const char *guest, const char *host)
{
	if (!cfg || !guest || !host || guest[0] == '\0' || host[0] == '\0')
		return 0;
	if (cfg->bind_count >= CONFIG_MAX_BINDS)
		return 0;
	copy_cstr(cfg->binds[cfg->bind_count].src, CONFIG_MAX_PATH, guest);
	copy_cstr(cfg->binds[cfg->bind_count].dst, CONFIG_MAX_PATH, host);
	cfg->bind_count++;
	return 1;
}

static int add_env_entry(payload_config_t *cfg, const char *kv)
{
	if (!cfg || !kv || kv[0] == '\0')
		return 0;
	if (cfg->env_count >= CONFIG_MAX_ENVS)
		return 0;
	copy_cstr(cfg->envs[cfg->env_count], CONFIG_MAX_PATH, kv);
	cfg->env_count++;
	return 1;
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

static int ensure_guest_memfd(int *fd_io)
{
	if (!fd_io)
		return -1;
	if (*fd_io >= 0)
		return *fd_io;
	int fd = z_memfd_create("guest-config", 0);
	if (fd < 0) {
		z_printf("[Loader] guest config memfd_create failed, errno=%d\n", z_errno);
		return -1;
	}
	z_printf("[Loader] guest config memfd created: fd=%d\n", fd);
	*fd_io = fd;
	return fd;
}

static void write_line_memfd(int fd, const char *line)
{
	if (fd < 0 || !line)
		return;
	size_t len = z_strlen(line);
	write_all(fd, (const unsigned char *)line, len);
	write_all(fd, (const unsigned char *)"\n", 1);
	z_printf("[Loader] guest config line: \"%s\"\n", line);
}

static void parse_loader_rc(payload_config_t *cfg, const char *path, char *payload_path_out, int *guest_fd_out)
{
	if (!cfg || !path || !path[0])
		return;

	z_printf("[Loader] parse loader.rc path=\"%s\"\n", path);
	copy_cstr(cfg->config_path, CONFIG_MAX_PATH, path);
	int fd = z_open(path, O_RDONLY);
	if (fd < 0) {
		z_printf("[Loader] failed to open config: %s (errno=%d)\n", path, z_errno);
		return;
	}
	char buf[8192];
	ssize_t n = z_read(fd, buf, sizeof(buf));
	z_close(fd);
	if (n <= 0) {
		z_printf("[Loader] read config failed: rc=%ld errno=%d\n",
			 (long)n, z_errno);
		return;
	}
	size_t len = (size_t)n;
	size_t pos = 0;
	while (pos < len) {
		size_t end = pos;
		while (end < len && buf[end] != '\n')
			end++;
		size_t start = pos;
		while (start < end && (buf[start] == ' ' || buf[start] == '\t'))
			start++;
		size_t line_len = (end > start) ? end - start : 0;
		char line[CONFIG_MAX_PATH * 2];
		if (line_len >= sizeof(line))
			line_len = sizeof(line) - 1;
		for (size_t i = 0; i < line_len; i++)
			line[i] = buf[start + i];
		line[line_len] = '\0';

		if (line_len == 0 || line[0] == '#') {
			pos = end + 1;
			continue;
		}

		if (line[0] == '[') {
			/* 标题注释行，忽略 */
			pos = end + 1;
			continue;
		}

		if (z_strncmp(line, "ROOT ", 5) == 0) {
			copy_cstr(cfg->root, CONFIG_MAX_PATH, line + 5);
			z_printf("[Loader] Host ROOT=\"%s\"\n", cfg->root);
			maybe_set_container_mode(cfg);
		} else if (z_strncmp(line, "BIND ", 5) == 0) {
			const char *val = line + 5;
			const char *colon = z_strchr(val, ':');
			if (colon) {
				char left[CONFIG_MAX_PATH];
				char right[CONFIG_MAX_PATH];
				copy_substr(left, sizeof(left), val, (size_t)(colon - val));
				copy_cstr(right, sizeof(right), colon + 1);
				add_bind_entry(cfg, left, right);
				z_printf("[Loader] Host BIND %s -> %s\n", left, right);
			}
		} else if (z_strncmp(line, "DEBUG ", 6) == 0) {
			cfg->log_enabled = (line[6] == 'o' || line[6] == 'O') ? 1 : 0;
			z_printf("[Loader] Host DEBUG=%d\n", cfg->log_enabled);
		} else if (z_strncmp(line, "PAYLOAD ", 8) == 0) {
			const char *p = line + 8;
			if (payload_path_out)
				copy_cstr(payload_path_out, CONFIG_MAX_PATH, p);
			copy_cstr(cfg->payload_path, CONFIG_MAX_PATH, p);
			z_printf("[Loader] Host PAYLOAD=\"%s\"\n", cfg->payload_path);
		} else if (z_strncmp(line, "MODE ", 5) == 0) {
			int mode = parse_mode_value(line + 5);
			if (mode >= 0) {
				apply_mode(cfg, mode, 1);
				z_printf("[Loader] Host MODE=%s\n", mode == CONFIG_MODE_CONTAINER ? "container" : "compat");
			}
		} else if (z_strncmp(line, "HOOK_RANGE ", 11) == 0) {
			int a = 0, b = 0x7fffffff;
			if (parse_range_str(line + 11, &a, &b)) {
				cfg->hook_min = a;
				cfg->hook_max = b;
				cfg->hook_range_set = 1;
				z_printf("[Hook] HOOK_RANGE set to [%d - %d]\n", a, b);
			}
		} else if (z_strncmp(line, "HOOK_RANGE_INTERP ", 19) == 0) {
			int a = 0, b = 0x7fffffff;
			if (parse_range_str(line + 19, &a, &b)) {
				cfg->hook_min_interp = a;
				cfg->hook_max_interp = b;
				cfg->hook_range_interp_set = 1;
				z_printf("[Hook] HOOK_RANGE_INTERP set to [%d - %d]\n", a, b);
			}
		} else {
			int gfd = ensure_guest_memfd(guest_fd_out);
			if (gfd >= 0)
				write_line_memfd(gfd, line);
		}

		pos = end + 1;
	}
	if (guest_fd_out && *guest_fd_out >= 0)
		z_lseek(*guest_fd_out, 0, SEEK_SET);
}

static int is_child_loader_arg(const char *arg)
{
	if (!arg)
		return 0;
	size_t key_len = z_strlen(CONFIG_CHILD_LOADER_ARG);
	return z_strncmp(arg, CONFIG_CHILD_LOADER_ARG, key_len) == 0 &&
		arg[key_len] == '\0';
}

static const char *find_config_path_arg(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!arg)
			break;
		if (arg[0] != '-' || arg[1] == '\0')
			break;
		if (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0') {
			i++;
			break;
		}
		if (z_strncmp(arg, "-c", 3) == 0 || z_strncmp(arg, "--config", 9) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			if (argv[i + 1][0] == '-')
				z_errx(1, "invalid config path for %s", arg);
			return argv[i + 1];
		}
		if (z_strncmp(arg, "-v", 3) == 0 || z_strncmp(arg, "--volume", 9) == 0 ||
		    z_strncmp(arg, "-e", 3) == 0 || z_strncmp(arg, "--env", 6) == 0 ||
		    z_strncmp(arg, "-w", 3) == 0 || z_strncmp(arg, "--workdir", 10) == 0 ||
		    z_strncmp(arg, "--root", 7) == 0 || z_strncmp(arg, "--log", 6) == 0 ||
		    z_strncmp(arg, "--hook-range", 13) == 0 ||
		    z_strncmp(arg, "--hook-range-interp", 20) == 0) {
			i++;
			continue;
		}
		if (is_child_loader_arg(arg) || z_strncmp(arg, "--init", 7) == 0 ||
		    z_strncmp(arg, "-d", 3) == 0 || z_strncmp(arg, "--detach", 9) == 0) {
			continue;
		}
		break;
	}
	return NULL;
}

static int parse_cli_options(int argc, char **argv, payload_config_t *cfg,
			     int *child_loader_out, int *target_index_out,
			     int *shell_mode_out)
{
	int child_loader = 0;
	int shell_mode = 0;
	int idx = argc;

	for (int i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (!arg)
			break;
		if (arg[0] != '-' || arg[1] == '\0') {
			idx = i;
			break;
		}
		if (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0') {
			idx = i + 1;
			break;
		}

		if (z_strncmp(arg, "--mode", 7) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			int mode = parse_mode_value(argv[i + 1]);
			if (mode < 0)
				z_errx(1, "invalid mode for %s (expect compat|container)", arg);
			apply_mode(cfg, mode, 1);
			i++;
			continue;
		}

		if (z_strncmp(arg, "-s", 3) == 0 || z_strncmp(arg, "--shell", 8) == 0) {
			shell_mode = 1;
			continue;
		}

		if (is_child_loader_arg(arg)) {
			child_loader = 1;
			continue;
		}

		if (z_strncmp(arg, "-c", 3) == 0 || z_strncmp(arg, "--config", 9) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			i++;
			continue;
		}

		if (z_strncmp(arg, "--hook-range", 13) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			int a = 0, b = 0x7fffffff;
			if (!parse_range_str(argv[i + 1], &a, &b))
				z_errx(1, "invalid value for %s", arg);
			cfg->hook_min = a;
			cfg->hook_max = b;
			cfg->hook_range_set = 1;
			i++;
			continue;
		}

		if (z_strncmp(arg, "--hook-range-interp", 20) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			int a = 0, b = 0x7fffffff;
			if (!parse_range_str(argv[i + 1], &a, &b))
				z_errx(1, "invalid value for %s", arg);
			cfg->hook_min_interp = a;
			cfg->hook_max_interp = b;
			cfg->hook_range_interp_set = 1;
			i++;
			continue;
		}

		if (z_strncmp(arg, "-v", 3) == 0 || z_strncmp(arg, "--volume", 9) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			const char *val = argv[++i];
			const char *colon = z_strchr(val, ':');
			if (!colon)
				z_errx(1, "volume needs host:container");
			size_t host_len = (size_t)(colon - val);
			char host[CONFIG_MAX_PATH];
			char guest[CONFIG_MAX_PATH];
			copy_substr(host, sizeof(host), val, host_len);
			copy_cstr(guest, sizeof(guest), colon + 1);
			if (!add_bind_entry(cfg, guest, host))
				z_errx(1, "volume exceeds bind limit or invalid");
			continue;
		}

		if (z_strncmp(arg, "-e", 3) == 0 || z_strncmp(arg, "--env", 6) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			const char *kv = argv[++i];
			if (!z_strchr(kv, '='))
				z_errx(1, "env needs KEY=VALUE");
			if (!add_env_entry(cfg, kv))
				z_errx(1, "env exceeds limit or invalid");
			continue;
		}

		if (z_strncmp(arg, "-w", 3) == 0 || z_strncmp(arg, "--workdir", 10) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			copy_cstr(cfg->workdir, CONFIG_MAX_PATH, argv[++i]);
			continue;
		}

		if (z_strncmp(arg, "--root", 7) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			copy_cstr(cfg->root, CONFIG_MAX_PATH, argv[++i]);
			maybe_set_container_mode(cfg);
			continue;
		}

		if (z_strncmp(arg, "--init", 7) == 0) {
			cfg->use_init = 1;
			continue;
		}

		if (z_strncmp(arg, "-d", 3) == 0 || z_strncmp(arg, "--detach", 9) == 0) {
			cfg->detach = 1;
			continue;
		}

		if (z_strncmp(arg, "--log", 6) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			copy_cstr(cfg->log_path, CONFIG_MAX_PATH, argv[++i]);
			continue;
		}

		idx = i;
		break;
	}

	if (child_loader_out)
		*child_loader_out = child_loader;
	if (target_index_out)
		*target_index_out = idx;
	if (shell_mode_out)
		*shell_mode_out = shell_mode;
	return 0;
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

static int parse_shebang(const char *path, char *interp, size_t interp_sz,
			 char *arg, size_t arg_sz)
{
	if (!path || !interp || interp_sz == 0)
		return 0;
	int fd = z_open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	char buf[256];
	ssize_t n = z_read(fd, buf, sizeof(buf));
	z_close(fd);
	if (n < 2 || buf[0] != '#' || buf[1] != '!')
		return 0;

	size_t pos = 2;
	while (pos < (size_t)n && (buf[pos] == ' ' || buf[pos] == '\t'))
		pos++;

	size_t out = 0;
	while (pos < (size_t)n && buf[pos] != '\n' && buf[pos] != '\r' &&
	       buf[pos] != ' ' && buf[pos] != '\t') {
		if (out + 1 < interp_sz)
			interp[out++] = buf[pos];
		pos++;
	}
	interp[out] = '\0';
	if (out == 0)
		return 0;

	while (pos < (size_t)n && (buf[pos] == ' ' || buf[pos] == '\t'))
		pos++;

	out = 0;
	while (pos < (size_t)n && buf[pos] != '\n' && buf[pos] != '\r') {
		if (out + 1 < arg_sz)
			arg[out++] = buf[pos];
		pos++;
	}
	if (arg && arg_sz)
		arg[out < arg_sz ? out : arg_sz - 1] = '\0';

	return 1;
}

static int is_elf_file(const char *path)
{
	if (!path)
		return 0;
	int fd = z_open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	unsigned char ident[4];
	if (z_read(fd, ident, sizeof(ident)) != (ssize_t)sizeof(ident)) {
		z_close(fd);
		return 0;
	}
	z_close(fd);
	return ident[0] == ELFMAG0 && ident[1] == ELFMAG1 &&
	       ident[2] == ELFMAG2 && ident[3] == ELFMAG3;
}

static void log_bind_list(payload_config_t *cfg, const char *tag)
{
	if (!cfg)
		return;
	z_printf("[Loader] %s: root=\"%s\" binds=%d config=\"%s\" payload=\"%s\"\n",
		 tag ? tag : "config", cfg->root, cfg->bind_count,
		 cfg->config_path, cfg->payload_path);
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		z_printf("[Loader]   bind[%d]: %s -> %s\n", i,
			 cfg->binds[i].src, cfg->binds[i].dst);
	}
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

static int has_prefix(const char *path, const char *prefix)
{
	size_t plen = z_strlen(prefix);
	if (plen == 0)
		return 0;
	if (z_strncmp(path, prefix, plen) != 0)
		return 0;
	char tail = path[plen];
	return tail == '\0' || tail == '/' ? 1 : 0;
}

static size_t join_paths(char *out, size_t out_sz,
			 const char *left, size_t left_len,
			 const char *right)
{
	size_t pos = 0;

	if (!out || out_sz == 0)
		return 0;

	while (pos + 1 < out_sz && left && pos < left_len) {
		out[pos] = left[pos];
		pos++;
	}

	if (!right || right[0] == '\0') {
		out[pos] = '\0';
		return pos;
	}

	int left_slash = (pos > 0 && out[pos - 1] == '/');
	int right_slash = (right && right[0] == '/');

	if (!left_slash && !right_slash) {
		if (pos + 1 < out_sz)
			out[pos++] = '/';
	} else if (left_slash && right_slash) {
		right++;
	}

	size_t i = 0;
	while (pos + 1 < out_sz && right && right[i]) {
		out[pos++] = right[i++];
	}
	out[pos] = '\0';
	return pos;
}

static size_t dirname_len(const char *path)
{
	size_t len = z_strlen(path);
	for (size_t i = len; i > 0; i--) {
		if (path[i - 1] == '/') {
			return (i == 1) ? 1 : i - 1;
		}
	}
	return 0;
}

static void build_rooted_path(payload_config_t *cfg, const char *path,
			      char *out, size_t out_sz)
{
	if (!out || out_sz == 0)
		return;
	if (!path) {
		out[0] = '\0';
		return;
	}
	if (!cfg || cfg->root[0] == '\0') {
		copy_cstr(out, out_sz, path);
		return;
	}
	if (has_prefix(path, cfg->root)) {
		copy_cstr(out, out_sz, path);
		return;
	}
	join_paths(out, out_sz, cfg->root, z_strlen(cfg->root), path);
}

static const char *resolve_child_loader_path(payload_config_t *cfg,
					     const char *path,
					     int is_child_loader,
					     char *out, size_t out_sz)
{
	if (!is_child_loader || !cfg || cfg->root[0] == '\0' ||
	    !path || !out || out_sz == 0)
		return path;

	char current[CONFIG_MAX_PATH];
	char target[CONFIG_MAX_PATH];
	char cwd_buf[CONFIG_MAX_PATH];
	const char *base = NULL;

	if (path[0] == '/') {
		build_rooted_path(cfg, path, current, sizeof(current));
	} else {
		if (z_getcwd(cwd_buf, sizeof(cwd_buf))) {
			base = cwd_buf;
			z_printf("[Loader]   cwd for resolve: \"%s\"\n", base);
		}
		if (base && has_prefix(base, cfg->root)) {
			join_paths(current, sizeof(current), base, z_strlen(base), path);
		} else if (cfg->root[0]) {
			join_paths(current, sizeof(current), cfg->root, z_strlen(cfg->root), path);
		} else if (base) {
			join_paths(current, sizeof(current), base, z_strlen(base), path);
		} else {
			copy_cstr(current, sizeof(current), path);
		}
	}

	z_printf("[Loader] child=%d resolve path \"%s\" -> start \"%s\"\n",
		 is_child_loader, path ? path : "(null)", current);

	for (int depth = 0; depth < SYMLINK_MAX_DEPTH; depth++) {
		ssize_t n = z_readlink(current, target, sizeof(target) - 1);
		if (n < 0) {
			z_printf("[Loader]   readlink failed on \"%s\": rc=%ld errno=%d\n",
				 current, (long)n, z_errno);
			if (z_errno == EINVAL)
				break; /* not a symlink */
			break;
		}
		if ((size_t)n >= sizeof(target))
			n = sizeof(target) - 1;
		target[n] = '\0';
		if (target[0] == '\0')
			break;

		z_printf("[Loader]   link hop %d: \"%s\" -> \"%s\"%s\n",
			 depth, current, target, target[0] == '/' ? " (abs)" : " (rel)");

		if (target[0] == '/') {
			join_paths(current, sizeof(current), cfg->root,
				   z_strlen(cfg->root), target);
		} else {
			size_t dir_len = dirname_len(current);
			join_paths(current, sizeof(current), current, dir_len, target);
		}
	}

	z_printf("[Loader] child=%d final resolved \"%s\"\n",
		 is_child_loader, current);

	copy_cstr(out, out_sz, current);
	return out;
}

static int apply_bind_overlay(payload_config_t *cfg, char *out, size_t out_sz, const char *in_path)
{
	if (!cfg)
		return 0;
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		const char *src = cfg->binds[i].src;
		const char *dst = cfg->binds[i].dst;
		size_t src_len = z_strlen(src);
		if (src_len == 0 || !has_prefix(in_path, src))
			continue;
		const char *suffix = in_path + src_len;
		join_paths(out, out_sz, dst, z_strlen(dst), suffix);
		return 1;
	}
	return 0;
}

static void apply_root_overlay(payload_config_t *cfg, char *out, size_t out_sz)
{
	if (!cfg || !out || out_sz == 0)
		return;
	if (cfg->root[0] == '\0' || out[0] != '/')
		return;
	if (has_prefix(out, cfg->root))
		return;
	char original[CONFIG_MAX_PATH];
	copy_cstr(original, sizeof(original), out);
	join_paths(out, out_sz, cfg->root, z_strlen(cfg->root), original);
}

static const char *rewrite_interp_path(payload_config_t *cfg, const char *in, char *out, size_t out_sz)
{
	if (!cfg || !in || !out || out_sz == 0)
		return in;
	copy_substr(out, out_sz, in, z_strlen(in));
	if (!apply_bind_overlay(cfg, out, out_sz, in))
		apply_root_overlay(cfg, out, out_sz);
	return out;
}

void z_entry(unsigned long *sp, void (*fini)(void))
{
	Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
	Elf_Phdr *phdr, *iter;
	Elf_auxv_t *av;
	char **argv, **env, **p, *elf_interp = NULL;
	char interp_path[CONFIG_MAX_PATH];
	char open_path[CONFIG_MAX_PATH];
	char shebang_interp[CONFIG_MAX_PATH];
	char shebang_interp_arg[CONFIG_MAX_PATH];
	char shebang_script[CONFIG_MAX_PATH];
	unsigned long base[2], entry[2];
	const char *file;
	ssize_t sz;
	int argc, fd, i;
	int load_interp_next = 0;
	int child_loader = 0;
	int shebang_mode = 0;
	int shell_mode = 0;
	int init_memfd = -1;
	int shell_memfd = -1;

	void *payload_base = NULL;
	size_t payload_entry_addr = 0;
	payload_config_t *payload_cfg = NULL;

	(void)fini;

	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	env = p = (char **)&argv[argc + 1];

	while (*p++ != NULL)
		;
	av = (void *)p;
	Elf_auxv_t *av_start = av;

	(void)env;
	const char *config_path = CONFIG_DEFAULT_CONFIG_PATH;
	char payload_path_override[CONFIG_MAX_PATH];
	z_memset(payload_path_override, 0, sizeof(payload_path_override));
	payload_config_t bootstrap_cfg;
	init_payload_config(&bootstrap_cfg);
	static char clean_env_store[CONFIG_MAX_ENVS][CONFIG_MAX_PATH];
	static char *clean_env_ptrs[CONFIG_MAX_ENVS + 1];
	char **compat_env_ptrs = NULL;
	int compat_envc = 0;
	int guest_cfg_fd = -1;
	const char *cli_cfg = find_config_path_arg(argc, argv);
	if (cli_cfg)
		config_path = cli_cfg;
	parse_loader_rc(&bootstrap_cfg, config_path, payload_path_override, &guest_cfg_fd);
	int target_index = 0;
	parse_cli_options(argc, argv, &bootstrap_cfg, &child_loader, &target_index,
			  &shell_mode);
	int argi = target_index;
	int has_config = (config_path && config_path[0]) ? 1 : 0;

	if (shell_mode) {
		apply_mode(&bootstrap_cfg, CONFIG_MODE_COMPAT, 1);
		if (bootstrap_cfg.use_init) {
			z_printf("[Loader] --shell disables --init\n");
			bootstrap_cfg.use_init = 0;
		}
	}

	/* Apply hook ranges from config/CLI */
	g_hook_min_default = bootstrap_cfg.hook_min;
	g_hook_max_default = bootstrap_cfg.hook_max;
	g_hook_min_interp = bootstrap_cfg.hook_min_interp;
	g_hook_max_interp = bootstrap_cfg.hook_max_interp;
	int compat_mode = (bootstrap_cfg.mode == CONFIG_MODE_COMPAT);
	int clean_envc = 0;
	for (int i = 0; i < bootstrap_cfg.env_count && i < CONFIG_MAX_ENVS; i++) {
		copy_cstr(clean_env_store[clean_envc], CONFIG_MAX_PATH, bootstrap_cfg.envs[i]);
		clean_env_ptrs[clean_envc] = clean_env_store[clean_envc];
		clean_envc++;
	}
	clean_env_ptrs[clean_envc] = NULL;
	if (bootstrap_cfg.use_init && guest_cfg_fd >= 0 && clean_envc + 1 < CONFIG_MAX_ENVS) {
		static char fd_env[32];
		int v = guest_cfg_fd;
		int pos = 0;
		const char *prefix = "INIT_CONFIG_FD=";
		while (prefix[pos]) {
			fd_env[pos] = prefix[pos];
			pos++;
		}
		char numbuf[16];
		int npos = 0;
		if (v == 0) {
			numbuf[npos++] = '0';
		} else {
			int tmp = v;
			char rev[16];
			int rpos = 0;
			while (tmp > 0 && rpos < (int)sizeof(rev)) {
				rev[rpos++] = '0' + (tmp % 10);
				tmp /= 10;
			}
			while (rpos > 0)
				numbuf[npos++] = rev[--rpos];
		}
		for (int i = 0; i < npos && pos + 1 < (int)sizeof(fd_env); i++)
			fd_env[pos++] = numbuf[i];
		fd_env[pos] = '\0';
		copy_cstr(clean_env_store[clean_envc], CONFIG_MAX_PATH, fd_env);
		clean_env_ptrs[clean_envc] = clean_env_store[clean_envc];
		clean_envc++;
		clean_env_ptrs[clean_envc] = NULL;
	}
	char **final_env_ptrs = clean_env_ptrs;
	int final_envc = clean_envc;
	if (compat_mode) {
		/* 兼容模式：保留宿主环境，再追加/覆盖 CLI 或配置注入的环境变量 */
		int parent_envc = 0;
		while (env && env[parent_envc])
			parent_envc++;
		int max_envc = parent_envc + clean_envc;
		compat_env_ptrs = z_alloca(sizeof(char *) * (max_envc + 1));
		for (int i = 0; i < parent_envc; i++)
			compat_env_ptrs[compat_envc++] = env[i];
		for (int i = 0; i < clean_envc; i++) {
			const char *kv = clean_env_store[i];
			size_t key_len = 0;
			while (kv[key_len] && kv[key_len] != '=')
				key_len++;
			int replaced = 0;
			for (int j = 0; j < compat_envc; j++) {
				size_t exist_len = 0;
				while (compat_env_ptrs[j][exist_len] && compat_env_ptrs[j][exist_len] != '=')
					exist_len++;
				if (exist_len == key_len &&
				    z_strncmp(compat_env_ptrs[j], kv, key_len) == 0) {
					compat_env_ptrs[j] = (char *)kv;
					replaced = 1;
					break;
				}
			}
			if (!replaced)
				compat_env_ptrs[compat_envc++] = clean_env_store[i];
		}
		compat_env_ptrs[compat_envc] = NULL;
		final_env_ptrs = compat_env_ptrs;
		final_envc = compat_envc;
	}
	log_bind_list(&bootstrap_cfg, "config loaded");
	z_printf("[Loader] child_loader=%d argv_target=\"%s\" payload_path_override=\"%s\" shell=%d\n",
		 child_loader,
		 (shell_mode || argi >= argc || !argv[argi]) ? "(none)" : argv[argi],
		 payload_path_override[0] ? payload_path_override : "(none)",
		 shell_mode);
	/* 主 loader 才主动 chdir 到 root；子 loader 保留调用方 cwd 以正确解析相对路径 */
	if (bootstrap_cfg.root[0] && !child_loader) {
		if (z_chdir(bootstrap_cfg.root) < 0)
			z_errx(1, "chdir to root %s failed", bootstrap_cfg.root);
	}
	if (!has_config && bootstrap_cfg.use_init)
		z_errx(1, "--init requires a config (-c)");
	if (!shell_mode && !has_config && argi >= argc)
		z_errx(1, "no input file");
	if (!shell_mode && has_config && !bootstrap_cfg.use_init && argi >= argc)
		z_errx(1, "no input file");
	if (bootstrap_cfg.use_init) {
		file = CONFIG_DEFAULT_INIT_PATH;
	} else if (shell_mode) {
		file = "(embedded shell)";
	} else {
		file = argv[argi];
	}
	if (bootstrap_cfg.root[0] && file && file[0] == '/' && !child_loader && !shell_mode)
		z_errx(1, "absolute path not allowed when PROOT_ROOT is set; use path relative to root");
	char **target_argv = NULL;
	if (shell_mode) {
		int shell_argc = argc - argi;
		if (shell_argc < 0)
			shell_argc = 0;
		target_argv = z_alloca(sizeof(char *) * (shell_argc + 2));
		int pos = 0;
		target_argv[pos++] = (char *)"dash";
		for (int k = 0; k < shell_argc; k++)
			target_argv[pos++] = argv[argi + k];
		target_argv[pos] = NULL;
	} else {
		static char *empty_argv[] = { NULL };
		target_argv = (argi < argc) ? &argv[argi] : empty_argv;
	}

	if (bootstrap_cfg.use_init) {
		init_memfd = create_tiny_init_memfd();
		if (init_memfd < 0)
			z_errx(1, "failed to prepare embedded tiny-init");
		if (guest_cfg_fd < 0 && argi >= argc)
			z_errx(1, "guest config not available (memfd_create missing?) and no target provided");
	}
	if (shell_mode) {
		shell_memfd = create_shell_memfd();
		if (shell_memfd < 0)
			z_errx(1, "failed to prepare embedded compat shell");
	}

	const char *payload_path = payload_path_override[0] ? payload_path_override : CONFIG_DEFAULT_PAYLOAD_PATH;
	const char *payload_source = payload_path_override[0] ? payload_path_override : "(embedded)";
	int payload_fd = -1;
	int used_embedded = 0;

	if (payload_path_override[0]) {
		z_printf("[Loader] Loading payload.bin from custom path \"%s\"...\n", payload_path);
		payload_base = load_elf_payload_path(payload_path, &payload_entry_addr);
	} else {
		z_printf("[Loader] Loading embedded payload...\n");
		payload_fd = create_payload_memfd();
		if (payload_fd >= 0)
			payload_base = load_elf_payload_fd(payload_fd, &payload_entry_addr);
		if (payload_fd >= 0)
			z_close(payload_fd);
		if (payload_base) {
			used_embedded = 1;
		} else {
			z_printf("[Loader] Embedded payload load failed, trying fallback path \"%s\"...\n",
				 payload_path);
			payload_base = load_elf_payload_path(payload_path, &payload_entry_addr);
			payload_source = payload_path;
		}
	}

	if (!payload_base) {
		z_printf("[Loader] Warning: payload.bin not found or invalid.\n");
	} else {
		z_printf("[Loader] Payload loaded from %s. Base: %p, Entry: %p\n",
			 payload_source, payload_base, (void *)payload_entry_addr);
		payload_cfg = locate_payload_config((void *)payload_entry_addr);
		if (payload_cfg) {
			init_payload_config(payload_cfg);
			z_memcpy(payload_cfg, &bootstrap_cfg, sizeof(*payload_cfg));
			if (!payload_path_override[0] && used_embedded)
				copy_cstr(payload_cfg->payload_path, CONFIG_MAX_PATH, "(embedded)");
			ensure_loader_bind(payload_cfg);
			log_bind_list(payload_cfg, "payload config");
		} else {
			z_printf("[Loader] Warning: payload config block not found.\n");
		}
	}

	for (i = 0;; i++, ehdr++) {
		int loading_interp = load_interp_next;
		fd = -1;
		const char *path_for_open = NULL;
		if (loading_interp)
			set_hook_range(g_hook_min_interp, g_hook_max_interp);
		else
			set_hook_range(g_hook_min_default, g_hook_max_default);
		if (shell_mode && !loading_interp) {
			path_for_open = "(embedded shell)";
			fd = shell_memfd;
		} else if (bootstrap_cfg.use_init && !loading_interp) {
			path_for_open = "(embedded tiny-init)";
			fd = init_memfd;
		} else {
			path_for_open = resolve_child_loader_path(&bootstrap_cfg,
					file, child_loader, open_path, sizeof(open_path));
		}
		z_printf("[Loader] child=%d open target \"%s\" (arg=\"%s\")\n",
			 child_loader, path_for_open, file);
		if (!bootstrap_cfg.use_init && !shell_mode && child_loader && !loading_interp && !shebang_mode) {
			z_memset(shebang_interp, 0, sizeof(shebang_interp));
			z_memset(shebang_interp_arg, 0, sizeof(shebang_interp_arg));
			if (parse_shebang(path_for_open, shebang_interp, sizeof(shebang_interp),
					  shebang_interp_arg, sizeof(shebang_interp_arg))) {
				copy_cstr(shebang_script, sizeof(shebang_script), path_for_open);
				char resolved_interp[CONFIG_MAX_PATH];
				if (shebang_interp[0] == '/') {
					resolve_child_loader_path(&bootstrap_cfg, shebang_interp,
								  child_loader, resolved_interp, sizeof(resolved_interp));
				} else {
					size_t dir_len = dirname_len(path_for_open);
					join_paths(resolved_interp, sizeof(resolved_interp),
						   path_for_open, dir_len, shebang_interp);
				}
				copy_cstr(shebang_interp, sizeof(shebang_interp), resolved_interp);
				z_printf("[Loader] shebang: script=\"%s\" interp=\"%s\" arg=\"%s\"\n",
					 shebang_script, shebang_interp, shebang_interp_arg);
				file = shebang_interp;
				shebang_mode = 1;
				/* Restart loop with interpreter path */
				i--;
				continue;
			}
		}
		if (child_loader && !bootstrap_cfg.use_init && !shell_mode) {
			int elf = is_elf_file(path_for_open);
			z_printf("[Loader] child=%d ELF check \"%s\": %s\n",
				 child_loader, path_for_open, elf ? "yes" : "no");
			if (!elf) {
				z_errx(1, "target is not ELF: %s", path_for_open);
			}
		}
		if (fd < 0 && (fd = z_open(path_for_open, O_RDONLY)) < 0)
			z_errx(1, "can't open %s", path_for_open);
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
		if (loading_interp) {
			z_close(fd);
			break;
		}

		for (iter = phdr; !loading_interp && iter < &phdr[ehdr->e_phnum]; iter++) {
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
			/* Resolve interpreter inside configured root/binds to avoid host escape */
			file = rewrite_interp_path(&bootstrap_cfg, elf_interp,
						   interp_path, sizeof(interp_path));
			z_printf("[Loader] interp \"%s\" -> \"%s\"\n", elf_interp, file);
			load_interp_next = 1;
			break;
		}

		z_close(fd);
		if (!load_interp_next)
			break;
	}

#define AVSET(t, v, expr) case (t): (v)->a_un.a_val = (expr); break
	while (av->a_type != AT_NULL) {
		switch (av->a_type) {
		AVSET(AT_PHDR, av, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
		AVSET(AT_PHNUM, av, ehdrs[Z_PROG].e_phnum);
		AVSET(AT_PHENT, av, ehdrs[Z_PROG].e_phentsize);
		AVSET(AT_ENTRY, av, entry[Z_PROG]);
		const char *execfn = bootstrap_cfg.use_init ? file : target_argv[0];
		if (shell_mode)
			execfn = target_argv[0];
		if (shebang_mode && shebang_script[0])
			execfn = shebang_script;
		AVSET(AT_EXECFN, av, (unsigned long)execfn);
		AVSET(AT_BASE, av, elf_interp ?
				base[Z_INTERP] : av->a_un.a_val);
		}
		++av;
	}
#undef AVSET
	++av;

	if (shebang_mode) {
		int envc = final_envc;

		int auxc = 0;
		Elf_auxv_t *aux_src = av_start;
		while (aux_src[auxc].a_type != AT_NULL)
			auxc++;
		auxc++; /* include AT_NULL */

		/* Build argv list: interp [arg] script_path <script args> */
		int orig_target_argc = argc - argi; /* includes script + its args */
		int extra = 1; /* script path */
		if (shebang_interp_arg[0])
			extra++;
		int new_argc = orig_target_argc + extra;

		char **dst = argv;
		int pos = 0;
		dst[pos++] = shebang_interp;
		if (shebang_interp_arg[0])
			dst[pos++] = shebang_interp_arg;
		dst[pos++] = shebang_script;
		for (int k = 1; k < orig_target_argc; k++)
			dst[pos++] = argv[argi + k];
		dst[new_argc] = NULL;

		char **dst_env = &dst[new_argc + 1];
		for (int e = 0; e < envc; e++)
			dst_env[e] = final_env_ptrs[e];
		dst_env[envc] = NULL;

		Elf_auxv_t *dst_aux = (Elf_auxv_t *)&dst_env[envc + 1];
		for (int a = 0; a < auxc; a++)
			dst_aux[a] = aux_src[a];

		*sp = new_argc;
	} else {
		int envc = final_envc;

		int auxc = 0;
		Elf_auxv_t *aux_src = av_start;
		while (aux_src[auxc].a_type != AT_NULL)
			auxc++;
		auxc++;

		int user_argc = argc - argi;
		if (user_argc < 0)
			user_argc = 0;
		int extra = (bootstrap_cfg.use_init && !shell_mode) ? 1 : 0;
		int new_argc = user_argc + extra;
		char **dst = argv;
		int pos = 0;
		if (shell_mode) {
			for (int k = 0; target_argv[k]; k++)
				dst[pos++] = target_argv[k];
			new_argc = pos;
		} else {
			if (bootstrap_cfg.use_init)
				dst[pos++] = (char *)file;
			for (int k = 0; k < user_argc; k++)
				dst[pos++] = argv[argi + k];
		}
		dst[new_argc] = NULL;

		char **dst_env = &dst[new_argc + 1];
		for (int e = 0; e < envc; e++)
			dst_env[e] = final_env_ptrs[e];
		dst_env[envc] = NULL;

		Elf_auxv_t *dst_aux = (Elf_auxv_t *)&dst_env[envc + 1];
		for (int a = 0; a < auxc; a++)
			dst_aux[a] = aux_src[a];

		*sp = new_argc;
	}

	z_trampo((void (*)(void))(elf_interp ?
			entry[Z_INTERP] : entry[Z_PROG]), sp, z_fini);
	z_exit(0);
}
