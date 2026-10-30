/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host paths, and the little of the guest view the loader resolves itself
 * (the initial program's PT_INTERP; the payload resolves everything a guest
 * exec names). */
#include "loader.h"

void copy_substr(char *dst, size_t dst_sz, const char *src, size_t len)
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

void copy_cstr(char *dst, size_t dst_sz, const char *src)
{
	if (!src)
		return;
	copy_substr(dst, dst_sz, src, z_strlen(src));
}

/* Host root and bind sources are compared and joined as strings: make them
 * absolute and remove ".", ".." and repeated slashes (PRoot canonicalizes
 * them too). "x/../y" in a bind source otherwise failed every access below
 * it with EINVAL. Symlinks are left to the kernel, as before. */
void normalize_host_path(char *path, size_t cap)
{
	char joined[CONFIG_MAX_PATH * 2];
	size_t len = 0;
	if (!path[0])
		return;
	if (path[0] != '/') {
		if (!z_getcwd(joined, CONFIG_MAX_PATH))
			return;
		len = z_strlen(joined);
		joined[len++] = '/';
	}
	copy_cstr(joined + len, sizeof(joined) - len, path);
	char out[CONFIG_MAX_PATH];
	size_t o = 0;
	const char *p = joined;
	while (*p) {
		while (*p == '/') p++;
		if (!*p) break;
		const char *q = p;
		while (*q && *q != '/') q++;
		size_t n = (size_t)(q - p);
		if (n == 1 && p[0] == '.') {
		} else if (n == 2 && p[0] == '.' && p[1] == '.') {
			while (o && out[o - 1] != '/') o--;
			if (o) o--;
		} else {
			if (o + n + 2 > sizeof(out))
				return; /* Too long: keep the original spelling. */
			out[o++] = '/';
			z_memcpy(out + o, p, n);
			o += n;
		}
		p = q;
	}
	if (!o)
		out[o++] = '/';
	out[o] = '\0';
	copy_cstr(path, cap, out);
}

int is_elf_file_at(int dirfd, const char *path)
{
	if (!path)
		return 0;
	int fd = z_openat(dirfd, path, O_RDONLY);
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

/* The loader binary, re-executed for every guest exec. */
int resolve_self_path(char *out, size_t cap)
{
	ssize_t n = z_readlink("/proc/self/exe", out, cap - 1);
	if (n <= 0)
		return 0;
	out[n] = '\0';
	return 1;
}

static int get_path_stat(const char *path, unsigned long long *dev_out,
			 unsigned long long *ino_out)
{
	if (!path || !dev_out || !ino_out)
		return 0;
	struct stat st;
	if (z_newfstatat(AT_FDCWD, path, &st, 0) < 0)
		return 0;
	*dev_out = (unsigned long long)st.st_dev;
	*ino_out = (unsigned long long)st.st_ino;
	return 1;
}

int has_prefix(const char *path, const char *prefix)
{
	size_t plen = z_strlen(prefix);
	if (plen == 0)
		return 0;
	if (z_strncmp(path, prefix, plen) != 0)
		return 0;
	char tail = path[plen];
	return tail == '\0' || tail == '/' ? 1 : 0;
}

/* Mounts are chosen by exact guest names, but some host storage (hmdfs,
 * sharefs) matches names regardless of case: a guest name differing only in
 * case from a nested mountpoint resolves through the parent mount to the
 * host object the nested mount shadows. When the two mounts' access differs
 * that would bypass the nested policy, so such mountpoints are marked and
 * path walking spells any case variant of them exactly (ASCII case). */
void mark_case_aliases(payload_config_t *cfg)
{
	const char *access = cfg->mount_access_observe;
	if (!access[0])
		return;
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		const char *guest = cfg->binds[i].src;
		int parent = -1;
		size_t best = 0;
		for (int j = 0; j < cfg->bind_count && j < CONFIG_MAX_BINDS; j++) {
			size_t len = z_strlen(cfg->binds[j].src);
			if (j != i && len > best && len < z_strlen(guest) &&
			    has_prefix(guest, cfg->binds[j].src)) {
				best = len;
				parent = j;
			}
		}
		if (access[parent + 1] == access[i + 1])
			continue;
		/* Walk the shadowed host path: parent source + the rest. */
		char path[CONFIG_MAX_PATH], alias[CONFIG_MAX_PATH];
		copy_cstr(path, sizeof(path), parent >= 0 ? cfg->binds[parent].dst : cfg->root);
		size_t len = z_strlen(path);
		while (len > 1 && path[len - 1] == '/')
			path[--len] = 0;
		for (const char *rest = guest + best; *rest && !cfg->binds[i].fold;) {
			while (*rest == '/')
				rest++;
			size_t n = 0;
			int letters = 0;
			while (rest[n] && rest[n] != '/') {
				char c = rest[n++];
				letters |= (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
			}
			if (!n)
				break;
			if (len + 1 + n + 1 > sizeof(path))
				z_errx(1, "mount path too long: %s", guest);
			if (len != 1 || path[0] != '/')
				path[len++] = '/';
			z_memcpy(path + len, rest, n);
			path[len + n] = 0;
			z_memcpy(alias, path, len + n + 1);
			for (size_t k = len; k < len + n; k++) {
				char c = alias[k];
				if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
					alias[k] = c ^ 0x20;
			}
			len += n;
			rest += n;
			unsigned long long dev, ino, alias_dev, alias_ino;
			if (!get_path_stat(path, &dev, &ino))
				break; /* Nothing shadowed here, so no alias of it either. */
			if (letters && get_path_stat(alias, &alias_dev, &alias_ino) &&
			    dev == alias_dev && ino == alias_ino)
				cfg->binds[i].fold = (uint32_t)best + 1;
		}
	}
}

size_t join_paths(char *out, size_t out_sz,
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

static int apply_bind_overlay(const payload_config_t *cfg, char *out, size_t out_sz, const char *in_path)
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

static void apply_root_overlay(const payload_config_t *cfg, char *out, size_t out_sz)
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

/* Host path of a canonical guest path: the longest bind, else the root. */
static int map_guest_path(const payload_config_t *cfg, const char *guest, char *out, size_t out_sz)
{
	size_t best = 0;
	int found = -1;
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		size_t len = z_strlen(cfg->binds[i].src);
		if (len > best && has_prefix(guest, cfg->binds[i].src)) {
			best = len;
			found = i;
		}
	}
	const char *host = found >= 0 ? cfg->binds[found].dst : cfg->root;
	const char *rest = guest + best;
	size_t host_len = z_strlen(host), rest_len = z_strlen(rest);
	if (host_len + rest_len + 2 > out_sz)
		return -1;
	z_memcpy(out, host, host_len);
	if (host_len && rest[0] == '/' && host[host_len - 1] == '/')
		rest++, rest_len--;
	z_memcpy(out + host_len, rest, rest_len + 1);
	if (!out[0])
		copy_cstr(out, out_sz, "/");
	return 0;
}

/* PRoot semantics for a guest path the loader opens itself (PT_INTERP):
 * resolve component by component through binds and root, following every
 * symlink in guest terms, so an absolute link inside the rootfs cannot
 * escape to the host. Lexical mapping is the fallback on failure. */
static int resolve_guest_path(const payload_config_t *cfg, const char *guest, char *out, size_t out_sz)
{
	char done[CONFIG_MAX_PATH], pending[CONFIG_MAX_PATH * 2];
	char link[CONFIG_MAX_PATH], host[CONFIG_MAX_PATH];
	size_t done_len = 0;
	int links = 0;
	if (guest[0] != '/' || z_strlen(guest) >= sizeof(pending))
		return -1;
	copy_cstr(pending, sizeof(pending), guest);
	done[0] = '\0';
	char *cursor = pending;
	while (*cursor) {
		while (*cursor == '/')
			cursor++;
		if (!*cursor)
			break;
		char *next = cursor;
		while (*next && *next != '/')
			next++;
		size_t len = (size_t)(next - cursor);
		if (len == 1 && cursor[0] == '.') {
			cursor = next;
			continue;
		}
		if (len == 2 && cursor[0] == '.' && cursor[1] == '.') {
			while (done_len && done[done_len - 1] != '/')
				done_len--;
			if (done_len)
				done_len--;
			done[done_len] = '\0';
			cursor = next;
			continue;
		}
		size_t start = done_len;
		if (done_len + len + 2 > sizeof(done))
			return -1;
		done[done_len++] = '/';
		z_memcpy(done + done_len, cursor, len);
		done_len += len;
		done[done_len] = '\0';
		cursor = next;
		if (map_guest_path(cfg, done, host, sizeof(host)) < 0)
			return -1;
		ssize_t n = z_readlink(host, link, sizeof(link) - 1);
		if (n < 0)
			continue; /* Not a link (or missing: the open reports it). */
		if (n == 0 || ++links > 40)
			return -1;
		link[n] = '\0';
		/* Splice the link body in front of the unresolved remainder. */
		size_t rest = z_strlen(cursor);
		if ((size_t)n + rest + 2 > sizeof(pending))
			return -1;
		char remainder[CONFIG_MAX_PATH * 2];
		copy_cstr(remainder, sizeof(remainder), cursor);
		z_memcpy(pending, link, (size_t)n);
		pending[n] = '/';
		z_memcpy(pending + n + 1, remainder, rest + 1);
		cursor = pending;
		done_len = link[0] == '/' ? 0 : start;
		done[done_len] = '\0';
	}
	if (!done_len)
		copy_cstr(done, sizeof(done), "/");
	return map_guest_path(cfg, done, out, out_sz);
}

const char *resolve_interp_path(const payload_config_t *cfg, const char *in, char *out, size_t out_sz)
{
	if (!cfg || !in || !out || out_sz == 0)
		return in;
	if ((cfg->root[0] || cfg->bind_count) && !resolve_guest_path(cfg, in, out, out_sz))
		return out;
	copy_substr(out, out_sz, in, z_strlen(in));
	if (!apply_bind_overlay(cfg, out, out_sz, in))
		apply_root_overlay(cfg, out, out_sz);
	return out;
}

