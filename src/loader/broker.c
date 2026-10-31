/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation mode, broker side (docs/ISOLATION.md). The initial loader forks
 * the broker before anything of the guest runs. It holds the host trees the
 * guest may reach (root, bind sources, glue directory, the loader binary),
 * each with its access, and executes the payload's host path calls: every
 * path is walked from a tree root one component at a time without following
 * symlinks, so nothing outside the trees is ever touched. Requests are not
 * trusted in any way. */
#include <asm/unistd.h>
#include <linux/stat.h>
#include <sys/socket.h>
#include "loader.h"
#include "broker_proto.h"

#define TREES (CONFIG_MAX_BINDS + 4)
#define PATH_BYTES 4096
#define LINKS_MAX 40
#define ENOENT_ 2
#define EACCES_ 13
#define EROFS_ 30
#define EINVAL_ 22
#define ELOOP_ 40
#define EBUSY_ 16
#define ENAMETOOLONG_ 36
#define ENOTDIR_ 20
#define O_PATH_ 010000000
#define O_DIRECTORY_ 0200000
#define O_CREAT_ 0100
#define O_TRUNC_ 01000
#define O_TMPFILE_ 020200000
#define O_ACCMODE_ 3
#define O_CLOEXEC_ 02000000
#define AT_SYMLINK_FOLLOW_ 0x400
#define AT_EACCESS_ 0x200
#define AT_REMOVEDIR_ 0x200
#define IN_DONT_FOLLOW_ 0x02000000

struct tree {
	char path[CONFIG_MAX_PATH];
	size_t length;
	int fd;
	unsigned long dev, ino;
	char access; /* 'd', 'r' or 'w' */
};
static struct tree trees[TREES];
static int tree_count;
static long peer_pid;

static long sys(long n, long a, long b, long c, long d, long e, long f)
{
	return z_syscall(n, a, b, c, d, e, f);
}

static int identity(int fd, const char *name, int flags, unsigned long *dev, unsigned long *ino)
{
	struct stat st;
	long rc = sys(__NR_newfstatat, fd, (long)name, (long)&st, flags, 0, 0);
	if (rc < 0)
		return (int)rc;
	*dev = st.st_dev;
	*ino = st.st_ino;
	return 0;
}

static void add_tree(const char *path, char access)
{
	if (tree_count == TREES || !path[0])
		return;
	struct tree *t = &trees[tree_count];
	copy_cstr(t->path, sizeof(t->path), path);
	t->length = z_strlen(t->path);
	while (t->length > 1 && t->path[t->length - 1] == '/')
		t->path[--t->length] = 0;
	t->fd = (int)sys(__NR_openat, AT_FDCWD, (long)t->path, O_PATH_ | O_CLOEXEC_, 0, 0, 0);
	if (t->fd < 0 || identity(t->fd, "", AT_EMPTY_PATH, &t->dev, &t->ino) < 0)
		return;
	t->access = access;
	tree_count++;
}

/* Lexically normalize an absolute path in place: no ".", "..", "//". */
static int normalize(char *path)
{
	if (path[0] != '/')
		return -EINVAL_;
	char *out = path, *in = path;
	while (*in) {
		while (*in == '/')
			in++;
		if (!*in)
			break;
		char *end = in;
		while (*end && *end != '/')
			end++;
		size_t n = (size_t)(end - in);
		if (n == 1 && in[0] == '.') {
		} else if (n == 2 && in[0] == '.' && in[1] == '.') {
			while (out > path && *--out != '/')
				;
		} else {
			*out++ = '/';
			for (size_t i = 0; i < n; i++)
				*out++ = in[i];
		}
		in = end;
	}
	if (out == path)
		*out++ = '/';
	*out = 0;
	return 0;
}

static int prefix_of(const char *prefix, size_t length, const char *path)
{
	if (length == 1 && prefix[0] == '/')
		return 1;
	return !z_strncmp(path, prefix, length) && (path[length] == '/' || !path[length]);
}

/* /proc/self and /proc/thread-self name the requesting process; other
 * processes' entries are not reachable. */
static int proc_rewrite(char *path)
{
	static const char *const selves[] = {"/proc/self", "/proc/thread-self"};
	for (int k = 0; k < 2; k++) {
		size_t n = z_strlen(selves[k]);
		if (z_strncmp(path, selves[k], n) || (path[n] && path[n] != '/'))
			continue;
		char rest[PATH_BYTES];
		copy_cstr(rest, sizeof(rest), path + n);
		char digits[24];
		int d = 0;
		long v = peer_pid;
		do
			digits[d++] = (char)('0' + v % 10);
		while ((v /= 10));
		char *p = path + 6; /* after "/proc/" */
		while (d)
			*p++ = digits[--d];
		copy_cstr(p, PATH_BYTES - (size_t)(p - path), rest);
		return 0;
	}
	if (z_strncmp(path, "/proc/", 6) || path[6] < '0' || path[6] > '9')
		return 0;
	long pid = 0;
	const char *p = path + 6;
	while (*p >= '0' && *p <= '9')
		pid = pid * 10 + (*p++ - '0');
	return pid == peer_pid ? 0 : -EACCES_;
}

/* Where a path leads: the directory holding the final component (or the
 * object itself, for a tree root), and the access of the tree it is in. */
struct target {
	int dir;          /* O_PATH FD of the parent directory, or of the object */
	char name[256];   /* final component; empty: dir is the object */
	char access;      /* of the tree holding the object */
	char parent;      /* of the tree holding the name (namespace changes) */
};

static void release(struct target *t)
{
	if (t->dir >= 0)
		sys(__NR_close, t->dir, 0, 0, 0, 0, 0);
	t->dir = -1;
}

static char tree_access(int fd, char current)
{
	unsigned long dev, ino;
	if (identity(fd, "", AT_EMPTY_PATH, &dev, &ino) < 0)
		return current;
	for (int i = 0; i < tree_count; i++)
		if (trees[i].dev == dev && trees[i].ino == ino)
			return trees[i].access;
	return current;
}

static int resolve(const char *input, int follow, struct target *t)
{
	char path[PATH_BYTES], link[PATH_BYTES];
	t->dir = -1;
	if (z_strlen(input) >= sizeof(path))
		return -ENAMETOOLONG_;
	copy_cstr(path, sizeof(path), input);
	for (int links = 0;; links++) {
		if (links > LINKS_MAX)
			return -ELOOP_;
		int rc = normalize(path);
		if (rc < 0)
			return rc;
		rc = proc_rewrite(path);
		if (rc < 0)
			return rc;
		const struct tree *tree = 0;
		for (int i = 0; i < tree_count; i++)
			if (prefix_of(trees[i].path, trees[i].length, path) &&
			    (!tree || trees[i].length > tree->length))
				tree = &trees[i];
		if (!tree)
			return -EACCES_;
		char access = tree->access;
		int fd = (int)sys(__NR_fcntl, tree->fd, 1030 /* F_DUPFD_CLOEXEC */, 3, 0, 0, 0);
		if (fd < 0)
			return fd;
		const char *rest = tree->length == 1 ? path + 1 : path + tree->length;
		while (*rest == '/')
			rest++;
		/* Walked prefix, for splicing relative links. */
		size_t walked = tree->length;
		int restart = 0;
		while (*rest) {
			const char *end = rest;
			while (*end && *end != '/')
				end++;
			size_t n = (size_t)(end - rest);
			char name[256];
			if (n >= sizeof(name)) {
				sys(__NR_close, fd, 0, 0, 0, 0, 0);
				return -ENAMETOOLONG_;
			}
			z_memcpy(name, rest, n);
			name[n] = 0;
			const char *next = end;
			while (*next == '/')
				next++;
			int last = !*next;
			if (last) {
				struct stat st;
				int lrc = (int)sys(__NR_newfstatat, fd, (long)name, (long)&st, AT_SYMLINK_NOFOLLOW, 0, 0);
				if (!follow || lrc < 0 || (st.st_mode & 0170000) != 0120000) {
					t->dir = fd;
					copy_cstr(t->name, sizeof(t->name), name);
					t->parent = access;
					t->access = access;
					if (lrc >= 0)
						for (int i = 0; i < tree_count; i++)
							if (trees[i].dev == st.st_dev && trees[i].ino == st.st_ino)
								t->access = trees[i].access;
					return 0;
				}
			} else {
				int child = (int)sys(__NR_openat, fd, (long)name,
						     O_PATH_ | O_DIRECTORY_ | O_NOFOLLOW | O_CLOEXEC_, 0, 0, 0);
				if (child >= 0) {
					sys(__NR_close, fd, 0, 0, 0, 0, 0);
					fd = child;
					access = tree_access(fd, access);
					walked = (size_t)(end - path);
					rest = next;
					continue;
				}
				if (child != -ELOOP_ && child != -ENOTDIR_) {
					sys(__NR_close, fd, 0, 0, 0, 0, 0);
					return child;
				}
			}
			/* A symlink: splice its target in front of the rest. */
			long len = sys(__NR_readlinkat, fd, (long)name, (long)link, sizeof(link) - 1, 0, 0);
			sys(__NR_close, fd, 0, 0, 0, 0, 0);
			if (len < 0)
				return (int)(len == -EINVAL_ ? -ENOTDIR_ : len);
			link[len] = 0;
			char spliced[PATH_BYTES];
			size_t s = 0;
			if (link[0] != '/') {
				if (walked >= sizeof(spliced))
					return -ENAMETOOLONG_;
				z_memcpy(spliced, path, walked);
				s = walked;
				spliced[s++] = '/';
			}
			size_t ln = (size_t)len, rn = z_strlen(next);
			if (s + ln + 1 + rn + 1 > sizeof(spliced))
				return -ENAMETOOLONG_;
			z_memcpy(spliced + s, link, ln);
			s += ln;
			spliced[s++] = '/';
			z_memcpy(spliced + s, next, rn + 1);
			copy_cstr(path, sizeof(path), spliced);
			restart = 1;
			break;
		}
		if (restart)
			continue;
		/* The tree root itself. */
		t->dir = fd;
		t->name[0] = 0;
		t->access = t->parent = access;
		return 0;
	}
}

static int check(const struct target *t, int write)
{
	if (t->access == 'd')
		return -ENOENT_;
	if (write && t->access != 'w')
		return -EROFS_;
	return 0;
}

/* "/proc/self/fd/N" of a broker FD: the object, followed by the kernel. */
static void fd_path(char *out, int fd)
{
	static const char prefix[] = "/proc/self/fd/";
	z_memcpy(out, prefix, sizeof(prefix) - 1);
	char digits[16];
	int d = 0;
	do
		digits[d++] = (char)('0' + fd % 10);
	while ((fd /= 10));
	char *p = out + sizeof(prefix) - 1;
	while (d)
		*p++ = digits[--d];
	*p = 0;
}

/* An O_PATH FD of the object a target names (not following a final link). */
static int object(const struct target *t)
{
	if (!t->name[0])
		return (int)sys(__NR_fcntl, t->dir, 1030, 3, 0, 0, 0);
	return (int)sys(__NR_openat, t->dir, (long)t->name, O_PATH_ | O_NOFOLLOW | O_CLOEXEC_, 0, 0, 0);
}

/* The access of an object given as an FD: its current host name must lead
 * back to the same object. Unnamed objects (memfd, unlinked) carry none. */
static int fd_target(int fd, struct target *t)
{
	char link[PATH_BYTES], magic[32];
	struct stat st;
	t->dir = -1;
	if (sys(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) < 0)
		return -EINVAL_;
	fd_path(magic, fd);
	long n = sys(__NR_readlinkat, AT_FDCWD, (long)magic, (long)link, sizeof(link) - 1, 0, 0);
	if (n <= 0 || link[0] != '/') {
		t->access = t->parent = 'w'; /* pipe:[…], socket:[…], anon_inode:… */
		return 0;
	}
	link[n] = 0;
	if (!st.st_nlink) {
		t->access = t->parent = 'w';
		return 0;
	}
	int rc = resolve(link, 0, t);
	if (rc < 0)
		return -EACCES_;
	unsigned long dev, ino;
	rc = identity(t->dir, t->name, t->name[0] ? AT_SYMLINK_NOFOLLOW : AT_EMPTY_PATH, &dev, &ino);
	if (rc < 0 || dev != st.st_dev || ino != st.st_ino) {
		release(t);
		return -EACCES_;
	}
	return 0;
}

struct call {
	long a[6];
	const char *path[6];   /* PATH, STR and IN data (NULL when absent) */
	int has_dir[6];        /* PATH i comes with an attached directory FD */
	int fd[BROKER_FDS_MAX];
	int fds;
	unsigned magic;        /* BROKER_MAGIC bits */
	uint32_t in_len[6];    /* bytes of PATH, STR and IN data */
	unsigned char *out[6];
	uint32_t out_len[6];
	int answer_fd;
};

/* The path argument i as a target (relative names under an attached
 * directory FD; an empty path or NULL means the attached FD itself). */
static int target_of(struct call *c, int i, int *next_fd, int follow, struct target *t)
{
	const char *path = c->path[i];
	int has_dir = c->has_dir[i];
	if ((c->magic & BROKER_MAGIC(i)) || !path || (!path[0] && has_dir)) {
		if (*next_fd >= c->fds)
			return -EINVAL_;
		return fd_target(c->fd[(*next_fd)++], t);
	}
	if (!path[0])
		return -ENOENT_;
	if (path[0] == '/') {
		if (has_dir)
			(*next_fd)++;
		return resolve(path, follow, t);
	}
	if (!has_dir || *next_fd >= c->fds)
		return -EINVAL_;
	char link[PATH_BYTES], magic[32];
	fd_path(magic, c->fd[(*next_fd)++]);
	long n = sys(__NR_readlinkat, AT_FDCWD, (long)magic, (long)link, sizeof(link) - 1, 0, 0);
	if (n <= 0 || link[0] != '/')
		return -EACCES_;
	link[n] = 0;
	size_t base = (size_t)n, length = z_strlen(path);
	if (base + 1 + length + 1 > sizeof(link))
		return -ENAMETOOLONG_;
	link[base] = '/';
	z_memcpy(link + base + 1, path, length + 1);
	return resolve(link, follow, t);
}

/* nr on the object a target names, through its /proc/self/fd magic link
 * (which reaches the object without further resolution). The magic path
 * is argument `at` (0 for path calls, 1 for fchmodat(AT_FDCWD, path),
 * 2 for inotify_add_watch(fd, path)); a1..a4 fill the others in order. */
static long on_object(const struct target *t, long nr, long a1, long a2, long a3, long a4, int at)
{
	int fd = object(t);
	if (fd < 0)
		return fd;
	char magic[32];
	fd_path(magic, fd);
	long rc;
	if (at == 1)
		rc = sys(nr, AT_FDCWD, (long)magic, a1, 0, 0, 0);
	else if (at == 2)
		rc = sys(nr, a1, (long)magic, a2, 0, 0, 0);
	else
		rc = sys(nr, (long)magic, a1, a2, a3, a4, 0);
	sys(__NR_close, fd, 0, 0, 0, 0, 0);
	return rc;
}

/* Reopening an FD the guest holds (/proc/self/fd/N) whose object lies in
 * no tree (a terminal, a pipe's peer device): at most the access the FD
 * itself has. */
static long held_access(int fd, int flags)
{
	long held = sys(__NR_fcntl, fd, 3 /* F_GETFL */, 0, 0, 0, 0);
	if (held < 0)
		return held;
	if (flags & O_PATH_)
		return 0;
	if ((held & O_PATH_) || (flags & (O_CREAT_ | O_TMPFILE_)))
		return -EACCES_;
	int want = flags & O_ACCMODE_, have = (int)(held & O_ACCMODE_);
	if (have == 2 || want == have)
		return 0;
	return -EACCES_;
}

/* bind/connect of a UNIX socket to a host path: the name is used relative
 * to its directory (this process's cwd), so its length does not matter. */
static long socket_name(struct call *c, long nr)
{
	struct target t = {.dir = -1};
	int next = 1, binding = nr == BROKER_BIND_PATH;
	if (!c->fds || !c->path[1] || c->path[1][0] != '/')
		return -EINVAL_;
	long rc = target_of(c, 1, &next, !binding, &t);
	if (rc >= 0 && !t.name[0])
		rc = binding ? -98 /* EADDRINUSE */ : -111 /* ECONNREFUSED */;
	if (rc >= 0)
		rc = binding ? (t.parent == 'w' ? 0 : t.parent == 'd' ? -ENOENT_ : -EROFS_) : check(&t, 0);
	struct { unsigned short family; char path[108]; } address;
	size_t n = z_strlen(t.name);
	if (rc >= 0 && n >= sizeof(address.path))
		rc = -ENAMETOOLONG_;
	if (rc >= 0)
		rc = sys(__NR_fchdir, t.dir, 0, 0, 0, 0, 0);
	if (rc >= 0) {
		z_memset(&address, 0, sizeof(address));
		address.family = AF_UNIX;
		z_memcpy(address.path, t.name, n);
		rc = sys(binding ? __NR_bind : __NR_connect, c->fd[0], (long)&address,
			 (long)(sizeof(address.family) + n + 1), 0, 0, 0);
	}
	release(&t);
	return rc;
}

static long execute(struct call *c, long nr)
{
	long *a = c->a;
	struct target t = {.dir = -1}, u = {.dir = -1};
	int next = 0;
	long rc;
	switch (nr) {
	case __NR_openat: {
		int flags = (int)a[2];
		int write = (flags & O_ACCMODE_) || (flags & (O_CREAT_ | O_TRUNC_)) ||
			    (flags & O_TMPFILE_) == O_TMPFILE_;
		if (flags & O_PATH_)
			write = 0;
		rc = target_of(c, 1, &next, !(flags & O_NOFOLLOW) && !((flags & O_CREAT_) && (flags & 0200)), &t);
		if (rc >= 0)
			rc = check(&t, write);
		else if (rc == -EACCES_ && (c->magic & BROKER_MAGIC(1)))
			rc = held_access(c->fd[0], flags);
		if (rc < 0)
			break;
		if ((c->magic & BROKER_MAGIC(1)) || !t.name[0]) {
			int fd = (c->magic & BROKER_MAGIC(1)) ? c->fd[0] : t.dir;
			char magic[32];
			fd_path(magic, fd);
			/* The object is already resolved; the magic link must be followed. */
			rc = sys(__NR_openat, AT_FDCWD, (long)magic, (flags & ~O_NOFOLLOW) | O_CLOEXEC_, a[3], 0, 0);
		} else {
			rc = sys(__NR_openat, t.dir, (long)t.name, flags | O_NOFOLLOW | O_CLOEXEC_, a[3], 0, 0);
		}
		if (rc >= 0) {
			c->answer_fd = (int)rc;
			rc = 0;
		}
		break;
	}
	case __NR_newfstatat:
	case __NR_statx: {
		int flags = (int)(nr == __NR_statx ? a[2] : a[3]);
		/* The metadata of an FD the guest holds: nothing to check. */
		if ((c->magic & BROKER_MAGIC(1)) || (c->has_dir[1] && c->path[1] && !c->path[1][0])) {
			if (!c->fds)
				return -EINVAL_;
			if (c->magic & BROKER_MAGIC(1))
				flags = (flags & ~AT_SYMLINK_NOFOLLOW) | AT_EMPTY_PATH;
			rc = nr == __NR_statx ? sys(nr, c->fd[0], (long)"", flags, a[3], (long)c->out[4], 0)
					      : sys(nr, c->fd[0], (long)"", (long)c->out[2], flags, 0, 0);
			break;
		}
		rc = target_of(c, 1, &next, !(flags & AT_SYMLINK_NOFOLLOW) || (c->magic & BROKER_MAGIC(1)), &t);
		if (rc >= 0)
			rc = check(&t, 0);
		if (rc < 0)
			break;
		int f = AT_SYMLINK_NOFOLLOW | (t.name[0] ? 0 : AT_EMPTY_PATH);
		if (nr == __NR_statx)
			rc = sys(nr, t.dir, (long)t.name, (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) | f,
				 a[3], (long)c->out[4], 0);
		else
			rc = sys(nr, t.dir, (long)t.name, (long)c->out[2], f, 0, 0);
		break;
	}
	case __NR_faccessat:
	case __NR_faccessat2: {
		int flags = nr == __NR_faccessat2 ? (int)a[3] : 0;
		rc = target_of(c, 1, &next, !(flags & AT_SYMLINK_NOFOLLOW), &t);
		if (rc >= 0)
			rc = check(&t, (int)a[2] & 2);
		if (rc >= 0)
			rc = sys(__NR_faccessat2, t.dir, (long)t.name, a[2],
				 (flags & AT_EACCESS_) | AT_SYMLINK_NOFOLLOW | (t.name[0] ? 0 : AT_EMPTY_PATH), 0, 0);
		break;
	}
	case __NR_readlinkat:
		if (c->magic & BROKER_MAGIC(1)) {
			char magic[32];
			fd_path(magic, c->fd[0]);
			rc = sys(nr, AT_FDCWD, (long)magic, (long)c->out[2], c->out_len[2], 0, 0);
			break;
		}
		rc = target_of(c, 1, &next, 0, &t);
		if (rc >= 0)
			rc = check(&t, 0);
		if (rc >= 0)
			rc = sys(nr, t.dir, (long)t.name, (long)c->out[2], c->out_len[2], 0, 0);
		break;
	case __NR_mkdirat:
	case __NR_mknodat:
	case __NR_unlinkat:
		rc = target_of(c, 1, &next, 0, &t);
		if (rc >= 0 && !t.name[0])
			rc = nr == __NR_mkdirat ? -17 /* EEXIST */ : -EBUSY_;
		if (rc >= 0)
			rc = t.parent == 'w' ? 0 : t.parent == 'd' ? -ENOENT_ : -EROFS_;
		if (rc >= 0)
			rc = sys(nr, t.dir, (long)t.name, a[2], a[3], 0, 0);
		break;
	case __NR_symlinkat:
		rc = target_of(c, 2, &next, 0, &t);
		if (rc >= 0 && !t.name[0])
			rc = -17;
		if (rc >= 0)
			rc = t.parent == 'w' ? 0 : t.parent == 'd' ? -ENOENT_ : -EROFS_;
		if (rc >= 0)
			rc = sys(nr, (long)c->path[0], t.dir, (long)t.name, 0, 0, 0);
		break;
	case __NR_linkat:
	case __NR_renameat:
	case __NR_renameat2: {
		int follow = nr == __NR_linkat && (a[4] & AT_SYMLINK_FOLLOW_);
		rc = target_of(c, 1, &next, follow, &t);
		if (rc >= 0)
			rc = target_of(c, 3, &next, 0, &u);
		if (rc >= 0 && (!t.name[0] || !u.name[0]))
			rc = -EBUSY_;
		/* Both ends writable: a read-only file cannot gain a writable name. */
		if (rc >= 0 && (t.parent != 'w' || u.parent != 'w' ||
				(nr == __NR_linkat && t.access != 'w')))
			rc = t.parent == 'd' || u.parent == 'd' ? -ENOENT_ : -EROFS_;
		if (rc < 0)
			break;
		if (nr == __NR_linkat)
			rc = sys(nr, t.dir, (long)t.name, u.dir, (long)u.name, 0, 0);
		else
			rc = sys(__NR_renameat2, t.dir, (long)t.name, u.dir, (long)u.name,
				 nr == __NR_renameat2 ? a[4] : 0, 0);
		break;
	}
	case __NR_fchmodat:
	case __NR_fchmodat2:
		rc = target_of(c, 1, &next, !(nr == __NR_fchmodat2 && (a[3] & AT_SYMLINK_NOFOLLOW)), &t);
		if (rc >= 0)
			rc = check(&t, 1);
		if (rc >= 0)
			rc = on_object(&t, __NR_fchmodat, a[2], 0, 0, 0, 1);
		break;
	case __NR_fchownat:
		rc = target_of(c, 1, &next, !(a[4] & AT_SYMLINK_NOFOLLOW), &t);
		if (rc >= 0)
			rc = check(&t, 1);
		if (rc >= 0)
			rc = sys(nr, t.dir, (long)t.name, a[2], a[3],
				 AT_SYMLINK_NOFOLLOW | (t.name[0] ? 0 : AT_EMPTY_PATH), 0);
		break;
	case __NR_utimensat:
		rc = target_of(c, 1, &next, !(a[3] & AT_SYMLINK_NOFOLLOW), &t);
		if (rc >= 0)
			rc = check(&t, 1);
		if (rc >= 0)
			rc = sys(nr, t.dir, (long)(t.name[0] ? t.name : ""),
				 c->path[2] ? (long)c->path[2] : 0,
				 AT_SYMLINK_NOFOLLOW | (t.name[0] ? 0 : AT_EMPTY_PATH), 0, 0);
		break;
	case __NR_truncate:
		rc = target_of(c, 0, &next, 1, &t);
		if (rc >= 0)
			rc = check(&t, 1);
		if (rc >= 0) {
			int fd = (c->magic & BROKER_MAGIC(0)) ? -1 : (int)sys(__NR_openat, t.dir, (long)(t.name[0] ? t.name : "."),
							  1 /* O_WRONLY */ | O_NOFOLLOW | O_CLOEXEC_, 0, 0, 0);
			if (c->magic & BROKER_MAGIC(0)) {
				char magic[32];
				fd_path(magic, c->fd[0]);
				fd = (int)sys(__NR_openat, AT_FDCWD, (long)magic, 1 | O_CLOEXEC_, 0, 0, 0);
			}
			rc = fd < 0 ? fd : sys(__NR_ftruncate, fd, a[1], 0, 0, 0, 0);
			if (fd >= 0)
				sys(__NR_close, fd, 0, 0, 0, 0, 0);
		}
		break;
	case __NR_statfs:
	case __NR_chdir:
		rc = target_of(c, 0, &next, 1, &t);
		if (rc >= 0)
			rc = check(&t, 0);
		if (rc < 0)
			break;
		{
			int fd = t.name[0] ? (int)sys(__NR_openat, t.dir, (long)t.name,
						      O_PATH_ | O_NOFOLLOW | O_CLOEXEC_ |
						      (nr == __NR_chdir ? O_DIRECTORY_ : 0), 0, 0, 0)
					   : (int)sys(__NR_fcntl, t.dir, 1030, 3, 0, 0, 0);
			if (fd < 0) {
				rc = fd;
				break;
			}
			if (nr == __NR_chdir) {
				c->answer_fd = fd;
				rc = 0;
			} else {
				rc = sys(__NR_fstatfs, fd, (long)c->out[1], 0, 0, 0, 0);
				sys(__NR_close, fd, 0, 0, 0, 0, 0);
			}
		}
		break;
	case __NR_setxattr: case __NR_lsetxattr:
	case __NR_getxattr: case __NR_lgetxattr:
	case __NR_listxattr: case __NR_llistxattr:
	case __NR_removexattr: case __NR_lremovexattr: {
		int link = nr == __NR_lsetxattr || nr == __NR_lgetxattr || nr == __NR_llistxattr ||
			   nr == __NR_lremovexattr;
		int write = nr == __NR_setxattr || nr == __NR_lsetxattr ||
			    nr == __NR_removexattr || nr == __NR_lremovexattr;
		rc = target_of(c, 0, &next, !link, &t);
		if (rc >= 0)
			rc = check(&t, write);
		if (rc < 0)
			break;
		/* The magic link jumps to the object without further resolution. */
		long base = nr == __NR_lsetxattr ? __NR_setxattr : nr == __NR_lgetxattr ? __NR_getxattr :
			    nr == __NR_llistxattr ? __NR_listxattr : nr == __NR_lremovexattr ? __NR_removexattr : nr;
		if (base == __NR_listxattr)
			rc = on_object(&t, base, (long)c->out[1], c->out_len[1], 0, 0, 0);
		else if (base == __NR_getxattr)
			rc = on_object(&t, base, (long)c->path[1], (long)c->out[2], c->out_len[2], 0, 0);
		else if (base == __NR_setxattr)
			rc = on_object(&t, base, (long)c->path[1], (long)c->path[2], a[3], a[4], 0);
		else
			rc = on_object(&t, base, (long)c->path[1], 0, 0, 0, 0);
		break;
	}
	case __NR_inotify_add_watch:
		next = 1;
		rc = target_of(c, 1, &next, !(a[2] & IN_DONT_FOLLOW_), &t);
		if (rc >= 0)
			rc = check(&t, 0);
		if (rc >= 0)
			rc = on_object(&t, nr, c->fd[0], a[2] & ~IN_DONT_FOLLOW_, 0, 0, 2);
		break;
	case __NR_fchmod:
	case __NR_fchown:
	case __NR_fsetxattr:
	case __NR_fremovexattr:
		if (!c->fds)
			return -EINVAL_;
		rc = fd_target(c->fd[0], &t);
		if (rc >= 0)
			rc = check(&t, 1);
		if (rc >= 0)
			rc = sys(nr, c->fd[0], nr == __NR_fsetxattr || nr == __NR_fremovexattr ?
				 (long)c->path[1] : a[1], nr == __NR_fsetxattr ? (long)c->path[2] : a[2],
				 a[3], a[4], 0);
		break;
	case __NR_socket:
		/* UNIX sockets only, never datagrams (they may name any path). */
		if (a[0] != AF_UNIX || ((a[1] & 0xf) != SOCK_STREAM && (a[1] & 0xf) != SOCK_SEQPACKET)) {
			rc = -1 /* EPERM */;
			break;
		}
		rc = sys(nr, a[0], a[1], a[2], 0, 0, 0);
		if (rc >= 0) {
			c->answer_fd = (int)rc;
			rc = 0;
		}
		break;
	case __NR_bind:
	case __NR_connect: {
		/* Any address except a UNIX path (BROKER_*_PATH checks those). */
		const unsigned char *address = (const unsigned char *)c->path[1];
		uint32_t length = c->in_len[1] < (uint32_t)a[2] ? c->in_len[1] : (uint32_t)a[2];
		if (!c->fds)
			return -EINVAL_;
		if (address && length > 2 && (address[0] | address[1] << 8) == AF_UNIX && address[2]) {
			rc = -1 /* EPERM */;
			break;
		}
		rc = sys(nr, c->fd[0], (long)address, length, 0, 0, 0);
		break;
	}
	case BROKER_BIND_PATH:
	case BROKER_CONNECT_PATH:
		rc = socket_name(c, nr);
		break;
	default:
		rc = -EACCES_;
	}
	release(&t);
	release(&u);
	return rc;
}

/* Checks a request against the argument table and points the call at its
 * data; answers outputs into `out`. */
static int parse(const struct broker_request *r, size_t size, const struct broker_spec *spec,
		 struct call *c, unsigned char *out)
{
	const unsigned char *data = (const unsigned char *)(r + 1), *end = (const unsigned char *)r + size;
	size_t total = 0;
	for (int i = 0; i < 6; i++) {
		const struct broker_arg *arg = &spec->arg[i];
		c->a[i] = r->args[i];
		c->path[i] = 0;
		c->has_dir[i] = arg->kind == BK_PATH && i > 0 && spec->arg[i - 1].kind == BK_DIRFD &&
				(int)r->args[i - 1] != AT_FDCWD;
		if (arg->kind == BK_PATH || arg->kind == BK_STR || arg->kind == BK_IN) {
			if (!r->len[i])
				continue;
			if (r->len[i] > (size_t)(end - data))
				return -EINVAL_;
			if (arg->kind != BK_IN && data[r->len[i] - 1])
				return -EINVAL_;
			c->path[i] = (const char *)data;
			c->in_len[i] = r->len[i];
			data += r->len[i];
		} else if (arg->kind == BK_OUT) {
			if (r->len[i] > BROKER_DATA_MAX - total)
				return -EINVAL_;
			c->out[i] = out + total;
			c->out_len[i] = r->len[i];
			total += r->len[i];
		}
	}
	return 0;
}

static long send_answer(int channel, const void *data, size_t length, int fd)
{
	char control[CMSG_SPACE(sizeof(int))];
	struct iovec io = {(void *)data, length};
	struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1};
	if (fd >= 0) {
		z_memset(control, 0, sizeof(control));
		m.msg_control = control;
		m.msg_controllen = sizeof(control);
		struct cmsghdr *h = CMSG_FIRSTHDR(&m);
		h->cmsg_level = SOL_SOCKET;
		h->cmsg_type = SCM_RIGHTS;
		h->cmsg_len = CMSG_LEN(sizeof(int));
		z_memcpy(CMSG_DATA(h), &fd, sizeof(int));
	}
	return sys(__NR_sendmsg, channel, (long)&m, MSG_NOSIGNAL, 0, 0, 0);
}

static void serve(int channel)
{
	static unsigned char request[BROKER_MESSAGE_MAX + 64];
	static unsigned char answer[sizeof(struct broker_answer) + BROKER_DATA_MAX];
	struct { int pid, uid, gid; } peer;
	unsigned length = sizeof(peer);
	if (sys(__NR_getsockopt, channel, SOL_SOCKET, SO_PEERCRED, (long)&peer, (long)&length, 0) < 0)
		z_exit(1);
	peer_pid = peer.pid;
	for (;;) {
		char control[CMSG_SPACE(sizeof(int) * BROKER_FDS_MAX)];
		struct iovec io = {request, sizeof(request)};
		struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1,
				   .msg_control = control, .msg_controllen = sizeof(control)};
		long n = sys(__NR_recvmsg, channel, (long)&m, MSG_CMSG_CLOEXEC, 0, 0, 0);
		if (n == -4 /* EINTR */)
			continue;
		if (n <= 0)
			z_exit(0);
		struct call c;
		z_memset(&c, 0, sizeof(c));
		c.answer_fd = -1;
		struct cmsghdr *h = CMSG_FIRSTHDR(&m);
		if (h && h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS) {
			c.fds = (int)((h->cmsg_len - CMSG_LEN(0)) / sizeof(int));
			if (c.fds > BROKER_FDS_MAX)
				c.fds = BROKER_FDS_MAX;
			z_memcpy(c.fd, CMSG_DATA(h), sizeof(int) * (size_t)c.fds);
		}
		const struct broker_request *r = (const struct broker_request *)request;
		struct broker_answer *a = (struct broker_answer *)answer;
		z_memset(a, 0, sizeof(*a));
		const struct broker_spec *spec = n >= (long)sizeof(*r) ? broker_spec(r->nr) : 0;
		long rc = spec ? parse(r, (size_t)n, spec, &c, answer + sizeof(*a)) : -EACCES_;
		if (rc >= 0 && (int)r->fds != c.fds)
			rc = -EINVAL_;
		if (rc >= 0) {
			c.magic = r->flags;
			rc = execute(&c, r->nr);
		}
		a->result = rc;
		z_printf("[broker %d] nr=%d path=%s flags=%x fds=%d -> %ld\n", (int)peer_pid, r->nr,
			 c.path[1] ? c.path[1] : c.path[0] ? c.path[0] : "-", r->flags, c.fds, rc);
		size_t out = 0;
		for (int i = 0; spec && i < 6 && rc >= 0; i++) {
			if (spec->arg[i].kind != BK_OUT)
				continue;
			/* Variable outputs carry rc bytes; fixed ones are filled on success. */
			uint32_t len = spec->arg[i].len_arg >= 0 ? (rc > 0 ? (uint32_t)rc : 0) : c.out_len[i];
			if (len > c.out_len[i])
				len = c.out_len[i];
			if (c.out[i] != answer + sizeof(*a) + out)
				z_memcpy(answer + sizeof(*a) + out, c.out[i], len);
			a->len[i] = len;
			out += len;
		}
		send_answer(channel, answer, sizeof(*a) + out, c.answer_fd);
		if (c.answer_fd >= 0)
			sys(__NR_close, c.answer_fd, 0, 0, 0, 0, 0);
		for (int i = 0; i < c.fds; i++)
			sys(__NR_close, c.fd[i], 0, 0, 0, 0, 0);
	}
}

static void broker_run(int control, const payload_config_t *cfg)
{
	const char *access = cfg->mount_access_observe;
	add_tree(cfg->root[0] ? cfg->root : "/", access[0] ? access[0] : 'w');
	for (int i = 0; i < cfg->bind_count; i++)
		add_tree(cfg->binds[i].dst, access[0] ? access[i + 1] : 'w');
	add_tree(cfg->glue_dir, 'w');
	add_tree(cfg->loader_path, 'r');
	/* Handlers are reaped by the kernel. */
	signal_install(SIGCHLD, (signal_handler_t)1 /* SIG_IGN */, 0);
	for (;;) {
		char byte, control_data[CMSG_SPACE(sizeof(int))];
		struct iovec io = {&byte, 1};
		struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1,
				   .msg_control = control_data, .msg_controllen = sizeof(control_data)};
		long n = sys(__NR_recvmsg, control, (long)&m, MSG_CMSG_CLOEXEC, 0, 0, 0);
		if (n == -4)
			continue;
		if (n <= 0)
			z_exit(0); /* Every guest process is gone. */
		struct cmsghdr *h = CMSG_FIRSTHDR(&m);
		if (!h || h->cmsg_type != SCM_RIGHTS)
			continue;
		int channel;
		z_memcpy(&channel, CMSG_DATA(h), sizeof(int));
		long pid = sys(__NR_clone, SIGCHLD, 0, 0, 0, 0, 0);
		if (pid == 0) {
			sys(__NR_close, control, 0, 0, 0, 0, 0);
			serve(channel);
		}
		sys(__NR_close, channel, 0, 0, 0, 0, 0);
	}
}

/* Forks the broker (detached: the guest never sees it as a child) and keeps
 * the guest end of the control socket, inherited by every guest process. */
void broker_start(payload_config_t *cfg)
{
	int pair[2];
	if (sys(__NR_socketpair, AF_UNIX, SOCK_SEQPACKET | O_CLOEXEC_, 0, (long)pair, 0, 0) < 0)
		z_errx(1, "isolate: cannot create the broker socket");
	long pid = sys(__NR_clone, SIGCHLD, 0, 0, 0, 0, 0);
	if (pid < 0)
		z_errx(1, "isolate: cannot start the broker");
	if (pid == 0) {
		if (sys(__NR_clone, SIGCHLD, 0, 0, 0, 0, 0) == 0) {
			sys(__NR_close, pair[0], 0, 0, 0, 0, 0);
			broker_run(pair[1], cfg);
		}
		z_exit(0);
	}
	sys(__NR_wait4, pid, 0, 0, 0, 0, 0);
	sys(__NR_close, pair[1], 0, 0, 0, 0, 0);
	long fd = sys(__NR_fcntl, pair[0], 0 /* F_DUPFD */, 899, 0, 0, 0);
	sys(__NR_close, pair[0], 0, 0, 0, 0, 0);
	if (fd < 0)
		z_errx(1, "isolate: cannot place the broker socket");
	cfg->isolate = 1;
	cfg->isolate_fd = (int32_t)fd;
}
