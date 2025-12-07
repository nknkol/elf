#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t g_child = -1;
static char g_workdir[256];
static char g_cmdline[256];

#define MAX_CMD_ARGS 32

static int parse_simple_args(const char *line, char *argv[], int max_argc)
{
	if (!line || !argv || max_argc <= 0)
		return -1;

	char buf[sizeof(g_cmdline)];
	snprintf(buf, sizeof(buf), "%s", line);

	int argc = 0;
	char *p = buf;
	while (*p) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\0')
			break;
		if (argc >= max_argc)
			return -1;

		char *start = p;
		char quote = 0;
		argv[argc++] = start;

		while (*p) {
			if (quote) {
				if (*p == quote) {
					/* Strip the closing quote */
					memmove(p, p + 1, strlen(p));
					quote = 0;
					continue;
				}
			} else {
				if (*p == '"' || *p == '\'') {
					quote = *p;
					/* Strip the quote */
					memmove(p, p + 1, strlen(p));
					continue;
				}
				if (*p == ' ' || *p == '\t') {
					*p = '\0';
					p++;
					break;
				}
			}
			p++;
		}
	}

	argv[argc] = NULL;
	/* Copy parsed tokens back into g_cmdline buffer so the strings persist */
	char *dst = g_cmdline;
	size_t remain = sizeof(g_cmdline);
	for (int i = 0; i < argc; i++) {
		size_t len = strlen(argv[i]);
		if (len + 1 > remain)
			return -1;
		memcpy(dst, argv[i], len + 1);
		argv[i] = dst;
		dst += len + 1;
		remain -= (len + 1);
	}
	argv[argc] = NULL;

	return argc;
}

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	_exit(1);
}

static void set_default_env(const char *key, const char *val)
{
	const char *cur = getenv(key);
	if (!cur || cur[0] == '\0')
		setenv(key, val, 1);
}

static void load_env_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return;
	char line[512];
	while (fgets(line, sizeof(line), fp)) {
		char *p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;
		char *eq = strchr(p, '=');
		if (!eq)
			continue;
		*eq = '\0';
		char *val = eq + 1;
		char *nl = strchr(val, '\n');
		if (nl)
			*nl = '\0';
		setenv(p, val, 1);
	}
	fclose(fp);
}

static void forward_handler(int sig)
{
	if (g_child > 0)
		kill(g_child, sig);
}

static void rstrip(char *s)
{
	if (!s)
		return;
	size_t len = strlen(s);
	while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r'))
		s[--len] = '\0';
}

static void parse_guest_config_fd(int fd)
{
	if (fd < 0)
		return;
	FILE *fp = fdopen(fd, "r");
	if (!fp)
		return;
	char line[512];
	while (fgets(line, sizeof(line), fp)) {
		char *p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;
		char *nl = strchr(p, '\n');
		if (nl)
			*nl = '\0';
		rstrip(p);
		if (strncmp(p, "ENV ", 4) == 0) {
			char *kv = p + 4;
			char *eq = strchr(kv, '=');
			if (!eq)
				continue;
			setenv(kv, eq + 1, 1);
		} else if (strncmp(p, "WORKDIR ", 8) == 0) {
			snprintf(g_workdir, sizeof(g_workdir), "%s", p + 8);
		} else if (strncmp(p, "CMD ", 4) == 0) {
			snprintf(g_cmdline, sizeof(g_cmdline), "%s", p + 4);
		} else if (strncmp(p, "RUN ", 4) == 0 || strncmp(p, "DAEMON ", 7) == 0 || strncmp(p, "USER ", 5) == 0) {
			/* 未实现的子命令：忽略 */
		}
	}
	/* fdclose handled by fclose */
	fclose(fp);
}

int main(int argc, char **argv)
{
	const char *cfg_fd_env = getenv("INIT_CONFIG_FD");
	if (cfg_fd_env && cfg_fd_env[0])
		parse_guest_config_fd(atoi(cfg_fd_env));

	/* 环境默认值 */
	set_default_env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
	set_default_env("HOME", "/root");
	set_default_env("TERM", "xterm-256color");
	set_default_env("USER", "root");
	set_default_env("LOGNAME", "root");

	load_env_file("/etc/environment");

	if (g_workdir[0] && chdir(g_workdir) < 0)
		die("tiny-init: chdir %s failed: %s\n", g_workdir, strerror(errno));

	char *child_argv[MAX_CMD_ARGS + 1] = {0};
	int child_argc = 0;
	if (argc >= 2) {
		child_argv[0] = argv[1];
		child_argc = 1;
		for (int i = 2; i < argc && child_argc + 1 < (int)(sizeof(child_argv)/sizeof(child_argv[0])); i++)
			child_argv[child_argc++] = argv[i];
		child_argv[child_argc] = NULL;
	} else {
		const char *cmd = g_cmdline[0] ? g_cmdline : "/bin/sh";
		int parsed = parse_simple_args(cmd, child_argv, MAX_CMD_ARGS);
		if (parsed <= 0)
			die("tiny-init: invalid CMD\n");
		child_argc = parsed;
	}

	/* Debug: log the final argv used to exec */
	if (child_argc > 0) {
		fprintf(stderr, "tiny-init: exec");
		for (int i = 0; i < child_argc; i++)
			fprintf(stderr, " %s", child_argv[i]);
		fprintf(stderr, "\n");
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = forward_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	g_child = fork();
	if (g_child < 0)
		die("tiny-init: fork failed: %s\n", strerror(errno));
	if (g_child == 0) {
		/* 子进程恢复默认信号，执行用户命令 */
		struct sigaction dfl;
		memset(&dfl, 0, sizeof(dfl));
		dfl.sa_handler = SIG_DFL;
		sigaction(SIGTERM, &dfl, NULL);
		sigaction(SIGINT, &dfl, NULL);
		sigaction(SIGQUIT, &dfl, NULL);
		sigaction(SIGHUP, &dfl, NULL);
		execvp(child_argv[0], child_argv);
		die("tiny-init: execvp failed: %s\n", strerror(errno));
	}

	for (;;) {
		int status = 0;
		pid_t pid = waitpid(-1, &status, 0);
		if (pid < 0) {
			if (errno == EINTR)
				continue;
			die("tiny-init: waitpid failed: %s\n", strerror(errno));
		}
		if (pid == g_child) {
			if (WIFEXITED(status))
				_exit(WEXITSTATUS(status));
			if (WIFSIGNALED(status)) {
				int sig = WTERMSIG(status);
				fprintf(stderr, "tiny-init: child killed by signal %d\n", sig);
				_exit(128 + sig);
			}
			_exit(1);
		}
		/* 其他子进程：静默回收，继续等待主进程 */
	}
	return 0;
}
