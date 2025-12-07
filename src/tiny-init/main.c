#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t g_child = -1;

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

int main(int argc, char **argv)
{
	if (argc < 2)
		die("tiny-init: missing command to run\n");

	/* 环境默认值 */
	set_default_env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
	set_default_env("HOME", "/root");
	set_default_env("TERM", "xterm-256color");
	set_default_env("USER", "root");
	set_default_env("LOGNAME", "root");

	load_env_file("/etc/environment");

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
		execvp(argv[1], &argv[1]);
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
			if (WIFSIGNALED(status))
				_exit(128 + WTERMSIG(status));
			_exit(1);
		}
		/* 其他子进程：静默回收，继续等待主进程 */
	}
	return 0;
}
