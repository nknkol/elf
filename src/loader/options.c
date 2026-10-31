/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Command line: options end at "--" or at the first non-option, which is
 * the program to run. Every invalid option is fatal. */
#include "loader.h"

static int is(const char *arg, const char *name)
{
	size_t n = z_strlen(name);
	return z_strncmp(arg, name, n + 1) == 0;
}

static const char *value(int argc, char **argv, int *i)
{
	if (*i + 1 >= argc || !argv[*i + 1][0])
		z_errx(1, "missing value for %s", argv[*i]);
	return argv[++*i];
}

static unsigned long number(const char *s, unsigned long max, const char *what)
{
	unsigned long v = 0;
	if (!*s)
		z_errx(1, "invalid %s", what);
	for (; *s; s++) {
		if (*s < '0' || *s > '9' || v > (max - (unsigned long)(*s - '0')) / 10)
			z_errx(1, "invalid %s", what);
		v = v * 10 + (unsigned long)(*s - '0');
	}
	return v;
}

/* "u:u:...": exactly count unsigned 32-bit values separated by sep. */
static int numbers(const char *s, char sep, uint32_t *out, int max, int exact)
{
	int count = 0;
	for (;;) {
		unsigned long long v = 0;
		const char *start = s;
		while (*s >= '0' && *s <= '9' && v <= 0xffffffffull)
			v = v * 10 + (unsigned)(*s++ - '0');
		if (s == start || v > 0xffffffffull || count == max || (*s && *s != sep))
			return -1;
		out[count++] = (uint32_t)v;
		if (!*s)
			break;
		s++;
	}
	return exact && count != exact ? -1 : count;
}

static void add_bind(payload_config_t *cfg, const char *spec)
{
	const char *colon = z_strchr(spec, ':');
	if (!colon || colon == spec || !colon[1])
		z_errx(1, "volume needs host:guest");
	if (cfg->bind_count >= CONFIG_MAX_BINDS)
		z_errx(1, "too many volumes");
	struct bind_entry *b = &cfg->binds[cfg->bind_count++];
	copy_substr(b->dst, CONFIG_MAX_PATH, spec, (size_t)(colon - spec));
	copy_cstr(b->src, CONFIG_MAX_PATH, colon + 1);
}

#ifdef GUARDED
static int guarded_option(const char *arg, payload_config_t *cfg, int argc, char **argv, int *i)
{
	if (is(arg, "--observe-mount-access") || is(arg, "--guard-path-mutations") ||
	    is(arg, "--guard-file-mutations") || is(arg, "--guard-file-access")) {
		if (cfg->mount_access_observe[0])
			z_errx(1, "duplicate mount access observation");
		if (*i + 1 >= argc)
			z_errx(1, "missing mount access observation");
		const char *v = argv[++*i];
		size_t count = z_strlen(v);
		if (!count || count > CONFIG_MAX_BINDS + 1)
			z_errx(1, "invalid mount access observation length");
		for (size_t j = 0; j < count; j++)
			if (v[j] != 'd' && v[j] != 'r' && v[j] != 'w')
				z_errx(1, "invalid mount access observation value");
		copy_cstr(cfg->mount_access_observe, sizeof(cfg->mount_access_observe), v);
		cfg->guard = is(arg, "--guard-file-access") ? GUARD_READS :
			is(arg, "--guard-file-mutations") ? GUARD_FILES :
			is(arg, "--guard-path-mutations") ? GUARD_PATHS : GUARD_OBSERVE;
		return 1;
	}
	static const struct { const char *name, *what; size_t offset; } flags[] = {
		{"--allow-stream-input", "stream input", offsetof(payload_config_t, allow_stream_input)},
		{"--revalidate-file-fds", "file FD revalidation",
		 offsetof(payload_config_t, revalidate_file_fds)},
		{"--allow-local-output", "local output", offsetof(payload_config_t, allow_local_output)},
		{"--allow-pipe-output", "pipe output", offsetof(payload_config_t, allow_pipe_output)},
		{"--allow-stdio-output", "stdio output", offsetof(payload_config_t, allow_stdio_output)},
	};
	for (size_t k = 0; k < sizeof(flags) / sizeof(flags[0]); k++) {
		if (!is(arg, flags[k].name))
			continue;
		int32_t *flag = (int32_t *)((char *)cfg + flags[k].offset);
		if (*flag)
			z_errx(1, "duplicate %s option", flags[k].what);
		*flag = 1;
		return 1;
	}
	if (is(arg, "--fd-state")) {
		cfg->fd_state = (int32_t)number(value(argc, argv, i), 2147483647ul, "fd state");
		return 1;
	}
	return 0;
}

/* Guarded options only make sense together. */
static void check_guarded(const payload_config_t *cfg, const struct loader_options *opt)
{
	if (cfg->mount_access_observe[0] &&
	    z_strlen(cfg->mount_access_observe) != (size_t)cfg->bind_count + 1)
		z_errx(1, "mount access observation requires root plus every bind");
	if (cfg->revalidate_file_fds && cfg->guard < GUARD_FILES)
		z_errx(1, "file FD revalidation requires file mutation guard");
	if (cfg->allow_local_output && cfg->guard < GUARD_FILES)
		z_errx(1, "local output requires file mutation guard");
	if (cfg->allow_pipe_output && cfg->guard < GUARD_FILES)
		z_errx(1, "pipe output requires file mutation guard");
	if (cfg->allow_stdio_output && cfg->guard < GUARD_FILES)
		z_errx(1, "stdio output requires file mutation guard");
	if (cfg->allow_stream_input && cfg->guard != GUARD_READS)
		z_errx(1, "stream input requires file access guard");
	if (cfg->fd_state >= 0 && !opt->child)
		z_errx(1, "fd state requires child loader");
	if (opt->exec_interp && (!opt->child || cfg->guard != GUARD_READS))
		z_errx(1, "exec interpreter requires file access child loader");
}
#endif

void options_parse(int argc, char **argv, payload_config_t *cfg, struct loader_options *opt)
{
	int mode_explicit = 0;
	z_memset(opt, 0, sizeof(*opt));
	opt->exec_fd = -1;
	opt->target = argc;
	z_memset(cfg, 0, sizeof(*cfg));
	cfg->mode = CONFIG_MODE_COMPAT;
	cfg->fake_group_count = -1;
	cfg->fd_state = -1;

	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (arg[0] != '-' || !arg[1]) {
			opt->target = i;
			break;
		}
		if (is(arg, "--")) {
			opt->target = i + 1;
			break;
		}
		if (is(arg, "--mode")) {
			const char *v = value(argc, argv, &i);
			if (is(v, "container"))
				cfg->mode = CONFIG_MODE_CONTAINER;
			else if (is(v, "compat"))
				cfg->mode = CONFIG_MODE_COMPAT;
			else
				z_errx(1, "invalid mode %s (expect compat|container)", v);
			mode_explicit = 1;
		} else if (is(arg, "--root")) {
			copy_cstr(cfg->root, CONFIG_MAX_PATH, value(argc, argv, &i));
			/* A root implies container mode unless a mode is given. */
			if (!mode_explicit)
				cfg->mode = CONFIG_MODE_CONTAINER;
		} else if (is(arg, "-v") || is(arg, "--volume")) {
			add_bind(cfg, value(argc, argv, &i));
		} else if (is(arg, "-e") || is(arg, "--env")) {
			const char *kv = value(argc, argv, &i);
			if (!z_strchr(kv, '='))
				z_errx(1, "env needs KEY=VALUE");
			if (opt->env_count >= LOADER_MAX_ENVS)
				z_errx(1, "too many env entries");
			opt->envs[opt->env_count++] = kv;
		} else if (is(arg, "--log")) {
			cfg->log_level = (int32_t)number(value(argc, argv, &i), LOG_LEVEL_DEBUG, "log level");
		} else if (is(arg, "--payload")) {
			opt->payload = value(argc, argv, &i);
		} else if (is(arg, "--link-copy")) {
			cfg->link_copy = 1;
		} else if (is(arg, "--seccomp-backstop")) {
			cfg->seccomp_backstop = 1;
		} else if (is(arg, "--isolate")) {
			opt->isolate = 1;
		} else if (is(arg, CONFIG_CHILD_ISOLATE_FD)) {
			cfg->isolate = 1;
			cfg->isolate_fd = (int32_t)number(value(argc, argv, &i), 2147483647ul, "isolate fd");
		} else if (is(arg, "--kernel-release") || is(arg, "--kernel-sysname")) {
			char *field = arg[9] == 'r' ? cfg->kernel_release : cfg->kernel_sysname;
			const char *v = value(argc, argv, &i);
			if (z_strlen(v) >= sizeof(cfg->kernel_release))
				z_errx(1, "invalid value for %s", arg);
			copy_cstr(field, sizeof(cfg->kernel_release), v);
		} else if (is(arg, CONFIG_CHILD_LOADER_ARG)) {
			opt->child = 1;
		} else if (is(arg, CONFIG_CHILD_EXEC_TARGET)) {
			opt->exec_target = value(argc, argv, &i);
		} else if (is(arg, CONFIG_CHILD_EXEC_PATH)) {
			opt->exec_path = value(argc, argv, &i);
		} else if (is(arg, CONFIG_CHILD_EXEC_FD)) {
			opt->exec_fd = (int)number(value(argc, argv, &i), 2147483647ul, "exec fd");
		} else if (is(arg, CONFIG_CHILD_EXEC_NAME)) {
			opt->exec_name = value(argc, argv, &i);
		} else if (is(arg, CONFIG_CHILD_EXEC_EXE) || is(arg, CONFIG_CHILD_EXEC_INTERP)) {
			const char *v = value(argc, argv, &i);
			if (v[0] != '/')
				z_errx(1, "invalid value for %s", arg);
			*(is(arg, CONFIG_CHILD_EXEC_EXE) ? &opt->exec_exe : &opt->exec_interp) = v;
		} else if (is(arg, CONFIG_CHILD_GLUE_DIR)) {
			const char *v = value(argc, argv, &i);
			if (v[0] != '/' || z_strlen(v) >= CONFIG_MAX_PATH)
				z_errx(1, "invalid value for %s", arg);
			copy_cstr(cfg->glue_dir, CONFIG_MAX_PATH, v);
		} else if (is(arg, CONFIG_CHILD_FAKE_IDS)) {
			if (numbers(value(argc, argv, &i), ':', cfg->fake_ids, 8, 8) < 0)
				z_errx(1, "invalid value for %s", arg);
		} else if (is(arg, CONFIG_CHILD_FAKE_GROUPS)) {
			const char *v = value(argc, argv, &i);
			int count = is(v, "-") ? 0 : numbers(v, ',', cfg->fake_groups, 32, 0);
			if (count < 0)
				z_errx(1, "invalid value for %s", arg);
			cfg->fake_group_count = count;
		}
#ifdef GUARDED
		else if (guarded_option(arg, cfg, argc, argv, &i)) {
		}
#endif
		else {
			z_errx(1, "unknown option %s", arg);
		}
	}
#ifdef GUARDED
	check_guarded(cfg, opt);
#else
	if (opt->exec_interp)
		z_errx(1, "exec interpreter requires file access child loader");
#endif
}
