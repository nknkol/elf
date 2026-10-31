/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation mode (docs/ISOLATION.md): the payload's host path syscalls are
 * requests to the broker process. Shared by the payload (marshaling) and
 * the loader (the broker). One request and one answer per SOCK_SEQPACKET
 * message; FDs travel as SCM_RIGHTS. */
#ifndef BROKER_PROTO_H
#define BROKER_PROTO_H
#include <stdint.h>
#include "syscall_nums.h"

#define BROKER_DATA_MAX   (64 * 1024)
#define BROKER_FDS_MAX    2
#define BROKER_MESSAGE_MAX (sizeof(struct broker_request) + BROKER_DATA_MAX)

enum broker_kind {
    BK_NONE,  /* unused argument */
    BK_VAL,   /* plain value */
    BK_DIRFD, /* directory FD of the following path (attached unless AT_FDCWD) */
    BK_FD,    /* object FD (attached) */
    BK_PATH,  /* NUL-terminated path; may be NULL (utimensat) */
    BK_STR,   /* NUL-terminated string that is not a path */
    BK_IN,    /* input buffer; may be NULL */
    BK_OUT,   /* output buffer */
};
struct broker_arg {
    uint8_t kind;
    int8_t len_arg;     /* argument holding the length, or -1 */
    uint16_t len_fixed; /* length when len_arg is -1 */
};
struct broker_spec {
    int nr;
    struct broker_arg arg[6];
};

/* Socket names that are host paths: bind/connect of the attached socket to
 * the path argument (raw __NR_bind/__NR_connect carry other addresses). */
#define BROKER_BIND_PATH    (-1)
#define BROKER_CONNECT_PATH (-2)

/* Request flags: path argument i was /proc/self/fd/N, so the request acts
 * on the attached FD N itself. */
#define BROKER_MAGIC(i) (1u << (i))
/* Optimistic lexical resolution: the paths should contain no symlink; the
 * broker answers ELOOP instead of traversing one (a final one too when the
 * call follows it) and the payload resolves the call fully again. */
#define BROKER_STRICT (1u << 8)

struct broker_request {
    int32_t nr;
    uint32_t flags;
    int64_t args[6];
    uint32_t len[6];   /* bytes of data for each argument, in order */
    uint32_t fds;      /* attached FDs, in argument order */
};
struct broker_answer {
    int64_t result;    /* value or -errno; an attached FD replaces a result >= 0 */
    uint32_t len[6];   /* output bytes for each BK_OUT argument, in order */
    /* BROKER_STRICT refusal (ELOOP): the symlink met, as its host path and
     * target, both NUL-terminated after the outputs (0: none). */
    uint32_t link[2];
};

#define A_V  {BK_VAL, -1, 0}
#define A_D  {BK_DIRFD, -1, 0}
#define A_F  {BK_FD, -1, 0}
#define A_P  {BK_PATH, -1, 0}
#define A_S  {BK_STR, -1, 0}
#define A_IN(n)  {BK_IN, -1, n}
#define A_INA(i) {BK_IN, i, 0}
#define A_OUT(n) {BK_OUT, -1, n}
#define A_OUTA(i) {BK_OUT, i, 0}

/* The calls the broker executes; everything else is refused. */
static const struct broker_spec broker_specs[] = {
    {__NR_openat,        {A_D, A_P, A_V, A_V}},
    {__NR_newfstatat,    {A_D, A_P, A_OUT(128), A_V}},
    {__NR_statx,         {A_D, A_P, A_V, A_V, A_OUT(256)}},
    {__NR_faccessat,     {A_D, A_P, A_V}},
    {__NR_faccessat2,    {A_D, A_P, A_V, A_V}},
    {__NR_readlinkat,    {A_D, A_P, A_OUTA(3), A_V}},
    {__NR_mkdirat,       {A_D, A_P, A_V}},
    {__NR_mknodat,       {A_D, A_P, A_V, A_V}},
    {__NR_unlinkat,      {A_D, A_P, A_V}},
    {__NR_symlinkat,     {A_S, A_D, A_P}},
    {__NR_linkat,        {A_D, A_P, A_D, A_P, A_V}},
    {__NR_renameat,      {A_D, A_P, A_D, A_P}},
    {__NR_renameat2,     {A_D, A_P, A_D, A_P, A_V}},
    {__NR_fchmodat,      {A_D, A_P, A_V}},
    {__NR_fchmodat2,     {A_D, A_P, A_V, A_V}},
    {__NR_fchownat,      {A_D, A_P, A_V, A_V, A_V}},
    {__NR_utimensat,     {A_D, A_P, A_IN(32), A_V}},
    {__NR_truncate,      {A_P, A_V}},
    {__NR_statfs,        {A_P, A_OUT(120)}},
    {__NR_chdir,         {A_P}},
    {__NR_setxattr,      {A_P, A_S, A_INA(3), A_V, A_V}},
    {__NR_lsetxattr,     {A_P, A_S, A_INA(3), A_V, A_V}},
    {__NR_getxattr,      {A_P, A_S, A_OUTA(3), A_V}},
    {__NR_lgetxattr,     {A_P, A_S, A_OUTA(3), A_V}},
    {__NR_listxattr,     {A_P, A_OUTA(2), A_V}},
    {__NR_llistxattr,    {A_P, A_OUTA(2), A_V}},
    {__NR_removexattr,   {A_P, A_S}},
    {__NR_lremovexattr,  {A_P, A_S}},
    {__NR_inotify_add_watch, {A_F, A_P, A_V}},
    {__NR_fchmod,        {A_F, A_V}},
    {__NR_fchown,        {A_F, A_V, A_V}},
    {__NR_fsetxattr,     {A_F, A_S, A_INA(3), A_V, A_V}},
    {__NR_fremovexattr,  {A_F, A_S}},
    /* Phase 2: the guest filter refuses these to the guest itself. */
    {__NR_socket,        {A_V, A_V, A_V}},
    {__NR_bind,          {A_F, A_INA(2), A_V}},
    {__NR_connect,       {A_F, A_INA(2), A_V}},
    {BROKER_BIND_PATH,   {A_F, A_P}},
    {BROKER_CONNECT_PATH, {A_F, A_P}},
};

static inline const struct broker_spec *broker_spec(long nr)
{
    for (unsigned i = 0; i < sizeof(broker_specs) / sizeof(broker_specs[0]); i++)
        if (broker_specs[i].nr == nr)
            return &broker_specs[i];
    return 0;
}
#endif
