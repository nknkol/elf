/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Compile without ptrace, talloc, arch.h, or generated build headers. */
#include "path/fs_namespace.h"
_Static_assert(sizeof(((FileSystemNameSpace *)0)->cwd) == sizeof(char *),
               "cwd remains a caller-owned pointer");
int main(void)
{
    FileSystemNameSpace fs = {0};
    return fs.cwd != 0 || fs.bindings.pending != 0 ||
           fs.bindings.guest != 0 || fs.bindings.host != 0;
}
