/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The layer image reader (R6, lazy_layer.h) shared with the payload, on the
 * loader's syscall entry: the broker expands caches for an isolated guest,
 * the initial loader for its program, interpreter and cwd. (Its own object:
 * the payload builds payload/logic/lazy_layer.o.) */
#define LAZY_LOADER
#include "../payload/logic/lazy_layer.c"
