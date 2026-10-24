#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# Syntax-only: verifies the new header needs neither ptrace nor talloc.
"${CC:-clang}" -std=c11 -Wall -Wextra -Werror -fsyntax-only \
    -I"$base/src" "$base/port-tests/namespace_header.c"
echo 'PASS: filesystem namespace header builds independently'

python3 "$base/port-tests/test_paths.py"
