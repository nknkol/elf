"""Numbers of src/payload/include/elf_abi.h, for Python tools and tests."""
import re
from pathlib import Path

_TEXT = (Path(__file__).resolve().parents[1] / 'src/payload/include/elf_abi.h').read_text()


def _define(name):
    return int(re.search(rf'#define {name}\s+(0x[0-9a-fA-F]+|\d+)', _TEXT).group(1), 0)


PAYLOAD_ABI_VERSION = _define('PAYLOAD_ABI_VERSION')
LOADER_FIXED_BASE = _define('LOADER_FIXED_BASE')
PAYLOAD_FIXED_BASE = _define('PAYLOAD_FIXED_BASE')
PR_GET_AUXV = _define('PR_GET_AUXV')
PR_ELF_FD_QUERY = _define('PR_ELF_FD_QUERY')
