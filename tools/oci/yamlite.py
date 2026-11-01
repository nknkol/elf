"""A YAML subset for compose files (the device's Python has no PyYAML).

Supported: block mappings and sequences (a sequence may sit at its key's
indentation), plain / 'single' / "double" quoted scalars, | and > block
scalars with - and + chomping, flow [..] and {..} (spanning lines), comments,
--- document start, anchors (&a), aliases (*a) and merge keys (<<).
Scalars: null ~ true false (any case), integers, floats; everything else is a
string. Not supported: tags, complex keys, several documents."""
import re


class YAMLError(ValueError):
    pass


def _strip_comment(line):
    """The line without a trailing comment (quotes respected)."""
    quote = None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                if quote == "'" and i + 1 < len(line) and line[i + 1] == "'":
                    continue
                quote = None
            elif c == '\\' and quote == '"':
                continue
        elif c in '\'"' and (i == 0 or line[i - 1] in ' \t[{,:-'):
            quote = c
        elif c == '#' and (i == 0 or line[i - 1] in ' \t'):
            return line[:i].rstrip()
    return line.rstrip()


_INT = re.compile(r'^[-+]?(0|[1-9][0-9_]*)$')
_OCT = re.compile(r'^0o[0-7]+$')
_HEX = re.compile(r'^0x[0-9a-fA-F]+$')
_FLOAT = re.compile(r'^[-+]?(\.[0-9]+|[0-9][0-9_]*(\.[0-9]*)?)([eE][-+]?[0-9]+)?$')


def _plain(text):
    t = text.strip()
    low = t.lower()
    if t in ('', '~') or low == 'null':
        return None
    if low == 'true':
        return True
    if low == 'false':
        return False
    if _INT.match(t):
        return int(t.replace('_', ''))
    if _OCT.match(t):
        return int(t[2:], 8)
    if re.match(r'^0[0-7]+$', t):  # 0755: octal, as Go's yaml reads file modes
        return int(t, 8)
    if _HEX.match(t):
        return int(t[2:], 16)
    if _FLOAT.match(t) and any(ch.isdigit() for ch in t):
        return float(t.replace('_', ''))
    if low in ('.inf', '+.inf'):
        return float('inf')
    if low == '-.inf':
        return float('-inf')
    if low == '.nan':
        return float('nan')
    return t


_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0', '"': '"', '\\': '\\', '/': '/', ' ': ' ',
            'a': '\a', 'b': '\b', 'e': '\x1b', 'f': '\f', 'v': '\v', 'N': '\x85', '_': '\xa0'}


def _double(body):
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == '\\' and i + 1 < len(body):
            n = body[i + 1]
            if n in 'xuU':
                width = {'x': 2, 'u': 4, 'U': 8}[n]
                out.append(chr(int(body[i + 2:i + 2 + width], 16)))
                i += 2 + width
                continue
            out.append(_ESCAPES.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def _fold_quoted(text):
    """Line breaks inside a quoted scalar fold to spaces (empty lines to newlines)."""
    if '\n' not in text:
        return text
    parts = [p.strip() for p in text.split('\n')]
    out = parts[0]
    for p in parts[1:]:
        out += '\n' if not p else (' ' + p if out and not out.endswith('\n') else p)
    return out


class _Parser:
    def __init__(self, text):
        self.anchors = {}
        self.lines = []  # (indent, content, raw line) of significant lines
        text = text.replace('\r\n', '\n')
        if text.endswith('\n'):
            text = text[:-1]  # the last line break ends a line, it does not start one
        self.lines = text.split('\n')
        self.pos = 0

    # ---- line access
    def _sig(self, i):
        """(indent, content) of line i with the comment removed, None if blank."""
        raw = self.lines[i]
        content = _strip_comment(raw)
        if not content.strip():
            return None
        return len(content) - len(content.lstrip(' ')), content.strip()

    def _next(self):
        """Index of the next significant line at or after pos."""
        i = self.pos
        while i < len(self.lines):
            s = self._sig(i)
            if s is not None:
                if s[1] in ('---', '...') and s[0] == 0:
                    i += 1
                    continue
                return i
            i += 1
        return None

    def parse(self):
        i = self._next()
        if i is None:
            return None
        indent, _ = self._sig(i)
        value = self._block(indent)
        rest = self._next()
        if rest is not None:
            raise YAMLError(f'line {rest + 1}: unexpected content: {self.lines[rest].strip()}')
        return value

    # ---- blocks
    def _block(self, indent):
        i = self._next()
        ind, content = self._sig(i)
        if content == '-' or content.startswith('- '):
            return self._sequence(ind)
        return self._mapping(ind)

    def _sequence(self, indent):
        out = []
        while True:
            i = self._next()
            if i is None:
                break
            ind, content = self._sig(i)
            if ind != indent or not (content == '-' or content.startswith('- ')):
                break
            rest = content[1:].lstrip(' ')
            self.pos = i + 1
            if not rest:
                n = self._next()
                if n is not None and self._sig(n)[0] > indent:
                    out.append(self._block(self._sig(n)[0]))
                else:
                    out.append(None)
                continue
            column = ind + (len(content) - len(rest))
            out.append(self._inline(rest, column, i))
        return out

    def _inline(self, rest, column, i):
        """A sequence item's value that starts on the dash line."""
        anchor = None
        if rest.startswith('&'):
            name, _, rest = rest.partition(' ')
            anchor, rest = name[1:], rest.lstrip()
            if not rest:
                value = self._nested(column - 1)
                self.anchors[anchor] = value
                return value
        if (rest == '-' or rest.startswith('- ')):
            # "- - x": a nested sequence starting on this line.
            self.lines[i] = ' ' * column + rest
            self.pos = i
            value = self._sequence(column)
        elif self._key_split(rest) is not None:
            # "- key: value": a mapping whose keys sit at column.
            self.lines[i] = ' ' * column + rest
            self.pos = i
            value = self._mapping(column)
        else:
            value = self._value(rest, column - 1, i)
        if anchor:
            self.anchors[anchor] = value
        return value

    def _key_split(self, content):
        """(key, rest) of 'key: rest', None if content is not a mapping entry."""
        if content[0] in '"\'':
            q = content[0]
            j = 1
            while j < len(content):
                if content[j] == q:
                    if q == "'" and j + 1 < len(content) and content[j + 1] == "'":
                        j += 2
                        continue
                    break
                if content[j] == '\\' and q == '"':
                    j += 1
                j += 1
            if j + 1 <= len(content) and content[j + 1:j + 2] == ':' and \
                    (j + 2 == len(content) or content[j + 2] == ' '):
                key = content[1:j]
                key = _double(key) if q == '"' else key.replace("''", "'")
                return key, content[j + 2:].strip()
            return None
        if content[0] in '[{':
            return None
        m = re.match(r'^([^#]*?):(?:\s+(.*)|$)', content)
        if not m:
            return None
        key = m.group(1)
        if not key or key.startswith(('- ', '&', '*', '!')) and key != '<<':
            if not key.startswith('*'):
                return None
        return key.strip(), (m.group(2) or '').strip()

    def _mapping(self, indent):
        out = {}
        merges = []
        while True:
            i = self._next()
            if i is None:
                break
            ind, content = self._sig(i)
            if ind != indent:
                if ind > indent:
                    raise YAMLError(f'line {i + 1}: bad indentation')
                break
            if content == '-' or content.startswith('- '):
                break
            split = self._key_split(content)
            if split is None:
                raise YAMLError(f'line {i + 1}: expected "key: value": {content}')
            key, rest = split
            self.pos = i + 1
            value = self._value(rest, indent, i) if rest else self._nested(indent, allow_seq=True)
            if key == '<<':
                merges.extend(value if isinstance(value, list) else [value])
                continue
            out[_plain(key) if key and key[0] not in '"\'' and _plain(key) is not None and
                not isinstance(_plain(key), str) else key] = value
        for m in merges:
            if not isinstance(m, dict):
                raise YAMLError('merge key needs a mapping')
            for k, v in m.items():
                out.setdefault(k, v)
        return out

    def _nested(self, indent, allow_seq=False):
        n = self._next()
        if n is None:
            return None
        ind, content = self._sig(n)
        if ind > indent:
            return self._block(ind)
        if allow_seq and ind == indent and (content == '-' or content.startswith('- ')):
            return self._sequence(ind)
        return None

    # ---- values
    def _value(self, rest, indent, i):
        anchor = None
        if rest.startswith('&'):
            name, _, rest = rest.partition(' ')
            anchor, rest = name[1:], rest.strip()
            if not rest:
                value = self._nested(indent, allow_seq=True)
                self.anchors[anchor] = value
                return value
        if rest.startswith('!'):
            _, _, rest = rest.partition(' ')  # tags ignored
            rest = rest.strip()
        if rest.startswith('*'):
            name = rest[1:].strip()
            if name not in self.anchors:
                raise YAMLError(f'line {i + 1}: unknown alias {name}')
            value = self.anchors[name]
        elif rest[0] in '|>':
            value = self._block_scalar(rest, indent)
        elif rest[0] in '[{':
            value = self._flow_value(rest, i)
        elif rest[0] in '"\'':
            value = self._quoted(rest, i)
        else:
            value = self._plain_multiline(rest, indent)
        if anchor:
            self.anchors[anchor] = value
        return value

    def _plain_multiline(self, rest, indent):
        parts = [rest]
        while True:
            n = self._next()
            if n is None:
                break
            ind, content = self._sig(n)
            if ind <= indent or self._key_split(content) is not None or content.startswith('- '):
                break
            parts.append(content)
            self.pos = n + 1
        return _plain(' '.join(parts)) if len(parts) == 1 else ' '.join(parts)

    def _quoted(self, rest, i):
        q = rest[0]
        text = rest
        line = i
        while True:
            j, end = 1, None
            while j < len(text):
                if text[j] == q:
                    if q == "'" and j + 1 < len(text) and text[j + 1] == "'":
                        j += 2
                        continue
                    end = j
                    break
                if text[j] == '\\' and q == '"':
                    j += 1
                j += 1
            if end is not None:
                break
            line += 1
            if line >= len(self.lines):
                raise YAMLError(f'line {i + 1}: unterminated string')
            text += '\n' + self.lines[line]
            self.pos = line + 1
        body = _fold_quoted(text[1:end])
        tail = text[end + 1:].strip()
        if tail and not tail.startswith('#'):
            raise YAMLError(f'line {i + 1}: text after a quoted string')
        return _double(body) if q == '"' else body.replace("''", "'")

    def _block_scalar(self, header, indent):
        style, chomp = header[0], ''
        for ch in header[1:]:
            if ch in '+-':
                chomp = ch
        explicit = next((int(ch) for ch in header[1:] if ch.isdigit()), None)
        lines = []
        block_indent = indent + explicit if explicit else None
        i = self.pos
        while i < len(self.lines):
            raw = self.lines[i]
            if raw.strip():
                ind = len(raw) - len(raw.lstrip(' '))
                if block_indent is None:
                    if ind <= indent:
                        break
                    block_indent = ind
                if ind < block_indent:
                    break
                lines.append(raw[block_indent:])
            else:
                lines.append('')
            i += 1
        self.pos = i
        trailing = 0
        while lines and lines[-1] == '':
            lines.pop()
            trailing += 1
        if not lines:
            return ''
        if style == '|':
            text = '\n'.join(lines)
        else:
            text, prev = '', None  # prev: None start, 'b' blank, 'm' more-indented, 't' text
            for ln in lines:
                if not ln:
                    text += '\n'
                    prev = 'b' if prev != 'm' else 'm'
                elif ln.startswith(' '):
                    text += ('\n' if prev == 't' else '') + ln + '\n'
                    prev = 'm'
                else:
                    text += (' ' if prev == 't' else '') + ln
                    prev = 't'
            if text.endswith('\n'):
                text = text[:-1]
        if chomp == '-':
            return text
        return text + '\n' + ('\n' * trailing if chomp == '+' else '')

    def _flow_value(self, rest, i):
        text, line = rest, i
        while not self._balanced(text):
            line += 1
            if line >= len(self.lines):
                raise YAMLError(f'line {i + 1}: unterminated flow collection')
            text += ' ' + _strip_comment(self.lines[line]).strip()
            self.pos = line + 1
        value, end = self._flow(text, 0)
        if text[end:].strip():
            raise YAMLError(f'line {i + 1}: text after a flow collection')
        return value

    @staticmethod
    def _balanced(text):
        depth, quote = 0, None
        for j, c in enumerate(text):
            if quote:
                if c == quote and not (quote == '"' and text[j - 1] == '\\'):
                    quote = None
            elif c in '"\'':
                quote = c
            elif c in '[{':
                depth += 1
            elif c in ']}':
                depth -= 1
        return depth == 0

    def _flow(self, text, j):
        while text[j] == ' ':
            j += 1
        c = text[j]
        if c in '[{':
            close = ']' if c == '[' else '}'
            out = [] if c == '[' else {}
            j += 1
            while True:
                while text[j] in ' ,':
                    j += 1
                if text[j] == close:
                    return out, j + 1
                if c == '[':
                    item, j = self._flow(text, j)
                    out.append(item)
                else:
                    key, j = self._flow_scalar(text, j, key=True)
                    while text[j] == ' ':
                        j += 1
                    if text[j] == ':':
                        value, j = self._flow(text, j + 1)
                    else:
                        value = None
                    out[key] = value
        return self._flow_scalar(text, j)

    def _flow_scalar(self, text, j, key=False):
        while text[j] == ' ':
            j += 1
        if text[j] in '"\'':
            q = text[j]
            k = j + 1
            while text[k] != q or (q == "'" and text[k + 1:k + 2] == "'"):
                k += 2 if (text[k] == '\\' and q == '"') or (q == "'" and text[k] == q) else 1
            body = text[j + 1:k]
            return (_double(body) if q == '"' else body.replace("''", "'")), k + 1
        if text[j] == '*':
            k = j + 1
            while k < len(text) and text[k] not in ' ,]}':
                k += 1
            return self.anchors[text[j + 1:k]], k
        k = j
        while k < len(text) and text[k] not in ',]}' and not (text[k] == ':' and
                                                              (key or text[k + 1:k + 2] in (' ', ',', ']', '}', ''))):
            k += 1
        raw = text[j:k].strip()
        return (raw if key else _plain(raw)), k


def load(text):
    """The value of a YAML document."""
    return _Parser(text).parse()


def dump(value, indent=0):
    """YAML text for value (block style; strings quoted when needed)."""
    pad = ' ' * indent
    if isinstance(value, dict):
        if not value:
            return pad + '{}\n'
        out = ''
        for k, v in value.items():
            key = _scalar(str(k))
            if isinstance(v, (dict, list)) and v:
                out += f'{pad}{key}:\n' + dump(v, indent + 2 if isinstance(v, dict) else indent + 2)
            else:
                out += f'{pad}{key}: {_scalar(v)}\n'
        return out
    if isinstance(value, list):
        if not value:
            return pad + '[]\n'
        out = ''
        for v in value:
            if isinstance(v, (dict, list)) and v:
                inner = dump(v, indent + 2)
                out += f'{pad}- ' + inner[indent + 2:]
            else:
                out += f'{pad}- {_scalar(v)}\n'
        return out
    return pad + _scalar(value) + '\n'


def _scalar(v):
    if v is None:
        return 'null'
    if v is True:
        return 'true'
    if v is False:
        return 'false'
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (dict, list)):
        return '{}' if isinstance(v, dict) else '[]'
    s = str(v)
    if s == '' or _plain(s) != s or s[0] in '-?:,[]{}#&*!|>\'"%@`' or ': ' in s or ' #' in s or \
            '\n' in s or s != s.strip():
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
    return s
