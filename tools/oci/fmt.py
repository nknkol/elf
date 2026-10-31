"""Output helpers: Docker's tables, ages and a --format template subset.

Templates: {{.Field}}, {{.A.B}}, {{json .X}}, {{index .X "key"}},
{{upper .X}}, {{lower .X}}, {{join .X ","}}, "table" prefix, \\t and \\n."""
import json
import re
import time
from datetime import datetime, timezone


def parse_time(text):
    if not text:
        return None
    return datetime.strptime(text[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp()


def human_duration(seconds):
    """github.com/docker/go-units HumanDuration."""
    s = int(seconds)
    if s < 1:
        return 'Less than a second'
    if s == 1:
        return '1 second'
    if s < 60:
        return f'{s} seconds'
    m = s // 60
    if m == 1:
        return 'About a minute'
    if m < 60:
        return f'{m} minutes'
    h = round(s / 3600)
    if h == 1:
        return 'About an hour'
    if h < 48:
        return f'{h} hours'
    if h < 24 * 7 * 2:
        return f'{h // 24} days'
    if h < 24 * 30 * 2:
        return f'{h // 24 // 7} weeks'
    if h < 24 * 365 * 2:
        return f'{h // 24 // 30} months'
    return f'{h // 24 // 365} years'


def ago(text):
    t = parse_time(text)
    return human_duration(time.time() - t) + ' ago' if t else ''


def table(rows, columns):
    """Docker's tabwriter: columns padded by 3 spaces."""
    widths = [max([len(c)] + [len(str(r[i])) for r in rows]) for i, c in enumerate(columns)]
    lines = ['   '.join(c.ljust(w) for c, w in zip(columns, widths)).rstrip()]
    for r in rows:
        lines.append('   '.join(str(v).ljust(w) for v, w in zip(r, widths)).rstrip())
    return '\n'.join(lines)


def lookup(obj, path):
    for part in path.strip('.').split('.'):
        if not part:
            continue
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            obj = getattr(obj, part, None)
    return obj


def text_of(value):
    if value is None:
        return '<no value>'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, list):
        return '[' + ' '.join(text_of(v) for v in value) + ']'
    if isinstance(value, dict):
        return 'map[' + ' '.join(f'{k}:{text_of(v)}' for k, v in sorted(value.items())) + ']'
    return str(value)


TOKEN = re.compile(r'{{\s*(.*?)\s*}}')


def evaluate(expr, obj):
    words = re.findall(r'"[^"]*"|\S+', expr)
    if not words:
        return ''
    if words[0].startswith('.'):
        return text_of(lookup(obj, words[0]))
    fn, args = words[0], [lookup(obj, w) if w.startswith('.') else w.strip('"') for w in words[1:]]
    if fn == 'json':
        return json.dumps(args[0] if args else obj)
    if fn == 'index' and len(args) == 2:
        container, key = args
        if isinstance(container, dict):
            return text_of(container.get(key))
        if isinstance(container, list):
            return text_of(container[int(key)])
    if fn in ('upper', 'lower') and args:
        return getattr(text_of(args[0]), fn)()
    if fn == 'join' and len(args) == 2:
        return args[1].join(text_of(v) for v in (args[0] or []))
    if fn == 'println':
        return ' '.join(text_of(a) for a in args) + '\n'
    raise ValueError(f'template: unsupported expression {{{{{expr}}}}}')


def render(template, obj):
    template = template.replace('\\t', '\t').replace('\\n', '\n')
    return TOKEN.sub(lambda m: evaluate(m.group(1), obj), template)


def print_formatted(template, items, default_columns=None):
    """--format: "table ..." prints a header from the field names."""
    if template.startswith('table'):
        body = template[5:].strip() or None
        if body is None:
            return False
        header = TOKEN.sub(lambda m: re.sub(r'(?<!^)(?=[A-Z])', ' ',
                                            m.group(1).split('.')[-1]).upper(), body)
        rows = [render(body, item).split('\t') for item in items]
        cols = header.replace('\\t', '\t').split('\t')
        print(table(rows, cols))
        return True
    for item in items:
        print(render(template, item))
    return True
