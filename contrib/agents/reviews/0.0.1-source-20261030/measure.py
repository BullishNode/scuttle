#!/usr/bin/env python3
"""Count nonblank, noncomment runtime source from immutable Git objects."""
import collections
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from pygments import lex
from pygments.lexers import RustLexer, SqlLexer, ProtoBufLexer, BashLexer
from pygments.token import Comment, Literal

REPO = os.environ.get('SCUTTLE_SOURCE_REPO') or subprocess.check_output(
    ['git', 'rev-parse', '--show-toplevel']).decode().strip()
OUT = Path(os.environ.get('SCUTTLE_LOC_OUTPUT', Path(__file__).parent))
OUT.mkdir(parents=True, exist_ok=True)

def git(*args):
    return subprocess.check_output(['git', '-C', REPO, *args])

def classify(path):
    if path.startswith(('testing/', 'wasm-testing/', 'fuzz/', 'bark-rest-client/')):
        return None
    if '/src/test_util/' in path or path in ('lib/src/napkin.rs', 'bark/src/persist/test_suite.rs'):
        return None
    if '/src/' in path and path.endswith('.rs'):
        return RustLexer()
    if path.startswith('server/src/database/migrations/') and path.endswith('.sql'):
        return SqlLexer()
    if path.startswith('server-rpc/protos/') and path.endswith('.proto'):
        return ProtoBufLexer()
    if path in ('.gitlab/images/releases/bark/run.sh', '.gitlab/images/releases/captaind/start.sh', 'contrib/docker/cln_start.sh'):
        return BashLexer()
    return None

def production_lines(source, lexer):
    # Preserve byte/line positions. Strings count as code but their braces cannot
    # terminate a cfg(test) item. Comments never count, including nested blocks.
    code, structure = [], []
    for token, value in lex(source, lexer):
        blank = ''.join('\n' if c == '\n' else ' ' for c in value)
        comment = token in Comment and token not in Comment.Preproc
        code.append(blank if comment else value)
        structure.append(blank if comment or token in Literal.String else value)
    code, structure = ''.join(code), ''.join(structure)
    removed = []
    if isinstance(lexer, RustLexer):
        # Only positive test-only configurations. cfg(not(test)) is production.
        pattern = r'#\[(?:cfg\((?:test|any\(test,\s*feature\s*=\s*"test-util"\))\)|(?:tokio::)?test)\]'
        # Find attributes in comment-stripped source; quoted feature values are
        # deliberately retained here, while item braces use the structure mask.
        for match in re.finditer(pattern, code):
            start, pos = match.start(), match.end()
            # Skip any following attributes before finding the annotated item.
            while True:
                while pos < len(structure) and structure[pos].isspace(): pos += 1
                if structure.startswith('#[', pos):
                    end = structure.find(']', pos)
                    if end < 0: raise ValueError('unterminated attribute')
                    pos = end + 1
                else: break
            brace, semi = structure.find('{', pos), structure.find(';', pos)
            # Conditional parameters, fields, and call arguments end at a
            # top-level comma, rather than at the next production statement.
            tail = structure[pos:]
            field = re.match(r'(?:pub(?:\([^)]*\))?\s+)?\w+\s*:', tail)
            inline = bool(structure[:start].split('\n')[-1].strip())
            if field or inline:
                depth, end = 0, pos
                while end < len(structure):
                    char = structure[end]
                    if depth == 0 and char in ',)': break
                    depth += (char in '(<[{') - (char in ')>]}')
                    end += 1
                if end < len(structure) and structure[end] == ',': end += 1
            elif semi >= 0 and (brace < 0 or semi < brace):
                end = semi + 1
            elif brace >= 0:
                depth, end = 1, brace + 1
                while depth and end < len(structure):
                    depth += (structure[end] == '{') - (structure[end] == '}')
                    end += 1
                if depth: raise ValueError('unbalanced cfg(test) item')
            else: raise ValueError('missing cfg(test) item')
            removed.append((start, end))
        chars = list(code)
        for start, end in removed:
            for i in range(start, end):
                if chars[i] != '\n': chars[i] = ' '
        code = ''.join(chars)
    return [line.strip() for line in code.splitlines() if line.strip()], len(removed)

def source_lines(source, lexer):
    lines, removed = production_lines(source, lexer)
    return len(lines), removed

def normalized(ref):
    result = {}
    for path in git('ls-tree', '-r', '--name-only', ref).decode().splitlines():
        lexer = classify(path)
        if lexer is None: continue
        source = git('show', ref+':'+path)
        key = hashlib.sha256(source).hexdigest()
        cache = OUT/'normalized-v2'/key
        if cache.exists(): lines = json.loads(cache.read_text())
        else:
            lines, _ = production_lines(source.decode(), lexer)
            cache.parent.mkdir(exist_ok=True)
            cache.write_text(json.dumps(lines)+'\n')
        result[path] = lines
    return result

def delta(base, fork):
    before, after = normalized(base), normalized(fork)
    files = []
    renames = []
    for row in git('diff', '--name-status', '--find-renames=100%', base, fork).decode().splitlines():
        fields = row.split('\t')
        if fields[0] == 'R100' and fields[1] in before and fields[2] in after:
            old, new = fields[1:]
            assert before[old] == after[new]
            renames.append(dict(before=old, after=new, lines=len(before[old])))
            before.pop(old)
            after.pop(new)
    for path in sorted(before.keys() | after.keys()):
        a, b = before.get(path, []), after.get(path, [])
        adds = deletes = 0
        for tag, i, j, k, l in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if tag != 'equal':
                deletes += j-i
                adds += l-k
        if adds or deletes: files.append(dict(path=path, added=adds, deleted=deletes, gross=adds+deletes))
    added, deleted = sum(f['added'] for f in files), sum(f['deleted'] for f in files)
    return dict(base=base, fork=fork, added=added, deleted=deleted, gross=added+deleted,
                net=added-deleted, exact_renames=renames, files=files)

def measure(ref):
    oid = git('rev-parse', ref).decode().strip()
    files = []
    for path in git('ls-tree', '-r', '--name-only', oid).decode().splitlines():
        lexer = classify(path)
        if lexer is None: continue
        content = git('show', oid + ':' + path)
        count, tests = source_lines(content.decode(), lexer)
        files.append(dict(path=path, lines=count, excluded_test_items=tests,
                          sha256=hashlib.sha256(content).hexdigest()))
    return dict(commit=oid, tree=git('rev-parse', oid+'^{tree}').decode().strip(),
                total=sum(f['lines'] for f in files),
                by_component=dict(sorted(collections.Counter({component: sum(f['lines'] for f in files if f['path'].split('/')[0] == component)
                    for component in {f['path'].split('/')[0] for f in files}}).items())),
                files=files)

if __name__ == '__main__':
    if sys.argv[1] == '--delta':
        data = delta(sys.argv[2], sys.argv[3])
        (OUT/(sys.argv[4]+'.json')).write_text(json.dumps(data, indent=2)+'\n')
        print({k:v for k,v in data.items() if k != 'files'})
        print(sorted(data['files'], key=lambda f:-f['gross'])[:35])
        sys.exit()
    result = {ref: measure(ref) for ref in sys.argv[1:]}
    (OUT/'loc.json').write_text(json.dumps(result, indent=2)+'\n')
    for ref, data in result.items():
        print(ref, data['commit'], data['tree'], data['total'], data['by_component'])
