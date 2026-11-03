#!/usr/bin/env python3
"""Scope manifest for the combined audit RFP (round 11).

Reads every file from git objects only (`git show <commit>:<path>`), so the
working tree, untracked files and local edits never enter the counts.

Usage:
  python3 -I scripts/audit-rfp/manifest.py <repo> <commit> <list-file>

<list-file> has one entry per line: `<tier> <path>`; blank lines and lines
starting with `#` are ignored. Output, tab separated:
  tier  lines  sloc  nsloc  sha256  path

Counting rules (the same as scripts/audit-rfp/nsloc.py, extended):
- Solidity and Rust: comments removed, blank lines dropped (SLOC); a line is
  joined to the previous one while a `(` or `[` is open (nSLOC). Rust: from the
  first top-level `#[cfg(test)]` on is excluded (inline tests).
- Python: SLOC = lines holding a token other than a comment or docstring;
  nSLOC = logical lines (tokenizer).
- JavaScript (.mjs, .js, .ts, .tsx) and shell (.sh): SLOC = non-blank lines
  that are not comment lines; nSLOC is reported equal to SLOC ("code lines").
- Any other file (JSON, TOML, Dockerfile, lock files): lines only; SLOC and
  nSLOC are `-`. Such files are pinned by hash, not sized.
"""
import hashlib
import io
import re
import subprocess
import sys
import tokenize


def strip_c(src):
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('//', i):
            j = src.find('\n', i)
            i = n if j < 0 else j
        elif src.startswith('/*', i):
            j = src.find('*/', i + 2)
            seg = src[i:(n if j < 0 else j + 2)]
            out.append('\n' * seg.count('\n'))
            i = n if j < 0 else j + 2
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def count_c(src, rust=False):
    if rust:
        m = re.search(r'^#\[cfg\(test\)\]', src, re.M)
        if m:
            src = src[:m.start()]
    lines = [l for l in strip_c(src).split('\n') if l.strip()]
    nsloc, depth = 0, 0
    for l in lines:
        if depth <= 0:
            nsloc += 1
        depth += l.count('(') + l.count('[') - l.count(')') - l.count(']')
        depth = max(depth, 0)
    return len(lines), nsloc


def count_py(src):
    toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    code, logical = set(), set()
    skip = (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
            tokenize.DEDENT, tokenize.ENDMARKER, tokenize.ENCODING)
    prev, start = tokenize.INDENT, True
    for t in toks:
        if t.type in skip:
            if t.type == tokenize.NEWLINE:
                start = True
            prev = t.type
            continue
        if t.type == tokenize.STRING and start and prev in (
                tokenize.INDENT, tokenize.DEDENT, tokenize.NEWLINE, tokenize.NL):
            prev = t.type
            continue
        code.update(range(t.start[0], t.end[0] + 1))
        if start:
            logical.add(t.start[0])
            start = False
        prev = t.type
    return len(code), len(logical)


def count_script(src, shell):
    if not shell:
        src = strip_c(src)
    n = 0
    for l in src.split('\n'):
        s = l.strip()
        if not s:
            continue
        if shell and s.startswith('#'):
            continue
        n += 1
    return n, n


def measure(path, data):
    src = data.decode('utf-8', errors='replace')
    lines = src.count('\n')
    if path.endswith('.sol'):
        s, n = count_c(src)
    elif path.endswith('.rs'):
        s, n = count_c(src, rust=True)
    elif path.endswith('.py'):
        s, n = count_py(src)
    elif path.endswith(('.mjs', '.js', '.ts', '.tsx')):
        s, n = count_script(src, shell=False)
    elif path.endswith('.sh'):
        s, n = count_script(src, shell=True)
    else:
        s, n = '-', '-'
    return lines, s, n


def main():
    repo, commit, listfile = sys.argv[1:4]
    totals = {}
    for raw in open(listfile, encoding='utf-8'):
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue
        tier, path = raw.split(None, 1)
        data = subprocess.run(['git', '-C', repo, 'show', f'{commit}:{path}'],
                              check=True, capture_output=True).stdout
        lines, s, n = measure(path, data)
        digest = hashlib.sha256(data).hexdigest()
        print(f'{tier}\t{lines}\t{s}\t{n}\t{digest}\t{path}')
        t = totals.setdefault(tier, [0, 0, 0])
        t[0] += lines
        if isinstance(s, int):
            t[1] += s
            t[2] += n
    for tier, (l, s, n) in totals.items():
        print(f'# total {tier}\t{l}\t{s}\t{n}')


if __name__ == '__main__':
    main()
