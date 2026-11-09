#!/usr/bin/env python3
"""Count lines, SLOC and nSLOC for Solidity/Rust (C-style comments) and Python files.
SLOC: non-blank lines after removing comments (and Python docstrings).
nSLOC: SLOC with multi-line constructs collapsed: a line is joined to the previous one while
an opening ( or [ is unclosed (C-style), or while Python's tokenizer is inside a logical line.
Rust: everything from the first top-level `#[cfg(test)]` on is excluded (inline tests)."""
import io, re, sys, tokenize

def strip_c(src):
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('//', i):
            j = src.find('\n', i); i = n if j < 0 else j
        elif src.startswith('/*', i):
            j = src.find('*/', i + 2); seg = src[i:(n if j < 0 else j + 2)]
            out.append('\n' * seg.count('\n')); i = n if j < 0 else j + 2
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            out.append(src[i:j + 1]); i = j + 1
        else:
            out.append(c); i += 1
    return ''.join(out)

def count_c(src, rust=False):
    if rust:
        m = re.search(r'^#\[cfg\(test\)\]', src, re.M)
        if m: src = src[:m.start()]
    s = strip_c(src)
    lines = [l for l in s.split('\n') if l.strip()]
    sloc = len(lines); nsloc = 0; depth = 0
    for l in lines:
        if depth <= 0: nsloc += 1
        depth += l.count('(') + l.count('[') - l.count(')') - l.count(']')
        if depth < 0: depth = 0
    return sloc, nsloc

def count_py(src):
    toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    code_lines, logical_starts = set(), set()
    prev = tokenize.INDENT; start_logical = True
    for t in toks:
        if t.type in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER, tokenize.ENCODING):
            if t.type == tokenize.NEWLINE: start_logical = True
            prev = t.type; continue
        if t.type == tokenize.STRING and start_logical and prev in (tokenize.INDENT, tokenize.DEDENT, tokenize.NEWLINE, tokenize.NL):
            # docstring or bare string statement: skip
            prev = t.type; continue
        for ln in range(t.start[0], t.end[0] + 1): code_lines.add(ln)
        if start_logical: logical_starts.add(t.start[0]); start_logical = False
        prev = t.type
    return len(code_lines), len(logical_starts)

for p in sys.argv[1:]:
    src = open(p, encoding='utf-8').read()
    total = src.count('\n')
    if p.endswith('.py'): s, n = count_py(src)
    else: s, n = count_c(src, rust=p.endswith('.rs'))
    print(f"{p}\t{total}\t{s}\t{n}")
