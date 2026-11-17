#!/usr/bin/env python3
"""No-regression check of the merges by test and assertion counts (agent 375, round 18). Standard library; git only.

  python3 tools/allnets/regress.py [--against COMMIT ...]

The owner's standard (BRIEF-ROUND18.md, "Standard of the work", items 3 and 6): integrators refuse to merge a tree
whose test or assertion counts dropped without a written reason. mergecheck.py proves no ADDED line of a side is lost;
this proves the complementary property by count, per test file, between every merged line tip (from
deployments/allnets/merge-lock.json), the freeze cc2511a, and this tree (HEAD):

  Solidity (`solidity-tests/**/*.sol`): functions named test*, testFuzz*, invariant*; and assertion calls
    (assert*, vm.expectRevert, require) inside the file.
  Python (`tools/**/test_*.py`, `tools/**/rehearse_*.py`, `scripts/tests/**/*.py`): methods named test* (AST), and
    assertion calls (self.assert*, assert statements, check(...) / ok(...) calls of the rehearsal drivers).

For every file present in a base, HEAD must have the file and at least as many tests and assertions as that base.
A drop prints the file and both counts; exit 1 while any drop is not justified in
tools/allnets/merge-justifications.json under "regress:<path>" (the reason, and which test now carries the property).
Limits (stated): counts are a proxy (a weakened assertion with the same count is not caught here; reviewers read the
diffs), and a test moved to another file shows as a drop in the old file plus a rise elsewhere (justify it).
"""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
JUSTIFY = HERE / 'merge-justifications.json'
SOL_TEST = re.compile(r'\bfunction\s+(test\w*|invariant\w*)\s*\(')
SOL_ASSERT = re.compile(r'\b(assert\w*|vm\.expectRevert|require)\s*\(')
PY_GLOBS = ('tools/', 'scripts/tests/')


def git(*a):
    return subprocess.run(['git', *a], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def files(commit):
    out = []
    for p in git('ls-tree', '-r', '--name-only', commit).splitlines():
        if p.startswith('solidity-tests/') and p.endswith('.sol'):
            out.append(p)
        elif p.endswith('.py') and p.startswith(PY_GLOBS) and (Path(p).name.startswith(('test_', 'rehearse_')) or p.startswith('scripts/tests/')):
            out.append(p)
    return out


def count(commit, path):
    text = git('show', f'{commit}:{path}')
    if path.endswith('.sol'):
        return len(SOL_TEST.findall(text)), len(SOL_ASSERT.findall(text))
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return 0, 0
    tests = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test') for n in ast.walk(tree))
    asserts = 0
    for n in ast.walk(tree):
        if isinstance(n, ast.Assert):
            asserts += 1
        elif isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ''
            if name.startswith('assert') or name in ('check', 'ok', 'expect', 'must'):
                asserts += 1
    return tests, asserts


def main(argv):
    lock = json.loads((ROOT / 'deployments/allnets/merge-lock.json').read_text())['lines']
    bases = [('freeze', 'cc2511a')] + [(n, e['commit']) for n, e in lock.items()]
    if '--against' in argv:
        bases = [(c, c) for c in argv[argv.index('--against') + 1:]]
    just = json.loads(JUSTIFY.read_text()) if JUSTIFY.exists() else {}
    head_files = set(files('HEAD'))
    cache, drops, compared = {}, 0, 0
    for name, commit in bases:
        for path in files(commit):
            compared += 1
            b = count(commit, path)
            if path not in head_files:
                h = (0, 0)
            else:
                h = cache.setdefault(path, count('HEAD', path))
            if h[0] < b[0] or h[1] < b[1]:
                ok = f'regress:{path}' in just
                print(f'{"JUSTIFIED" if ok else "DROP"} {path}: {name} {commit[:7]} tests {b[0]} asserts {b[1]} -> HEAD tests {h[0]} asserts {h[1]}')
                drops += not ok
    total = [sum(cache.setdefault(p, count('HEAD', p))[i] for p in head_files) for i in (0, 1)]
    print(f'{compared} (base, file) pairs compared over {len(bases)} bases; HEAD has {len(head_files)} test files, '
          f'{total[0]} tests, {total[1]} assertions; {drops} unjustified drop(s)')
    return 1 if drops else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
