#!/usr/bin/env python3
"""Lost-change check of the all-networks merges (agent 375, round 18). Standard library only.

  python3 tools/allnets/mergecheck.py [RANGE]      every merge commit in RANGE (default cc2511a..HEAD)
  python3 tools/allnets/mergecheck.py --commit M   one merge commit

Why: the integrator resolves conflicts between route lines that edit the same shared tools. The owner's standard
(BRIEF-ROUND18.md, "Standard of the work") forbids resolving a conflict by dropping one side's checks. This tool
proves it mechanically for every merge M with parents P1, P2 and merge base B:

  for every file changed by both sides, every line that P1 or P2 ADDED relative to B (the `+` lines of `git diff B Pi`)
  must occur in M's version of the file at least as many times as that side added it (multiset containment; blank
  lines and lines of only punctuation are ignored).

A JSON file (`*.json`, both sides and the result parse) is compared by meaning instead of by line: every leaf
(JSON path -> value; a list is one leaf; `description`, `title` and `$comment` are text, not constraints) that a side
added or changed relative to B must have the same value in M. This is the rule that proves the schema resolution
("the schema owner's version wins", remerge.py rule 1) lossless: an older copy of the schema carried by a route line
must have every one of its constraints present, unchanged, in the owner's version.

A missing line or leaf is printed with the side that added it. Every one must be justified in writing in
`tools/allnets/merge-justifications.json` ({"<merge commit>": {"<path>": {"<exact missing line or leaf>": "reason"}}});
the exit code is 1 while any is not justified. Files changed by one side only are taken whole by git and cannot lose a
line of that side; they are counted, not compared.

Limits (stated, not hidden): a line can be present but moved out of the function that needed it; a side's DELETION
that the resolution undid is not detected here (the regression check `regress.py` compares refusal and test counts
per file for that). The tool reads git objects only; it changes nothing.
"""
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
JUSTIFY = HERE / 'merge-justifications.json'
TRIVIAL = re.compile(r'^[\s{}()\[\];,.:]*$')


def git(*args):
    done = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f'git {" ".join(args)}: {done.stderr.strip()}')
    return done.stdout


def added_lines(base, side, path):
    out = Counter()
    for line in git('diff', '--no-color', '-U0', base, side, '--', path).splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            text = line[1:]
            if not TRIVIAL.match(text):
                out[text] += 1
    return out


INDEX = ':'  # the result of a merge staged with --no-commit (stage 0 of the index), checked before it is committed


def show(rev, path):
    return git('show', f':{path}' if rev == INDEX else f'{rev}:{path}')


def file_lines(commit, path):
    try:
        text = show(commit, path)
    except SystemExit:
        return Counter()  # deleted in the result
    return Counter(text.splitlines())


def changed(base, side):
    return set(p for p in git('diff', '--name-only', base, side).splitlines() if p)


TEXT_KEYS = ('description', 'title', '$comment')


def json_at(commit, path):
    """The parsed JSON of path at commit; {} when absent; None when present but not JSON."""
    try:
        text = show(commit, path)
    except SystemExit:
        return {}
    try:
        return json.loads(text)
    except ValueError:
        return None


def leaves(node, path=''):
    out = {}
    if isinstance(node, dict):
        for k, v in node.items():
            if k not in TEXT_KEYS:
                out.update(leaves(v, f'{path}/{k}'))
    else:
        out[path] = json.dumps(node, sort_keys=True)
    return out


def json_missing(base, sides, merge, path):
    """[(side name, 'leaf <path> = <value>', result value)] for every leaf a side set that the result lacks.
    None when the file is not JSON on every side (then lines are compared)."""
    docs = [json_at(c, path) for c in (base, *[s for s, _ in sides], merge)]
    if any(d is None for d in docs):
        return None
    b, result = leaves(docs[0]), leaves(docs[-1])
    out = []
    for (_, name), doc in zip(sides, docs[1:-1]):
        for k, v in leaves(doc).items():
            if b.get(k) != v and result.get(k) != v:
                out.append((name, f'leaf {k or "/"} = {v}', result.get(k)))
    return out


def check_merge(merge, parents=None):
    """merge: a commit, or INDEX with parents=(HEAD, the tip being merged)."""
    parents = parents or git('rev-list', '--parents', '-n', '1', merge).split()[1:]
    if len(parents) != 2:
        return None
    p1, p2 = parents
    base = git('merge-base', p1, p2).strip()
    both = sorted(changed(base, p1) & changed(base, p2))
    missing = {}
    for path in both:
        if path.endswith('.json'):
            found = json_missing(base, ((p1, 'ours'), (p2, 'theirs')), merge, path)
            if found is not None:
                for name, text, now in found:
                    missing.setdefault(path, []).append({'side': name, 'line': text, 'added': 1, 'present': 0,
                                                         'result': now})
                continue
        result = file_lines(merge, path)
        for side, name in ((p1, 'ours'), (p2, 'theirs')):
            for text, n in added_lines(base, side, path).items():
                if result[text] < n:
                    missing.setdefault(path, []).append({'side': name, 'line': text, 'added': n, 'present': result[text]})
    return {'merge': merge, 'parents': parents, 'base': base, 'filesChangedByBoth': len(both),
            'filesOneSide': len((changed(base, p1) | changed(base, p2)) - set(both)), 'missing': missing}


def staged(tip):
    """Missing lines of the merge of `tip` into HEAD as staged in the index (remerge.py calls this before committing).
    Returns the list of (path, entry) not justified in merge-justifications.json under the key 'staged:<tip>'."""
    res = check_merge(INDEX, (git('rev-parse', 'HEAD').strip(), git('rev-parse', tip).strip()))
    just = json.loads(JUSTIFY.read_text()) if JUSTIFY.exists() else {}
    ok = just.get(f'staged:{git("rev-parse", tip).strip()}', {})
    return [(p, x) for p, xs in res['missing'].items() for x in xs if x['line'] not in ok.get(p, {})]


def main(argv):
    if argv[:1] == ['--staged']:
        lost = staged(argv[1])
        for p, x in lost:
            print(f'    {p}: line added by {x["side"]} {x["added"]}x, present {x["present"]}x: {x["line"].strip()[:160]}')
        print(f'staged merge of {argv[1]}: {"OK" if not lost else f"LOST {len(lost)} line(s)"}')
        return 1 if lost else 0
    if argv[:1] == ['--commit']:
        merges = [git('rev-parse', argv[1]).strip()]
    else:
        rng = argv[0] if argv else 'cc2511a..HEAD'
        merges = git('rev-list', '--merges', '--reverse', rng).split()
    just = json.loads(JUSTIFY.read_text()) if JUSTIFY.exists() else {}
    bad = 0
    for m in merges:
        res = check_merge(m)
        if res is None:
            continue
        subject = git('log', '-1', '--format=%s', m).strip()
        lost = [(p, x) for p, xs in res['missing'].items() for x in xs]
        unjust = [(p, x) for p, x in lost
                  if x['line'] not in just.get(m, {}).get(p, {}) and x['line'] not in just.get(m[:7], {}).get(p, {})]
        state = 'OK' if not lost else ('JUSTIFIED' if not unjust else 'LOST')
        print(f'{m[:7]} {state:9} both-sides files {res["filesChangedByBoth"]:3}, one-side files {res["filesOneSide"]:4}, '
              f'missing lines {len(lost)} (unjustified {len(unjust)}): {subject}')
        for p, x in unjust:
            print(f'    {p}: line added by {x["side"]} {x["added"]}x, present {x["present"]}x: {x["line"].strip()[:160]}')
        bad += len(unjust)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
