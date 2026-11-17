#!/usr/bin/env python3
"""Re-merge of the bridge lines into the all-networks tree. One command, repeatable:

  python3 tools/allnets/remerge.py            merge every line whose tip moved (tools/allnets/lines.json, in order)
  python3 tools/allnets/remerge.py --status   what moved, nothing changed
  python3 tools/allnets/remerge.py --record   after a conflict was resolved by hand: remember the resolution and commit

A conflict is resolved by a rule kept in this tree, never by a setting of the shared repository:
  1. `deployments/schema/bridge.network.schema.json`: the schema owner's version (the EVM-networks line) wins; every
     `bridge.network.json` is validated against it after the merge, so a line that needs a property the owner's schema
     lacks stops the merge here.
  2. Any other file: a resolution recorded in `tools/allnets/resolutions/` under the SHA-256 of the conflicted text
     (markers included). The same conflict gets the same resolution; a different conflict (a line moved in the
     conflicted region) stops the merge for a person, with the files named.
After every merge: `deployments/allnets/merge-lock.json` (branch -> commit taken) and the registry
`deployments/bridges.json` are rewritten and the quick checks run (`registry.py check`).
Nothing is pushed. No branch other than the current one is written.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LINES = json.loads((HERE / 'lines.json').read_text())
SCHEMA = 'deployments/schema/bridge.network.schema.json'
SCHEMA_OWNER = 'evm-nets'
LOCK = ROOT / 'deployments/allnets/merge-lock.json'
TRAILER = 'Co-Authored-By: Claude Mythos 5.2 <noreply@anthropic.com>'


def git(*args, check=True):
    done = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True)
    if check and done.returncode:
        raise SystemExit(f'git {" ".join(args)}: {done.stderr.strip() or done.stdout.strip()}')
    return done.stdout.strip()


def gitdir():
    return Path(git('rev-parse', '--absolute-git-dir'))


def lock():
    return json.loads(LOCK.read_text()) if LOCK.exists() else {'base': LINES['base'], 'lines': {}}


def moved():
    out = []
    for line in LINES['lines']:
        tip = git('rev-parse', line['branch'])
        merged = subprocess.run(['git', 'merge-base', '--is-ancestor', tip, 'HEAD'], cwd=ROOT).returncode == 0
        out.append((line, tip, merged))
    return out


def unmerged():
    return [p for p in git('diff', '--name-only', '--diff-filter=U').splitlines() if p]


def key(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def slot(path, digest):
    return HERE / 'resolutions' / (path.replace('/', '__') + '.' + digest[:16])


def resolve(line):
    """Apply the rules. Returns (resolved, left): lists of (path, how)."""
    resolved, left = [], []
    for path in unmerged():
        if path == SCHEMA:
            side = '--theirs' if line['id'] == SCHEMA_OWNER else '--ours'
            git('checkout', side, '--', path)
            git('add', path)
            resolved.append((path, f'schema owner\'s version ({"theirs" if side == "--theirs" else "ours"})'))
            continue
        digest = key(path)
        kept = slot(path, digest)
        if kept.exists():
            (ROOT / path).write_bytes(kept.read_bytes())
            git('add', path)
            resolved.append((path, f'recorded resolution {kept.name}'))
        else:
            left.append((path, digest))
    return resolved, left


def finish(line, tip, resolved):
    state = lock()
    state['lines'][line['id']] = {'branch': line['branch'], 'commit': tip, 'agent': line['agent'], 'routes': line['routes'],
                                  'conflicts': [{'path': p, 'resolution': how} for p, how in resolved]}
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    LOCK.write_text(json.dumps(state, indent=2) + '\n')
    git('add', str(LOCK.relative_to(ROOT)))
    registry = HERE / 'registry.py'
    if registry.exists():
        done = subprocess.run([sys.executable, str(registry), 'write'], cwd=ROOT, capture_output=True, text=True)
        if done.returncode:
            print(f'registry.py write refused after merging {line["id"]} (the merge is committed; fix, then rerun):\n'
                  f'{done.stdout}{done.stderr}')
        else:
            git('add', 'deployments/bridges.json')
    text = [f'Merge {line["id"]} line: {line["branch"]} at {tip[:7]}', '']
    text += [f'Conflict {p}: {how}' for p, how in resolved] or ['No textual conflict.']
    text += ['', TRAILER]
    git('commit', '--no-verify', '-m', '\n'.join(text))
    print(f'merged {line["id"]} {tip[:7]}: {len(resolved)} conflict(s) resolved by rule')


def pending_file():
    return gitdir() / 'allnets-pending.json'


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'merge'
    if mode == '--status':
        for line, tip, merged in moved():
            taken = lock()['lines'].get(line['id'], {}).get('commit', '')[:7] or '-'
            dirty = ''
            print(f'{line["id"]:13} {line["branch"]:45} tip {tip[:7]} taken {taken:7} {"merged" if merged else "MOVED"}{dirty}')
        return 0
    if mode == '--record':
        pend = json.loads(pending_file().read_text())
        if unmerged_markers := [p for p, _ in pend['left'] if b'<<<<<<< ' in (ROOT / p).read_bytes()]:
            raise SystemExit(f'conflict markers remain in {unmerged_markers}')
        for path, digest in pend['left']:
            kept = slot(path, digest)
            kept.write_bytes((ROOT / path).read_bytes())
            git('add', path, str(kept.relative_to(ROOT)))
            pend['resolved'].append([path, f'recorded resolution {kept.name}'])
        line = next(x for x in LINES['lines'] if x['id'] == pend['line'])
        finish(line, pend['tip'], [tuple(x) for x in pend['resolved']])
        pending_file().unlink()
        return main_merge()
    return main_merge()


def main_merge():
    if git('status', '--porcelain', '--untracked-files=no'):
        raise SystemExit('the worktree has uncommitted changes; commit them first')
    for name in LINES['never']:
        tip = git('rev-parse', '--verify', '--quiet', name, check=False)
        if tip and subprocess.run(['git', 'merge-base', '--is-ancestor', tip, 'HEAD'], cwd=ROOT).returncode == 0:
            raise SystemExit(f'{name} is an ancestor of this branch; it must never be merged')
    for line, tip, merged in moved():
        if merged:
            continue
        for name in LINES['never']:
            bad = git('rev-parse', '--verify', '--quiet', name, check=False)
            if bad and subprocess.run(['git', 'merge-base', '--is-ancestor', bad, tip], cwd=ROOT).returncode == 0:
                raise SystemExit(f'{line["branch"]} contains {name}; refused')
        subprocess.run(['git', '-c', 'rerere.enabled=false', 'merge', '--no-ff', '--no-commit', tip], cwd=ROOT,
                       capture_output=True, text=True)
        resolved, left = resolve(line)
        if left:
            pending_file().write_text(json.dumps({'line': line['id'], 'tip': tip, 'left': left, 'resolved': resolved}))
            print(f'STOPPED at {line["id"]} {tip[:7]}: resolve by hand, then `python3 tools/allnets/remerge.py --record`')
            for path, digest in left:
                print(f'  {path} (conflict {digest[:16]})')
            return 1
        finish(line, tip, resolved)
    print('every line is merged at its current tip')
    return 0


if __name__ == '__main__':
    sys.exit(main())
