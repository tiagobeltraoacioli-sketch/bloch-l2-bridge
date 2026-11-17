#!/usr/bin/env python3
"""Re-merge of the bridge lines into the all-networks tree. One command, repeatable:

  python3 tools/allnets/remerge.py            fetch, then merge every line whose published tip moved (lines.json order)
  python3 tools/allnets/remerge.py --status   what moved, nothing changed
  python3 tools/allnets/remerge.py --record   after a conflict was resolved by hand: remember the resolution and commit
  python3 tools/allnets/remerge.py --local    use the local branch refs instead of origin (never for a tree to publish)

What is merged: `origin/<branch>` of each line, i.e. what the line's developer has published (and scanned before the
push) - never an unpublished local commit of another agent (agent 375, round 18).

A conflict is resolved by a rule kept in this tree, never by a setting of the shared repository:
  1. `deployments/schema/bridge.network.schema.json`: the schema owner's version (the EVM-networks line) wins; every
     `bridge.network.json` is validated against it after the merge (registry.py), and mergecheck.py proves that every
     constraint of the other side's copy is present, unchanged, in the result.
  2. Any other file: a resolution recorded in `tools/allnets/resolutions/` under the SHA-256 of the conflicted text
     (markers included). The same conflict gets the same resolution; a different conflict (a line moved in the
     conflicted region) stops the merge for a person, with the files named.
  3. A tip whose TREE equals the tree of a commit already merged (the EVM audit line: one commit on cc2511a carrying the
     tree of a developer-line commit) is recorded with `git merge -s ours`: it brings no change, and the equality is
     checked by git (`git diff --quiet`) before, never assumed.
Before every merge commit: `mergecheck.py --staged` (no line or JSON constraint added by either side may be missing
from the staged result: the owner's standard forbids resolving a conflict by dropping one side's checks), the
`never` branches and the `forbiddenPaths` (no commit of a merged history may have touched them).
After every merge: `deployments/allnets/merge-lock.json` (line -> commit taken) and the registry
`deployments/bridges.json` are rewritten. Nothing is pushed. No branch other than the current one is written.
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
TRAILER = 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
LOCAL = '--local' in sys.argv

sys.path.insert(0, str(HERE))
import mergecheck  # noqa: E402


def git(*args, check=True):
    done = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True)
    if check and done.returncode:
        raise SystemExit(f'git {" ".join(args)}: {done.stderr.strip() or done.stdout.strip()}')
    return done.stdout.strip()


def ancestor(a, b):
    return subprocess.run(['git', 'merge-base', '--is-ancestor', a, b], cwd=ROOT).returncode == 0


def gitdir():
    return Path(git('rev-parse', '--absolute-git-dir'))


def lock():
    return json.loads(LOCK.read_text()) if LOCK.exists() else {'base': LINES['base'], 'lines': {}}


def ref(line):
    return line['branch'] if LOCAL else f'origin/{line["branch"]}'


def moved():
    out = []
    for line in LINES['lines']:
        tip = git('rev-parse', ref(line))
        out.append((line, tip, ancestor(tip, 'HEAD')))
    return out


def unmerged():
    return [p for p in git('diff', '--name-only', '--diff-filter=U').splitlines() if p]


def key(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def slot(path, digest):
    return HERE / 'resolutions' / (path.replace('/', '__') + '.' + digest[:16])


def refuse_history(line, tip):
    for name in LINES['never']:
        bad = git('rev-parse', '--verify', '--quiet', name, check=False)
        if bad and ancestor(bad, tip):
            raise SystemExit(f'{line["branch"]} contains {name}; refused')
    for path in LINES.get('forbiddenPaths', []):
        if git('rev-list', '-n', '1', tip, '--', path):
            raise SystemExit(f'{line["branch"]} at {tip[:7]} has {path} in its history; refused')


def same_tree_as_merged(tip):
    """A commit already in HEAD's history whose tree equals tip's tree (rule 3), or None."""
    tree = git('rev-parse', f'{tip}^{{tree}}')
    for entry in lock()['lines'].values():
        for c in [entry.get('commit')] + [h.get('commit') for h in entry.get('history', [])]:
            if c and ancestor(c, 'HEAD') and git('rev-parse', f'{c}^{{tree}}') == tree:
                return c
    return None


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


def finish(line, tip, resolved, how=None):
    lost = mergecheck.staged(tip)
    if lost:
        for p, x in lost:
            print(f'    {p}: line added by {x["side"]} {x["added"]}x, present {x["present"]}x: {x["line"].strip()[:160]}')
        git('merge', '--abort')  # never leave a half-merge behind: a later plain `git commit` would conclude it
        raise SystemExit(f'the staged merge of {line["id"]} {tip[:7]} loses {len(lost)} line(s) or constraint(s) of a side '
                         '(listed above); nothing was committed. Fix the resolution, or justify each in '
                         f'tools/allnets/merge-justifications.json under "staged:{tip}", then rerun.')
    state = lock()
    old = state['lines'].get(line['id'])
    history = (old.get('history', []) + [{k: old[k] for k in ('branch', 'commit') if k in old}]) if old else []
    state['lines'][line['id']] = {'branch': line['branch'], 'commit': tip, 'agent': line['agent'], 'routes': line['routes'],
                                  'conflicts': [{'path': p, 'resolution': h} for p, h in resolved],
                                  **({'rule': how} if how else {}), 'history': history}
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
            git('add', 'deployments/bridges.json', 'README.md')
    text = [f'Merge {line["id"]} line: {line["branch"]} at {tip[:7]}', '']
    if how:
        text += [how]
    text += [f'Conflict {p}: {h}' for p, h in resolved] or (['No textual conflict.'] if not how else [])
    text += ['Lost-change check (tools/allnets/mergecheck.py --staged): no line or JSON constraint of either side missing.']
    text += ['', TRAILER]
    git('commit', '--no-verify', '-m', '\n'.join(text))
    print(f'merged {line["id"]} {tip[:7]}: {len(resolved)} conflict(s) resolved by rule' + (f'; {how}' if how else ''))


def pending_file():
    return gitdir() / 'allnets-pending.json'


def main():
    mode = next((a for a in sys.argv[1:] if a != '--local'), 'merge')
    if not LOCAL and mode != '--record':
        git('fetch', '--quiet', 'origin')
    if mode == '--status':
        for line, tip, merged in moved():
            taken = lock()['lines'].get(line['id'], {}).get('commit', '')[:7] or '-'
            local = git('rev-parse', line['branch'])
            note = '' if local == tip else f' (local branch {local[:7]} differs from the published tip)'
            print(f'{line["id"]:13} {ref(line):55} tip {tip[:7]} taken {taken:7} {"merged" if merged else "MOVED"}{note}')
        return 0
    if mode == '--record':
        pend = json.loads(pending_file().read_text())
        if unmerged_markers := [p for p, _ in pend['left'] if b'<<<<<<< ' in (ROOT / p).read_bytes()]:
            raise SystemExit(f'conflict markers remain in {unmerged_markers}')
        for path, digest in pend['left']:
            kept = slot(path, digest)
            kept.parent.mkdir(parents=True, exist_ok=True)
            kept.write_bytes((ROOT / path).read_bytes())
            git('add', path, str(kept.relative_to(ROOT)))
            pend['resolved'].append([path, f'recorded resolution {kept.name}'])
        line = next(x for x in LINES['lines'] if x['id'] == pend['line'])
        finish(line, pend['tip'], [tuple(x) for x in pend['resolved']])
        pending_file().unlink()
        return main_merge()
    return main_merge()


def main_merge():
    if (gitdir() / 'MERGE_HEAD').exists():
        raise SystemExit('a merge is in progress (MERGE_HEAD exists); finish it with --record or `git merge --abort` first')
    if git('status', '--porcelain', '--untracked-files=no'):
        raise SystemExit('the worktree has uncommitted changes; commit them first')
    for name in LINES['never']:
        tip = git('rev-parse', '--verify', '--quiet', name, check=False)
        if tip and ancestor(tip, 'HEAD'):
            raise SystemExit(f'{name} is an ancestor of this branch; it must never be merged')
    for line, tip, merged in moved():
        if merged:
            continue
        refuse_history(line, tip)
        equal = same_tree_as_merged(tip)
        if equal:
            git('merge', '--no-ff', '--no-commit', '-s', 'ours', tip)
            finish(line, tip, [], how=f'Tree of {tip[:7]} equals the tree of {equal[:7]}, already merged (git rev-parse '
                                      f'{tip[:7]}^{{tree}} = {equal[:7]}^{{tree}}): recorded with -s ours, no content change.')
            continue
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
