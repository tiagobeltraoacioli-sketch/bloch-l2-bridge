#!/usr/bin/env python3
"""Round 20: the route-file identity check with recorded integration changes: python3 -m unittest test_identity_r20.

`test_all.py --identity` holds every path a route line owns to that line's merged tip, byte for byte. Round 20 changes
line-owned files in the integration tree (the launch limits of 2026-11-19 in tools/evm-nets, the three networks'
deployment files and the owner's ceremony kit). Such a change is recorded in
deployments/allnets/integration-changes.json with the git blob of the file, and the check holds the file to that blob.

The cases run on a throwaway git repository (a line tip, then the integration's HEAD): no file of this tree is touched.
The last class runs the check on this tree itself.
"""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import test_all  # noqa: E402

OWNED = {'evm': ['tools/evm', 'deployments/arb'], 'kit': ['docs/KIT.md']}


def git(root, *argv):
    done = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', *argv],
                          cwd=root, capture_output=True, text=True)
    if done.returncode:
        raise AssertionError(done.stderr)
    return done.stdout.strip()


class Rig:
    """A repository with two lines merged at one tip, then one integration commit made by `change(root)`."""

    def __init__(self, tmp, change, record=None):
        self.root = Path(tmp)
        git(self.root, 'init', '-q', '.')
        for rel, text in (('tools/evm/a.py', 'a = 1\n'), ('tools/evm/b.py', 'b = 1\n'), ('deployments/arb/net.json', '{"cap": 1}\n'),
                          ('docs/KIT.md', 'kit\n'), ('README.md', 'readme\n')):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text(text)
        git(self.root, 'add', '-A')
        git(self.root, 'commit', '-q', '-m', 'line tips')
        self.tip = git(self.root, 'rev-parse', 'HEAD')
        (self.root / 'deployments/allnets').mkdir(parents=True)
        (self.root / 'deployments/allnets/merge-lock.json').write_text(json.dumps(
            {'lines': {'evm': {'commit': self.tip}, 'kit': {'commit': self.tip}}}))
        change(self.root)
        git(self.root, 'add', '-A')
        git(self.root, 'commit', '-q', '-m', 'integration')
        if record is not None:
            self.write(record(self))
            git(self.root, 'add', '-A')
            git(self.root, 'commit', '-q', '-m', 'record')

    def blob(self, rel):
        return git(self.root, 'rev-parse', f'HEAD:{rel}')

    def rec(self, line, rel, **over):
        return {'line': line, 'path': rel, 'lineTip': self.tip, 'blob': self.blob(rel), 'decision': 'limits', **over}

    def write(self, changes, decisions=None, **extra):
        doc = {'domain': 'bloch.bridge.allnets.integration-changes.v1', 'note': 'test',
               'decisions': {'limits': 'the launch limits decided by the coordinator on 2026-11-19'} if decisions is None else decisions,
               'changes': changes, **extra}
        (self.root / test_all.CHANGES).write_text(json.dumps(doc))

    def check(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                rc = test_all.identity(self.root, OWNED)
            except SystemExit as e:
                return 2, str(e)
        return rc, buf.getvalue()


def edit_a(root):
    (root / 'tools/evm/a.py').write_text('a = 2\n')


def edit_a_and_net(root):
    edit_a(root)
    (root / 'deployments/arb/net.json').write_text('{"cap": 5}\n')


class Identity(unittest.TestCase):
    def rig(self, change, record=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Rig(tmp.name, change, record)

    def test_an_untouched_tree_passes_with_and_without_the_file(self):
        r = self.rig(lambda root: None)
        self.assertEqual(r.check()[0], 0)
        r = self.rig(lambda root: None, lambda r: [])
        self.assertEqual(r.check()[0], 0)

    def test_a_file_outside_every_owned_path_is_not_this_checks_business(self):
        r = self.rig(lambda root: (root / 'README.md').write_text('changed\n'))
        self.assertEqual(r.check()[0], 0)

    def test_an_unrecorded_difference_fails_as_before(self):
        rc, text = self.rig(edit_a).check()
        self.assertEqual(rc, 1)
        self.assertIn('tools/evm/a.py: DIFFERS from', text)
        self.assertIn('no integration change is recorded', text)
        # a record of ANOTHER file does not cover it
        r = self.rig(edit_a_and_net, lambda r: [r.rec('evm', 'deployments/arb/net.json')])
        rc, text = r.check()
        self.assertEqual(rc, 1)
        self.assertIn('tools/evm/a.py: DIFFERS from', text)

    def test_recorded_changes_pass_and_are_printed(self):
        r = self.rig(edit_a_and_net, lambda r: [r.rec('evm', 'tools/evm/a.py'), r.rec('evm', 'deployments/arb/net.json')])
        rc, text = r.check()
        self.assertEqual(rc, 0, text)
        self.assertIn('tools/evm/a.py: integration change, blob', text)
        self.assertIn('1 file(s) differ from', text)
        self.assertIn('docs/KIT.md', text)
        self.assertIn('0 identity failure(s)', text)

    def test_a_recorded_file_that_drifts_after_its_record_fails(self):
        r = self.rig(edit_a, lambda r: [r.rec('evm', 'tools/evm/a.py')])
        self.assertEqual(r.check()[0], 0)
        (r.root / 'tools/evm/a.py').write_text('a = 3\n')
        git(r.root, 'commit', '-q', '-am', 'drift')
        rc, text = r.check()
        self.assertEqual(rc, 1)
        self.assertIn('DIFFERS from the recorded blob', text)

    def test_wrong_records_fail(self):
        cases = {
            'a wrong blob': (lambda r: [r.rec('evm', 'tools/evm/a.py', blob='0' * 40)], 'DIFFERS from the recorded blob'),
            'the blob of the line tip': (lambda r: [r.rec('evm', 'tools/evm/a.py', blob=git(r.root, 'rev-parse', f'{r.tip}:tools/evm/a.py'))],
                                         'DIFFERS from the recorded blob'),
            'another tip': (lambda r: [r.rec('evm', 'tools/evm/a.py', lineTip='1' * 40)], 'record again after a re-merge'),
            'a stale record': (lambda r: [r.rec('evm', 'tools/evm/a.py'), r.rec('evm', 'tools/evm/b.py')], 'stale record'),
            'the wrong line': (lambda r: [r.rec('kit', 'tools/evm/a.py')], 'not a path that line owns'),
            'an unknown line': (lambda r: [r.rec('other', 'tools/evm/a.py')], 'not a path that line owns'),
            'a path no line owns': (lambda r: [r.rec('evm', 'tools/evm/a.py'), r.rec('evm', 'README.md')], 'not a path that line owns'),
            'a path that only starts like an owned one': (lambda r: [r.rec('evm', 'tools/evm/a.py'), {'line': 'evm', 'path': 'tools/evm-other/a.py', 'lineTip': r.tip, 'blob': '2' * 40, 'decision': 'limits'}],
                                                          'not a path that line owns'),
            'an unknown decision': (lambda r: [r.rec('evm', 'tools/evm/a.py', decision='because')], 'is not stated in `decisions`'),
            'the same file twice': (lambda r: [r.rec('evm', 'tools/evm/a.py'), r.rec('evm', 'tools/evm/a.py')], 'recorded twice'),
        }
        for what, (record, needle) in cases.items():
            rc, text = self.rig(edit_a, record).check()
            self.assertEqual(rc, 1, what)
            self.assertIn(needle, text, what)

    def test_a_removed_file_cannot_be_recorded(self):
        r = self.rig(lambda root: (root / 'tools/evm/b.py').unlink(),
                     lambda r: [{'line': 'evm', 'path': 'tools/evm/b.py', 'lineTip': r.tip, 'blob': '3' * 40, 'decision': 'limits'}])
        rc, text = r.check()
        self.assertEqual(rc, 1)
        self.assertIn('removed from the tree', text)

    def test_a_new_file_under_an_owned_path_must_be_recorded_too(self):
        add = lambda root: (root / 'tools/evm/new.py').write_text('n = 1\n')  # noqa: E731
        rc, text = self.rig(add).check()
        self.assertEqual(rc, 1)
        self.assertIn('tools/evm/new.py: DIFFERS', text)
        self.assertEqual(self.rig(add, lambda r: [r.rec('evm', 'tools/evm/new.py')]).check()[0], 0)

    def test_the_file_is_read_fail_closed(self):
        r = self.rig(edit_a, lambda r: [r.rec('evm', 'tools/evm/a.py')])
        good = json.loads((r.root / test_all.CHANGES).read_text())
        shapes = {
            'not JSON': '{not json',
            'a list': '[]',
            'an unknown top-level key': json.dumps({**good, 'allow': ['tools/evm']}),
            'no decisions': json.dumps({k: v for k, v in good.items() if k != 'decisions'}),
            'changes not a list': json.dumps({**good, 'changes': {}}),
            'a decision without text': json.dumps({**good, 'decisions': {'limits': ''}}),
            'an entry with a key more': json.dumps({**good, 'changes': [{**good['changes'][0], 'anyBlob': True}]}),
            'an entry with a key less': json.dumps({**good, 'changes': [{k: v for k, v in good['changes'][0].items() if k != 'blob'}]}),
            'an empty blob': json.dumps({**good, 'changes': [{**good['changes'][0], 'blob': ''}]}),
            'a blob that is not text': json.dumps({**good, 'changes': [{**good['changes'][0], 'blob': None}]}),
            'a wildcard path': json.dumps({**good, 'changes': [{**good['changes'][0], 'path': 'tools/evm'}]}),
        }
        for what, text in shapes.items():
            (r.root / test_all.CHANGES).write_text(text)
            rc, out = r.check()
            self.assertNotEqual(rc, 0, what)

    def test_there_is_no_wildcard_flag_or_environment_variable(self):
        src = (HERE / 'test_all.py').read_text()
        body = src[src.index('def owned_differences'):src.index('def identity_record')]
        self.assertFalse('os.environ' in body or 'getenv' in body or 'fnmatch' in body or 'glob' in body)
        self.assertIn("'--no-renames'", body)


class ThisTree(unittest.TestCase):
    def test_the_recorded_changes_of_this_tree_are_exact_and_only_what_round_20_decided(self):
        doc = test_all.load_changes(ROOT)
        self.assertEqual(set(doc['decisions']), {'launch-limits-2026-11-19'})
        for text in ('2026-11-19', 'owner', 'coordinator', '500,000', '250,000', 'audit'):
            self.assertIn(text, doc['decisions']['launch-limits-2026-11-19'], text)
        lock = json.loads((ROOT / 'deployments/allnets/merge-lock.json').read_text())['lines']
        by_line = {}
        for c in doc['changes']:
            self.assertEqual(c['lineTip'], lock[c['line']]['commit'], c['path'])
            self.assertRegex(c['blob'], r'^[0-9a-f]{40}$')
            by_line.setdefault(c['line'], set()).add(c['path'])
        # only the EVM-network line and the ceremony kit; never a held route's line, never Base or BNB
        self.assertEqual(set(by_line), {'evm-nets', 'ceremony'})
        for path in by_line['evm-nets']:
            self.assertTrue(path.startswith(('tools/evm-nets/', 'deployments/arbitrum-one/', 'deployments/op-mainnet/',
                                             'deployments/linea/')), path)
            self.assertFalse(path.startswith(('deployments/base', 'deployments/bnb')), path)
        for must in ('tools/evm-nets/networks.json', 'tools/evm-nets/launch.py', 'tools/evm-nets/evm_nets.py',
                     'deployments/arbitrum-one/busdc-vault.config.json', 'deployments/op-mainnet/busdc-token.config.json',
                     'deployments/linea/bridge.network.json'):
            self.assertIn(must, by_line['evm-nets'], must)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = test_all.identity()
        self.assertEqual(rc, 0, buf.getvalue())
        for line in ('bitcoin', 'tron', 'solana', 'stellar', 'operator-pkg'):
            for p in test_all.OWNED[line]:
                self.assertRegex(buf.getvalue(), rf'{line}\s+{p}\s+identical to ', (line, p))
        for p in ('deployments/base', 'deployments/bnb'):
            self.assertRegex(buf.getvalue(), rf'evm-nets\s+{p}\s+identical to ', p)


if __name__ == '__main__':
    unittest.main()
