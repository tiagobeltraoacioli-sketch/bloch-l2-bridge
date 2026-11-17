"""Round 17: the index directory has one writer, and nothing on disk is believed on load (review R325-TRX-2P-1).
Run: python3 -m unittest test_tron_index_r17 -v   (in tools/signatario-tron).
The reviewer's own demonstration is test_review_r16_tron_2p.py, kept unchanged; these tests cover what it cannot:
a second PROCESS, a directory that was already corrupted before the lock existed, and a crash of the lock holder."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

import tron_log_index as li
from test_review_r16_tron_2p import Chain, VAULT, index

HERE = Path(__file__).resolve().parent
OTHER = textwrap.dedent('''
    import sys, time
    sys.path.insert(0, %r)
    import tron_log_index as li
    from test_review_r16_tron_2p import Chain, index
    idx = index(Chain(60, deposits=[10, 40]), sys.argv[1])
    print('opened', flush=True)
    if sys.argv[2] == 'hold':
        time.sleep(600)
    idx.advance(4000)
    print('advanced', idx.verified, idx.deposits, flush=True)
''') % str(HERE)


def deposit_nonces(idx):
    return [int(l['data'][2:66], 16) for l in idx.logs if l['topics'][:1] == [li.DEPOSITED]]


def quiet(fn, *args):
    """Run `fn` and return (result, what it wrote to stderr): the rebuild alert is one JSON line there."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = fn(*args)
    return out, err.getvalue()


class OneWriter(unittest.TestCase):
    def test_a_second_process_on_the_same_directory_is_refused_with_the_holders_pid(self):
        with tempfile.TemporaryDirectory() as d:
            holder = subprocess.Popen([sys.executable, '-c', OTHER, d, 'hold'], stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(holder.stdout.readline().strip(), 'opened')
                # another process: refused before it reads or writes anything
                second = subprocess.run([sys.executable, '-c', OTHER, d, 'run'], capture_output=True, text=True)
                self.assertNotEqual(second.returncode, 0)
                self.assertIn('in use by another process', second.stderr)
                self.assertIn(f'pid {holder.pid}', second.stderr)
                self.assertNotIn('opened', second.stdout)
                self.assertFalse((Path(d) / 'cursor.json').exists())   # the refused process wrote nothing
                # this process too
                with self.assertRaises(SystemExit) as e:
                    index(Chain(60, deposits=[10, 40]), d)
                self.assertIn('one shim per index directory', str(e.exception))
            finally:
                holder.kill()
                holder.wait()
            # the holder died without any cleanup: the kernel released the lock, the directory opens at once
            third = subprocess.run([sys.executable, '-c', OTHER, d, 'run'], capture_output=True, text=True)
            self.assertEqual((third.returncode, third.stdout.split()), (0, ['opened', 'advanced', '60', '2']), third.stderr)

    def test_the_lock_is_held_for_the_life_of_the_object_and_released_by_close(self):
        with tempfile.TemporaryDirectory() as d:
            a = index(Chain(60, deposits=[10, 40]), d)
            blocked = subprocess.run([sys.executable, '-c', OTHER, d, 'run'], capture_output=True, text=True)
            self.assertIn('in use by another process', blocked.stderr)
            self.assertIn(f'pid {os.getpid()}', blocked.stderr)
            a.advance(4000)
            blocked = subprocess.run([sys.executable, '-c', OTHER, d, 'run'], capture_output=True, text=True)
            self.assertNotEqual(blocked.returncode, 0)          # still held after work was done
            a.close()
            free = subprocess.run([sys.executable, '-c', OTHER, d, 'run'], capture_output=True, text=True)
            self.assertEqual(free.returncode, 0, free.stderr)

    def test_a_stale_writer_in_the_same_process_reloads_instead_of_appending(self):
        chain = Chain(60, deposits=[10, 40])
        with tempfile.TemporaryDirectory() as d:
            a, b = index(chain, d), index(chain, d)
            chain.height = 20
            a.advance(4000)
            chain.height = 60
            b.advance(4000)
            self.assertEqual((b.stats['reloads'], deposit_nonces(b), b.verified), (1, [0, 1], 60))
            lines = (Path(d) / 'logs.jsonl').read_text().splitlines()
            self.assertEqual(len(lines), 2)                     # never the same deposit twice on disk
            # the writer that fell behind serves nothing stale: its query is an error until its next round reloads
            with self.assertRaises(li.Behind):
                a.query(1, 20, [li.DEPOSITED])
            a.advance(4000)
            self.assertEqual((deposit_nonces(a), a.verified, len(a.query(1, 60, [li.DEPOSITED]))), ([0, 1], 60, 2))
            a.close()
            b.close()


class NothingOnDiskIsBelieved(unittest.TestCase):
    """Directories as the round-16 code could leave them (two shims, one directory), and other damage."""

    def built(self, d):
        chain = Chain(60, deposits=[10, 40])
        idx = index(chain, d)
        idx.advance(4000)
        self.assertEqual((deposit_nonces(idx), idx.verified), ([0, 1], 60))
        idx.close()
        return chain

    def reopen(self, chain, d):
        idx, err = quiet(index, chain, d)
        return idx, err

    def assert_rebuilt(self, chain, d, word):
        idx, err = self.reopen(chain, d)
        alert = json.loads(err.strip().splitlines()[-1])
        self.assertEqual((alert['kind'], alert['severity'], alert['component']), ('alert', 'critical', 'tron-log-index'))
        self.assertIn(word, alert['reason'])
        # nothing from the damaged files is served: the index is empty and unverified until it has read the chain again
        self.assertEqual((idx.logs, idx.deposits, idx.verified, idx.cursor, idx.stats['rebuilds']), ([], 0, 0, 0, 1))
        with self.assertRaises(li.Behind):
            idx.query(1, 60, [li.DEPOSITED])
        idx.advance(4000)
        self.assertEqual((deposit_nonces(idx), idx.verified, idx.deposits), ([0, 1], 60, 2))
        idx.close()
        again, err = self.reopen(chain, d)                     # and the rebuilt directory is a good one
        self.assertEqual((err, again.stats['rebuilds'], deposit_nonces(again), again.verified), ('', 0, [0, 1], 60))
        again.close()

    def edit(self, d, logs=None, cursor=None, rebind=True):
        """Damage as a writer that also rewrites the cursor coherently would leave it. Format 2 (round 18, R342-TRX-2):
        such a writer also names the new byte length and sha256 (`rebind`), so the checks INSIDE the file are still the
        ones tested here; with rebind=False the cursor's binding of the file is what must catch it."""
        import hashlib
        p, c = Path(d) / 'logs.jsonl', Path(d) / 'cursor.json'
        lines = p.read_text().splitlines()
        cur = json.loads(c.read_text())
        if logs:
            lines = logs(lines)
            p.write_text(''.join(x + '\n' for x in lines))
            cur['lines'] = len(lines)
            if rebind:
                data = p.read_bytes()
                cur['bytes'], cur['sha256'] = len(data), hashlib.sha256(data).hexdigest()
        if cursor:
            cursor(cur)
        c.write_text(json.dumps(cur) + '\n')

    def test_the_reviewers_corruption_one_deposit_twice_and_one_missing_is_rebuilt(self):
        # what 51c1d4d demonstrated on disk: deposits [0, 0], "verified" to the tip, stored count 2
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            self.edit(d, logs=lambda l: [l[0], l[0]])
            self.assert_rebuilt(chain, d, 'carry nonces [0, 0]')

    def test_a_stored_count_that_is_not_the_recount_is_rebuilt(self):
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            self.edit(d, logs=lambda l: l[:1], cursor=lambda c: c.update(deposits=2))   # one log, "2 deposits", verified
            self.assert_rebuilt(chain, d, 'cursor counts 2 deposits, the logs hold 1')

    def test_a_missing_first_deposit_a_gap_and_a_wrong_order_are_rebuilt(self):
        for change, word in ((lambda l: l[1:], 'carry nonces [1]'), (lambda l: [l[1], l[0]], 'carry nonces [1, 0]')):
            with tempfile.TemporaryDirectory() as d:
                chain = self.built(d)
                self.edit(d, logs=change, cursor=lambda c: c.update(deposits=c['lines']))
                self.assert_rebuilt(chain, d, word)

    def test_a_truncated_or_torn_file_is_rebuilt_not_left_for_a_person(self):
        # Restated in round 18: the cursor now binds the file by byte length and sha256, so a file shortened under an
        # intact cursor is caught by that first; the round-17 checks behind it (line count, unreadable line) are kept
        # and reached by a cursor rewritten coherently (rebind).
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            p = Path(d) / 'logs.jsonl'
            p.write_text(p.read_text().splitlines()[0] + '\n')                       # a line lost; the cursor still names 2
            self.assert_rebuilt(chain, d, 'the cursor names')
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            self.edit(d, logs=lambda l: l[:1], cursor=lambda c: c.update(lines=2))     # bytes rebound, the line count is not
            self.assert_rebuilt(chain, d, 'holds 1 lines, the cursor names 2')
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            p = Path(d) / 'logs.jsonl'
            p.write_text(p.read_text()[:-40] + '\n')                                # the last line torn
            self.assert_rebuilt(chain, d, 'the cursor names')
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            self.edit(d, logs=lambda l: l[:-1] + [l[-1][:-40]])                     # torn, and the cursor rebound to it
            self.assert_rebuilt(chain, d, 'cannot be read as an index')
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            (Path(d) / 'cursor.json').write_text('{"version": 1, ')
            self.assert_rebuilt(chain, d, 'not JSON')

    def test_logs_above_the_cursor_or_a_verified_mark_above_the_cursor_are_rebuilt(self):
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            self.edit(d, cursor=lambda c: c.update(cursor=30))                       # a log of block 40 above the cursor
            self.assert_rebuilt(chain, d, 'not in block order below the cursor')
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            self.edit(d, cursor=lambda c: c.update(verified=10**9))
            self.assert_rebuilt(chain, d, 'not in block order below the cursor')

    def test_a_good_directory_is_loaded_without_reading_the_chain_again(self):
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            before = sum(chain.requests.values())
            idx, err = self.reopen(chain, d)
            self.assertEqual((err, idx.stats['rebuilds'], deposit_nonces(idx), idx.verified, sum(chain.requests.values()) - before),
                             ('', 0, [0, 1], 60, 0))
            idx.close()

    def test_another_vaults_directory_is_still_refused_not_rebuilt(self):
        with tempfile.TemporaryDirectory() as d:
            chain = self.built(d)
            with self.assertRaises(SystemExit) as e:
                li.LogIndex(chain, '0x' + '99' * 20, 1, d, 728126428, workers=1, grace_s=0)
            self.assertIn('belongs to another vault', str(e.exception))
            self.assertEqual(len((Path(d) / 'logs.jsonl').read_text().splitlines()), 2)   # untouched
            self.assertNotIn(os.path.realpath(d), li._LOCKS)                              # and the lock was given back


if __name__ == '__main__':
    unittest.main()
