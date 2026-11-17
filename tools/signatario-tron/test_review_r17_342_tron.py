"""Review 342 (round 17) of the TRON log index after the lock and the recount (R325-TRX-2P-1). Demonstrations only.

  python3 -m unittest test_review_r17_342_tron -v   (in tools/signatario-tron)

Class `Findings`: each test states the needed property and FAILS where the code lacks it. Class `Held`: what I tried
and could not break; these pass.
"""
import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

import tron_log_index as li
from test_review_r16_tron_2p import Chain, VAULT, index

HERE = Path(__file__).resolve().parent
OTHER_TOPIC = 'ee' * 32   # any vault log that is not `Deposited`: Released, GuardianPaused, a control change, FeesSwept


class Chain2(Chain):
    """`Chain` plus vault logs that are not deposits, in the blocks named in `others`."""

    def __init__(self, height, deposits=(), others=()):
        super().__init__(height, deposits)
        self.others = sorted(others)

    def block_infos(self, n, solid=False):
        if n in self.others:
            self.requests['gettransactioninfobyblocknum'] += 1
            return [{'id': f'{n:064x}', 'blockNumber': n, 'receipt': {'result': 'SUCCESS'},
                     'log': [{'address': VAULT[2:], 'topics': [OTHER_TOPIC, f'{n:064x}'], 'data': f'{n:064x}'}]}]
        return super().block_infos(n, solid)

    def tx_info(self, tx, solid=False):
        n = int(tx, 16)
        if n in self.others:
            return self.block_infos(n)[0]
        return super().tx_info(tx, solid)


def quiet(fn, *args):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = fn(*args)
    return out, err.getvalue()


def others(idx):
    return [int(l['blockNumber'], 16) for l in idx.logs if l['topics'][:1] == ['0x' + OTHER_TOPIC]]


class Findings(unittest.TestCase):
    def test_r342_trx_2_after_two_writers_the_vaults_other_logs_are_each_there_once(self):
        """Two hosts on one index directory over a network filesystem. There `flock` does not exclude across hosts in
        common setups (NFS mounted `nolock` or `local_lock=flock`, most FUSE filesystems), and the second guard, the
        comparison of the cursor file's (inode, mtime, size), reads attributes the client caches for seconds. Simulated
        here by a second index object whose stat answer is the cached one. The recount on load catches a doubled or
        missing DEPOSIT (rebuild). It does not look at the vault's other logs: after the next restart a release or a
        pause is in the index twice and a later one is missing, and the index calls itself verified. The guardian's
        "release with no burn" rule reads exactly those logs."""
        chain = Chain2(20, others=[30, 50])
        with tempfile.TemporaryDirectory() as d:
            a, b = index(chain, d), index(chain, d)
            b._stamp = lambda: b._seen                 # host B: the attribute cache answers
            chain.height = 35
            a.advance(4000)                            # host A indexes the log of block 30
            b.advance(4000)                            # host B, on its own stale view, appends it again
            chain.height = 60
            b.advance(4000)                            # and the log of block 50 behind it
            self.assertEqual(others(b), [30, 50])      # B's memory is right; the file is not
            a.close(), b.close()
            c, alert = quiet(index, chain, d)          # the next restart, of either host
            c.advance(4000)
            self.assertEqual((others(c), c.verified, c.stats['rebuilds']), ([30, 50], 60, 0),
                             f'after the restart the index holds the logs of blocks {others(c)}, verified to {c.verified}, '
                             f"rebuilds {c.stats['rebuilds']}")

    def test_r342_trx_3_a_kill_during_the_start_does_not_cost_the_history(self):
        """Every start rewrote logs.jsonl in place (round 17); a kill inside that write cost a rebuild from the first block.
        Restated by agent 370 (round 18) for the fix, the property kept: (a) a start writes NOTHING to a consistent
        index (any write to logs.jsonl during the start fails this test); (b) a kill inside the one rewrite left, a
        rollback's write-then-rename, leaves the old file whole: the next start does not rebuild."""
        import os as _os
        chain = Chain2(60, deposits=[10, 40], others=[20, 30])
        with tempfile.TemporaryDirectory() as d:
            a = index(chain, d)
            a.advance(4000)
            self.assertEqual((a.deposits, a.verified), (2, 60))
            a.close()
            real_wt, real_open = Path.write_text, open
            real_replace = _os.replace

            def no_write(self, *args, **kw):
                if self.name == 'logs.jsonl':
                    raise KeyboardInterrupt('a start wrote the log file')
                return real_wt(self, *args, **kw)
            Path.write_text = no_write
            li.os.replace = lambda src, dst: (_ for _ in ()).throw(KeyboardInterrupt('a start replaced a file')) \
                if str(dst).endswith('logs.jsonl') else real_replace(src, dst)
            try:
                b, alert = quiet(index, chain, d)                       # (a) the start reads, it does not write
            finally:
                Path.write_text, li.os.replace = real_wt, real_replace
            self.assertEqual((b.stats['rebuilds'], b.deposits, b.verified), (0, 2, 60))
            # (b) a rollback killed between writing logs.jsonl.tmp and the rename
            li.os.replace = lambda src, dst: (_ for _ in ()).throw(KeyboardInterrupt('killed')) \
                if str(dst).endswith('logs.jsonl') else real_replace(src, dst)
            try:
                with self.assertRaises(KeyboardInterrupt):
                    b.truncate(35)
            finally:
                li.os.replace = real_replace
            b.close()
            before = sum(chain.requests.values())
            c, alert = quiet(index, chain, d)
            c.advance(4000)
            cost = sum(chain.requests.values()) - before
            self.assertEqual((c.stats['rebuilds'], 'tron-log-index-rebuilt' in alert), (0, False),
                             f"the start after the kill rebuilt the index from the first block ({cost} node requests): "
                             f"{c.stats['rebuilt_because']}")
            self.assertEqual((c.deposits, c.verified), (2, 60))
            c.close()


class Held(unittest.TestCase):
    def test_a_crash_between_the_append_and_the_cursor_write_loses_nothing_and_adds_nothing(self):
        """The logs are appended and synced first, the cursor replaced after. A crash between the two leaves lines the
        cursor does not name: the next start drops them, reads those blocks again and ends with each log once."""
        chain = Chain2(25, deposits=[10, 40], others=[20, 50])
        with tempfile.TemporaryDirectory() as d:
            a = index(chain, d)
            a.advance(4000)
            chain.height = 60
            real = os.replace
            os.replace = lambda *x: (_ for _ in ()).throw(KeyboardInterrupt('killed'))
            try:
                with self.assertRaises(KeyboardInterrupt):
                    a.advance(4000)
            finally:
                os.replace = real
            lines = (Path(d) / 'logs.jsonl').read_text().count('\n')
            self.assertGreater(lines, 2)               # the appended lines are on disk, the cursor still names 2
            a.close()
            c, alert = quiet(index, chain, d)
            c.advance(4000)
            nonces = [int(l['data'][2:66], 16) for l in c.logs if l['topics'][:1] == [li.DEPOSITED]]
            self.assertEqual((nonces, others(c), c.verified, c.stats['rebuilds'], alert), ([0, 1], [20, 50], 60, 0, ''))

    def test_a_killed_holder_with_a_live_child_leaves_no_lock(self):
        """The shim runs `cast` as a child. If the shim is killed while a child lives, the child must not keep the
        directory's lock (it would, if the lock's file descriptor were inherited)."""
        holder_src = textwrap.dedent('''
            import subprocess, sys, time
            sys.path.insert(0, %r)
            from test_review_r16_tron_2p import Chain, index
            idx = index(Chain(60, deposits=[10, 40]), sys.argv[1])
            child = subprocess.Popen(['sleep', '30'])
            print(child.pid, flush=True)
            time.sleep(600)
        ''') % str(HERE)
        with tempfile.TemporaryDirectory() as d:
            holder = subprocess.Popen([sys.executable, '-c', holder_src, d], stdout=subprocess.PIPE, text=True)
            child = int(holder.stdout.readline())
            try:
                with self.assertRaises(SystemExit):
                    with contextlib.redirect_stderr(io.StringIO()):
                        index(Chain(60, deposits=[10, 40]), d)   # held
                holder.kill()
                holder.wait()
                os.kill(child, 0)                                # the child is still alive
                idx = index(Chain(60, deposits=[10, 40]), d)     # and the directory is free
                idx.advance(4000)
                self.assertEqual(idx.deposits, 2)
                idx.close()
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(child, signal.SIGKILL)
                if holder.poll() is None:
                    holder.kill()

    def test_two_writers_never_serve_a_wrong_deposit_and_the_next_start_rebuilds(self):
        """The same two-host simulation with DEPOSITS: each writer's answers come from its own memory, read from the
        chain and checked against the vault's state, so neither serves a wrong or doubled deposit; the file they
        share is caught by the recount at the next start (rebuild), as the developer says."""
        chain = Chain2(20, deposits=[30, 50])
        with tempfile.TemporaryDirectory() as d:
            a, b = index(chain, d), index(chain, d)
            b._stamp = lambda: b._seen
            chain.height = 35
            a.advance(4000)
            b.advance(4000)
            chain.height = 60
            b.advance(4000)
            for idx, want in ((b, [0, 1]),):
                got = [int(l['data'][2:66], 16) for l in idx.query(1, idx.verified, [li.DEPOSITED])]
                self.assertEqual(got, want)
            a.close(), b.close()
            c, alert = quiet(index, chain, d)
            # Restated by agent 370 (round 18): with the cursor binding the file (byte length, sha256) and every append
            # written at the cursor's own byte, the directory the two writers leave is either the last writer's whole
            # state (no rebuild needed: it was read from the chain and checked against the vault) or a mismatch that
            # is rebuilt. Round 17 always rebuilt here. The property tested is unchanged: no wrong deposit, ever.
            self.assertIn(c.stats['rebuilds'], (0, 1))
            c.advance(4000)
            self.assertEqual([int(l['data'][2:66], 16) for l in c.logs if l['topics'][:1] == [li.DEPOSITED]], [0, 1])


if __name__ == '__main__':
    unittest.main()
