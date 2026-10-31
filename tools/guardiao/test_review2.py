#!/usr/bin/env python3
"""Second adversarial bridge review (agents/57): guardian. No chain and no key material.

  python3 -m unittest -v test_review2

A FAILURE IS THE REPRODUCTION of a finding; `control` tests pass. Guardian.round and Guardian.act are the real code, and
the L2 and Ethereum reads are stubs.
"""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import guardiao

T0 = 2_000_000_000
GRACE = 2700
FORGED = ('hard', 'release-unknown:0xf0', GRACE, {'reason': 'vault release without a matching L2 burn'})


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='review2-g-'))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        cfg = {'kind': 'stable', 'l2_rpc': 'http://l2', 'l2_tx_rpc': 'http://tx', 'l2_chain_id': 700770, 'token': '0x' + '11' * 20,
               'vault': '0x' + '22' * 20, 'vault_pause': True, 'state': str(self.d / 'state.json'),
               'keystore': 'unused', 'password_file': 'unused', 'eth_rpc': 'http://eth', 'eth_chain_id': 1}
        path = self.d / 'cfg.json'
        path.write_text(json.dumps(cfg))
        self.g = guardiao.Guardian(path)
        self.g.log = lambda **kw: None
        self.g.pause = lambda now, reasons: None


class G1FrozenClock(Base):
    """The grace clock is the L2 head timestamp, so it stops when the L2 view stops."""

    def rounds(self, head_times, wall_times):
        paused = []
        self.g.pause_vault = paused.append
        self.g.setup = lambda: None
        self.g.finalized_l2 = lambda: None
        self.g.read_l2 = lambda b: (0, 0, [], [])
        self.g.eth_source = lambda burns, fin: (0, {}, [FORGED])
        for head, wall in zip(head_times, wall_times):
            self.g.block = lambda url, tag, head=head: (100, head, '0x')
            with mock.patch.object(guardiao.time, 'time', lambda wall=wall: wall):
                self.g.act(*self.g.round())
        return paused

    def test_control_a_forged_release_pauses_after_the_grace_on_a_live_l2(self):
        times = [T0, T0 + GRACE + 1]
        self.assertTrue(self.rounds(times, times))

    def test_a_forged_release_pauses_after_the_grace_while_the_l2_head_is_frozen(self):
        walls = [T0, T0 + 86_400, T0 + 7 * 86_400]
        self.assertTrue(self.rounds([T0, T0, T0], walls),
                        'no vault pause 7 days after a forged release: the L2 head stopped, and with it the grace')


class G2OpenForever(Base):
    """A finding from the log history never closes, so one event pauses again after every cooldown."""

    def test_a_committee_unpause_is_not_undone_by_the_same_old_finding(self):
        vault = {'pausedUntil': 0, 'guardianBlockedUntil': 0, 'pauseCount': 0}
        now = [T0]
        sent = []

        def call(url, to, sig, *args, block='latest'):
            if sig == 'verifier()':
                return ['00' * 32]
            if sig == 'guardianCanPause(address)':
                ok = now[0] >= vault['pausedUntil'] and now[0] >= vault['guardianBlockedUntil']
                return [f'{int(ok):064x}']
            return [f'{vault[sig[:-2]]:064x}']

        def run(argv):
            sent.append(now[0])
            vault['pausedUntil'] = now[0] + 259200
            vault['pauseCount'] += 1
            return 0, json.dumps({'status': '0x1', 'transactionHash': '0x01'}), ''

        self.g.call, self.g.run = call, run
        self.g.block = lambda url, tag: (1, now[0], '0x')
        self.g._eth_me = '0x' + '77' * 20
        self.g.act(now[0], [FORGED])
        now[0] += GRACE + 1
        self.g.act(now[0], [FORGED])
        self.assertEqual(len(sent), 1, 'the first pause')
        now[0] = vault['pausedUntil'] - 100  # 6 of 7 signers reviewed it and ended the pause
        vault['pausedUntil'] = now[0]
        vault['guardianBlockedUntil'] = now[0] + 259200
        for _ in range(8):  # 24 days, the finding still listed by every rescan of the logs
            now[0] += 259200 + 1
            self.g.act(now[0], [FORGED])
            if vault['pausedUntil'] > now[0]:
                now[0] = vault['pausedUntil'] + 259200 + 1
        self.assertEqual(len(sent), 1, f'the same finding paused the vault {len(sent)} times')


if __name__ == '__main__':
    unittest.main()
