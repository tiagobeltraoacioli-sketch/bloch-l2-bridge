"""Round 15 review finding R310-1 (agent 310), fixed by agent 314: regression tests.

The reviewer's demonstration (commit 78b7ac0, cherry-picked) passed while the defect existed: a release nonce reserved
for a burn that another relayer released stopped every later release of this relayer. The first test below is that
demonstration with the assertions turned around; the others pin the limits of the fix.

  python3 -m unittest -v test_r310_review
"""
import contextlib
import io
import json
import unittest

import test_release_submission_r13 as r13
import test_relayer_review as review
from test_relayer_r11 import BURN

LATER = ('0x' + 'ee' * 32, '0x' + 'ef' * 32, '0x' + 'f0' * 32)


class R310JournalWedge(review.Base):
    ready, pending, reserved = r13.ReleaseSubmission.ready, r13.ReleaseSubmission.pending, r13.ReleaseSubmission.reserved

    def orphan(self, final=True, accepted=True):
        """The primary's release of burn A (nonce 0) left the pool unmined; a backup relayer released A."""
        daemon, journal, original = self.reserved()
        if accepted:
            journal.accept(original)            # burn A broadcast and acknowledged at nonce 0
        self.sent_transactions.clear()          # ... then gone from the node, never mined (latest = pending = 0)
        daemon.burn_done = lambda d, burn: 'known' if burn == BURN else None
        daemon.release_finished = lambda burn: burn == BURN
        daemon.finished = lambda: {'mint': set(), 'executed': set(), 'release': {BURN} if final else set()}
        return daemon, journal, original

    def send(self, daemon, burn):
        cast_out = daemon.cast_out

        def for_burn(*args):                    # the stub's release calldata always names BURN: name this burn
            value = cast_out(*args)
            return value[:-64] + burn[2:] if args[0] == 'calldata' else value

        daemon.cast_out = for_burn
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                tx = daemon.send('eth', daemon.vault, ['release()'], release_id=burn)
        finally:
            daemon.cast_out = cast_out
        return tx, [json.loads(line) for line in out.getvalue().splitlines() if line.startswith('{')]

    def test_R310_1_a_reservation_for_a_burn_released_elsewhere_is_retired(self):
        daemon, journal, original = self.orphan()
        directory = self.d / 'shared' / 'release' / BURN[2:]
        sends = len(self.sent)
        daemon.relay_release(directory)         # the relayer's only path to A: returns at burn_done
        self.assertEqual(len(self.sent), sends, 'A is finished: nothing is sent for it again')
        tx, logs = self.send(daemon, LATER[0])
        self.assertEqual(len(self.sent), sends + 1, 'the next burn leaves this relayer')
        self.assertEqual(int(self.sent_transactions[tx]['nonce'], 16), 0, 'at the freed nonce')
        alerts = [entry for entry in logs if entry.get('id') == 'release-reservation-orphaned']
        self.assertEqual([(a['nonce'], a['burn'], a['tx'], a['reason']) for a in alerts],
                         [(0, BURN, original[0]['hash'], 'released-elsewhere')])
        self.assertEqual(journal.retired(0), [{'burn': BURN, 'hash': original[0]['hash'], 'reason': 'released-elsewhere'}])
        self.assertIsNone(journal.read_accepted(BURN), 'the spent bytes are dropped')
        self.assertEqual(journal.read(journal.nonce_path(0))[0]['burn'], LATER[0], 'nonce 0 now reserved for the new burn')
        # The same burn again resumes its own reservation; nothing new is signed.
        again, _ = self.send(daemon, LATER[0])
        self.assertEqual((again, len(self.sent)), (tx, sends + 1))

    def test_a_release_seen_only_below_finality_keeps_the_reservation(self):
        daemon, journal, _ = self.orphan(final=False)
        for other in LATER:
            with self.assertRaisesRegex(RuntimeError, 'reserved for another signed release'):
                self.send(daemon, other)
        self.assertTrue(journal.nonce_path(0).exists())
        self.assertIsNone(journal.retired(0))

    def test_a_reserved_transaction_the_node_still_knows_keeps_the_reservation(self):
        daemon, journal, original = self.orphan()
        signed = original[1]
        self.sent_transactions[original[0]['hash']] = {**signed, 'from': signed['signer'], 'blockNumber': None}
        with self.assertRaisesRegex(RuntimeError, 'reserved for another signed release'):
            self.send(daemon, LATER[0])
        self.assertIsNone(journal.retired(0))

    def test_an_unreleased_burn_keeps_its_reservation_while_the_nonce_is_unconsumed(self):
        daemon, journal, _ = self.orphan()
        daemon.release_finished = lambda burn: False
        daemon.finished = lambda: {'mint': set(), 'executed': set(), 'release': set()}
        with self.assertRaisesRegex(RuntimeError, 'reserved for another signed release'):
            self.send(daemon, LATER[0])
        self.assertIsNone(journal.retired(0))

    def test_a_pending_record_of_a_burn_released_elsewhere_is_not_broadcast_again(self):
        daemon, journal, original = self.orphan(accepted=False)   # the reply was lost: only pending.json exists
        sends = len(self.sent)
        tx, _ = self.send(daemon, LATER[0])
        self.assertEqual(len(self.sent), sends + 1)
        self.assertTrue(self.sent_transactions[tx]['input'].endswith(LATER[0][2:]))
        self.assertNotEqual(tx, original[0]['hash'], 'the spent bytes of A were not repeated')
        self.assertEqual(journal.retired(0)[0]['reason'], 'released-elsewhere')
        self.assertIsNone(journal.read(journal.pending))

    def test_the_old_bytes_mined_later_cost_the_new_release_only_a_new_nonce(self):
        """After the nonce was reused for burn B, A's old transaction is mined after all (it reverts: A is paid) and
        takes nonce 0. B's transaction can then never be included: it is retired and B goes out at nonce 1."""
        daemon, journal, _ = self.orphan()
        first, _ = self.send(daemon, LATER[0])
        self.sent_transactions.clear()          # B's transaction lost its nonce to A's old bytes
        self.answers['eth_getTransactionCount'] = '0x1'   # latest, pending and finalized
        second, logs = self.send(daemon, LATER[0])
        self.assertNotEqual(second, first)
        self.assertEqual(int(self.sent_transactions[second]['nonce'], 16), 1)
        self.assertEqual([entry['reason'] for entry in logs if entry.get('id') == 'release-reservation-orphaned'],
                         ['nonce-consumed'])
        self.assertEqual([entry['reason'] for entry in journal.retired(0)], ['released-elsewhere', 'nonce-consumed'])

    def test_a_consumed_nonce_seen_only_below_finality_repeats_the_same_bytes(self):
        daemon, journal, _ = self.orphan()
        first, _ = self.send(daemon, LATER[0])
        self.sent_transactions.clear()
        self.answers['eth_getTransactionCount'] = lambda url, args: '0x0' if args[1] == 'finalized' else '0x1'
        again, _ = self.send(daemon, LATER[0])
        self.assertEqual(again, first, 'unknown outcome below finality: only the reserved bytes are repeated')


if __name__ == '__main__':
    unittest.main()
