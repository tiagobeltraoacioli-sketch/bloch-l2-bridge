"""Round 15 independent review (agent 310): demonstrations against 1aef47c. Each test PASSES while the defect exists.

  python3 -m unittest -v test_r310_review
"""
import unittest

import test_release_submission_r13 as r13
import test_relayer_review as review
from test_relayer_r11 import BURN


class R310JournalWedge(review.Base):
    ready, pending, reserved = r13.ReleaseSubmission.ready, r13.ReleaseSubmission.pending, r13.ReleaseSubmission.reserved

    """R310-1: a nonce reserved for a burn that someone else released is never freed.

    The primary's release of burn A (nonce 0) leaves the pool unmined (eviction, node restart, a changed
    eth_rpc). A backup relayer releases A with its own key. The primary never sends A again (relay_release
    returns at burn_done), so nothing resumes or retires A's reservation; the chain nonce is still 0, and
    every later burn is refused at nonce 0, pass after pass. Before round 13 the nonce was simply reused.
    """

    def test_R310_1_a_reservation_for_a_burn_released_elsewhere_stops_every_later_release(self):
        daemon, journal, original = self.reserved()
        journal.accept(original)                # burn A broadcast and acknowledged at nonce 0
        self.sent_transactions.clear()          # ... then gone from the node, never mined (latest = pending = 0)
        directory = self.d / 'shared' / 'release' / BURN[2:]
        daemon.burn_done = lambda d, burn: 'known' if burn == BURN else None   # a backup relayer released A
        sends = len(self.sent)
        daemon.relay_release(directory)         # the relayer's only path to A: returns at burn_done
        self.assertEqual(len(self.sent), sends, 'A is finished: nothing is sent for it again')
        for other in ('0x' + 'ee' * 32, '0x' + 'ef' * 32, '0x' + 'f0' * 32):
            for _ in range(3):                  # every pass, every later burn
                with self.assertRaisesRegex(RuntimeError, 'reserved for another signed release'):
                    daemon.send('eth', daemon.vault, ['release()'], release_id=other)
        self.assertEqual(len(self.sent), sends, 'no release of any later burn ever leaves this relayer')
        self.assertTrue(journal.nonce_path(0).exists())


if __name__ == '__main__':
    unittest.main()
