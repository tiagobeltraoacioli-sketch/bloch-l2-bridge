#!/usr/bin/env python3
"""Review 331, fourth pass (round 18, agent 377): offline demonstrations against developer 373's revision 4.

Brought into the line by developer 373 (round 18) with each DEFECT case turned into a regression test of the fixed
behaviour (renamed FIXED_..., the reviewer's scenario unchanged; the docstrings keep the reviewer's text of the
defect). Run from this directory: python3 -m unittest test_r377_fourth_pass
"""
import contextlib
import io
import json
import unittest
from unittest import mock

import test_stellar_tools as T
from test_stellar_tools import (FakeL2, FakeVault, MALLORY, PAYEE, PAYEE2, PASS, ROUTER, BURNER, block_hash,
                                g_address, sn)


class HalfSignsForAnAddressThatCannotReceive(T.SignerDestination):
    """R331-XLM-4P-1. The half asks whether the burnTo address can receive ONLY when a redirect exists. Without one it
    signs for an address that cannot receive; with the recommended configuration (release_delay on every release)
    the vault QUEUES that release, pins its recipient (lib.rs `execute_release`: the pending entry's recipient), every
    execution then fails, `burn_status` is 1, and the half refuses any later certificate for the burn ('already
    recorded by the vault (queued)'): a redirect or a newer claim made after that is never honoured, until a guardian
    pause voids the whole queue. Fixed behaviour: the half refuses (holds) whenever the address it would pay cannot
    receive, for every `via`, so nothing is queued and the burner's redirect / newer claim can be paid."""

    def asset(self):
        issuer = g_address(b'issuer')
        return {'asset_code': 'USDC', 'asset_issuer': issuer, 'asset_contract': sn.asset_contract_id(PASS, 'USDC', issuer)}

    def test_FIXED_router_exit_without_redirect_is_held_for_an_address_that_cannot_receive(self):
        b = self.burn(1, 100, PAYEE)
        intent = {'release': {'nonce': 1, 'recipient': b['recipient']},
                  'l2': {'from': ROUTER, 'finalized_number': 236,
                         'stellar': {'recipient': PAYEE, 'via': 'router', 'router': ROUTER}}}
        asked = []
        self.assertIn('held:', self.half(intent, unable={PAYEE: ['no trustline']}, asked=asked, **self.asset()))
        self.assertEqual(asked, [PAYEE])                                             # asked, and held

    def test_FIXED_direct_burn_claim_is_held_for_an_address_that_cannot_receive(self):
        d = self.burn(2, 110, direct=True)
        self.claim(2, PAYEE, 200)
        intent = {'release': {'nonce': 2, 'recipient': d['recipient']},
                  'l2': {'from': BURNER, 'finalized_number': 236,
                         'stellar': {'recipient': PAYEE, 'via': 'claim', 'router': ROUTER}}}
        self.assertIn('held:', self.half(intent, unable={PAYEE: ['the account does not exist']}, l2_rpc='a',
                                         **self.asset()))

    def test_a_queued_burn_is_never_signed_again(self):
        """The other half of the argument: once queued, the half refuses (stellar_half.py `release`, burn_status 1)."""
        src = (T.HERE / 'stellar_half.py').read_text()
        self.assertIn("if status in (1, 2):", src)
        self.assertIn("already recorded by the vault", src)
        vault = (T.ROOT / 'stellar/vault/src/lib.rs').read_text()
        body = vault[vault.index('pub fn execute_release'):vault.index('// ── guardians')]
        self.assertIn('pay(&env, &cfg, &mut st, &pending.recipient, pending.amount)', body)


class StallRuleOnSomethingElseThanAStall(T.GuardianCheck):
    """R331-XLM-4P-3. The stall rule turns EVERY 'cannot judge' of a queued release with answering sources into a
    finding after the deadline, also when L2 finality moves and the cause is this guardian's own log source (pruned
    logs, `token_from_block` too high). The brief asked: pause only after a stated time WITHOUT L2 finality progress.
    Fixed behaviour: a 'cannot judge' whose cause is not the final view being behind the release (the burn is final
    and its id matches) stays exit 3 (page), never a pause."""

    def test_FIXED_an_honest_final_burn_whose_log_the_source_does_not_serve_is_never_paused_for(self):
        b = self.burn(1, 100, PAYEE)                           # final long ago (final block 236)
        self.release(b, PAYEE, ledger=270, event='release_queued')   # queued 3,650 s ago: past the 3,600 s deadline
        self.still(3650)                                       # and finality has stood still that long, too
        code, out = self.check()
        self.assertEqual(code, 0)                              # with the log served: ok
        with mock.patch.object(FakeL2, 'logs', return_value=[]):   # a pruning RPC, or token_from_block above 100
            code, out = self.check()
        self.assertEqual((code, out['findings']), (3, []))     # paged, no pause
        self.assertIn('does not serve its', out['cannot_judge'][0]['reason'])

    def test_finality_moving_and_view_reaching_the_release_is_judged(self):
        b = self.burn(1, 230, PAYEE)
        self.release(b, PAYEE, ledger=270, event='release_queued')
        self.assertEqual(self.check()[0], 0)


class PaidForgeryUnderAnUnreachableBlock(T.GuardianCheck):
    """R331-XLM-4P-2 (regression against 22ea9a4). Revision 3's later-block rules made a forgery naming a block nobody
    reaches (or a call through another contract) a finding once the L2 had a later block. Revision 4 removed them
    (4ee58b3: 'the later-block rules and the host clock are gone') in favour of the stall rule, which applies to a
    QUEUED release only. A PAID forgery of that kind (release_delay 0, an owner option the documents offer, or a
    release below a threshold) is therefore never a finding, however far the L2 moves: no guardian pauses, so the
    next forgeries are not stopped either. Fixed behaviour: a height rule (the release's burn nonce is above the
    token's burn count at a FINAL block that is at or past a height this guardian recorded when it first saw the
    release) is a finding whatever the queue state; it needs no clock."""

    def test_FIXED_a_paid_forgery_naming_an_unreachable_block_becomes_a_finding(self):
        FakeVault.delay = 0
        self.release(self.forged(5), MALLORY, ledger=1, names=(10**9, '0x' + '11' * 32))   # paid, nonce 5, no burns
        for (fin, head), want in (((236, 300), 3), ((5000, 5100), 2), ((10**6, 10**6 + 64), 2)):
            for s in FakeL2.state.values():
                s.update(fin=fin, head=head)
            code, out = self.check(l2_clock_alert_seconds=0)
            self.assertEqual(code, want, (fin, head))          # first seen at head 300; a finding past 300 + 256

    def test_FIXED_same_through_another_contract(self):
        FakeVault.delay = 0
        self.release(self.forged(5), MALLORY, ledger=1, named=False)
        self.assertEqual(self.check()[0], 3)                   # first seen at head 300
        for s in FakeL2.state.values():
            s.update(fin=10**6, head=10**6 + 64)
        self.assertEqual(self.check(l2_clock_alert_seconds=0)[0], 2)


class NamingsAtTheGuardian(T.GuardianCheck):
    """Checks that hold (no defect): the guardian accepts any naming of the burn's own burner and nothing else."""

    def test_a_claim_made_after_the_release_is_still_a_naming_of_the_burner(self):
        d = self.burn(1, 100, direct=True)
        self.claim(1, PAYEE, 150)
        self.release(d, PAYEE, event='release_queued')
        self.assertEqual(self.check()[0], 0)

    def test_a_strangers_claim_for_the_nonce_is_a_finding(self):
        d = self.burn(1, 100, direct=True)
        self.claim(1, MALLORY, 150, burner=T.STRANGER)
        self.release(d, MALLORY, event='release_queued')
        code, out = self.check()
        self.assertEqual(code, 2)

    def test_a_redirect_of_a_direct_burn_is_not_a_naming(self):
        d = self.burn(1, 100, direct=True)
        self.redirect(1, MALLORY, 150)
        self.release(d, MALLORY, event='release_queued')
        self.assertEqual(self.check()[0], 2)


def load_tests(loader, tests, pattern):
    """Only the cases defined here (the base classes' own tests are the developer's and run in their own file)."""
    suite = unittest.TestSuite()
    for cls in (HalfSignsForAnAddressThatCannotReceive, StallRuleOnSomethingElseThanAStall,
                PaidForgeryUnderAnUnreachableBlock, NamingsAtTheGuardian):
        for name in sorted(n for n in vars(cls) if n.startswith('test_')):
            suite.addTest(cls(name))
    return suite


if __name__ == '__main__':
    unittest.main()
