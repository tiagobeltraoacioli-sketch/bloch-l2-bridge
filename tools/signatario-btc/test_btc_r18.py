"""Round 18 (agent 370): review 342's fixes that have no test elsewhere.

  ThreadAudit     R342-BTC-2: the thread is compared with the finalized L2 afterwards (btc_audit), by the reserves
                  monitor at each set-aside's own L2 block and by every signer at its finalized block.
  RelayerAuth     proposals reach a signer only from an allow-listed relayer key, fresh, rate-limited, a replay counted
                  once (btc_signer.authenticated_relayer, btc_core.proposal_text).

Run: python3 -m unittest test_btc_r18   (standard library only; no node, no L2)
"""
import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path

import btc_audit
import btc_core as c
import btc_policy as pol
import btc_signer
import test_btc_policy as t

DAY = 86_400


def router_terms(rate, block, claimed=True):
    return {'through_router': claimed, 'destination': b'\x01' * 20 if claimed else None, 'max_fee_rate': rate if claimed else None,
            'updated_block': block if claimed else 0, 'state': 'payable' if claimed else 'unclaimed', 'contract_burner': False}


class ThreadAudit(unittest.TestCase):
    def thread(self, v, steps):
        """entries as btc_vault.VaultView keeps them, from (build kwargs, confirmation time) steps on a funded anchor."""
        s0 = t.after(pol.build_vault_tx(v, t.tip(200_000), [t.dep(0, 10**8)], [], [], 1))
        entries = [{'txid': 'anchor', 'time': 0, 'confirmations': 9, 'build': None, 'state': s0}]
        state = s0
        for kw, when in steps:
            b = pol.build_vault_tx(v, state, kw.get('deposits', []), [], kw.get('burns', []), kw['feerate'],
                                   aside_through=kw.get('aside_through', 0), aside_block=kw.get('aside_block', 0))
            state = t.after(b)
            entries.append({'txid': b['tx'].txid(), 'time': when, 'confirmations': 1, 'build': b, 'state': state})
        return entries

    def audit(self, v, entries, terms_now, terms_then=None, times=None, historical=True):
        burns = {n: {'nonce': n, 'units': 1_000} for n in range(1, 10)}
        times = times or {}

        def terms_at(b, block):
            if block is None or terms_then is None:
                return terms_now[b['nonce']]
            return terms_then.get((b['nonce'], block), terms_now[b['nonce']])
        return btc_audit.audit_thread(v, entries, burns, terms_at, lambda b: times.get(b['nonce'], 0), historical)

    def test_a_set_aside_the_rule_did_not_allow_is_found_and_an_allowed_one_is_not(self):
        v = t.vault()
        # burns 1 and 2 set aside at L2 block 10 in a transaction that pays burn 3 at 2 sat/vB, four days after burn 2
        entries = self.thread(v, [({'burns': [t.burn(3)], 'feerate': 2, 'aside_through': 2, 'aside_block': 10}, 4 * DAY)])
        terms = {1: router_terms(5, 3), 2: router_terms(None, 0, claimed=False), 3: router_terms(200, 4)}
        bad = self.audit(v, entries, terms)
        # burn 1 is a router burn with a ceiling of 5 at a fee rate of 2, nothing beyond the window: NOT allowed
        self.assertEqual([(x['rule'], x['nonce']) for x in bad], [('set-aside-outside-the-rule', 1)])
        # burn 2 (unclaimed, older than setAsideAgeSeconds) is allowed: 'age'
        terms[1] = router_terms(None, 0, claimed=False)
        self.assertEqual(self.audit(v, entries, terms), [])
        # the same unclaimed burn made one hour before the set-aside is too young: found
        self.assertEqual([x['nonce'] for x in self.audit(v, entries, terms, times={1: 4 * DAY - 3600})], [1])
        # a ceiling below the policy floor is allowed ('floor')
        terms[1] = router_terms(1, 3)
        self.assertEqual(self.audit(v, entries, terms), [])

    def test_judged_at_the_set_aside_block_by_the_monitor_and_never_on_a_false_alarm_by_a_signer(self):
        v = t.vault()
        entries = self.thread(v, [({'burns': [t.burn(3)], 'feerate': 2, 'aside_through': 1, 'aside_block': 10}, 4 * DAY)])
        # at block 10 burn 1 was unclaimed (allowed); its burner claimed it at block 12 with a ceiling of 50
        now = {1: router_terms(50, 12), 3: router_terms(200, 4)}
        then = {(1, 10): router_terms(None, 0, claimed=False)}
        self.assertEqual(self.audit(v, entries, now, then), [])
        # a signer that only has the finalized block cannot judge it, and says nothing
        self.assertEqual(self.audit(v, entries, now, historical=False), [])
        # but a claimed burn at block 10 with a payable ceiling is found by the monitor
        then = {(1, 10): router_terms(50, 8)}
        self.assertEqual([x['rule'] for x in self.audit(v, entries, now, then)], ['set-aside-outside-the-rule'])
        # and a burner's call AFTER the set-aside block that the terms then already show is a violation of rule 4c
        then = {(1, 10): router_terms(1, 11)}
        self.assertEqual([x['rule'] for x in self.audit(v, entries, now, then)], ['set-aside-after-burner-call'])

    def test_payouts_above_the_ceiling_and_late_payments_without_a_burner_call_are_found(self):
        v = t.vault()
        entries = self.thread(v, [({'burns': [t.burn(3)], 'feerate': 2, 'aside_through': 2, 'aside_block': 10}, 4 * DAY),
                                  ({'burns': [t.burn(2)], 'feerate': 3}, 5 * DAY)])
        terms = {1: router_terms(None, 0, claimed=False), 2: router_terms(3, 10), 3: router_terms(200, 4)}
        then = {(2, 10): router_terms(None, 0, claimed=False)}   # unclaimed when it was set aside (allowed: 'age')
        # burn 2 paid late, but its burner's latest call (block 10) is not after the set-aside block (10)
        self.assertEqual([(x['rule'], x['nonce']) for x in self.audit(v, entries, terms, then)],
                         [('late-payment-without-burner-call', 2)])
        terms[2] = router_terms(3, 11)
        self.assertEqual(self.audit(v, entries, terms, then), [])
        # a ceiling of 2 under a payment at 3 sat/vB (ceilings only rise: the finalized ceiling bounds every earlier one)
        terms[2] = router_terms(2, 11)
        self.assertEqual([x['rule'] for x in self.audit(v, entries, terms, then)], ['paid-above-ceiling'])
        # and a direct burn paid while unclaimed
        terms[2] = router_terms(None, 0, claimed=False)
        self.assertIn('paid-without-claim', [x['rule'] for x in self.audit(v, entries, terms, then)])

    def test_payable_burns_left_unpaid_are_reported_as_stalled_and_waiting_ones_are_not(self):
        v = t.vault()
        entries = self.thread(v, [({'burns': [t.burn(3)], 'feerate': 2, 'aside_through': 2, 'aside_block': 10}, 4 * DAY)])
        tip = entries[-1]['state']
        burns = {n: {'nonce': n, 'units': 1_000} for n in (1, 2, 3, 4, 5)}
        terms = {1: router_terms(None, 0, claimed=False), 2: router_terms(9, 10), 3: router_terms(200, 4),
                 4: router_terms(9, 5), 5: router_terms(4, 5)}
        got = btc_audit.stalled_burns(v, tip, burns, lambda b, blk: terms[b['nonce']], lambda b: 0, 5, 10 * DAY, 21_600)
        # 1 unclaimed, 2 set aside and waiting for its burner's call, 3 paid, 5 under a ceiling below 5 sat/vB: not stalled
        self.assertEqual([x['nonce'] for x in got], [4])
        terms[2] = router_terms(9, 11)   # its burner called again: now the vault owes it a payment
        got = btc_audit.stalled_burns(v, tip, burns, lambda b, blk: terms[b['nonce']], lambda b: 0, 5, 10 * DAY, 21_600)
        self.assertEqual([(x['nonce'], x['set_aside']) for x in got], [(2, True), (4, False)])


class RelayerAuth(unittest.TestCase):
    VAULT_ID = bytes(range(32))

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.relayer = c.eth_address(c.pubkey(t.PRIVS[0]))
        self.cfg = {'relayers': [self.relayer], 'journal': str(Path(self.dir.name) / 'journal.json'), 'max_proposals_per_hour': 3}

    def tearDown(self):
        self.dir.cleanup()

    def signed(self, priv=None, issued=None, **body):
        p = {'kind': 'btc-vault-proposal', 'version': 3, 'tip': 'aa' * 32, 'feerate': 5, **body,
             'issued': int(time.time()) if issued is None else issued, 'relayer': self.relayer}
        r, s, v = c.sign(c.personal_digest(c.proposal_text(self.VAULT_ID, p)), t.PRIVS[0] if priv is None else priv)
        return {**p, 'relayer_signature': '0x' + (r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + v])).hex()}

    def check(self, proposal, cfg=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                return btc_signer.authenticated_relayer(cfg or self.cfg, self.VAULT_ID, proposal, time.time())
            except SystemExit:
                return json.loads(out.getvalue())['reason']

    def test_only_a_listed_relayer_with_its_own_signature_is_served(self):
        self.assertEqual(self.check(self.signed()), self.relayer)
        self.assertIn('allow-list', self.check({**self.signed(), 'relayer': '0x' + '11' * 20}))
        self.assertIn('not signed by the relayer', self.check(self.signed(priv=t.PRIVS[1])))
        for bad in ('', '--help', '-h' + 'a' * 130, '0x' + '00' * 65, None, 5):
            self.assertIn('malformed', self.check({**self.signed(), 'relayer_signature': bad}))
        # the signature covers the proposal: change one field and it no longer verifies
        self.assertIn('not signed by the relayer', self.check({**self.signed(), 'feerate': 6}))
        self.assertIn('works for nobody', self.check(self.signed(), {**self.cfg, 'relayers': []}))

    def test_stale_or_future_proposals_are_dropped_and_a_replay_counts_once(self):
        self.assertIn('not fresh', self.check(self.signed(issued=int(time.time()) - 601)))
        self.assertIn('not fresh', self.check(self.signed(issued=int(time.time()) + 600)))
        bare = {'kind': 'btc-vault-proposal', 'version': 3, 'tip': 'aa' * 32, 'feerate': 5, 'relayer': self.relayer}
        r, s_, v = c.sign(c.personal_digest(c.proposal_text(self.VAULT_ID, bare)), t.PRIVS[0])
        bare['relayer_signature'] = '0x' + (r.to_bytes(32, 'big') + s_.to_bytes(32, 'big') + bytes([27 + v])).hex()
        self.assertIn('not fresh', self.check(bare))          # validly signed, but without an issue time
        one = self.signed(feerate=7)
        for _ in range(10):                                   # the same proposal handed in again: one slot of three
            self.assertEqual(self.check(one), self.relayer)
        self.assertEqual(self.check(self.signed(feerate=8)), self.relayer)
        self.assertEqual(self.check(self.signed(feerate=9)), self.relayer)
        self.assertIn('hourly limit', self.check(self.signed(feerate=10)))
        self.assertEqual(self.check(one), self.relayer)       # already counted: still served, not counted again


if __name__ == '__main__':
    unittest.main()
