#!/usr/bin/env python3
"""Review 376 (fourth pass of reviewer 330's line) on developer 371's exit rule: demonstrations and controls.

  python3 -m unittest tools/signatario-solana/test_r376_review.py

A test named `test_r376_sol_4p_N_...` PASSED while the defect R330-SOL-4P-N was present; developer 371 (round 18)
fixed 4P-1, 4P-2 and 4P-3 and inverted the three demonstrations below (each now asserts the fixed behaviour on the
reviewer's unchanged scenario; the reviewer's original assertions are kept in the comments).
A test named `test_control_...` checks a property that holds and must keep holding (several restate unit tests that
the round-17 WIP removed from test_solana_tools.py, see review 330, fourth pass, R330-SOL-4P-4).
Fake L2 and Solana endpoints on loopback (testkit.py); throwaway keys only. Not product code.
"""
from pathlib import Path
import random
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_half  # noqa: E402
import sol_recipient as R  # noqa: E402
import test_solana_tools as T  # noqa: E402
import testkit as K  # noqa: E402

ABSENT = {'hold': None, 'exists': False, 'fundedSystemAccount': False}


def absent(wallet):
    return dict(ABSENT)


class GuardianBlindRound(unittest.TestCase):
    """R330-SOL-4P-1: a PAID release first judged in a round without the L2 is remembered as checked for good."""

    def setUp(self):
        import sol_guardiao
        self.c = T.Cluster()
        self.l2 = K.L2(self, self.c)
        self.fake = T.Fake(self.c.answer)
        self.addCleanup(self.fake.close)
        node = sol_half.Node(self.c.files(Path(tempfile.mkdtemp()), self.fake.url))
        g = sol_guardiao.SolGuardian.__new__(sol_guardiao.SolGuardian)
        g.router_cfg, g.cfg, g.l2, g.token = self.l2.cfg(), {}, self.l2.fake.url, self.l2.token
        g._senders, g._paid_checked, g.blind = None, {}, False
        g.provenance_grace, g.release_before_final, g.route = 600, 'hard', S.hx(self.c.a.route)
        g.node = lambda *a: node
        self.g, self.node = g, node

    def findings_for(self, burn, recipient20):
        """eth_source over one PAID release record of `burn` naming `recipient20` (the record of a vault whose five
        signers skipped the rule: an old half, the loss case of R330-SOL-3P-2)."""
        b = dict(burn, eth_recipient=burn['recipient'])
        record = {'nonce': burn['nonce'], 'seq': 1, 'state': 2, 'recipient': recipient20, 'amount': burn['amount'],
                  'native_burn': S.unhex(burn['burn_id'], 32), 'key': 'record', 'ready_at': 0}
        self.g.records = lambda: []
        self.g.release_records = lambda: [record]
        self.node.token_balance = lambda address: {'mint': self.node.config.mint, 'owner': self.node.a.vault,
                                                   'amount': 10**12}
        self.g._senders = None
        _, _, findings = self.g.eth_source([b], fin=None)
        return [f[1] for f in findings if not f[1].startswith('release-before-final')]

    def test_control_a_paid_release_without_a_proof_is_a_hard_finding(self):
        unproven = self.l2.exit(text=S.b58encode(K.keyless_address('g4')), proof=bytes(65))
        self.assertEqual(self.findings_for(unproven, S.unhex(unproven['recipient'], 20)),
                         [f"release-mismatch:unproven-{unproven['nonce']}"])

    def test_r376_sol_4p_1_fixed_a_payment_first_seen_in_a_blind_round_is_reported_once_the_l2_answers(self):
        unproven = self.l2.exit(text=S.b58encode(K.keyless_address('g4 blind')), proof=bytes(65))
        recipient = S.unhex(unproven['recipient'], 20)
        self.g.blind = True  # the guardian's L2 endpoint does not answer in the round that first sees the payment
        self.assertEqual(self.findings_for(unproven, recipient), [], 'a blind round cannot judge: expected')
        self.g.blind = False  # the L2 answers again
        # was: findings [] ('DEFECT: ... never reported once the L2 is back') and the record in _paid_checked
        self.assertEqual(self.findings_for(unproven, recipient), [f"release-mismatch:unproven-{unproven['nonce']}"])
        self.assertNotIn((unproven['nonce'], 1), self.g._paid_checked)


class RedirectAfterApproval(unittest.TestCase):
    """R330-SOL-4P-3: an honest approval (or payment) for the burner's FIRST redirect becomes a hard guardian finding
    (grace 0: the vault is paused) as soon as the same burner sends a second redirect."""

    setUp = GuardianBlindRound.setUp
    findings_for = GuardianBlindRound.findings_for

    def verdict(self, burn, recipient20):
        self.g._senders = None
        return self.g.recipient_verdict(dict(burn, eth_recipient=burn['recipient']), recipient20, None)

    def test_r376_sol_4p_3_fixed_a_second_redirect_does_not_turn_the_first_ones_approval_into_a_finding(self):
        held = self.l2.direct(S.account_id(K.wallet_of('typed by habit')[1]))  # any held burn: direct, or no valid proof
        first = self.l2.redirect(held, 'first wallet, never creates its USDC account')
        w1 = S.account_id(first['wallet'])
        self.assertEqual(self.verdict(held, w1), ('ok', None), 'the signers certify and the relayer approves W1: honest')
        # The approval stands while W1 has no associated token account (the burner never creates it; the relayer
        # creates none by default). Then the burner sends a second redirect.
        second = self.l2.redirect(held, 'second wallet')
        # was: ('mismatch', None)
        self.assertEqual(self.verdict(held, w1), ('ok', None), 'an approval for an earlier PROVEN redirect stays honest')
        self.assertEqual(self.verdict(held, S.account_id(second['wallet'])), ('ok', None))
        self.assertEqual(self.verdict(held, S.account_id(K.wallet_of('never named')[1]))[0], 'mismatch')
        record = dict(held, nonce=held['nonce'])
        b = dict(record, eth_recipient=held['recipient'])
        unpaid = {'nonce': held['nonce'], 'seq': 1, 'state': 1, 'recipient': w1, 'amount': held['amount'],
                  'native_burn': S.unhex(held['burn_id'], 32), 'key': 'record', 'ready_at': 0}
        self.g.records = lambda: []
        self.g.release_records = lambda: [unpaid]
        self.node.token_balance = lambda address: {'mint': self.node.config.mint, 'owner': self.node.a.vault, 'amount': 10**12}
        self.node.vault['void_through_seq'] = 0
        self.g._senders = None
        _, _, findings = self.g.eth_source([b], fin=None)
        hard = [(f[0], f[1], f[2]) for f in findings if f[1].startswith('release-mismatch')]
        # was: [('hard', 'release-mismatch:approval-N-1', 0)] ('DEFECT: any burner of a held burn makes the guardians
        # pause the whole vault (72 h), repeatably')
        self.assertEqual(hard, [])
        # The same for a PAID record judged after the second redirect (a guardian restarted within the retention)
        self.g._paid_checked = {}
        self.assertEqual(self.findings_for(held, w1), [])  # was: ['release-mismatch:N']


class LatchFromOneEndpoint(unittest.TestCase):
    """R330-SOL-4P-2: one endpoint that shows a non-wallet once latches the hold for good, whatever the others say."""

    def test_r376_sol_4p_2_fixed_one_disagreeing_endpoint_holds_for_its_read_and_latches_nothing(self):
        c = T.Cluster()
        l2 = K.L2(self, c)
        holds = R.Holds(Path(tempfile.mkdtemp()) / 'db.json')
        burn = l2.exit('a real wallet with a valid proof')
        honest, lying = T.Fake(c.answer), None

        class Lying:
            """An endpoint (another operator's, or a lagging or faulty one) that shows a token account once."""
            calls = 0

            def account_info(self, wallet, commitment):
                Lying.calls += 1
                return {'owner': S.TOKEN_PROGRAM, 'data': bytes(165), 'executable': False, 'lamports': 2039280} \
                    if Lying.calls == 1 else None
        self.addCleanup(honest.close)
        lying = Lying()
        honest_rpc = S.Rpc(honest.url)
        view = R.exit_view(l2.cfg(), c.a, burn)
        first = R.decide(view, burn['burn_id'], holds, lambda w: R.destination([lying, honest_rpc], w, c.a))
        self.assertEqual(first['hold'], 'destination-not-a-wallet')  # any endpoint that shows a non-wallet holds
        self.assertFalse(first['destination']['unanimous'])
        self.assertIsNone(holds.get(burn['burn_id']), 'one endpoint alone latches nothing')
        # every endpoint now agrees that the address is absent (a fresh wallet whose key signed the proof)
        again = R.decide(view, burn['burn_id'], holds, lambda w: R.destination([lying, honest_rpc], w, c.a))
        # was: ('destination-not-a-wallet', True) ('DEFECT (availability): held for good by one endpoint's answer')
        self.assertEqual((again['hold'], again['latched'], again['target']), (None, False, 'original'))

    def test_every_endpoint_showing_the_non_wallet_still_latches(self):
        """Round 18 (agent 371), control for the 4P-2 fix: R330-SOL-3P-1's latch is kept when the endpoints agree."""
        c = T.Cluster()
        l2 = K.L2(self, c)
        holds = R.Holds(Path(tempfile.mkdtemp()) / 'db.json')
        burn = l2.exit('a token account at a keypair address')
        c.accounts[burn['wallet']] = (S.TOKEN_PROGRAM, bytes(165))
        one, two = T.Fake(c.answer), T.Fake(c.answer)
        self.addCleanup(one.close)
        self.addCleanup(two.close)
        rpcs = [S.Rpc(one.url), S.Rpc(two.url)]
        view = R.exit_view(l2.cfg(), c.a, burn)
        first = R.decide(view, burn['burn_id'], holds, lambda w: R.destination(rpcs, w, c.a))
        self.assertEqual((first['hold'], first['destination']['unanimous']), ('destination-not-a-wallet', True))
        del c.accounts[burn['wallet']]  # the owner closes it: every endpoint now shows the address absent
        again = R.decide(view, burn['burn_id'], holds, lambda w: R.destination(rpcs, w, c.a))
        self.assertEqual((again['hold'], again['latched']), ('destination-not-a-wallet', True))


class Controls(unittest.TestCase):
    """Properties that hold at b2fa301; restated where the WIP removed the older unit test."""

    def setUp(self):
        self.c = T.Cluster()
        self.l2 = K.L2(self, self.c)

    def decide(self, burn):
        return R.decide(R.exit_view(self.l2.cfg(), self.c.a, burn), burn['burn_id'], R.Holds(None), absent)

    def test_control_a_router_log_that_names_another_commitment_or_amount_counts_for_nothing(self):
        """Restates test_solana_tools `test_a_log_that_does_not_hash_to_the_recipient_counts_for_nothing` (removed)."""
        for field in ('commitment', 'amount'):
            burn = self.l2.exit(f'target {field}')
            log = next(l for l in reversed(self.l2.logs) if l['address'] == self.l2.router)
            data = bytearray(bytes.fromhex(log['data'][2:]))
            if field == 'commitment':
                data[44:64] = S.account_id(K.wallet_of('elsewhere')[1])
            else:
                data[0:32] = (burn['amount'] + 1).to_bytes(32, 'big')
            log['data'] = S.hx(bytes(data))
            verdict = self.decide(burn)
            self.assertEqual((verdict['target'], verdict['hold']), (None, 'no-router-log'), field)

    def test_control_two_router_logs_for_one_burn_hold_it(self):
        burn = self.l2.exit('doubled')
        log = next(l for l in reversed(self.l2.logs) if l['address'] == self.l2.router)
        self.l2.logs.append(dict(log))
        self.assertEqual(self.decide(burn)['hold'], 'no-router-log')

    def test_control_a_redirect_from_the_router_itself_or_another_contract_does_not_count(self):
        held = self.l2.exit(text=S.b58encode(K.keyless_address('r376')), proof=bytes(65))
        self.l2.redirect(held, 'router', sender=self.l2.router)
        self.assertEqual(self.decide(held)['hold'], 'invalid-proof')
        log = self.l2.logs[-1]
        log['address'] = '0x' + '33' * 20  # the same log emitted by a contract that is not the router
        log['topics'][2] = '0x' + '00' * 12 + held['burner'][2:]
        self.assertEqual(self.decide(held)['hold'], 'invalid-proof')

    def test_control_a_redirect_for_another_burn_id_does_not_carry_over(self):
        held = self.l2.exit(text=S.b58encode(K.keyless_address('r376 a')), proof=bytes(65))
        other = self.l2.exit(text=S.b58encode(K.keyless_address('r376 b')), proof=bytes(65))
        r = self.l2.redirect(other, 'mine')
        log = self.l2.logs[-1]
        log['topics'][1] = held['burn_id']  # the proof names `other`; the log is moved under `held`
        self.assertEqual(self.decide(held)['hold'], 'redirect-invalid-proof')
        self.assertTrue(r['nonce'] >= 0)

    def test_control_jacobian_secp256k1_equals_the_affine_reference(self):
        """The round-17 WIP replaced the affine scalar multiplication behind every in-process recovery."""
        def add(a, b):
            if a is None:
                return b
            if b is None:
                return a
            (x1, y1), (x2, y2) = a, b
            if x1 == x2:
                if (y1 + y2) % S._SP == 0:
                    return None
                m = 3 * x1 * x1 * pow(2 * y1, S._SP - 2, S._SP) % S._SP
            else:
                m = (y2 - y1) * pow(x2 - x1, S._SP - 2, S._SP) % S._SP
            x = (m * m - x1 - x2) % S._SP
            return x, (m * (x1 - x) - y1) % S._SP

        def mul(k, p):
            out = None
            while k:
                if k & 1:
                    out = add(out, p)
                p = add(p, p)
                k >>= 1
            return out
        rnd = random.Random(376)
        ks = [0, 1, 2, 3, S._SN - 1, S._SN, S._SN + 1, 2**256 - 1] + [rnd.randrange(1, 2**256) for _ in range(40)]
        points = [S._SG, mul(0xdeadbeef, S._SG)]
        for p in points:
            for k in ks:
                self.assertEqual(S._secp_mul(k, p), mul(k, p), k)
        for i in range(20):  # recovery end to end against the test kit's signer (the same throwaway keys)
            key = rnd.randrange(1, S._SN)
            digest = S.keccak256(bytes([i]))
            self.assertEqual(S.secp256k1_recover(digest, K.secp_sign(key, digest)), K.secp_address(key))


if __name__ == '__main__':
    unittest.main()
