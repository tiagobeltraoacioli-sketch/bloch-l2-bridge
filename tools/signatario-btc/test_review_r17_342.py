#!/usr/bin/env python3
"""Review 342 (round 17) of the bBTC marker v2 / set-aside rules. Demonstrations only; not product code.

Brought into the developer's branch by agent 332 from the review branch (commit b9592ee) for the fixes of
R342-BTC-1 and R342-BTC-4. Every change made to it is marked "332:" and says why; everything else is the reviewer's
text. `test_r342_btc_1_a_set_aside_needs_a_paying_item` and `test_r342_btc_4_...` pass UNCHANGED.

  python3 -m unittest test_review_r17_342

Class `Findings`: each test states the property the documents claim or the route needs; it FAILS where the code does
not have it (the finding id is in the name). Class `Held`: attacks that did not work; these pass.
"""
import random
import unittest

import btc_core as c
import btc_policy as pol
from test_btc_policy import vault, tip, dep


def after(b):
    return {'txid': b['tx'].txid(), 'vout': 0, 'value': b['tx'].outputs[0][0], 'marker': b['marker'], 'aside': b['aside']}


def burn(n, units=1_000):
    return {'nonce': n, 'units': units, 'recipient': bytes([1 + n % 250]) * 20}


def funded(v, sats=10**9):
    return after(pol.build_vault_tx(v, {**tip(200_000), 'aside': frozenset()}, [dep(0, sats)], [], [], 1))


class Findings(unittest.TestCase):
    def test_r342_btc_1_a_set_aside_needs_a_paying_item(self):
        """docs/BTC-BRIDGE.md 4a: "A transaction that only sets aside pays no miner charge and is refused by the pool
        rule, so a set-aside always rides with a paying item." A stray output that covers the fee is enough: nobody is
        paid, no deposit is swept, and the burns are set aside."""
        v = vault()
        s = funded(v)
        stray = {'txid': 'cd' * 32, 'vout': 0, 'value': 20_000}
        with self.assertRaises(pol.PolicyError, msg='a transaction that pays no burn and sweeps no deposit set burns 1..3 aside'):
            pol.build_vault_tx(v, s, [], [stray], [], 11, aside_through=3)

    def test_r342_btc_1_cost_of_setting_aside_512_burns(self):
        """One transaction sets aside 512 burns; getting them out again takes 128 transactions (4 late payments each),
        one per block at best. The asymmetry is what makes the move a brake."""
        v = vault()
        s = funded(v)
        stray = {'txid': 'cd' * 32, 'vout': 0, 'value': 20_000}
        # 332: the fix removes the asymmetry at its source, so the reviewer's body (set 512 aside in one transaction,
        # then count the transactions that pay them, expecting at most 13) can no longer start: one transaction sets
        # aside at most 4 burns, exactly what one transaction can pay late, and never with a stray alone. The
        # property is restated: N transactions in, N transactions out.
        for mark in (512, 5):
            with self.assertRaises(pol.PolicyError):
                pol.build_vault_tx(v, s, [], [stray], [burn(600)], 11, aside_through=mark)
        with self.assertRaises(pol.PolicyError):
            pol.build_vault_tx(v, s, [], [stray], [], 11, aside_through=4)
        txs_in = txs_out = 0
        for k in range(3):                                   # 12 burns: three transactions in
            s = after(pol.build_vault_tx(v, s, [], [], [burn(100 + k)], 11, aside_through=4 * (k + 1)))
            txs_in += 1
        self.assertEqual(len(s['aside']), 12)
        while s['aside']:
            s = after(pol.build_vault_tx(v, s, [], [], [burn(n) for n in sorted(s['aside'])[:4]], 1))
            txs_out += 1
        self.assertEqual((txs_in, txs_out), (3, 3))

    def test_r342_btc_4_a_late_payment_fits_whenever_an_ordinary_payment_fits(self):
        """A burn that was set aside and became payable should be payable whenever the thread can pay anything. The
        late list takes its 8 bytes from the bitmap: with a hole 257 or more nonces below the newest settled burn (a
        large release in its 12 h delay, a burn waiting for the daily window) no late payment can be encoded at all,
        and four late payments need the hole within 64 nonces."""
        v = vault()
        s = funded(v)
        m = s['marker']
        # burns 1, 2 set aside earlier; burn 4 is a claimed large burn in its delay (a hole); 5..300 already paid
        held = {**s, 'marker': c.Marker(m.next_deposit, 3, m.liabilities, m.owner_due, 1, range(5, 301)), 'aside': frozenset({1, 2})}
        pol.build_vault_tx(v, held, [], [], [burn(301)], 1)          # an ordinary payment fits
        try:
            pol.build_vault_tx(v, held, [], [], [burn(1)], 1)        # the late payment of burn 1 does not
        except pol.PolicyError as e:
            self.fail(f'late payment refused while an ordinary payment is accepted: {e.reason}')


class Held(unittest.TestCase):
    """Attacks on the rules that did not work."""

    def test_v1_markers_are_not_read_at_all(self):
        """There is no mixed v1/v2 thread: a round-16 marker (tag BBTC\\x01, no operations byte) is refused by decode, so
        replay holds on any thread that carries one. Stated here because the vault id, the thread tag and the policy
        `version` did not change with the marker format."""
        v1 = b'BBTC\x01' + (0).to_bytes(8, 'big') * 4 + (1).to_bytes(2, 'big')
        spk = bytes([c.OP_RETURN, len(v1)]) + v1
        with self.assertRaises(ValueError):
            c.Marker.decode(spk)
        v = vault()
        s = funded(v)
        b = pol.build_vault_tx(v, s, [], [], [burn(1)], 1)
        with self.assertRaises(pol.PolicyError):
            pol.replay_tx(v, s, b['inputs'], [b['tx'].outputs[0], (0, spk)] + b['tx'].outputs[2:])

    def test_marker_bytes_have_one_meaning(self):
        """300,000 random and mutated marker scripts: decode raises ValueError or returns a marker whose encoding is
        the same bytes; two different byte strings never decode to the same fields."""
        rnd = random.Random(342)
        seeds = [c.Marker(3, 7, 10**6, 55, 9, {9, 12, 200}).encode(),
                 c.Marker(3, 7, 10**6, 55, 9, {9, 12, 100}, 6, (2, 4)).encode(),
                 c.Marker(1, 0, 5, 0, 1, (), 0, (1, 2, 3, 4)).encode(),
                 c.Marker(1, 600, 5, 0, 1, range(602, 602 + 250), 600, ()).encode()]
        seen = {}
        for i in range(300_000):
            raw = bytearray(rnd.choice(seeds))
            for _ in range(rnd.randrange(1, 4)):
                k = rnd.randrange(3)
                if k == 0 and raw:
                    raw[rnd.randrange(len(raw))] ^= 1 << rnd.randrange(8)
                elif k == 1 and len(raw) > 2:
                    del raw[rnd.randrange(2, len(raw))]
                    raw[1] = (len(raw) - 2) & 0xff if raw[1] < 76 else raw[1]
                else:
                    raw.insert(rnd.randrange(2, len(raw) + 1), rnd.randrange(256))
                    raw[1] = (len(raw) - 2) & 0xff if raw[1] < 76 and len(raw) - 2 < 76 else raw[1]
            raw = bytes(raw)
            try:
                m = c.Marker.decode(raw)
            except ValueError:
                continue
            self.assertEqual(m.encode(), raw)
            # 332: format 3 has one more field (the L2 block of a set-aside); it is part of the meaning
            key = (m.next_deposit, m.burn_base, m.liabilities, m.owner_due, m.feerate, m.paid, m.aside_through, m.late, m.aside_block)
            self.assertEqual(seen.setdefault(key, raw), raw)

    def test_adversarial_sequences_replay_to_the_same_state_and_never_pay_twice(self):
        """An independent random walk that tries what a relayer or five keys inside the rules could try: marks over
        ranges that hold paid bits, late payments in any mix, payments of burns already settled, paid twice, set aside
        and paid at once, revived after a late payment. Every accepted transaction replays from its own bytes to the
        same marker and the same set; liabilities fall only by burns paid; no nonce is ever paid twice or set aside
        again after it was paid; a burn set aside is never dropped from the set except by its late payment."""
        rnd = random.Random(3420)
        v = vault(windowLimitSats=10**13)
        s = funded(v, 10**9)
        owed0 = s['marker'].liabilities
        paid_once, ever_aside, top = set(), set(), 0
        accepted = 0
        for step in range(45_000):   # 370: 30,000 in pass 1; longer so the restored floors hold
            m = s['marker'].normalised()
            top = max(top, m.burn_base + max([0] + [n - m.burn_base for n in m.paid]))
            mark = rnd.choice([0, 0, m.burn_base + rnd.randrange(1, 12), m.burn_base + rnd.randrange(1, 900), rnd.randrange(0, top + 3),
                               m.burn_base + rnd.randrange(1, 6), m.burn_base + rnd.randrange(1, 6)])   # 370: marks the rules can accept
            pool = list(range(max(1, m.burn_base - 6), m.burn_base + 30)) + sorted(s['aside'])[:8] + sorted(paid_once)[-3:]
            names = rnd.sample(pool, min(len(pool), rnd.randrange(0, 7)))
            if rnd.random() < 0.05 and names:
                names.append(names[0])
            try:
                b = pol.build_vault_tx(v, s, [], [], [burn(n) for n in names], rnd.choice([1, 3, 50]), aside_through=mark)
            except pol.PolicyError:
                continue
            accepted += 1
            for x in b['payouts']:
                self.assertNotIn(x['nonce'], paid_once)
                paid_once.add(x['nonce'])
            for n in b['set_aside']:
                self.assertNotIn(n, paid_once)
                self.assertNotIn(n, ever_aside)
                ever_aside.add(n)
            self.assertEqual(set(b['aside']), ever_aside - paid_once)
            self.assertEqual(b['marker'].liabilities, owed0 - 100_000 * len(paid_once))
            again = pol.replay_tx(v, s, b['inputs'], b['tx'].outputs)
            self.assertEqual((again['tx'].serialize(), again['marker'].encode(), again['aside'], again['late'], again['set_aside']),
                             (b['tx'].serialize(), b['marker'].encode(), b['aside'], b['late'], b['set_aside']))
            # the same outputs do not replay on any other parent state (the next one)
            s2 = after(b)
            with self.assertRaises(pol.PolicyError):
                pol.replay_tx(v, s2, [{**b['inputs'][0], 'txid': s2['txid'], 'value': s2['value']}], b['tx'].outputs)
            s = s2
            for n in paid_once:
                self.assertTrue(pol.burn_paid(s, n))
            for n in s['aside']:
                self.assertTrue(s['marker'].is_paid(n) and not pol.burn_paid(s, n))
        # Review 342's floors restored (round 18, R342-BTC-2P-6): the stricter rules (at most 4 set aside, only with a
        # paying item) accept fewer of the generator's moves, so the generator also proposes marks the rules can accept
        # (two more choices, within 5 of the base); every earlier move is still proposed and checked.
        self.assertGreater(accepted, 1_500)
        self.assertGreater(len(ever_aside & paid_once), 100)   # late payments happened

    def test_replay_cannot_be_made_to_drop_or_invent_a_set_aside_burn(self):
        """Markers edited by hand on a transaction that sets aside 1..2 and pays 3, and on a late payment: every edit
        of `aside_through` or `late` that keeps the same settled nonces (1, 2, 3) but changes which of them were paid
        is refused by replay."""
        v = vault()
        s0 = funded(v)
        b = pol.build_vault_tx(v, s0, [], [], [burn(3)], 2, aside_through=2)
        good = c.Marker.decode(b['tx'].outputs[1][1])
        rnd = random.Random(1)
        refused = 0
        for _ in range(3_000):
            base = good.burn_base + rnd.choice([0, 0, -1, 1, 2])
            paid = set(good.paid) ^ set(rnd.sample(range(base + 1, base + 12), rnd.randrange(0, 3)))
            m = c.Marker(good.next_deposit, max(0, base), good.liabilities, good.owner_due, good.feerate, paid,
                         rnd.choice([0, 1, 2, 3, 4]), tuple(sorted(rnd.sample(range(1, 6), rnd.randrange(0, 3)))))
            try:
                spk = m.encode()
            except ValueError:
                continue
            n = m.normalised()
            settled = set(range(1, n.burn_base + 1)) | set(n.paid)
            if spk == b['tx'].outputs[1][1] or settled != {1, 2, 3}:
                continue   # another settled set is another transaction (the payout then belongs to another nonce)
            with self.assertRaises(pol.PolicyError):
                pol.replay_tx(v, s0, b['inputs'], [b['tx'].outputs[0], (0, spk)] + b['tx'].outputs[2:])
            refused += 1
        self.assertGreater(refused, 100)


if __name__ == '__main__':
    unittest.main()
