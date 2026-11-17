#!/usr/bin/env python3
"""Review 378 (round 18, second pass of review 342) of agent 370's bBTC fixes. Demonstrations only; not product code.

  python3 -m unittest test_review_r18_378

Class `Findings`: each test states a property the route needs or its documents claim; it FAILS where the code does not
have it (the finding id is in the name). Class `Held`: attacks that did not work; these pass.
"""
import unittest

import btc_core as c
import btc_policy as pol
from test_btc_policy import vault, tip, dep


def after(b):
    return {'txid': b['tx'].txid(), 'vout': 0, 'value': b['tx'].outputs[0][0], 'marker': b['marker'], 'aside': b['aside'],
            'aside_at': b['aside_at']}


def burn(n, units=1_000):
    return {'nonce': n, 'units': units, 'recipient': bytes([1 + n % 200]) * 20}


def funded(v, sats=10**9):
    return after(pol.build_vault_tx(v, tip(200_000), [dep(0, sats)], [], [], 1))


def park(v, s, count):
    """`count` burns set aside, four per transaction, each transaction paying the next burn (the rule's shape:
    a set-aside travels with a paid burn). Returns (state, nonces set aside)."""
    parked = []
    while len(parked) < count:
        base = s['marker'].normalised().burn_base
        k = min(4, count - len(parked))
        b = pol.build_vault_tx(v, s, [], [], [burn(base + k + 1)], 1, aside_through=base + k, aside_block=10)
        parked += b['set_aside']
        s = after(b)
    return s, parked


class Findings(unittest.TestCase):
    def test_r342_btc_2p_1_a_burn_set_aside_after_256_abandoned_ones_is_payable(self):
        """A late payment names its burn by RANK among the burns set aside, in one byte (btc_core.LATE_RANKS 256;
        btc_policy.build_vault_tx refuses rank >= 256). The 256 oldest burns set aside are only paid after their own
        burners call the router (btc_signer.py check 4d). 256 direct burns that are never claimed (abandoned, lost
        keys, or one party that keeps them unclaimed on purpose: its coins are not lost, it can claim them any day) are
        set aside by the age rule and occupy ranks 0..255 for ever. Every burn set aside after them, whose burner DID
        call the router, can then never be paid."""
        v = vault()
        s, parked = park(v, funded(v), 256)
        self.assertEqual(len(s['aside']), 256)
        # an honest exit is set aside later (for example `blocked`, or a claim that came after the age rule)
        base = s['marker'].normalised().burn_base
        victim = base + 1
        s = after(pol.build_vault_tx(v, s, [], [], [burn(victim + 1)], 1, aside_through=victim, aside_block=20))
        self.assertIn(victim, s['aside'])
        # its burner calls the router (the signer's 4d is satisfied); the builder must be able to pay it late
        try:
            pol.build_vault_tx(v, s, [], [], [burn(victim)], 1)
        except pol.PolicyError as e:
            self.fail(f'R342-BTC-2P-1: the burn set aside after 256 unclaimed ones can never be paid late: {e.reason}')


class Held(unittest.TestCase):
    def test_a_set_aside_burn_is_not_set_aside_twice_and_is_paid_once(self):
        v = vault()
        s, parked = park(v, funded(v), 8)
        base = s['marker'].normalised().burn_base
        with self.assertRaises(pol.PolicyError):
            pol.build_vault_tx(v, s, [], [], [burn(base + 2)], 1, aside_through=parked[0], aside_block=11)
        s = after(pol.build_vault_tx(v, s, [], [], [burn(parked[0])], 1))
        with self.assertRaises(pol.PolicyError):
            pol.build_vault_tx(v, s, [], [], [burn(parked[0])], 1)

    def test_at_most_four_set_aside_per_transaction_and_never_with_a_stray_alone(self):
        v = vault()
        s = funded(v)
        with self.assertRaises(pol.PolicyError):
            pol.build_vault_tx(v, s, [], [], [burn(6)], 1, aside_through=5, aside_block=1)
        with self.assertRaises(pol.PolicyError):
            pol.build_vault_tx(v, s, [], [{'txid': 'cd' * 32, 'vout': 0, 'value': 20_000}], [], 1, aside_through=2, aside_block=1)


if __name__ == '__main__':
    unittest.main()
