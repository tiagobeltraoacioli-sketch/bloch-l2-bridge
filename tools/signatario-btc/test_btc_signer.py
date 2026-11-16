#!/usr/bin/env python3
"""Offline tests of the signer's fee band and of the signed requests.  python3 -m unittest test_btc_signer"""
from decimal import Decimal
import unittest

import btc_core as c
import btc_signer
import test_btc_policy as t


class FakeNode:
    def __init__(self, estimate):
        self.estimate = estimate

    def call(self, method, *params):
        assert method == 'estimatesmartfee' and params == (2,)
        return {'blocks': 2, **({'feerate': self.estimate} if self.estimate is not None else {'errors': ['Insufficient data']})}


class FeeBand(unittest.TestCase):
    def test_the_ceiling_is_one_and_a_half_times_the_nodes_own_estimate(self):
        v = t.vault()
        for btc_per_kvb, want in (('0.00001000', 2), ('0.00010000', 15), ('0.00013000', 20), ('0.00100000', 150),
                                  ('0.00500000', 200), ('0.00000100', 1)):
            self.assertEqual(btc_signer.fee_ceiling({}, FakeNode(Decimal(btc_per_kvb)), v), want, btc_per_kvb)
        # a relayer cannot lift it: no configured value is read when the node has an estimate
        self.assertEqual(btc_signer.fee_ceiling({'feerate_without_estimate': 200}, FakeNode(Decimal('0.00001000')), v), 2)

    def test_without_an_estimate_mainnet_signs_nothing_and_a_test_network_uses_its_setting(self):
        self.assertEqual(btc_signer.fee_ceiling({'feerate_without_estimate': 6}, FakeNode(None), t.vault()), 6)
        self.assertEqual(btc_signer.fee_ceiling({}, FakeNode(None), t.vault()), 1)
        import btc_policy as pol
        mainnet = pol.Vault('bitcoin-mainnet', 5, t.KEYS, 'aa' * 32, 0, 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk', pol.DEFAULT_POLICY)
        with self.assertRaises(SystemExit):
            btc_signer.fee_ceiling({'feerate_without_estimate': 200}, FakeNode(None), mainnet)


class Requests(unittest.TestCase):
    def test_refund_and_claim_texts_bind_everything_and_recover_the_signer(self):
        priv = t.PRIVS[0]
        who = c.eth_address(c.pubkey(priv))
        vid = t.vault().vault_id
        text = c.refund_text(vid, 'ab' * 32, 1, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
        r, s, v = c.sign(c.personal_digest(text), priv)
        sig = '0x' + (r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + v])).hex()
        self.assertEqual(c.signer_of(text, sig), who)
        for other in (c.refund_text(vid, 'ab' * 32, 2, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
                      c.refund_text(bytes(12), 'ab' * 32, 1, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
                      c.refund_text(vid, 'ab' * 32, 1, 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk'),
                      c.claim_text(vid, 700770, '0x' + '11' * 20, 1, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')):
            self.assertNotEqual(c.signer_of(other, sig), who)
        self.assertNotEqual(c.claim_text(vid, 700770, '0x' + '11' * 20, 1, 'a'), c.claim_text(vid, 700770, '0x' + '11' * 20, 2, 'a'))
        self.assertNotEqual(c.claim_text(vid, 700770, '0x' + '11' * 20, 1, 'a'), c.claim_text(vid, 700771, '0x' + '11' * 20, 1, 'a'))

    def test_only_a_p2wpkh_address_of_the_network_is_a_destination(self):
        self.assertEqual(c.p2wpkh_hash('bitcoin-mainnet', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').hex(),
                         '751e76e8199196d454941c45d1b3a323f1433bd6')
        for bad in ('0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544', 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
                    'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', '', None, 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'):
            with self.assertRaises(c.BadAddress):
                c.p2wpkh_hash('bitcoin-mainnet', bad)


if __name__ == '__main__':
    unittest.main()
