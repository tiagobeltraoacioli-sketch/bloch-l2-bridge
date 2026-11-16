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
        # R325-BTC-2P-3: target and mode are pinned by the signer, never the node's default
        assert method == 'estimatesmartfee' and params == (2, 'economical'), params
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
    def test_refund_texts_bind_everything_and_recover_the_signer(self):
        priv = t.PRIVS[0]
        who = c.eth_address(c.pubkey(priv))
        vid = t.vault().vault_id
        text = c.refund_text(vid, 'ab' * 32, 1, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
        r, s, v = c.sign(c.personal_digest(text), priv)
        sig = '0x' + (r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + v])).hex()
        self.assertEqual(c.signer_of(text, sig), who)
        for other in (c.refund_text(vid, 'ab' * 32, 2, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
                      c.refund_text(bytes(12), 'ab' * 32, 1, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
                      c.refund_text(vid, 'ab' * 32, 1, 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk')):
            self.assertNotEqual(c.signer_of(other, sig), who)

    def test_only_a_p2wpkh_address_of_the_network_is_a_destination(self):
        self.assertEqual(c.p2wpkh_hash('bitcoin-mainnet', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').hex(),
                         '751e76e8199196d454941c45d1b3a323f1433bd6')
        for bad in ('0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544', 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
                    'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', '', None, 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'):
            with self.assertRaises(c.BadAddress):
                c.p2wpkh_hash('bitcoin-mainnet', bad)


class FakeRouterRpc:
    """Stands for the L2 RPC a btc_l2.Router reads: maxFeeRateOf(bytes32) and claimOf(address,uint64)."""

    def __init__(self, rates=None, claims=None):
        self.rates, self.claims, self.asked = rates or {}, claims or {}, []

    def rpc(self, method, params):
        assert method == 'eth_call'
        data = bytes.fromhex(params[0]['data'][2:])
        self.asked.append((data[:4].hex(), params[1]))
        if data[:4] == c.keccak256(b'maxFeeRateOf(bytes32)')[:4]:
            return '0x' + self.rates.get(data[4:36].hex(), 0).to_bytes(32, 'big').hex()
        if data[:4] == c.keccak256(b'claimOf(address,uint64)')[:4]:
            key, rate = self.claims.get((data[16:36].hex(), int.from_bytes(data[36:68], 'big')), (bytes(20), 0))
            return '0x' + (key.ljust(32, b'\0') + rate.to_bytes(32, 'big')).hex()
        raise AssertionError('unexpected call')


class BurnTerms(unittest.TestCase):
    """R325-BTC-2P-1 and -2P-2: where a burn is paid and the highest fee rate its burner accepts."""
    ROUTER, ALICE, BOB = '0x' + 'aa' * 20, '0x' + '0a' * 20, '0x' + '0b' * 20
    NAMED = bytes.fromhex('0a' * 20)   # a direct burner named its own Ethereum address

    def terms(self, rpc, burner, burn_id='11' * 32, nonce=5):
        import btc_l2
        return btc_l2.burn_terms(btc_l2.Router(rpc, self.ROUTER), self.ROUTER, burner, '0x' + burn_id, nonce, self.NAMED, '0x10')

    def test_a_router_burn_is_paid_as_named_under_its_own_ceiling(self):
        rpc = FakeRouterRpc(rates={'11' * 32: 37})
        t = self.terms(rpc, self.ROUTER.upper().replace('0X', '0x'))
        self.assertEqual(t, {'through_router': True, 'destination': self.NAMED, 'max_fee_rate': 37, 'state': 'payable'})
        self.assertEqual(rpc.asked[0][1], '0x10')   # read at the block the caller verified, not at the latest

    def test_a_direct_burn_without_a_claim_is_never_payable_whatever_it_names_and_whoever_burned(self):
        import btc_l2
        for burner in (self.ALICE, self.BOB):
            t = self.terms(FakeRouterRpc(), burner)
            self.assertEqual((t['state'], t['destination'], t['max_fee_rate']), ('unclaimed', None, None))
        # a claim by ANOTHER account for the same nonce does not make it payable
        key = bytes.fromhex('cc' * 20)
        rpc = FakeRouterRpc(claims={(self.BOB[2:], 5): (key, 20)})
        self.assertEqual(self.terms(rpc, self.ALICE)['state'], 'unclaimed')
        # the burner's own claim does, and the 20 bytes the burn named are not the destination
        t = self.terms(rpc, self.BOB)
        self.assertEqual(t, {'through_router': False, 'destination': key, 'max_fee_rate': 20, 'state': 'payable'})
        self.assertNotEqual(t['destination'], self.NAMED)
        # a claim for another nonce is not this burn's
        self.assertEqual(self.terms(rpc, self.BOB, nonce=6)['state'], 'unclaimed')
        # a router that records no ceiling for a burn it supposedly made is not the pinned router
        with self.assertRaises(btc_l2.L2Error):
            self.terms(FakeRouterRpc(), self.ROUTER)

    def test_the_signer_has_no_timeout_and_no_claim_by_signature_left(self):
        import inspect
        import btc_policy as pol
        self.assertNotIn('directBurnClaimSeconds', pol.DEFAULT_POLICY)
        self.assertFalse(hasattr(pol, 'direct_burn_payable_at') or hasattr(c, 'claim_text'))
        src = inspect.getsource(btc_signer.cmd_sign)
        self.assertNotIn('destination = named', src)       # the old blind payment
        self.assertIn("t['state'] == 'unclaimed'", src)


class FeeStatus(unittest.TestCase):
    """R325-BTC-2P-3: a signer without an estimate is an alert of its own."""

    def run_status(self, estimate, network):
        import contextlib
        import io
        import json
        import btc_policy as pol
        import btc_vault
        v = pol.Vault(network, 5, t.KEYS, 'aa' * 32, 0, 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk' if network == 'bitcoin-mainnet'
                      else t.owner_regtest(), pol.DEFAULT_POLICY)
        node = FakeNode(estimate)
        node.check_network = lambda: None
        saved = btc_vault.load_vault, btc_vault.Node
        btc_vault.load_vault, btc_vault.Node = (lambda path: v), (lambda *a, **k: node)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                try:
                    btc_signer.cmd_fee_status({'vault': 'x', 'btc_rpc': 'x', 'btc_cookie': 'x'})
                    code = 0
                except SystemExit as e:
                    code = e.code
        finally:
            btc_vault.load_vault, btc_vault.Node = saved
        return code, json.loads(out.getvalue())

    def test_fee_status(self):
        code, line = self.run_status(Decimal('0.00020000'), 'bitcoin-mainnet')
        self.assertEqual((code, line['status'], line['ceiling'], line['estimate_mode'], line['signs']), (0, 'ok', 30, 'economical', True))
        code, line = self.run_status(None, 'bitcoin-mainnet')
        self.assertEqual((code, line['status'], line['severity'], line['signs']), (2, 'alert', 'critical', False))
        code, line = self.run_status(None, 'bitcoin-regtest')
        self.assertEqual((code, line['status'], line['severity'], line['signs']), (2, 'alert', 'warning', True))


if __name__ == '__main__':
    unittest.main()
