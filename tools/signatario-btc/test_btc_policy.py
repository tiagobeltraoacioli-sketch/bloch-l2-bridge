#!/usr/bin/env python3
"""Unit and property tests of the pure Bitcoin vault rules (no node needed).  python3 -m unittest test_btc_policy"""
import hashlib
import random
import unittest

import btc_core as c
import btc_policy as pol

PRIVS = [int.from_bytes(hashlib.sha256(b'throwaway-btc-signer-%d' % i).digest(), 'big') % c.N for i in range(7)]
KEYS = [c.pubkey(k) for k in PRIVS]
OWNER = 'bcrt1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx229k7gu9'


def owner_regtest():
    return c.address_from_spk('bitcoin-regtest', c.spk_from_address('bitcoin-mainnet', 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk'))


BIG = {'maxDepositSats': 10**9, 'capSats': 10**13}


def vault(**over):
    return pol.Vault('bitcoin-regtest', 5, KEYS, 'aa' * 32, 0, owner_regtest(), {**pol.DEFAULT_POLICY, **BIG, **over})


def tip(value=300_000, marker=None, txid='bb' * 32):
    return {'txid': txid, 'vout': 0, 'value': value, 'marker': marker or c.Marker()}


def dep(i, value, recipient=None):
    return {'txid': '%064x' % (1000 + i), 'vout': i % 3, 'value': value, 'recipient': recipient or bytes([i + 1]) * 20}


class Core(unittest.TestCase):
    def test_bip173_vectors(self):
        self.assertEqual(c.spk_from_address('bitcoin-mainnet', 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4').hex(),
                         '0014751e76e8199196d454941c45d1b3a323f1433bd6')
        spk = bytes.fromhex('00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262')
        self.assertEqual(c.address_from_spk('bitcoin-testnet4', spk),
                         'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7')
        for bad in ('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5', 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
                    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du', ''):
            with self.assertRaises(c.BadAddress):
                c.spk_from_address('bitcoin-mainnet', bad)

    def test_owner_address_is_p2wpkh(self):
        spk = c.spk_from_address('bitcoin-mainnet', 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk')
        self.assertTrue(c.is_standard_payout(spk))
        self.assertEqual(c.address_from_spk('bitcoin-mainnet', spk), 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk')

    def test_keccak_and_ecdsa(self):
        self.assertEqual(c.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(c.eth_address(c.pubkey(int('59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', 16))),
                         '0x70997970c51812dc3a010c7d01b50e0d17dc79c8')
        d = c.sha256(b'digest')
        r, s, v = c.sign(d, PRIVS[0])
        self.assertTrue(c.verify(d, r, s, KEYS[0]) and not c.verify(d, r, s, KEYS[1]))
        self.assertEqual(c.recover(d, r, s, v + 27), KEYS[0])
        self.assertLessEqual(s, c.N // 2)
        der = c.der_sig(r, c.N - s)  # a high s is normalised
        self.assertEqual(der, c.der_sig(r, s))
        self.assertTrue(der[0] == 0x30 and der[-1] == 1 and len(der) <= 72)

    def test_bip143_p2wsh_known_answer(self):
        # BIP143 "P2WSH" example is multi-input with other sighash types; this is the native P2WPKH example's
        # hashPrevouts/hashSequence/hashOutputs machinery checked through a one-input vector built by hand.
        tx = c.Tx([('00' * 31 + '01', 0)], [(1000, b'\x00\x14' + b'\x11' * 20)])
        pre = (b'\x02\x00\x00\x00' + c.sha256d(bytes.fromhex('00' * 31 + '01')[::-1] + b'\0\0\0\0')
               + c.sha256d(c.SEQUENCE.to_bytes(4, 'little')) + bytes.fromhex('00' * 31 + '01')[::-1] + b'\0\0\0\0'
               + b'\x01\x51' + (5000).to_bytes(8, 'little') + c.SEQUENCE.to_bytes(4, 'little')
               + c.sha256d((1000).to_bytes(8, 'little') + b'\x16\x00\x14' + b'\x11' * 20) + b'\0\0\0\0' + b'\x01\0\0\0')
        self.assertEqual(tx.sighash(0, b'\x51', 5000), c.sha256d(pre))

    def test_marker_roundtrip_and_canonical(self):
        rnd = random.Random(1)
        for _ in range(300):
            base = rnd.randrange(0, 1 << 40)
            paid = {base + 1 + rnd.randrange(0, 8 * c.MAX_BITMAP) for _ in range(rnd.randrange(0, 30))}
            m = c.Marker(rnd.randrange(1 << 40), base, rnd.randrange(1 << 50), rnd.randrange(1 << 30), rnd.randrange(1, 500), paid)
            try:
                spk = m.encode()
            except ValueError:
                continue  # normalisation pushed a nonce out of the window: refused, never mis-encoded
            self.assertLessEqual(len(spk), 83)
            back = c.Marker.decode(spk)
            self.assertEqual(back.as_dict(), m.normalised().as_dict())
            for n in paid:
                self.assertTrue(back.is_paid(n))
        with self.assertRaises(ValueError):
            c.Marker(0, 0, 0, 0, 1, {1 + 8 * c.MAX_BITMAP}).encode()
        spk = c.Marker(1, 0, 5, 0, 1, {2}).encode()
        with self.assertRaises(ValueError):
            c.Marker.decode(spk + b'\0')
        with self.assertRaises(ValueError):
            c.Marker.decode(spk[:1] + bytes([spk[1] + 1]) + spk[2:] + b'\0')  # trailing zero bitmap byte


class Addresses(unittest.TestCase):
    def test_deposit_address_commits_recipient_vault_and_keys(self):
        v = vault()
        a = v.deposit_address(b'\x01' * 20)
        self.assertNotEqual(a, v.deposit_address(b'\x02' * 20))
        self.assertNotEqual(a, v.thread_address())
        other = pol.Vault('bitcoin-regtest', 5, KEYS, 'ab' * 32, 0, owner_regtest(), pol.DEFAULT_POLICY)
        self.assertNotEqual(a, other.deposit_address(b'\x01' * 20))
        self.assertEqual(v.thread_address(), other.thread_address())
        self.assertEqual(v.recipient_of_script(v.deposit_script(b'\x07' * 20)), b'\x07' * 20)
        self.assertIsNone(v.recipient_of_script(v.thread_script))
        with self.assertRaises(pol.PolicyError):
            v.recipient_of_script(other.deposit_script(b'\x07' * 20))
        with self.assertRaises(c.BadAddress):
            v.deposit_script(b'\0' * 20)
        self.assertLessEqual(len(v.deposit_script(b'\x01' * 20)), 3600)

    def test_route_moves_with_every_fixed_value(self):
        base = vault().route
        self.assertNotEqual(base, vault(windowLimitSats=1).route)
        self.assertNotEqual(base, pol.Vault('bitcoin-regtest', 4, KEYS, 'aa' * 32, 0, owner_regtest(), vault().policy).route)
        self.assertNotEqual(base, pol.Vault('bitcoin-regtest', 5, KEYS, 'aa' * 32, 1, owner_regtest(), vault().policy).route)
        self.assertNotEqual(base, pol.Vault('bitcoin-regtest', 5, KEYS, 'aa' * 32, 0, vault().thread_address(), vault().policy).route)
        self.assertEqual(base, pol.Vault('bitcoin-regtest', 5, list(reversed(KEYS)), 'aa' * 32, 0, owner_regtest(), vault().policy).route)

    def test_policy_validation(self):
        for bad in ({'depositFeeBps': 31}, {'releaseFeeBps': 0}, {'unitSats': 1}, {'minConfirmations': 0}, {'dustSats': 100}):
            with self.assertRaises(pol.PolicyError):
                vault(**bad)
        with self.assertRaises(pol.PolicyError):
            pol.policy_hash({**pol.DEFAULT_POLICY, 'extra': 1})


class Builder(unittest.TestCase):
    def test_deposit_then_release_accounting(self):
        v = vault()
        b = pol.build_vault_tx(v, tip(), [dep(0, 1_000_000)], [], [], 2)
        cr = b['credits'][0]
        fee, charge = 500, 2 * (v.deposit_vb + v.overhead_vb)
        self.assertEqual(cr['units'], (1_000_000 - fee - charge) // 100)
        self.assertEqual(int.from_bytes(cr['deposit_id'][:8], 'big'), 0)
        m = b['marker']
        self.assertEqual((m.next_deposit, m.liabilities), (1, cr['units'] * 100))
        tx = b['tx']
        self.assertEqual(300_000 + 1_000_000, sum(s for s, _ in tx.outputs) + b['fee'])
        self.assertGreaterEqual(tx.outputs[0][0], m.liabilities + m.owner_due)
        t2 = {'txid': tx.txid(), 'vout': 0, 'value': tx.outputs[0][0], 'marker': m}
        b2 = pol.build_vault_tx(v, t2, [], [], [{'nonce': 1, 'units': 5000, 'recipient': b'\x33' * 20}], 2)
        pay = b2['payouts'][0]
        self.assertEqual(pay['sats'], 500_000 - 250 - 2 * (31 + v.overhead_vb))
        self.assertEqual(b2['marker'].burn_base, 1)
        self.assertEqual(b2['marker'].liabilities, m.liabilities - 500_000)
        t3 = {'txid': b2['tx'].txid(), 'vout': 0, 'value': b2['tx'].outputs[0][0], 'marker': b2['marker']}
        with self.assertRaises(pol.PolicyError) as e:  # replay
            pol.build_vault_tx(v, t3, [], [], [{'nonce': 1, 'units': 5000, 'recipient': b'\x33' * 20}], 2)
        self.assertIn('already paid', e.exception.reason)
        with self.assertRaises(pol.PolicyError) as e:  # more than the vault owes
            pol.build_vault_tx(v, t3, [], [], [{'nonce': 2, 'units': 10**7, 'recipient': b'\x33' * 20}], 2)
        self.assertIn('exceed what the vault owes', e.exception.reason)

    def test_refusals(self):
        v = vault()
        for kw, word in (({'deposits': [dep(0, 19_999)]}, 'below the minimum'),
                         ({'deposits': [dep(0, 10**9 + 1)]}, 'above the maximum'),
                         ({'deposits': [dep(0, 30_000)], 'feerate': 60}, 'miner charge exceeds'),
                         ({'feerate': 0, 'deposits': [dep(0, 10**6)]}, 'fee rate'),
                         ({'feerate': 501, 'deposits': [dep(0, 10**6)]}, 'fee rate'),
                         ({'deposits': [dep(0, 10**6), dep(0, 10**6)]}, 'named twice'),
                         ({}, 'empty vault transaction'),
                         ({'burns': [{'nonce': 0, 'units': 5, 'recipient': b'\x01' * 20}]}, 'already paid'),
                         ({'burns': [{'nonce': 1, 'units': 5000, 'recipient': b'\0' * 20}]}, 'no Bitcoin key hash'),
                         ({'burns': [{'nonce': 400, 'units': 5000, 'recipient': b'\x01' * 20}],
                           'deposits': [dep(0, 10**6)]}, 'outside the marker window')):
            args = {'deposits': [], 'donations': [], 'burns': [], 'feerate': 2, **kw}
            with self.assertRaises(pol.PolicyError, msg=word) as e:
                pol.build_vault_tx(v, tip(value=150_000), args['deposits'], args['donations'], args['burns'], args['feerate'])
            self.assertIn(word, e.exception.reason)

    def test_owner_fee_output_and_pool_surplus(self):
        v = vault()
        b = pol.build_vault_tx(v, tip(value=300_000), [dep(0, 50_000_000)], [], [], 1)
        self.assertEqual(b['tx'].outputs[-1][1], v.owner_spk)
        # bridge fee 25,000 + the pool surplus above the target
        self.assertEqual(b['owner_paid'], 25_000 + (300_000 + b['credits'][0]['charge'] + (50_000_000 - 25_000 - b['credits'][0]['charge']) % 100
                                                    - b['fee'] - 200_000))
        self.assertEqual(b['marker'].owner_due, 0)
        self.assertEqual(b['pool'], 200_000)
        small = pol.build_vault_tx(v, tip(value=100_000), [dep(0, 1_000_000)], [], [], 1)
        self.assertEqual(small['owner_paid'], 0)
        self.assertEqual(small['marker'].owner_due, 500)  # carried until it reaches ownerPayoutMinSats
        self.assertNotIn(v.owner_spk, [k for _, k in small['tx'].outputs])

    def test_property_conservation_solvency_replay(self):
        rnd = random.Random(7)
        v = vault(windowLimitSats=10**12)
        state = tip(value=250_000)
        nonce, burned, outstanding_units, used = 0, 0, 0, set()
        for step in range(250):
            deposits = [dep(step * 5 + j, rnd.choice([20_000, 55_555, 123_456, 10**6, 3 * 10**8, rnd.randrange(20_000, 10**7)]),
                            bytes([rnd.randrange(1, 255)]) * 20) for j in range(rnd.randrange(0, 4))]
            burns = []
            for _ in range(rnd.randrange(0, 4)):
                units = rnd.randrange(500, 200_000)
                if units <= outstanding_units:
                    burned += 1
                    burns.append({'nonce': burned, 'units': units, 'recipient': bytes([rnd.randrange(1, 255)]) * 20})
                    outstanding_units -= units
            donations = [{'txid': '%064x' % (9_000_000 + step), 'vout': 1, 'value': 4_000}] if rnd.random() < 0.1 else []
            feerate = rnd.choice([1, 1, 2, 3, 5, 8])
            try:
                b = pol.build_vault_tx(v, state, deposits, donations, burns, feerate)
            except pol.PolicyError as e:
                # the only acceptable refusals in this generator
                self.assertTrue(e.wait or 'empty' in e.reason or 'below' in e.reason, e.reason)
                for x in burns:
                    outstanding_units += x['units']
                burned -= len(burns)
                continue
            tx, m = b['tx'], b['marker']
            total_in = state['value'] + sum(d['value'] for d in deposits) + sum(d['value'] for d in donations)
            self.assertEqual(total_in, sum(s for s, _ in tx.outputs) + b['fee'])           # conservation
            self.assertGreaterEqual(tx.outputs[0][0], m.liabilities + m.owner_due)          # solvency
            self.assertEqual(tx.outputs[0][0] - m.liabilities - m.owner_due, b['pool'])
            self.assertLessEqual(b['pool'], v.policy['poolTargetSats'])
            outstanding_units += sum(cr['units'] for cr in b['credits'])
            self.assertEqual(m.liabilities, outstanding_units * 100)                        # books = L2 supply
            for cr in b['credits']:
                self.assertEqual(cr['nonce'], nonce)
                nonce += 1
                self.assertNotIn(cr['deposit_id'], used)
                used.add(cr['deposit_id'])
            for x in burns:
                self.assertTrue(m.is_paid(x['nonce']))
            # anyone can re-derive the transaction from chain data alone
            again = pol.replay_tx(v, state, b['inputs'], tx.outputs)
            self.assertEqual(again['tx'].txid(), tx.txid())
            self.assertEqual([(x['nonce'], x['units']) for x in again['payouts']], [(x['nonce'], x['units']) for x in b['payouts']])
            # a tampered output is not a rules transaction
            if len(tx.outputs) > 2:
                bad = list(tx.outputs)
                bad[2] = (bad[2][0] + 1, bad[2][1])
                with self.assertRaises(pol.PolicyError):
                    pol.replay_tx(v, state, b['inputs'], bad)
            state = {'txid': tx.txid(), 'vout': 0, 'value': tx.outputs[0][0], 'marker': m}
        self.assertGreater(nonce, 100)

    def test_out_of_order_burns_and_bitmap(self):
        v = vault()
        b = pol.build_vault_tx(v, tip(), [dep(0, 10**8)], [], [], 1)
        s = {'txid': b['tx'].txid(), 'vout': 0, 'value': b['tx'].outputs[0][0], 'marker': b['marker']}
        b = pol.build_vault_tx(v, s, [], [], [{'nonce': 3, 'units': 1000, 'recipient': b'\x05' * 20}], 1)
        self.assertEqual((b['marker'].burn_base, sorted(b['marker'].paid)), (0, [3]))
        s = {'txid': b['tx'].txid(), 'vout': 0, 'value': b['tx'].outputs[0][0], 'marker': b['marker']}
        b = pol.build_vault_tx(v, s, [], [], [{'nonce': n, 'units': 1000, 'recipient': b'\x05' * 20} for n in (2, 1)], 1)
        self.assertEqual((b['marker'].burn_base, sorted(b['marker'].paid)), (3, []))
        self.assertEqual([x['nonce'] for x in b['payouts']], [1, 2])

    def test_replacement_conflicts_and_charges_more(self):
        v = vault()
        low = pol.build_vault_tx(v, tip(), [dep(0, 10**7)], [], [], 1)
        high = pol.build_vault_tx(v, tip(), [dep(0, 10**7)], [], [], 9)
        self.assertEqual(low['tx'].inputs, high['tx'].inputs)  # same inputs: only one can confirm
        self.assertGreater(high['fee'], low['fee'])
        self.assertLess(high['credits'][0]['units'], low['credits'][0]['units'])
        self.assertNotEqual(high['credits'][0]['deposit_id'], low['credits'][0]['deposit_id'])


class Cap(unittest.TestCase):
    def test_sweeps_stop_at_the_supply_cap_and_resume_after_burns(self):
        v = vault(maxDepositSats=10**7, capSats=2 * 10**7)
        b = pol.build_vault_tx(v, tip(), [dep(0, 10**7), dep(1, 10**7)], [], [], 1)
        s = {'txid': b['tx'].txid(), 'vout': 0, 'value': b['tx'].outputs[0][0], 'marker': b['marker']}
        with self.assertRaises(pol.PolicyError) as e:
            pol.build_vault_tx(v, s, [dep(2, 10**6)], [], [], 1)
        self.assertTrue(e.exception.wait and 'supply cap' in e.exception.reason)
        # a burn in the same transaction makes room; releases alone are never blocked by the cap
        ok = pol.build_vault_tx(v, s, [dep(2, 10**6)], [], [{'nonce': 1, 'units': 20_000, 'recipient': b'\x01' * 20}], 1)
        self.assertLessEqual(ok['marker'].liabilities, 2 * 10**7)
        pol.build_vault_tx(v, s, [], [], [{'nonce': 1, 'units': 600, 'recipient': b'\x01' * 20}], 1)
        for bad in ({'maxDepositSats': 10}, {'capSats': 10**6, 'maxDepositSats': 10**7}):
            with self.assertRaises(pol.PolicyError):
                vault(**bad)


class Rules(unittest.TestCase):
    def test_required_confirmations(self):
        p = pol.DEFAULT_POLICY
        self.assertEqual(pol.required_confirmations(p, 20_000), 6)
        self.assertEqual(pol.required_confirmations(p, 6 * 10**8), 6)
        self.assertEqual(pol.required_confirmations(p, 6 * 10**8 + 1), 7)
        self.assertEqual(pol.required_confirmations(p, 50 * 10**8), 50)
        self.assertEqual(pol.required_confirmations(p, 10**12), 144)

    def test_release_delay_and_window(self):
        p = pol.DEFAULT_POLICY
        self.assertEqual(pol.release_ready_at(p, 1000, 500_000), 0)
        self.assertEqual(pol.release_ready_at(p, 1000, 500_001), 1000 + 43_200)
        ok, used = pol.window_allows(p, [(100, 150_000_000), (90_000, 40_000_000)], 10_000_000, 100_000)
        self.assertTrue(ok and used == 40_000_000)
        ok, used = pol.window_allows(p, [(20_000, 150_000_000), (90_000, 40_000_000)], 10_000_001, 100_000)
        self.assertFalse(ok)

    def test_mint_chain_matches_token_formula(self):
        v = vault()
        b = pol.build_vault_tx(v, tip(), [dep(0, 10**6), dep(1, 2 * 10**6)], [], [], 1)
        chain = pol.mint_chain(v, b['credits'])
        self.assertEqual([x[0] for x in chain], [0, 1, 2])
        self.assertEqual(chain[2][1], sum(cr['units'] for cr in b['credits']))
        self.assertEqual(len({x[2] for x in chain}), 3)


if __name__ == '__main__':
    unittest.main()
