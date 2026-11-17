#!/usr/bin/env python3
"""Unit and property tests of the pure Bitcoin vault rules (no node needed).  python3 -m unittest test_btc_policy"""
import hashlib
import random
import unittest

import btc_core as c
import btc_policy as pol

PRIVS = [int.from_bytes(hashlib.sha256(b'throwaway-btc-signer-%d' % i).digest(), 'big') % c.N for i in range(7)]
KEYS = [c.pubkey(k) for k in PRIVS]
OWNER = 'bcrt1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22tkfggv'


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

    def test_marker_operations_roundtrip_and_canonical(self):
        rnd = random.Random(2)
        seen = 0
        for _ in range(600):
            base = rnd.randrange(1, 1 << 40)
            late = sorted(rnd.sample(range(c.LATE_RANKS), rnd.randrange(0, 5)))
            through = rnd.choice([0, base, max(1, base - rnd.randrange(0, 60_000))])
            block = rnd.randrange(1 << 40) if through else 0
            room = 8 * (c.MARKER_PAYLOAD - c.MARKER_FIXED - (c.ASIDE_BYTES if through else 0) - len(late))
            paid = {base + 2 + rnd.randrange(0, max(1, room - 1)) for _ in range(rnd.randrange(0, 12))} if room > 1 else set()
            m = c.Marker(rnd.randrange(1 << 40), base, rnd.randrange(1 << 50), rnd.randrange(1 << 30), rnd.randrange(1, 500),
                         paid, through, late, block)
            spk = m.encode()
            self.assertLessEqual(len(spk), 83)   # 80 bytes of payload: standard under every relay policy deployed
            back = c.Marker.decode(spk)
            self.assertEqual(back.as_dict(), m.normalised().as_dict())
            seen += bool(through) and bool(late)
        self.assertGreater(seen, 50)
        self.assertEqual(len(c.Marker().encode()), 2 + c.MARKER_FIXED)
        # the window: 320 nonces with no operation, 264 with a set-aside, 312..288 with late payments, 232 with everything
        self.assertEqual(8 * c.MAX_BITMAP, 320)
        c.Marker(0, 0, 0, 0, 1, {320}).encode()
        with self.assertRaises(ValueError):
            c.Marker(0, 0, 0, 0, 1, {321}).encode()
        for through, late, room in ((10, (), 264), (0, (0,), 312), (0, (0, 1, 2, 3), 288), (10, (0, 1, 2, 3), 232)):
            c.Marker(0, 10, 0, 0, 1, {10 + room}, through, late, 7 if through else 0).encode()
            with self.assertRaises(ValueError):
                c.Marker(0, 10, 0, 0, 1, {11 + room}, through, late, 7 if through else 0).encode()
        for bad in ((3, 2), (2, 2), (256,), (-1,), (0, 1, 2, 3, 4)):
            with self.assertRaises(ValueError):
                c.Marker(0, 9, 0, 0, 1, (), 0, bad).encode()
        with self.assertRaises(ValueError):          # a mark above the burn base is no set-aside
            c.Marker(0, 9, 0, 0, 1, (), 11, ()).encode()
        with self.assertRaises(ValueError):          # an L2 block needs a mark
            c.Marker(0, 9, 0, 0, 1, (), 0, (), 5).encode()
        # non-canonical encodings are not markers: unknown operation bits, a zero mark behind its flag
        good = c.Marker(1, 4, 5, 0, 1, {6}, 0, (2,)).encode()
        at = 2 + 39
        self.assertEqual(good[at], 1)
        for ops in (0x11, 0x41, 0x05):
            with self.assertRaises(ValueError):
                c.Marker.decode(good[:at] + bytes([ops]) + good[at + 1:])
        plain = c.Marker(1, 4, 5, 0, 1, (), 0, ()).encode()
        zero_mark = plain[:1] + bytes([plain[1] + 7]) + plain[2:at] + b'\x80' + (4).to_bytes(2, 'big') + bytes(5)   # mark 4 - 4 = 0
        with self.assertRaises(ValueError):
            c.Marker.decode(zero_mark)

    def test_formats_1_and_2_are_refused_and_the_policy_version_names_the_format(self):
        # format 1 (round 16): no operations byte; format 2 (round 17, first form): 8-byte mark, 8-byte late nonces
        fixed = (3).to_bytes(8, 'big') + (7).to_bytes(8, 'big') + (10**6).to_bytes(8, 'big') + (55).to_bytes(8, 'big') + (9).to_bytes(2, 'big')
        v1 = b'BBTC\x01' + fixed + bytes([0b101])                       # a bitmap byte
        v2 = b'BBTC\x02' + fixed + bytes([0x81]) + (6).to_bytes(8, 'big') + (2).to_bytes(8, 'big') + bytes([0b101])
        v3 = c.Marker(3, 7, 10**6, 55, 9, {9, 11}, 6, (2,), 77).encode()
        for payload in (v1, v2):
            with self.assertRaises(ValueError):
                c.Marker.decode(bytes([c.OP_RETURN, len(payload)]) + payload)
        self.assertEqual(c.Marker.decode(v3).as_dict()['aside_block'], 77)
        self.assertEqual(c.MARKER_TAG, b'BBTC\x03')
        # a thread transaction carrying a format-1 or format-2 marker does not replay: every tool holds on it
        v = vault()
        s0 = {**tip(200_000), 'aside': frozenset()}
        b = pol.build_vault_tx(v, s0, [dep(0, 10**7)], [], [], 1)
        for payload in (v1, v2):
            with self.assertRaises(pol.PolicyError):
                pol.replay_tx(v, s0, b['inputs'], [b['tx'].outputs[0], (0, bytes([c.OP_RETURN, len(payload)]) + payload)] + b['tx'].outputs[2:])
        self.assertEqual(pol.replay_tx(v, s0, b['inputs'], b['tx'].outputs)['tx'].txid(), b['tx'].txid())
        # the policy version is inside the route: a policy of the earlier formats is not a policy, so no token can be
        # bound to a vault that would write another marker format
        self.assertEqual(pol.DEFAULT_POLICY['version'], 3)
        for old in (1, 2):
            with self.assertRaises(pol.PolicyError):
                vault(version=old)


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
        fee, charge = 1_000, 2 * (v.deposit_vb + v.overhead_vb)   # 10 bps of 1,000,000
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
        self.assertEqual(pay['sats'], 500_000 - 500 - 2 * (31 + v.overhead_vb))
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
        for kw, word in (({'deposits': [dep(0, 99_999)]}, 'below the minimum'),
                         ({'deposits': [dep(0, 10**9 + 1)]}, 'above the maximum'),
                         ({'deposits': [dep(0, 100_000)], 'feerate': 60}, 'miner charge exceeds'),
                         ({'feerate': 0, 'deposits': [dep(0, 10**6)]}, 'fee rate'),
                         ({'feerate': 201, 'deposits': [dep(0, 10**6)]}, 'fee rate'),
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
        # bridge fee 50,000 (10 bps) + the pool surplus above the target
        self.assertEqual(b['owner_paid'], 50_000 + (300_000 + b['credits'][0]['charge'] + (50_000_000 - 50_000 - b['credits'][0]['charge']) % 100
                                                    - b['fee'] - 200_000))
        self.assertEqual(b['marker'].owner_due, 0)
        self.assertEqual(b['pool'], 200_000)
        small = pol.build_vault_tx(v, tip(value=100_000), [dep(0, 1_000_000)], [], [], 1)
        self.assertEqual(small['owner_paid'], 0)
        self.assertEqual(small['marker'].owner_due, 1_000)  # 10 bps of 1,000,000, carried until it reaches ownerPayoutMinSats
        self.assertNotIn(v.owner_spk, [k for _, k in small['tx'].outputs])

    def test_property_conservation_solvency_replay(self):
        rnd = random.Random(7)
        v = vault(windowLimitSats=10**12)
        state = tip(value=250_000)
        nonce, burned, outstanding_units, used = 0, 0, 0, set()
        for step in range(250):
            deposits = [dep(step * 5 + j, rnd.choice([100_000, 155_555, 123_456, 10**6, 3 * 10**8, rnd.randrange(100_000, 10**7)]),
                            bytes([rnd.randrange(1, 255)]) * 20) for j in range(rnd.randrange(0, 4))]
            burns = []
            for _ in range(rnd.randrange(0, 4)):
                units = rnd.randrange(1_000, 200_000)
                if units <= outstanding_units:
                    burned += 1
                    burns.append({'nonce': burned, 'units': units, 'recipient': bytes([rnd.randrange(1, 255)]) * 20})
                    outstanding_units -= units
            donations = [{'txid': '%064x' % (9_000_000 + step), 'vout': 1, 'value': rnd.choice([546, 4_000])}] if rnd.random() < 0.15 else []
            refunds = [{'txid': '%064x' % (7_000_000 + step), 'vout': 0, 'value': rnd.choice([30_000, 99_999, 5 * 10**9]),
                        'recipient': b'\x0a' * 20, 'dest': bytes([rnd.randrange(1, 255)]) * 20}] if rnd.random() < 0.2 else []
            feerate = rnd.choice([1, 1, 2, 3, 5, 8, 40, 200])
            pool_before = state['value'] - state['marker'].liabilities - state['marker'].owner_due
            try:
                b = pol.build_vault_tx(v, state, deposits, donations, burns, feerate, refunds)
            except pol.PolicyError as e:
                # the only acceptable refusals in this generator
                self.assertTrue(e.wait or 'empty' in e.reason, e.reason)
                for x in burns:
                    outstanding_units += x['units']
                burned -= len(burns)
                continue
            tx, m = b['tx'], b['marker']
            total_in = state['value'] + sum(d['value'] for d in deposits + donations + refunds)
            # the fee pool never pays miners, whatever the batch and the fee rate (R325-BTC-3)
            self.assertGreaterEqual(b['pool'], min(pool_before, v.policy['poolTargetSats']))
            self.assertGreaterEqual(sum(x['charge'] for x in b['credits'] + b['payouts'] + b['refunds'])
                                    + sum(d['value'] for d in donations), b['fee'])
            self.assertEqual([(x['txid'], x['spk'][2:]) for x in b['refunds']], [(x['txid'], x['dest']) for x in refunds])
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


def after(b):
    """The thread state a build leaves, as btc_vault.VaultView keeps it."""
    return {'txid': b['tx'].txid(), 'vout': 0, 'value': b['tx'].outputs[0][0], 'marker': b['marker'], 'aside': b['aside'],
            'aside_at': b['aside_at']}


def burn(n, units=1_000):
    return {'nonce': n, 'units': units, 'recipient': bytes([1 + n % 200]) * 20}


class SetAside(unittest.TestCase):
    """Round 17 (R325-BTC-2P-1, -2P-2): a burn that is never paid without a claim, or that waits under its burner's fee
    ceiling, must not hold the burns after it. It is set aside: settled in the marker, not paid, payable later."""

    def funded(self, v, sats=10**8):
        return after(pol.build_vault_tx(v, tip(200_000), [dep(0, sats)], [], [], 1))

    def test_a_burn_set_aside_is_not_paid_keeps_its_coins_and_is_paid_later_once(self):
        v = vault()
        s0 = self.funded(v)
        owed = s0['marker'].liabilities
        # burns 1 and 2 cannot be paid (unclaimed); burn 3 can. One transaction sets 1..2 aside and pays 3.
        b = pol.build_vault_tx(v, s0, [], [], [burn(3)], 2, aside_through=2)
        self.assertEqual((b['set_aside'], b['late'], sorted(b['aside'])), ([1, 2], [], [1, 2]))
        self.assertEqual([x['nonce'] for x in b['payouts']], [3])
        self.assertEqual(len(b['tx'].outputs), 3)                       # thread, marker, ONE payout: nobody else is paid
        self.assertEqual(b['marker'].liabilities, owed - 100_000)       # only burn 3 left the books
        self.assertEqual(b['marker'].burn_base, 3)                      # the window moved past all three
        s1 = after(b)
        self.assertTrue(pol.burn_paid(s1, 3))
        self.assertFalse(pol.burn_paid(s1, 1) or pol.burn_paid(s1, 2))  # settled in the marker, NOT paid
        self.assertTrue(s1['marker'].is_paid(1))
        again = pol.replay_tx(v, s0, b['inputs'], b['tx'].outputs)      # chain data alone gives the same state
        self.assertEqual((again['tx'].txid(), again['aside'], again['set_aside']), (b['tx'].txid(), b['aside'], [1, 2]))
        # later burn 2 is claimed: a late payment, charged like any release
        late = pol.build_vault_tx(v, s1, [], [], [burn(2, 5_000)], 3)
        self.assertEqual((late['late'], sorted(late['aside']), late['marker'].late), ([2], [1], (1,)))   # burn 2 is rank 1 of {1, 2}
        self.assertEqual(late['payouts'][0]['sats'], 500_000 - 500 - 3 * v.release_vb)
        self.assertEqual(late['marker'].liabilities, owed - 100_000 - 500_000)
        s2 = after(late)
        self.assertTrue(pol.burn_paid(s2, 2))
        again = pol.replay_tx(v, s1, late['inputs'], late['tx'].outputs)
        self.assertEqual((again['tx'].txid(), again['aside']), (late['tx'].txid(), frozenset({1})))
        # never twice: neither the late one nor an ordinary one
        for n in (2, 3):
            with self.assertRaises(pol.PolicyError) as e:
                pol.build_vault_tx(v, s2, [], [], [burn(n)], 3)
            self.assertIn('already paid', e.exception.reason)
        # and the same late payment on the same state twice conflicts on Bitcoin: same thread input
        self.assertEqual(late['tx'].inputs[0], pol.build_vault_tx(v, s1, [], [], [burn(2, 5_000), burn(1)], 3)['tx'].inputs[0])

    def test_one_unpayable_burn_no_longer_holds_the_burns_behind_the_window(self):
        v = vault()
        s = self.funded(v, 10**9)
        m = s['marker']
        # burn 1 never claimed; 320 later burns already paid: the next one (322) is outside the window
        held = {**s, 'marker': c.Marker(m.next_deposit, 0, m.liabilities, m.owner_due, 1, range(2, 321))}
        with self.assertRaises(pol.PolicyError) as e:
            pol.build_vault_tx(v, held, [], [], [burn(322)], 1)
        self.assertTrue(e.exception.wait and 'set aside' in e.exception.reason)
        b = pol.build_vault_tx(v, held, [], [], [burn(322)], 1, aside_through=1)
        self.assertEqual((b['marker'].burn_base, sorted(b['marker'].paid), sorted(b['aside'])), (320, [322], [1]))
        self.assertEqual(pol.replay_tx(v, held, b['inputs'], b['tx'].outputs)['aside'], frozenset({1}))

    def test_setting_aside_is_refused_where_it_is_not_what_the_rules_allow(self):
        v = vault()
        s0 = self.funded(v)
        cases = [
            (dict(burns=[burn(1)], aside_through=1), 'both set aside and paid'),
            (dict(burns=[burn(2)], aside_through=3), 'both set aside and paid'),
            (dict(burns=[burn(3)], aside_through=0 - 1), 'malformed'),
            (dict(burns=[burn(9000)], aside_through=5000), 'too far'),
        ]
        for kw, word in cases:
            with self.assertRaises(pol.PolicyError) as e:
                pol.build_vault_tx(v, s0, [], [], kw['burns'], 1, aside_through=kw['aside_through'])
            self.assertIn(word, e.exception.reason, kw)
        # a set-aside travels only with a paid burn, a swept deposit or a refund; a stray that pays the miner is not one
        for donations in ([], [{'txid': 'cd' * 32, 'vout': 0, 'value': 20_000}]):
            with self.assertRaises(pol.PolicyError) as e:
                pol.build_vault_tx(v, s0, [], donations, [], 1, aside_through=2)
            self.assertIn('travels only with', e.exception.reason)
        pol.build_vault_tx(v, s0, [dep(5, 10**6)], [], [], 1, aside_through=2)            # with a sweep
        # at most four in one transaction: never more than one transaction can pay late
        with self.assertRaises(pol.PolicyError) as e:
            pol.build_vault_tx(v, s0, [], [], [burn(6)], 1, aside_through=5)
        self.assertTrue(e.exception.wait and 'at most 4' in e.exception.reason)
        self.assertEqual(pol.build_vault_tx(v, s0, [], [], [burn(5)], 1, aside_through=4, aside_block=9)['aside_at'], {1: 9, 2: 9, 3: 9, 4: 9})
        with self.assertRaises(pol.PolicyError):
            pol.build_vault_tx(v, s0, [], [], [burn(5)], 1, aside_block=9)                 # an L2 block without a mark
        s1 = after(pol.build_vault_tx(v, s0, [], [], [burn(4)], 1, aside_through=2))   # 1, 2 aside; 3 open; 4 paid
        for mark in (1, 2, 4):  # already settled: the mark must be an unsettled burn
            with self.assertRaises(pol.PolicyError) as e:
                pol.build_vault_tx(v, s1, [], [], [burn(6)], 1, aside_through=mark)
            self.assertIn('not an unsettled burn', e.exception.reason)
        b = pol.build_vault_tx(v, s1, [], [], [burn(6)], 1, aside_through=5)
        self.assertEqual((b['set_aside'], sorted(b['aside']), b['marker'].burn_base), ([3, 5], [1, 2, 3, 5], 6))
        # at most four late payments in one transaction
        s2 = after(b)
        mixed = pol.build_vault_tx(v, s2, [], [], [burn(n) for n in (1, 2, 3, 5)] + [burn(7)], 1)   # four late and one ordinary
        self.assertEqual(([x['nonce'] for x in mixed['payouts']], mixed['late']), ([1, 2, 3, 5, 7], [1, 2, 3, 5]))
        four = pol.build_vault_tx(v, s2, [], [], [burn(n) for n in (1, 2, 3, 5)], 1)
        self.assertEqual((four['late'], sorted(four['aside'])), ([1, 2, 3, 5], []))
        s3 = after(pol.build_vault_tx(v, s2, [], [], [burn(8)], 1, aside_through=7))
        with self.assertRaises(pol.PolicyError) as e:
            pol.build_vault_tx(v, s3, [], [], [burn(n) for n in (1, 2, 3, 5, 7)], 1)
        self.assertTrue(e.exception.wait and 'late payments' in e.exception.reason)

    def test_replay_refuses_a_marker_that_lies_about_what_was_set_aside_or_paid_late(self):
        v = vault()
        s0 = self.funded(v)
        b = pol.build_vault_tx(v, s0, [], [], [burn(3)], 2, aside_through=2)
        s1 = after(b)
        outs = list(b['tx'].outputs)

        def with_marker(m):
            return [outs[0], (0, m.encode())] + outs[2:]

        good = c.Marker.decode(outs[1][1])
        lies = [
            c.Marker(good.next_deposit, good.burn_base, good.liabilities, good.owner_due, good.feerate, good.paid, 0, ()),       # 1, 2 "paid" with no payout
            c.Marker(good.next_deposit, good.burn_base, good.liabilities, good.owner_due, good.feerate, good.paid, 1, ()),       # only 1 set aside
            c.Marker(good.next_deposit, good.burn_base, good.liabilities, good.owner_due, good.feerate, good.paid, 3, ()),       # 3 set aside but paid
            c.Marker(good.next_deposit, good.burn_base, good.liabilities - 100_000, good.owner_due, good.feerate, good.paid, 2, ()),
            c.Marker(good.next_deposit, 10**9, good.liabilities, good.owner_due, good.feerate, (), 2, ()),                       # a base no transaction reaches
        ]
        for m in lies:
            try:
                outputs = with_marker(m)
            except ValueError:
                continue                     # a lie that format 3 cannot even write (a mark far below the base)
            with self.assertRaises(pol.PolicyError):
                pol.replay_tx(v, s0, b['inputs'], outputs)
        # a late payment of a burn that was never set aside, or was already paid late
        late = pol.build_vault_tx(v, s1, [], [], [burn(2)], 2)
        louts = list(late['tx'].outputs)
        lm = c.Marker.decode(louts[1][1])
        forged = c.Marker(lm.next_deposit, lm.burn_base, lm.liabilities, lm.owner_due, lm.feerate, lm.paid, 0, (3,))
        with self.assertRaises(pol.PolicyError):
            pol.replay_tx(v, s1, late['inputs'], [louts[0], (0, forged.encode())] + louts[2:])
        s2 = after(late)
        with self.assertRaises(pol.PolicyError):   # the same outputs on the next state: burn 2 is no longer set aside
            pol.replay_tx(v, s2, [{**late['inputs'][0], 'txid': s2['txid']}], louts)

    def test_property_books_and_replay_with_burns_set_aside(self):
        rnd = random.Random(17)
        v = vault(windowLimitSats=10**13)
        state = {**tip(value=200_000), 'aside': frozenset()}
        next_burn, units_of, waiting, outstanding, paid_once = 0, {}, set(), 0, set()
        pays = asides = lates = 0
        for step in range(400):
            deposits = [dep(step * 5 + j, rnd.choice([10**6, 3 * 10**7, rnd.randrange(200_000, 10**7)]), bytes([1 + step % 250]) * 20)
                        for j in range(rnd.randrange(0, 3))]
            # new burns appear on the L2; a third of them cannot be paid now (unclaimed, or a low fee ceiling)
            for _ in range(rnd.randrange(0, 5)):
                u = rnd.randrange(1_000, 50_000)
                if u <= outstanding:
                    next_burn += 1
                    units_of[next_burn] = u
                    outstanding -= u
                    if rnd.random() < 0.35:
                        waiting.add(next_burn)
            for n in list(waiting):          # some waiting burns become payable (claimed, market fell)
                if rnd.random() < 0.08:
                    waiting.discard(n)
            m = state['marker'].normalised()
            aside = set(state['aside'])
            unsettled = [n for n in range(m.burn_base + 1, next_burn + 1) if n not in m.paid]
            # set aside the leading run of waiting burns, if any; pay payable ones above it and a few late ones
            mark = 0
            for n in unsettled:
                if n in waiting:
                    mark = n
                else:
                    break
            run = [n for n in unsettled if n <= mark]
            mark = run[min(len(run), 4) - 1] if run else 0           # at most four per transaction
            if mark and rnd.random() < 0.3:
                mark = 0
            payable = [n for n in unsettled if n > mark and n not in waiting][:rnd.randrange(0, 5)]
            late = [n for n in sorted(aside) if n not in waiting][:rnd.randrange(0, 5)]
            burns = [{'nonce': n, 'units': units_of[n], 'recipient': bytes([1 + n % 250]) * 20} for n in payable + late]
            if not (burns or deposits):
                mark = 0                                              # a set-aside travels with a paying item
            l2_block = 1000 + step if mark else 0
            try:
                b = pol.build_vault_tx(v, state, deposits, [], burns, rnd.choice([1, 2, 7, 60]), aside_through=mark, aside_block=l2_block)
            except pol.PolicyError as e:
                self.assertTrue(e.wait or 'empty' in e.reason, e.reason)
                continue
            tx, new = b['tx'], b['marker']
            for x in b['payouts']:
                self.assertNotIn(x['nonce'], paid_once)                 # no burn is ever paid twice
                paid_once.add(x['nonce'])
                self.assertNotIn(x['nonce'], waiting)
            self.assertEqual(len(tx.outputs) - 2 - (1 if b['owner_paid'] else 0), len(burns))   # one output per burn PAID
            self.assertEqual(sorted(b['aside']), sorted((aside | set(b['set_aside'])) - set(late)))
            outstanding += sum(cr['units'] for cr in b['credits'])
            unpaid_units = sum(u for n, u in units_of.items() if n not in paid_once)
            # the books: what the vault owes = the L2 supply + every burn not paid yet (set aside or not)
            self.assertEqual(new.liabilities, (outstanding + unpaid_units) * 100)
            self.assertGreaterEqual(tx.outputs[0][0], new.liabilities + new.owner_due)
            self.assertEqual(state['value'] + sum(d['value'] for d in deposits), sum(o[0] for o in tx.outputs) + b['fee'])
            again = pol.replay_tx(v, state, b['inputs'], tx.outputs)
            self.assertEqual((again['tx'].txid(), again['aside'], again['late'], again['set_aside'], again['aside_at']),
                             (tx.txid(), b['aside'], b['late'], b['set_aside'], b['aside_at']))
            self.assertTrue(all(b['aside_at'][n] == l2_block for n in b['set_aside']) and set(b['aside_at']) == set(b['aside']))
            state = after(b)
            for n in paid_once:
                self.assertTrue(pol.burn_paid(state, n))
            for n in state['aside']:
                self.assertFalse(pol.burn_paid(state, n))
            pays, asides, lates = pays + len(payable), asides + len(b['set_aside']), lates + len(b['late'])
        self.assertTrue(pays > 100 and asides > 40 and lates > 20, (pays, asides, lates))

    def test_the_rule_that_allows_a_set_aside(self):
        # review R342-BTC-1: a function of finalized L2 data, the thread and the transaction; never the relayer's choice
        p = pol.DEFAULT_POLICY
        old = c.Marker(burn_base=10)
        day = 86_400
        direct = lambda age: {'nonce': 11, 'time': 1_000_000 - age, 'claimed': False, 'max_fee_rate': None}   # noqa: E731
        router = lambda rate: {'nonce': 11, 'time': 1_000_000 - 30 * day, 'claimed': True, 'max_fee_rate': rate}   # noqa: E731
        rule = lambda b, feerate, paid: pol.may_set_aside(p, old, b, feerate, paid, 1_000_000)   # noqa: E731
        self.assertEqual((p['setAsideAgeSeconds'], p['burnFeerateFloor']), (3 * day, 2))
        # age: an unclaimed direct burn, three days after it was made, not before
        self.assertEqual((rule(direct(3 * day), 1, [12]), rule(direct(3 * day - 1), 1, [12])), ('age', None))
        # floor: a ceiling below the policy floor
        self.assertEqual((rule(router(1), 1, [12]), rule(router(2), 1, [12])), ('floor', None))
        # a ceiling merely below this transaction's fee rate, however old the burn and whatever the rate: it WAITS
        for feerate in (11, 50, 200):
            self.assertIsNone(rule(router(10), feerate, [12, 13, 330]))
        # blocked: only when the transaction pays a burn the window would otherwise stop (beyond base + 320)
        self.assertEqual(rule(router(10), 11, [331]), 'blocked')
        self.assertIsNone(rule(router(10), 10, [331]))               # payable at this rate: paid, not set aside
        self.assertIsNone(rule(router(200), 200, [331]))
        self.assertEqual(rule(direct(0), 1, [331]), 'blocked')       # an unclaimed burn of any age, when it blocks
        self.assertTrue(pol.beyond_window(old, 331) and not pol.beyond_window(old, 330))


class ReviewR16(unittest.TestCase):
    """Reviewer 325's demonstrations (41006b8, test_review_r16.py), turned around: each now passes."""

    def mainnet(self):
        return vault(windowLimitSats=10_000_000, largeReleaseSats=5_000_000)

    def test_btc1_a_parent_with_a_scriptsig_is_readable(self):
        v = self.mainnet()
        legacy = (b'\x01\x00\x00\x00' + b'\x01' + b'\x11' * 32 + b'\x00\x00\x00\x00' + b'\x02\x51\x51' + b'\xff\xff\xff\xff'
                  + b'\x01' + (546).to_bytes(8, 'little') + c.ser_script(v.thread_spk) + b'\x00\x00\x00\x00')
        tx, version, locktime, sequences = c.parse_tx(legacy)
        self.assertEqual((tx.outputs[0][0], tx.script_sigs, version, sequences), (546, [b'\x51\x51'], 1, [0xffffffff]))
        self.assertEqual(tx.txid(), c.sha256d(legacy)[::-1].hex())
        coinbase = (b'\x02\x00\x00\x00\x00\x01\x01' + bytes(32) + b'\xff' * 4 + b'\x03\x01\x02\x03' + b'\xff' * 4 + b'\x01'
                    + (50 * 10**8).to_bytes(8, 'little') + c.ser_script(v.thread_spk) + b'\x01\x20' + bytes(32) + bytes(4))
        self.assertEqual(c.parse_tx(coinbase)[0].outputs[0][1], v.thread_spk)

    def test_btc1_the_parser_fails_only_with_valueerror(self):
        rnd = random.Random(325)
        v = self.mainnet()
        good = pol.build_vault_tx(v, tip(), [dep(0, 10**6)], [], [], 2)['tx']
        good.witnesses = [[b'', b'\x30' * 71, good.inputs[0][0].encode()], [b'x' * 300]]
        seeds = [good.serialize(), good.stripped()]
        for n in range(4000):
            raw = bytearray(rnd.choice(seeds))
            for _ in range(rnd.randrange(1, 6)):
                kind = rnd.randrange(4)
                if kind == 0 and raw:
                    raw[rnd.randrange(len(raw))] = rnd.randrange(256)
                elif kind == 1 and raw:
                    del raw[rnd.randrange(len(raw)):rnd.randrange(len(raw)) + 1 + rnd.randrange(8)]
                elif kind == 2:
                    raw[rnd.randrange(len(raw) + 1):0] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 9)))
                else:
                    raw = raw[:rnd.randrange(len(raw) + 1)]
            try:
                tx, *_ = c.parse_tx(bytes(raw))
                tx.txid()
            except ValueError:
                pass  # the only failure a caller has to expect
        for junk in (b'', b'\x00' * 9, bytes(rnd.randrange(256) for _ in range(500)), 'text', None):
            with self.assertRaises(ValueError):
                c.parse_tx(junk)

    def test_btc2_a_stray_only_transaction_does_not_spend_the_fee_pool(self):
        v = self.mainnet()
        with self.assertRaises(pol.PolicyError) as e:
            pol.build_vault_tx(v, tip(250_000), [], [{'txid': 'cc' * 32, 'vout': 0, 'value': 546}], [], 30)
        self.assertIn('does not pay for its own input', e.exception.reason)
        with self.assertRaises(pol.PolicyError) as e:  # pays its input but not the transaction: still not from the pool
            pol.build_vault_tx(v, tip(200_000), [], [{'txid': 'cc' * 32, 'vout': 0, 'value': 30 * v.donation_vb}], [], 30)
        self.assertIn('out of the fee pool', e.exception.reason)
        big = 30 * (v.donation_vb + v.overhead_vb)
        b = pol.build_vault_tx(v, tip(200_000), [], [{'txid': 'cc' * 32, 'vout': 0, 'value': big}], [], 30)
        self.assertGreaterEqual(b['pool'] + b['owner_paid'] + b['marker'].owner_due, 200_000)
        with self.assertRaises(pol.PolicyError):  # an owner-only transaction cannot draw the pool down either
            pol.build_vault_tx(v, tip(150_000, c.Marker(owner_due=20_000)), [], [], [], 30)

    def test_btc3_a_minimum_burn_is_payable_at_every_fee_rate_the_signers_may_sign(self):
        v = self.mainnet()
        m = c.Marker(next_deposit=3, burn_base=0, liabilities=60_000_000)
        for rate in (1, 14, 100, v.policy['maxFeerate']):
            b = pol.build_vault_tx(v, tip(60_250_000, m), [], [], [{'nonce': 1, 'units': 1_000, 'recipient': b'\x07' * 20}], rate)
            self.assertEqual(b['payouts'][0]['sats'], 100_000 - 100 - rate * (31 + v.overhead_vb))
            self.assertGreaterEqual(b['payouts'][0]['sats'], 546)
        self.assertEqual((31 + v.overhead_vb, (100_000 - 100 - 546) // (31 + v.overhead_vb)), (402, 247))

    def test_btc4_no_burn_waits_for_fees_so_the_marker_window_is_not_held_by_one(self):
        # burn 1 (the smallest allowed) is payable at the ceiling even with 328 later burns already paid
        v = self.mainnet()
        m = c.Marker(next_deposit=3, burn_base=0, liabilities=60_000_000, paid=range(2, 330))
        b = pol.build_vault_tx(v, tip(60_250_000, m), [], [], [{'nonce': 1, 'units': 1_000, 'recipient': b'\x07' * 20}], 200)
        self.assertEqual(b['marker'].burn_base, 329)
        with self.assertRaises(pol.PolicyError) as e:  # the window itself still exists; it is a wait, never a loss
            pol.build_vault_tx(v, tip(60_250_000, m), [], [], [{'nonce': 330, 'units': 100_000, 'recipient': b'\x07' * 20}], 14)
        self.assertTrue(e.exception.wait)


class Refunds(unittest.TestCase):
    def test_a_refund_returns_the_deposit_less_fee_and_charge_and_credits_nobody(self):
        v = vault()
        for value in (30_000, 99_999, 5 * 10**9):  # below the minimum, and above the maximum
            r = {'txid': 'dd' * 32, 'vout': 1, 'value': value, 'recipient': b'\x0a' * 20, 'dest': b'\x0b' * 20}
            b = pol.build_vault_tx(v, tip(), [], [], [], 3, [r])
            self.assertEqual(b['refunds'][0]['sats'], value - value * 10 // 10_000 - 3 * (v.deposit_vb + 31 + v.overhead_vb))
            self.assertEqual((b['marker'].next_deposit, b['marker'].liabilities, b['credits']), (0, 0, []))
            self.assertIn((b['refunds'][0]['sats'], c.p2wpkh(b'\x0b' * 20)), b['tx'].outputs)
            again = pol.replay_tx(v, tip(), b['inputs'], b['tx'].outputs)
            self.assertEqual(again['refunds'][0]['spk'], c.p2wpkh(b'\x0b' * 20))
        with self.assertRaises(pol.PolicyError) as e:
            pol.build_vault_tx(v, tip(), [], [], [], 3, [{**r, 'value': 2_000}])
        self.assertIn('dust', e.exception.reason)
        with self.assertRaises(pol.PolicyError):
            pol.build_vault_tx(v, tip(), [], [], [], 3, [{**r, 'dest': bytes(20)}])
        with self.assertRaises(pol.PolicyError):  # one outpoint cannot be both credited and refunded
            pol.build_vault_tx(v, tip(), [dep(0, 10**6)], [], [], 3, [{**dep(0, 10**6), 'dest': b'\x0b' * 20}])

    def test_sweep_and_refund_in_one_transaction_replay(self):
        v = vault()
        r = {'txid': '00' * 31 + '01', 'vout': 0, 'value': 50_000, 'recipient': b'\x0a' * 20, 'dest': b'\x0b' * 20}
        b = pol.build_vault_tx(v, tip(), [dep(0, 10**6), dep(1, 10**6)], [{'txid': 'ee' * 32, 'vout': 0, 'value': 9_000}],
                               [], 2, [r])
        again = pol.replay_tx(v, tip(), b['inputs'], b['tx'].outputs)
        self.assertEqual((len(again['credits']), len(again['refunds']), again['tx'].txid()), (2, 1, b['tx'].txid()))
        forged = list(b['tx'].outputs)
        i = forged.index((b['refunds'][0]['sats'], b['refunds'][0]['spk']))
        forged[i] = (forged[i][0] + 1, forged[i][1])
        with self.assertRaises(pol.PolicyError):
            pol.replay_tx(v, tip(), b['inputs'], forged)


if __name__ == '__main__':
    unittest.main()
