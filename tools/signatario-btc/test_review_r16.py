"""Reviewer 325 (round 16): demonstrations against the bBTC tools at 7b13bdb. Each test states the property the
bridge needs and FAILS on the reviewed code. Run: python3 -m unittest test_review_r16 -v   (in tools/signatario-btc)."""
import unittest

import btc_core as c
import btc_policy as pol

KEYS = [c.pubkey(i) for i in range(1, 8)]
OWNER = c.address_from_spk('bitcoin-regtest', c.spk_from_address('bitcoin-mainnet', 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk'))
MAINNET_POLICY = {**pol.DEFAULT_POLICY, 'windowLimitSats': 10_000_000, 'largeReleaseSats': 5_000_000}


def vault():
    return pol.Vault('bitcoin-regtest', 5, KEYS, 'aa' * 32, 0, OWNER, MAINNET_POLICY)


def tip(value, marker):
    return {'txid': 'bb' * 32, 'vout': 0, 'value': value, 'marker': marker}


class ReviewR16(unittest.TestCase):
    def test_btc1_a_parent_with_a_scriptsig_is_readable(self):
        """R325-BTC-1. Node.tx() parses every parent of a vault input and every stranger's transaction that pays the
        thread address at vout 0 with parse_tx. Those are ordinary Bitcoin transactions: legacy (P2PKH), nested segwit
        (P2SH-P2WPKH) and coinbase inputs carry a scriptSig."""
        legacy = (b'\x01\x00\x00\x00' + b'\x01' + b'\x11' * 32 + b'\x00\x00\x00\x00' + b'\x02\x51\x51' + b'\xff\xff\xff\xff'
                  + b'\x01' + (546).to_bytes(8, 'little') + c.ser_script(vault().thread_spk) + b'\x00\x00\x00\x00')
        tx, version, locktime, sequences = c.parse_tx(legacy)  # raises ValueError('a vault transaction has empty scriptSigs')
        self.assertEqual(tx.outputs[0][0], 546)

    def test_btc2_a_stray_only_transaction_does_not_spend_the_fee_pool(self):
        """R325-BTC-3. A relayer (no key) sends 546 sat to the thread address and proposes a transaction with that stray
        alone at the signers' fixed 30 sat/vB ceiling. The pool must not pay more than the stray brought in."""
        v = vault()
        built = pol.build_vault_tx(v, tip(250_000, c.Marker()), [], [{'txid': 'cc' * 32, 'vout': 0, 'value': 546}], [], 30)
        pool_before = 250_000
        pool_after = built['pool'] + built['owner_paid'] + built['marker'].owner_due
        self.assertGreaterEqual(pool_after, pool_before, f"pool lost {pool_before - pool_after} sat to miners for a 546 sat stray")

    def test_btc3_a_minimum_burn_is_payable_at_a_fee_rate_the_signers_accept(self):
        """R325-BTC-4 (a). minBurn is 500 units (50,000 sat); the charge cap is 10%; a release is charged
        fee rate x 370 vB. Above 13 sat/vB the smallest burn can never be paid."""
        v = vault()
        m = c.Marker(next_deposit=3, burn_base=0, liabilities=60_000_000)
        pol.build_vault_tx(v, tip(60_250_000, m), [], [], [{'nonce': 1, 'units': 500, 'recipient': b'\x07' * 20}], 14)

    def test_btc4_an_unpaid_old_burn_does_not_stop_later_burns(self):
        """R325-BTC-4 (b). While burn 1 waits (test above), burn 330 and every later one is refused: the marker's
        bitmap holds 328 nonces above the oldest unpaid burn."""
        v = vault()
        m = c.Marker(next_deposit=3, burn_base=0, liabilities=60_000_000, paid=range(2, 330))
        pol.build_vault_tx(v, tip(60_250_000, m), [], [], [{'nonce': 330, 'units': 100_000, 'recipient': b'\x07' * 20}], 14)

    def test_btc5_replay_binds_a_payout_to_the_burn_recipient(self):
        """R325-BTC-5. replay_tx reads the recipient of a paid burn from the Bitcoin output itself, and
        btc_reservas.py compares only nonces and unit totals with the L2. A rule-shaped transaction that pays burn 1
        to another key hash replays as valid and leaves the reserves report 'ok'. The replay API has no way to be told
        the L2 burn's recipient; this test documents it by checking that the build result names the thief."""
        v = vault()
        m = c.Marker(next_deposit=3, burn_base=0, liabilities=60_000_000)
        t = tip(60_250_000, m)
        thief = b'\x66' * 20
        built = pol.build_vault_tx(v, t, [], [], [{'nonce': 1, 'units': 100_000, 'recipient': thief}], 2)
        replayed = pol.replay_tx(v, t, built['inputs'], built['tx'].outputs)
        l2_burn_recipient = b'\x07' * 20
        self.assertEqual(replayed['payouts'][0]['spk'][2:], l2_burn_recipient,
                         'the replay accepted a payout to a key hash the L2 burn does not name; nothing downstream compares it')


if __name__ == '__main__':
    unittest.main()
