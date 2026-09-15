"""Offline vectors; syntactic matching never authorizes minting."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from btc_observer.transaction import decode, inspect_deposit, Invalid, MAX_MONEY, MAX_RAW_BYTES

SCRIPT = b'\x00\x20' + b'\x22' * 32
INPUT = b'\x11' * 32 + bytes(4) + b'\x00' + b'\xff' * 4


def tx(witness=None, amounts=(1000, 2000), script=SCRIPT):
    outputs = bytes([len(amounts)]) + b''.join(a.to_bytes(8, 'little') + bytes([len(script)]) + script for a in amounts)
    return b'\x02\0\0\0' + (b'\0\x01' if witness is not None else b'') + b'\x01' + INPUT + outputs + (witness or b'') + bytes(4)


def inspect(raw, **overrides):
    params = dict(network='bitcoin-regtest', expected_txid=decode(raw).txid, vout=0, script_pubkey=SCRIPT)
    params.update(overrides)
    return inspect_deposit(raw, **params)


class BitcoinTransactionTest(unittest.TestCase):
    def test_known_genesis_txid_and_coinbase_refusal(self):
        raw = bytes.fromhex(
            '0100000001' + '00' * 32 + 'ffffffff4d04ffff001d010445'
            '5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73'
            'ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000')
        parsed = decode(raw)
        self.assertEqual(parsed.txid, '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')
        self.assertEqual(parsed.txid, parsed.wtxid)
        self.assertEqual(parsed.outputs[0].satoshis, 5_000_000_000)
        with self.assertRaisesRegex(Invalid, 'Coinbase'):
            inspect(raw, script_pubkey=parsed.outputs[0].script_pubkey)

    def test_legacy_and_segwit_share_txid_not_wtxid(self):
        plain = tx()
        first, second = tx(b'\x01\x02\xaa\xbb'), tx(b'\x01\x02\xcc\xdd')
        self.assertEqual(decode(plain).txid, decode(first).txid)
        self.assertEqual(decode(first).txid, decode(second).txid)
        self.assertNotEqual(decode(first).wtxid, decode(second).wtxid)
        self.assertEqual(inspect(first)['outpoint_key'], inspect(second)['outpoint_key'])
        self.assertEqual(decode(first).weight, len(plain) * 3 + len(first))

    def test_output_index_and_network_are_part_of_identity(self):
        first, second = inspect(tx()), inspect(tx(), vout=1)
        self.assertEqual(first['amount_sats'], '1000')
        self.assertEqual(second['amount_sats'], '2000')
        self.assertNotEqual(first['outpoint_key'], second['outpoint_key'])
        self.assertNotEqual(first['outpoint_key'], inspect(tx(), network='bitcoin-mainnet')['outpoint_key'])
        for flag in ('inclusion_verified', 'finality_verified', 'custody_verified', 'mint_authorized', 'bridge_ready'):
            self.assertIs(first[flag], False)

    def test_all_truncations_and_trailing_bytes_refused(self):
        for raw in (tx(), tx(b'\x01\x02\xaa\xbb')):
            for length in range(len(raw)):
                with self.subTest(length=length), self.assertRaises(Invalid):
                    decode(raw[:length])
            with self.assertRaises(Invalid):
                decode(raw + b'\0')

    def test_noncanonical_sizes_unknown_flags_and_empty_witness(self):
        for raw in (tx()[:4] + b'\xfd\x01\0' + tx()[5:], tx(b'\0'), tx(b'\x01\x02ab')[:5] + b'\x02' + tx(b'\x01\x02ab')[6:]):
            with self.assertRaises(Invalid):
                decode(raw)

    def test_money_bounds_and_zero_deposit(self):
        for amounts in ((MAX_MONEY + 1,), (MAX_MONEY, 1)):
            with self.assertRaisesRegex(Invalid, 'money range'):
                decode(tx(amounts=amounts))
        with self.assertRaises(Invalid):
            inspect(tx(amounts=(0,)))
        self.assertEqual(inspect(tx(amounts=(MAX_MONEY,)))['amount_sats'], str(MAX_MONEY))

    def test_duplicate_inputs(self):
        raw = tx()[:4] + b'\x02' + INPUT + INPUT + tx()[5 + len(INPUT):]
        with self.assertRaisesRegex(Invalid, 'Duplicate input'):
            decode(raw)

    def test_untrusted_selection_is_refused(self):
        for params in ({'expected_txid': '00' * 32}, {'expected_txid': 'AB' * 32}, {'vout': True}, {'vout': -1}, {'vout': 2}, {'vout': 0.0}, {'network': []}, {'network': 'ethereum-mainnet'}, {'script_pubkey': b'\x51'}, {'script_pubkey': b''}):
            with self.subTest(params=params), self.assertRaises(Invalid):
                inspect(tx(), **params)

    def test_raw_resource_and_type_bounds(self):
        for raw in (bytearray(tx()), '00', b'\0' * (MAX_RAW_BYTES + 1)):
            with self.assertRaises(Invalid):
                decode(raw)

    def test_canonical_long_script_and_weight_limit(self):
        script = b'\x51' * 10_000
        output = (1).to_bytes(8, 'little') + b'\xfd\x10\x27' + script
        raw = b'\x02\0\0\0\x01' + INPUT + b'\x65' + output * 101 + bytes(4)
        with self.assertRaisesRegex(Invalid, 'weight'):
            decode(raw)
        small = b'\x02\0\0\0\x01' + INPUT + b'\x01' + output + bytes(4)
        self.assertEqual(decode(small).outputs[0].script_pubkey, script)

class BitcoinCliTest(unittest.TestCase):
    def test_cli_is_offline_and_fails_closed(self):
        import json
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'transaction.hex'
            path.write_text(tx().hex() + '\n')
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'inspect-btc-deposit.py'),
                       '--raw-tx-file', str(path), '--network', 'bitcoin-regtest',
                       '--txid', decode(tx()).txid, '--vout', '0', '--script-pubkey', SCRIPT.hex()]
            good = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIs(json.loads(good.stdout)['mint_authorized'], False)
            path.write_text('not a transaction')
            bad = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(bad.stdout, '')
            self.assertNotIn('not a transaction', bad.stderr)


if __name__ == '__main__':
    unittest.main()
