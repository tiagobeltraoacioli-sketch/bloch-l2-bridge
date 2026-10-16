from hashlib import sha256
from pathlib import Path
import sys
import json
import subprocess
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from btc_observer.proof import verify_branch
from btc_observer.transaction import Invalid, decode, digest
from test_btc_transaction import tx, SCRIPT


def h(data):
    return sha256(sha256(data).digest()).digest()


def fixture(index=0, count=3):
    raws = [tx(amounts=(100 + i,)) for i in range(count)]
    row = [bytes.fromhex(decode(raw).txid)[::-1] for raw in raws]
    siblings = []
    cursor = index
    while len(row) > 1:
        if len(row) % 2:
            row.append(row[-1])
        siblings.append(row[cursor ^ 1][::-1].hex())
        row = [h(row[i] + row[i+1]) for i in range(0, len(row), 2)]
        cursor //= 2
    # Deliberately unmined synthetic header: membership does not validate PoW.
    header = b'\x01\0\0\0' + bytes(32) + row[0] + bytes(12)
    return raws[index], dict(header=header, expected_block_hash=digest(header),
                            tx_index=index, tx_count=count, siblings=siblings)


class BitcoinProofTest(unittest.TestCase):
    def test_every_leaf_in_even_odd_and_single_trees(self):
        for count in (1, 2, 3, 5, 8):
            for index in range(count):
                raw, proof = fixture(index, count)
                result = verify_branch(raw, **proof)
                self.assertIs(result['merkle_membership_verified'], True)
                for flag in ('header_chain_verified', 'inclusion_verified', 'finality_verified', 'custody_verified', 'mint_authorized', 'bridge_ready'):
                    self.assertIs(result[flag], False)

    def test_real_genesis_header_and_known_coinbase_txid(self):
        # Header serialization independently pins the root and displayed block hash.
        header = bytes.fromhex('01000000' + '00' * 32 +
            '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'
            '29ab5f49ffff001d1dac2b7c')
        self.assertEqual(digest(header), '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
        self.assertEqual(header[36:68][::-1].hex(), '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')

    def test_different_transaction_or_header_is_rejected(self):
        raw, proof = fixture()
        with self.assertRaises(Invalid):
            verify_branch(tx(amounts=(999,)), **proof)
        proof['header'] = bytes(80)
        with self.assertRaisesRegex(Invalid, 'header hash'):
            verify_branch(raw, **proof)

    def test_wrong_depth_index_count_and_types(self):
        raw, original = fixture()
        for field, value in (('siblings', []), ('siblings', original['siblings'] + ['00' * 32]),
                             ('tx_index', -1), ('tx_index', 3), ('tx_index', True),
                             ('tx_count', 0), ('tx_count', 100001), ('tx_count', 3.0),
                             ('header', bytes(81)), ('expected_block_hash', 'AB' * 32)):
            proof = dict(original, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(Invalid):
                verify_branch(raw, **proof)

    def test_wrong_endianness_and_corrupt_sibling(self):
        raw, proof = fixture()
        for sibling in (bytes.fromhex(proof['siblings'][0])[::-1].hex(), 'ff' * 32, '00'):
            changed = dict(proof, siblings=[sibling] + proof['siblings'][1:])
            with self.assertRaises(Invalid):
                verify_branch(raw, **changed)

    def test_required_odd_duplication_and_mutation_are_distinguished(self):
        raw, proof = fixture(2, 3)
        verify_branch(raw, **proof)
        with self.assertRaisesRegex(Invalid, 'odd Merkle'):
            verify_branch(raw, **dict(proof, siblings=['00' * 32] + proof['siblings'][1:]))
        raw, proof = fixture(0, 2)
        duplicate = bytes.fromhex(decode(raw).txid)[::-1]
        header = proof['header'][:36] + h(duplicate + duplicate) + proof['header'][68:]
        proof.update(header=header, expected_block_hash=digest(header), siblings=[decode(raw).txid])
        with self.assertRaisesRegex(Invalid, 'Mutated'):
            verify_branch(raw, **proof)

    def test_64_byte_leaf_is_refused(self):
        raw = tx(amounts=(1,), script=b'\x51' * 4)
        self.assertEqual(len(raw), 64)
        root = bytes.fromhex(decode(raw).txid)[::-1]
        header = bytes(36) + root + bytes(12)
        with self.assertRaisesRegex(Invalid, '64-byte'):
            verify_branch(raw, header=header, expected_block_hash=digest(header), tx_index=0, tx_count=1, siblings=[])

    def test_witness_changes_do_not_change_transaction_membership(self):
        raw, proof = fixture(0, 1)
        witness = tx(b'\x01\x02ab', amounts=(100,))
        self.assertEqual(decode(raw).txid, decode(witness).txid)
        self.assertEqual(verify_branch(raw, **proof), verify_branch(witness, **proof))


    def test_cli_proof_validation_precedes_journal_writes(self):
        raw, proof = fixture()
        document = {key: value for key, value in proof.items()
                    if key not in ('header', 'expected_block_hash')}
        document['header_hex'] = proof['header'].hex()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, proof_path, journal = root / 'tx.hex', root / 'proof.json', root / 'btc.sqlite'
            raw_path.write_text(raw.hex())
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'inspect-btc-deposit.py'),
                       '--raw-tx-file', str(raw_path), '--network', 'bitcoin-regtest',
                       '--txid', decode(raw).txid, '--vout', '0', '--script-pubkey', SCRIPT.hex(),
                       '--journal', str(journal)]
            proof_args = ['--proof-file', str(proof_path), '--block-hash', proof['expected_block_hash']]
            invalid_documents = [
                '{', '[]', json.dumps(dict(document, unexpected=True)),
                json.dumps(dict(document, tx_index=True)),
                json.dumps(dict(document, header_hex=123)),
                json.dumps(dict(document, siblings=[])),
                json.dumps(document)[:-1] + ',"tx_count":3}',
                json.dumps(document).replace('"tx_count": 3', '"tx_count": NaN'),
                json.dumps(document).replace('"tx_count": 3', '"tx_count": 1.0'),
                json.dumps(document).replace('"tx_count": 3', '"tx_count": ' + '9' * 21),
                ' ' * 4097, '[' * 1500 + ']' * 1500,
            ]
            for encoded in invalid_documents:
                proof_path.write_text(encoded)
                result = subprocess.run(command + proof_args, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse(journal.exists())
            proof_path.write_text(json.dumps(document))
            for extra in (proof_args[:-1] + ['00' * 32], proof_args[:2], proof_args[2:]):
                result = subprocess.run(command + extra, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(journal.exists())
            result = subprocess.run(command + proof_args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            self.assertTrue(output['proof']['merkle_membership_verified'])
            self.assertFalse(output['inclusion_verified'])
            self.assertFalse(output['mint_authorized'])
            self.assertFalse(output['proof']['bridge_ready'])
            self.assertEqual(output['journal']['inserted'], 1)
            before = journal.read_bytes()
            proof_path.write_text('{}')
            result = subprocess.run(command + proof_args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(journal.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
