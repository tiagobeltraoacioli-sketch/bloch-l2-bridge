"""Synthetic, offline adversarial Ethereum receipt evidence tests."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.ethereum import MAX_LOG_DATA_BYTES, MAX_LOGS, validate

DEPOSIT_TOPIC = '0x86f22d28da637559602e716d294d9c661cb8177451cfdf19c194c0c79503c174'
TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'


def abi(value):
    if isinstance(value, int):
        return value.to_bytes(32, 'big')
    return bytes.fromhex(value[2:]).rjust(32, b'\0')


def tagged(tag, *values):
    return '0x' + hashlib.sha256(tag.encode().ljust(32, b'\0') + b''.join(abi(v) for v in values)).hexdigest()


def fixture():
    route = {'network': 'ethereum-mainnet', 'genesis_hash': '0x' + '11' * 32,
             'source_domain': '0x' + '22' * 32, 'native_domain': '0x' + '33' * 32,
             'native_asset': '0x' + '44' * 32,
             'token_vm_hex': '0xdac17f958d2ee523a2206206994597c13d831ec7',
             'vault_vm_hex': '0x' + '55' * 20, 'cap': 1_000_000_000}
    route['route_id'] = tagged('BLOCH-USDT-ROUTE-v1', route['source_domain'], route['native_domain'],
                               route['native_asset'], route['token_vm_hex'], route['vault_vm_hex'], 6, route['cap'])
    tx = '0x' + '66' * 32
    block = '0x' + '77' * 32
    evidence = {'chain_id': '0x1', 'genesis': {'number': '0x0', 'hash': route['genesis_hash']},
                'receipt': {'status': '0x1', 'transactionHash': tx, 'transactionIndex': '0x1',
                            'blockHash': block, 'blockNumber': '0x64', 'logs': []},
                'canonical_block': {'number': '0x64', 'hash': block,
                                    'transactions': ['0x' + '88' * 32, tx]},
                'finalized_block': {'number': '0x65', 'hash': '0x' + '99' * 32}}
    append_deposit(route, evidence, 0, 1_000_000)
    return route, evidence


def append_deposit(route, evidence, nonce, amount):
    sender = '0x' + 'aa' * 20
    pq = '0x' + 'bb' * 32
    receipt = evidence['receipt']
    metadata = {key: receipt[key] for key in ('transactionHash', 'transactionIndex', 'blockHash', 'blockNumber')}
    start = 17 + len(receipt['logs'])
    metadata['removed'] = False
    receipt['logs'].append(dict(metadata, address=route['token_vm_hex'], logIndex=hex(start),
                                 topics=[TRANSFER_TOPIC, '0x' + abi(sender).hex(), '0x' + abi(route['vault_vm_hex']).hex()],
                                 data='0x' + abi(amount).hex()))
    deposit_id = tagged('BLOCH-USDT-DEPOSIT-v1', route['route_id'], nonce, sender, amount, pq)
    receipt['logs'].append(dict(metadata, address=route['vault_vm_hex'], logIndex=hex(start + 1),
                                 topics=[DEPOSIT_TOPIC, deposit_id, route['route_id']],
                                 data='0x' + b''.join(abi(v) for v in (nonce, sender, amount, pq)).hex()))


class EthereumObserverTest(unittest.TestCase):
    def test_finalized_deposit_and_multiple_logs(self):
        route, evidence = fixture()
        untouched = copy.deepcopy(evidence)
        observations = validate(route, evidence)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]['tx_hash'], evidence['receipt']['transactionHash'])
        self.assertEqual(observations[0]['block_hash'], evidence['receipt']['blockHash'])
        self.assertEqual(observations[0]['block_number'], 100)
        self.assertEqual(observations[0]['network'], 'ethereum-mainnet')
        self.assertEqual(evidence, untouched)
        append_deposit(route, evidence, 1, 2_000_000)
        self.assertEqual(len(validate(route, evidence)), 2)

    def test_same_height_finality_requires_matching_hash(self):
        route, evidence = fixture()
        evidence['finalized_block'] = dict(evidence['canonical_block'])
        self.assertEqual(len(validate(route, evidence)), 1)
        evidence['finalized_block']['hash'] = '0x' + 'ff' * 32
        with self.assertRaises(ValueError):
            validate(route, evidence)

    def test_network_genesis_failed_pending_and_reorg_rejected(self):
        route, original = fixture()
        mutations = [lambda e: e.update(chain_id='0x2'),
                     lambda e: e.update(chain_id='0x01'),
                     lambda e: e['genesis'].update(number='0x1'),
                     lambda e: e['genesis'].update(hash='0x' + 'ff' * 32),
                     lambda e: e['receipt'].update(status='0x0'),
                     lambda e: e['receipt'].pop('status'),
                     lambda e: e.update(receipt=None),
                     lambda e: e['receipt'].update(blockHash=None),
                     lambda e: e['canonical_block'].update(hash='0x' + 'ff' * 32),
                     lambda e: e['canonical_block'].update(number='0x63'),
                     lambda e: e['finalized_block'].update(number='0x63'),
                     lambda e: e.update(finalized_block=None),
                     lambda e: e.update(latest_block=e.pop('finalized_block'))]
        for mutation in mutations:
            evidence = copy.deepcopy(original)
            mutation(evidence)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate(route, evidence)

    def test_transaction_hash_index_and_canonical_inclusion_rejected(self):
        route, original = fixture()
        mutations = [lambda e: e['receipt'].update(transactionIndex='0x2'),
                     lambda e: e['receipt'].update(transactionHash='0x' + 'ff' * 32),
                     lambda e: e['canonical_block'].update(transactions=[]),
                     lambda e: e['canonical_block']['transactions'].reverse(),
                     lambda e: e['canonical_block']['transactions'].append(e['receipt']['transactionHash']),
                     lambda e: e['canonical_block'].update(transactions=[{'hash': e['receipt']['transactionHash']}])]
        for mutation in mutations:
            evidence = copy.deepcopy(original)
            mutation(evidence)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate(route, evidence)

    def test_every_log_metadata_is_checked_including_non_deposit_logs(self):
        route, original = fixture()
        for key, bad in [('removed', True), ('removed', 0), ('removed', None),
                         ('transactionHash', '0x' + 'dd' * 32), ('transactionIndex', '0x0'),
                         ('blockHash', '0x' + 'dd' * 32), ('blockNumber', '0x63'),
                         ('logIndex', True), ('logIndex', '0x01'), ('address', '0x01'),
                         ('topics', ['0x01']), ('topics', ['0x' + '00' * 32] * 5),
                         ('data', '0x0'), ('data', '0xgg')]:
            evidence = copy.deepcopy(original)
            evidence['receipt']['logs'][0][key] = bad
            with self.subTest(key=key, value=bad), self.assertRaises(ValueError):
                validate(route, evidence)

    def test_duplicate_reordered_indices_and_oversized_logs_fail(self):
        route, original = fixture()
        variants = []
        duplicate = copy.deepcopy(original)
        duplicate['receipt']['logs'][1]['logIndex'] = duplicate['receipt']['logs'][0]['logIndex']
        variants.append(duplicate)
        reversed_logs = copy.deepcopy(original)
        reversed_logs['receipt']['logs'].reverse()
        variants.append(reversed_logs)
        huge = copy.deepcopy(original)
        huge['receipt']['logs'][0]['data'] = '0x' + '00' * (MAX_LOG_DATA_BYTES + 1)
        variants.append(huge)
        too_many = copy.deepcopy(original)
        too_many['receipt']['logs'] *= MAX_LOGS
        variants.append(too_many)
        for evidence in variants:
            with self.assertRaises(ValueError):
                validate(route, evidence)

    def test_aggregate_byte_limit_and_unrelated_zero_data_log(self):
        route, evidence = fixture()
        unrelated = dict(evidence['receipt']['logs'][0], logIndex='0x10', topics=[], data='0x')
        evidence['receipt']['logs'].insert(0, unrelated)
        self.assertEqual(len(validate(route, evidence)), 1)
        evidence['receipt']['logs'] = [dict(unrelated, logIndex=hex(i),
                                                 data='0x' + '00' * MAX_LOG_DATA_BYTES)
                                     for i in range(17)]
        with self.assertRaisesRegex(ValueError, 'bytes exceed'):
            validate(route, evidence)

    def test_missing_middle_log_cannot_hide_ambiguous_backing_transfer(self):
        route, evidence = fixture()
        logs = evidence['receipt']['logs']
        duplicate_transfer = copy.deepcopy(logs[0])
        duplicate_transfer['logIndex'] = hex(int(logs[0]['logIndex'], 16) + 1)
        logs[1]['logIndex'] = hex(int(logs[1]['logIndex'], 16) + 1)
        logs.insert(1, duplicate_transfer)
        # The full receipt has two identical candidate backing transfers.
        with self.assertRaises(ValueError):
            validate(route, evidence)
        # Omitting the middle transfer must not make the deposit acceptable.
        logs.pop(1)
        with self.assertRaises(ValueError):
            validate(route, evidence)

    def test_wrong_vault_cross_route_and_unbacked_deposit_never_accepted(self):
        route, original = fixture()
        mutations = [lambda e: e['receipt']['logs'][1].update(address='0x' + 'cc' * 20),
                     lambda e: e['receipt']['logs'][1]['topics'].__setitem__(2, '0x' + 'dd' * 32),
                     lambda e: e['receipt']['logs'][0].update(address='0x' + 'ee' * 20),
                     lambda e: e['receipt']['logs'][0].update(data='0x' + abi(999999).hex()),
                     lambda e: e['receipt']['logs'].pop(0)]
        for mutation in mutations:
            evidence = copy.deepcopy(original)
            mutation(evidence)
            try:
                observations = validate(route, evidence)
            except ValueError:
                continue
            self.assertEqual(observations, [])

    def test_empty_unrelated_logs_and_malformed_evidence(self):
        route, evidence = fixture()
        evidence['receipt']['logs'] = []
        try:
            observations = validate(route, evidence)
        except ValueError:
            observations = []
        self.assertEqual(observations, [])
        for bad in [None, [], {}, {'result': evidence}]:
            with self.assertRaises(ValueError):
                validate(route, bad)


if __name__ == '__main__':
    unittest.main()
