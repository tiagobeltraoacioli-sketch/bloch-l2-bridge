"""Independent wire vectors and adversarial shared receipt decoding tests."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.common import (
    DEPOSIT_TOPIC, TRANSFER_TOPIC, MAX_JSON, MAX_LOG_DATA, Invalid, abi_uint,
    decode_deposits, deposit_digest, integer, load_json, parse_json, quantity,
    route_digest, word,
)

VECTORS = load_json(Path(__file__).resolve().parents[2] / 'test-vectors' / 'usdt-v1.json')


def fixture(case_index=0):
    vector = VECTORS
    case = vector['cases'][case_index]
    route = {'network': ('ethereum-mainnet', 'tron-mainnet')[case_index],
             'source_domain': case['source_domain'], 'native_domain': vector['native_domain'],
             'native_asset': vector['native_asset'], 'token_vm_hex': vector['token'],
             'vault_vm_hex': vector['vault'], 'cap': vector['cap'], 'route_id': case['route_id']}
    sender = word(vector['sender'], 20)
    recipient = word(vector['pq_recipient_hash'], 32)
    amount = vector['amount']
    nonce = vector['nonce']
    logs = [
        {'address': word(vector['token'], 20),
         'topics': [TRANSFER_TOPIC, sender.rjust(32, b'\0'), word(vector['vault'], 20).rjust(32, b'\0')],
         'data': abi_uint(amount), 'log_index': 27},
        {'address': word(vector['vault'], 20),
         'topics': [DEPOSIT_TOPIC, word(case['deposit_id'], 32), word(case['route_id'], 32)],
         'data': abi_uint(nonce) + sender.rjust(32, b'\0') + abi_uint(amount) + recipient,
         'log_index': 28},
    ]
    return route, logs


def changed_deposit(route, log, nonce=None, amount=None, sender=None):
    log = copy.deepcopy(log)
    raw = log['data']
    nonce = int.from_bytes(raw[:32], 'big') if nonce is None else nonce
    sender = raw[44:64] if sender is None else sender
    amount = int.from_bytes(raw[64:96], 'big') if amount is None else amount
    recipient = raw[96:128]
    log['data'] = abi_uint(nonce) + sender.rjust(32, b'\0') + abi_uint(amount) + recipient
    log['topics'][1] = deposit_digest(word(route['route_id'], 32), nonce, sender, amount, recipient)
    return log


class SharedObserverTest(unittest.TestCase):
    def test_independent_existing_vectors_for_both_source_domains(self):
        ids = []
        for index, case in enumerate(VECTORS['cases']):
            route, logs = fixture(index)
            self.assertEqual(route_digest(route).hex(), case['route_id'][2:])
            digest = deposit_digest(word(case['route_id'], 32), VECTORS['nonce'],
                                    word(VECTORS['sender'], 20), VECTORS['amount'],
                                    word(VECTORS['pq_recipient_hash'], 32))
            self.assertEqual(digest.hex(), case['deposit_id'][2:])
            result = decode_deposits(route, logs)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['deposit_id'], case['deposit_id'])
            self.assertEqual(result[0]['amount'], VECTORS['amount'])
            self.assertEqual(result[0]['nonce'], VECTORS['nonce'])
            self.assertEqual((result[0]['transfer_log_index'], result[0]['log_index']), (27, 28))
            ids.append(result[0]['deposit_id'])
        self.assertNotEqual(*ids)

    def test_wrong_transfer_amount_sender_destination_or_emitter_fails(self):
        route, original = fixture()
        mutations = [lambda l: l[0].update(data=abi_uint(VECTORS['amount'] - 1)),
                     lambda l: l[0]['topics'].__setitem__(1, b'\0' * 12 + b'\xaa' * 20),
                     lambda l: l[0]['topics'].__setitem__(2, b'\0' * 12 + b'\xaa' * 20),
                     lambda l: l[0].update(address=b'\xaa' * 20),
                     lambda l: l[0]['topics'].__setitem__(0, b'\xaa' * 32)]
        for mutation in mutations:
            logs = copy.deepcopy(original)
            mutation(logs)
            with self.subTest(mutation=mutation), self.assertRaises(Invalid):
                decode_deposits(route, logs)

    def test_ambiguous_preceding_transfers_and_reused_transfer_fail(self):
        route, logs = fixture()
        duplicate_transfer = copy.deepcopy(logs[0])
        duplicate_transfer['log_index'] = 26
        with self.assertRaises(Invalid):
            decode_deposits(route, [duplicate_transfer, *logs])
        second = changed_deposit(route, logs[1], nonce=VECTORS['nonce'] + 1)
        second['log_index'] = 29
        with self.assertRaises(Invalid):
            decode_deposits(route, [*logs, second])
        logs[0]['log_index'] = 29
        with self.assertRaises(Invalid):
            decode_deposits(route, [logs[1], logs[0]])

    def test_duplicate_deposit_id_and_same_nonce_different_id_fail(self):
        route, logs = fixture()
        repeated = copy.deepcopy(logs)
        repeated[0]['log_index'], repeated[1]['log_index'] = 29, 30
        with self.assertRaises(Invalid):
            decode_deposits(route, logs + repeated)
        repeated[0]['data'] = abi_uint(VECTORS['amount'] + 1)
        repeated[1] = changed_deposit(route, repeated[1], amount=VECTORS['amount'] + 1)
        with self.assertRaises(Invalid):
            decode_deposits(route, logs + repeated)

    def test_abi_integer_and_address_padding_are_canonical(self):
        route, original = fixture()
        for offset in (0, 32, 64):
            logs = copy.deepcopy(original)
            raw = bytearray(logs[1]['data'])
            raw[offset] = 1
            logs[1]['data'] = bytes(raw)
            with self.subTest(offset=offset), self.assertRaises(Invalid):
                decode_deposits(route, logs)
        for topic in (1, 2):
            logs = copy.deepcopy(original)
            logs[0]['topics'][topic] = b'\1' + logs[0]['topics'][topic][1:]
            with self.subTest(topic=topic), self.assertRaises(Invalid):
                decode_deposits(route, logs)
        for target in (0, 1):
            for suffix in (b'\0', b'\0' * 32):
                logs = copy.deepcopy(original)
                logs[target]['data'] += suffix
                with self.assertRaises(Invalid):
                    decode_deposits(route, logs)

    def test_wrong_route_or_digest_cannot_cross_source_domains(self):
        eth_route, eth_logs = fixture(0)
        tron_route, _ = fixture(1)
        with self.assertRaises(Invalid):
            decode_deposits(tron_route, eth_logs)
        eth_logs[1]['topics'][1] = b'\xaa' * 32
        with self.assertRaises(Invalid):
            decode_deposits(eth_route, eth_logs)
        eth_route['cap'] += 1
        with self.assertRaises(Invalid):
            decode_deposits(eth_route, eth_logs)

    def test_duplicate_unordered_and_floating_log_indices_rejected(self):
        route, original = fixture()
        for index in (27, 26, 28.0, True, -1, 1 << 32):
            logs = copy.deepcopy(original)
            logs[1]['log_index'] = index
            with self.subTest(index=index), self.assertRaises(Invalid):
                decode_deposits(route, logs)

    def test_missing_intermediate_log_index_is_rejected(self):
        route, logs = fixture()
        logs[1]['log_index'] += 1
        with self.assertRaises(Invalid):
            decode_deposits(route, logs)

    def test_json_duplicate_nested_nonfinite_and_oversized_documents_fail(self):
        for raw in (b'{"nonce":1,"nonce":2}', b'{"x":{"n":1,"n":2}}',
                    b'{"nonce":NaN}', b'{"nonce":Infinity}', b'{"nonce":-Infinity}',
                    b' ' * (MAX_JSON + 1), b'\xff', b'{'):
            with self.subTest(raw=raw[:40]), self.assertRaises(Invalid):
                parse_json(raw)
        for value in (1.0, True, -1, 1 << 64, '1'):
            with self.subTest(value=value), self.assertRaises(Invalid):
                integer(value)
        with self.assertRaises(Invalid):
            abi_uint(parse_json(b'{"nonce":1.0}')['nonce'])
        with self.assertRaises(Invalid):
            abi_uint(parse_json(b'{"nonce":1e999}')['nonce'])
        for value in ('0x00', '0x01', '1', '0X1', '0x10000000000000000', 1.0):
            with self.assertRaises(Invalid):
                quantity(value)

    def test_limits_are_checked_before_event_matching(self):
        route, logs = fixture()
        unrelated = {'address': b'\xaa' * 20, 'topics': [], 'data': b'\0' * (MAX_LOG_DATA + 1), 'log_index': 29}
        with self.assertRaises(Invalid):
            decode_deposits(route, [*logs, unrelated])
        with self.assertRaises(Invalid):
            decode_deposits(route, logs * 4096)

    def test_source_vault_counter_cannot_emit_max_nonce(self):
        route, logs = fixture()
        logs[1] = changed_deposit(route, logs[1], nonce=(1 << 64) - 1)
        with self.assertRaises(Invalid):
            decode_deposits(route, logs)

    def test_multiple_deposits_must_have_consecutive_nonce_in_receipt(self):
        route, original = fixture()
        for nonce in (VECTORS['nonce'] - 1, VECTORS['nonce'] + 2):
            logs = copy.deepcopy(original)
            transfer = copy.deepcopy(logs[0])
            transfer['log_index'] = 29
            deposit = changed_deposit(route, logs[1], nonce=nonce)
            deposit['log_index'] = 30
            with self.subTest(nonce=nonce), self.assertRaises(Invalid):
                decode_deposits(route, [*logs, transfer, deposit])

    def test_vault_self_transfer_cannot_back_its_own_deposit(self):
        route, logs = fixture()
        vault = word(route['vault_vm_hex'], 20)
        logs[0]['topics'][1] = vault.rjust(32, b'\0')
        logs[1] = changed_deposit(route, logs[1], sender=vault)
        with self.assertRaises(Invalid):
            decode_deposits(route, logs)


if __name__ == '__main__':
    unittest.main()
