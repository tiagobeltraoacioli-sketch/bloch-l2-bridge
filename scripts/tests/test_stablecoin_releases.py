"""Synthetic exact-release matching, transfer binding and CLI boundary tests."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from usdt_observer.common import Invalid
from usdt_observer.releases import match_release, decode_releases
from usdt_observer.ethereum import validate_events
from usdt_observer.stablecoins import select_route
from test_stablecoin_observer import catalog_fixture, evidence_for, configuration_for
from test_usdt_ethereum_observer import abi, tagged, TRANSFER_TOPIC

TOPIC = '0xefc74236f44fee676210517e8c459916af27488f41cc5bcb7973c09a425a4e1a'


def add_release(route, evidence, nonce=7, burn='0x' + 'bb' * 32):
    recipient, amount = '0x' + 'ac' * 20, 1_000_000
    receipt = evidence['receipt']
    metadata = {k: receipt[k] for k in ('transactionHash', 'transactionIndex', 'blockHash', 'blockNumber')}
    metadata['removed'] = False
    index = 17 + len(receipt['logs'])
    receipt['logs'].append(dict(metadata, address=route['token_vm_hex'], logIndex=hex(index),
        topics=[TRANSFER_TOPIC, '0x' + abi(route['vault_vm_hex']).hex(), '0x' + abi(recipient).hex()],
        data='0x' + abi(amount).hex()))
    identity = tagged('BLOCH-USDT-RELEASE-v1', route['route_id'], nonce, recipient, amount, burn)
    receipt['logs'].append(dict(metadata, address=route['vault_vm_hex'], logIndex=hex(index + 1),
        topics=[TOPIC, identity, route['route_id']],
        data='0x' + b''.join(abi(x) for x in [nonce, recipient, amount, burn]).hex()))
    return dict(native_domain=route['native_domain'], native_asset=route['native_asset'],
                route_id=route['route_id'], nonce=str(nonce), recipient=recipient,
                amount=str(amount), native_burn=burn)


class ReleaseObserverTest(unittest.TestCase):
    def setUp(self):
        self.catalog = catalog_fixture()
        self.route = select_route(self.catalog, 'bUSDC', 'ethereum-mainnet', True)
        self.evidence = evidence_for(self.route)
        self.evidence['receipt']['logs'] = []
        self.expected = add_release(self.route, self.evidence)

    def test_matching_release_does_not_settle_or_authenticate_native_burn(self):
        result = match_release(self.route, self.evidence, self.expected)
        self.assertTrue(result['release_observation_matched'])
        self.assertEqual(result['observation']['amount'], '1000000')
        for flag in ['native_release_authenticated', 'finality_verified', 'redemption_settled',
                     'mint_authorized', 'bridge_ready']:
            self.assertIs(result[flag], False)

    def test_every_native_identity_field_must_match(self):
        for key in self.expected:
            changed = dict(self.expected)
            changed[key] = '8' if key == 'nonce' else '1000001' if key == 'amount' else '0x' + 'cd' * (20 if key == 'recipient' else 32)
            with self.subTest(key=key), self.assertRaises(Invalid):
                match_release(self.route, self.evidence, changed)

    def test_canonical_decimal_native_fields_required(self):
        for key in ['nonce', 'amount']:
            for value in [7, True, '07', '+7', '7.0', str(1 << 64), '٧', '']:
                with self.assertRaises(Invalid):
                    match_release(self.route, self.evidence, dict(self.expected, **{key: value}))

    def test_wrong_token_direction_amount_and_destination_refused(self):
        for change in ['token', 'direction', 'amount', 'recipient']:
            evidence = copy.deepcopy(self.evidence)
            log = evidence['receipt']['logs'][0]
            if change == 'token': log['address'] = '0x' + 'cd' * 20
            if change == 'direction': log['topics'][1], log['topics'][2] = log['topics'][2], log['topics'][1]
            if change == 'amount': log['data'] = '0x' + abi(999999).hex()
            if change == 'recipient': log['topics'][2] = '0x' + abi('0x' + 'cd' * 20).hex()
            with self.assertRaises(Invalid):
                match_release(self.route, evidence, self.expected)

    def test_out_of_order_unique_nonces_are_valid(self):
        add_release(self.route, self.evidence, 2, '0x' + 'bc' * 32)
        self.assertEqual(len(validate_events(self.route, self.evidence, decode_releases)), 2)

    def test_duplicate_nonce_or_burn_refused(self):
        for nonce, burn in [(7, '0x' + 'bc' * 32), (8, self.expected['native_burn'])]:
            evidence = copy.deepcopy(self.evidence)
            add_release(self.route, evidence, nonce, burn)
            with self.assertRaises(Invalid):
                match_release(self.route, evidence, self.expected)

    def test_ambiguous_transfer_or_transfer_reuse_refused(self):
        logs = self.evidence['receipt']['logs']
        logs.insert(1, copy.deepcopy(logs[0]))
        for i, log in enumerate(logs): log['logIndex'] = hex(17 + i)
        with self.assertRaises(Invalid): match_release(self.route, self.evidence, self.expected)
        logs.pop(1)
        for i, log in enumerate(logs): log['logIndex'] = hex(17 + i)
        add_release(self.route, self.evidence, 8, '0x' + 'bc' * 32)
        logs.pop(2)
        for i, log in enumerate(logs): log['logIndex'] = hex(17 + i)
        with self.assertRaises(Invalid): match_release(self.route, self.evidence, self.expected)

    def test_failed_removed_nonfinal_receipts_refused(self):
        for mode in ['status', 'removed', 'finality', 'digest', 'gap']:
            e = copy.deepcopy(self.evidence)
            if mode == 'status': e['receipt']['status'] = '0x0'
            if mode == 'removed': e['receipt']['logs'][1]['removed'] = True
            if mode == 'finality': e['finalized_block']['number'] = '0x63'
            if mode == 'digest': e['receipt']['logs'][1]['topics'][1] = '0x' + 'ab' * 32
            if mode == 'gap': e['receipt']['logs'][1]['logIndex'] = '0x20'
            with self.assertRaises(Invalid): match_release(self.route, e, self.expected)

    def test_cli_requires_complete_vault_checks_and_keeps_settlement_false(self):
        captured = copy.deepcopy(self.evidence)
        captured['vault_runtime'] = {
            'block_hash': captured['receipt']['blockHash'], 'block_number': captured['receipt']['blockNumber'],
            'address': self.route['vault_vm_hex'],
            'code': self.catalog['assets'][1]['manifest']['routes'][0]['deployment']['runtime_code'],
            'configuration': configuration_for(self.route),
            'reserves': {'total_locked': '0x' + abi(0).hex(), 'token_balance': '0x' + abi(0).hex()}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, data in [('config', self.catalog), ('release', self.expected), ('evidence', captured)]:
                (root / name).write_text(json.dumps(data))
            cmd = [sys.executable, str(SCRIPTS / 'inspect-stablecoin-release.py'), '--config', str(root / 'config'),
                   '--release', str(root / 'release'), '--evidence', str(root / 'evidence'),
                   '--asset', 'bUSDC', '--allow-synthetic']
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['redemption_settled'])
            captured['vault_runtime']['reserves']['total_locked'] = '0x' + abi(1).hex()
            (root / 'evidence').write_text(json.dumps(captured))
            refused = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(refused.stdout, '')
