"""Synthetic stablecoin identity separation and CLI tests; no funded routes."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from usdt_observer.common import Invalid, normalized_route
from usdt_observer.stablecoins import select_route
from usdt_observer.ethereum import validate
from usdt_observer.journal import record
from test_usdt_ethereum_observer import fixture, append_deposit


def catalog_fixture():
    usdt = json.loads((SCRIPTS / 'usdt-routes.synthetic.json').read_text())
    usdc = copy.deepcopy(usdt)
    usdc['native_asset'] = '0x' + hashlib.sha256(b'synthetic-bUSDC').hexdigest()
    usdc['routes'] = [usdc['routes'][0]]
    usdc['routes'][0]['token'] = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
    usdc['routes'][0]['vault'] = '0x' + hashlib.sha256(b'synthetic-USDC-vault').hexdigest()[:40]
    return {'version': 1, 'assets': [
        {'source_symbol': 'USDT', 'symbol': 'bUSDT', 'manifest': usdt},
        {'source_symbol': 'USDC', 'symbol': 'bUSDC', 'manifest': usdc}]}


def evidence_for(route):
    _, evidence = fixture()
    evidence['genesis']['hash'] = route['genesis_hash']
    tx = '0x' + hashlib.sha256(route['route_id'].encode()).hexdigest()
    evidence['receipt']['transactionHash'] = tx
    evidence['canonical_block']['transactions'][1] = tx
    evidence['receipt']['logs'] = []
    append_deposit(route, evidence, 7, 1_000_000)
    return evidence


class StablecoinObserverTest(unittest.TestCase):
    def setUp(self):
        self.catalog = catalog_fixture()

    def route(self, symbol='bUSDC', network='ethereum-mainnet'):
        return select_route(self.catalog, symbol, network, True)

    def test_both_assets_and_legacy_ids_are_stable(self):
        before = copy.deepcopy(self.catalog)
        usdt, usdc = self.route('bUSDT'), self.route()
        old = normalized_route(self.catalog['assets'][0]['manifest'], 'ethereum-mainnet', True)
        self.assertEqual(usdt['route_id'], old['route_id'])
        self.assertNotEqual(usdt['native_asset'], usdc['native_asset'])
        self.assertNotEqual(usdt['route_id'], usdc['route_id'])
        self.assertEqual(self.catalog, before)
        self.assertEqual(self.route('bUSDT', 'tron-mainnet')['source_symbol'], 'USDT')

    def test_synthetic_requires_opt_in(self):
        with self.assertRaises(Invalid):
            select_route(self.catalog, 'bUSDC', 'ethereum-mainnet')

    def test_no_usdc_tron_or_unknown_symbol_fallback(self):
        for symbol, network in [('bUSDC', 'tron-mainnet'), ('USDC', 'ethereum-mainnet'),
                                ('bETH', 'ethereum-mainnet'), ('bUSDC', 'base-mainnet')]:
            with self.subTest(symbol=symbol, network=network), self.assertRaises(Invalid):
                self.route(symbol, network)

    def test_catalog_schema_and_duplicate_assets(self):
        for mutate in [lambda c: c.update(version=True), lambda c: c.update(extra=1),
                       lambda c: c['assets'].pop(),
                       lambda c: c['assets'].__setitem__(1, copy.deepcopy(c['assets'][0])),
                       lambda c: c['assets'][1].update(symbol='USDC'),
                       lambda c: c['assets'][1].update(source_symbol='ETH')]:
            self.catalog = catalog_fixture()
            mutate(self.catalog)
            with self.assertRaises(ValueError):
                self.route()

    def test_shared_native_asset_or_vault_refused_even_case_changed(self):
        for field in ['native_asset', 'vault']:
            self.catalog = catalog_fixture()
            a, b = [x['manifest'] for x in self.catalog['assets']]
            if field == 'vault':
                a, b = a['routes'][0], b['routes'][0]
            b[field] = '0x' + a[field][2:].upper()
            with self.assertRaises(Invalid):
                self.route()

    def test_wrong_token_or_decimals_refused(self):
        for symbol in ['bUSDT', 'bUSDC']:
            for field, value in [('token', '0x' + '12' * 20), ('decimals', 18), ('decimals', True)]:
                self.catalog = catalog_fixture()
                entry = next(e for e in self.catalog['assets'] if e['symbol'] == symbol)
                entry['manifest']['routes'][0][field] = value
                with self.assertRaises(ValueError):
                    self.route(symbol)

    def test_invalid_unselected_asset_also_refuses(self):
        self.catalog['assets'][0]['manifest']['routes'][1]['cap'] = 1 << 64
        with self.assertRaises(ValueError):
            self.route('bUSDC')

    def test_destination_and_synthetic_mode_must_match(self):
        for field, value in [('native_domain', '0x' + hashlib.sha256(b'other-chain').hexdigest()),
                             ('synthetic', False)]:
            self.catalog = catalog_fixture()
            self.catalog['assets'][1]['manifest'][field] = value
            with self.assertRaises(Invalid):
                self.route()

    def test_same_network_cannot_name_different_genesis_across_assets(self):
        route = self.catalog['assets'][1]['manifest']['routes'][0]
        genesis = hashlib.sha256(b'other-genesis').digest()
        route['genesis_hash'] = '0x' + genesis.hex()
        route['source_domain'] = '0x' + hashlib.sha256(
            b'BLOCH-USDT-SOURCE-CONFIG-v1\0ethereum-mainnet\0' + genesis).hexdigest()
        with self.assertRaises(Invalid):
            self.route()

    def test_same_nonce_separates_deposits_and_wrong_transfer_refuses(self):
        usdt, usdc = self.route('bUSDT'), self.route()
        a, b = evidence_for(usdt), evidence_for(usdc)
        self.assertNotEqual(validate(usdt, a)[0]['deposit_id'], validate(usdc, b)[0]['deposit_id'])
        b['receipt']['logs'][0]['address'] = usdt['token_vm_hex']
        with self.assertRaises(Invalid):
            validate(usdc, b)

    def test_wrong_route_event_refuses_even_with_correct_token_transfer(self):
        usdt, usdc = self.route('bUSDT'), self.route()
        evidence = evidence_for(usdc)
        evidence['receipt']['logs'][1]['topics'][2] = usdt['route_id']
        with self.assertRaises(Invalid):
            validate(usdc, evidence)

    def test_legacy_entrypoint_refuses_usdc_manifest(self):
        with self.assertRaises(Invalid):
            normalized_route(self.catalog['assets'][1]['manifest'], 'ethereum-mainnet', True)

    def test_same_source_event_cannot_be_reassigned_between_tokens(self):
        usdt, usdc = self.route('bUSDT'), self.route()
        a, b = evidence_for(usdt), evidence_for(usdc)
        tx = a['receipt']['transactionHash']
        b['receipt']['transactionHash'] = tx
        b['canonical_block']['transactions'][1] = tx
        for log in b['receipt']['logs']:
            log['transactionHash'] = tx
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'journal.sqlite'
            record(path, usdt, validate(usdt, a), 'ab' * 32)
            with self.assertRaises(Invalid):
                record(path, usdc, validate(usdc, b), 'cd' * 32)

    def test_cli_output_and_journal_remain_non_authorizing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, evidence = root / 'config.json', root / 'evidence.json'
            config.write_text(json.dumps(self.catalog))
            for symbol in ['bUSDT', 'bUSDC']:
                evidence.write_text(json.dumps(evidence_for(self.route(symbol))))
                result = subprocess.run([
                    sys.executable, str(SCRIPTS / 'observe-stablecoin-deposit.py'),
                    '--config', str(config), '--asset', symbol, '--network', 'ethereum-mainnet',
                    '--allow-synthetic', '--evidence', str(evidence), '--journal', str(root / 'journal.sqlite')],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                output = json.loads(result.stdout)
                self.assertEqual(output['symbol'], symbol)
                self.assertEqual(output['native_asset'], self.route(symbol)['native_asset'])
                self.assertEqual(output['observations'][0]['amount'], '1000000')
                for flag in ['mint_authorized', 'bridge_ready', 'finality_verified',
                             'deployment_verified', 'native_execution_performed']:
                    self.assertIs(output[flag], False)


if __name__ == '__main__':
    unittest.main()
