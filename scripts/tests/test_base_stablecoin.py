"""Base USDC route, deposit, payout, runtime and source-identity isolation."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from test_stablecoin_observer import catalog_fixture, evidence_for, configuration_for, SCRIPTS
from test_stablecoin_releases import add_release
from test_custody_deployment_manifest import candidate
from usdt_observer.networks import BASE_GENESIS, BASE_USDC, BASE_SOURCE_DOMAIN
from usdt_observer.stablecoins import select_route
from usdt_observer.ethereum import validate
from usdt_observer.collect import collect
from usdt_observer.releases import match_release
from custody_deployment_manifest import validate_custody_deployment_manifest


def base_catalog():
    catalog = catalog_fixture()
    manifest = catalog['assets'][1]['manifest']
    manifest['version'] = 3
    route = manifest['routes'][0]
    route.update(network='base-mainnet', chain_id='eip155:8453', genesis_hash=BASE_GENESIS,
                 source_domain=BASE_SOURCE_DOMAIN, token=BASE_USDC)
    return catalog


class BaseStablecoinTest(unittest.TestCase):
    def setUp(self):
        self.catalog = base_catalog()
        self.route = select_route(self.catalog, 'bUSDC', 'base-mainnet', True)
        self.evidence = evidence_for(self.route)
        self.evidence['chain_id'] = '0x2105'

    def runtime(self):
        return dict(block_hash=self.evidence['receipt']['blockHash'],
                    block_number=self.evidence['receipt']['blockNumber'],
                    address=self.route['vault_vm_hex'],
                    code=self.catalog['assets'][1]['manifest']['routes'][0]['deployment']['runtime_code'],
                    configuration=configuration_for(self.route),
                    reserves={'total_locked': '0x' + (1_000_000).to_bytes(32, 'big').hex(),
                              'token_balance': '0x' + (1_000_000).to_bytes(32, 'big').hex()})

    def test_deposit_and_release_bind_base_route(self):
        self.assertEqual(len(validate(self.route, self.evidence)), 1)
        self.evidence['receipt']['logs'] = []
        expected = add_release(self.route, self.evidence)
        result = match_release(self.route, self.evidence, expected)
        self.assertTrue(result['release_observation_matched'])
        self.assertFalse(result['redemption_settled'])
        self.assertFalse(result['bridge_ready'])
        ethereum = select_route(catalog_fixture(), 'bUSDC', 'ethereum-mainnet', True)
        self.assertNotEqual(ethereum['route_id'], self.route['route_id'])
        with self.assertRaises(ValueError):
            match_release(ethereum, self.evidence, expected)

    def test_wrong_chain_genesis_or_finality_rejected(self):
        for key, value in [('chain_id', '0x1'), ('chain_id', '0x14a34'),
                           ('genesis', dict(self.evidence['genesis'], hash='0x'+'ab'*32)),
                           ('finalized_block', dict(self.evidence['finalized_block'], number='0x1'))]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(self.route, dict(self.evidence, **{key: value}))

    def test_collection_uses_base_chain_and_finalized_boundary(self):
        e = self.evidence
        source = Mock()
        source.eth.side_effect = [e['chain_id'], e['genesis'], e['receipt'],
                                 e['canonical_block'], e['finalized_block'],
                                 e['finalized_block'], e['canonical_block']]
        collected = collect(self.route, e['receipt']['transactionHash'], source)
        self.assertEqual(collected, e)
        self.assertIn(unittest.mock.call('eth_getBlockByNumber', ['finalized', False]), source.eth.call_args_list)
        source.eth.side_effect = ['0x1']
        with self.assertRaises(ValueError):
            collect(self.route, e['receipt']['transactionHash'], source)

    def test_explicit_opt_in_canonical_usdc_and_aggregate_cap(self):
        for field, value in [('version', 2), ('token', '0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca'),
                             ('chain_id', 'eip155:1')]:
            catalog = base_catalog()
            manifest = catalog['assets'][1]['manifest']
            (manifest if field == 'version' else manifest['routes'][0])[field] = value
            with self.assertRaises(ValueError):
                select_route(catalog, 'bUSDC', 'base-mainnet', True)
        manifest = self.catalog['assets'][1]['manifest']
        ethereum = catalog_fixture()['assets'][1]['manifest']['routes'][0]
        manifest['routes'].append(ethereum)
        manifest['native_supply_cap'] = sum(r['cap'] for r in manifest['routes'])
        self.assertEqual(select_route(self.catalog, 'bUSDC', 'base-mainnet', True)['route_id'], self.route['route_id'])
        manifest['native_supply_cap'] -= 1
        with self.assertRaises(ValueError):
            select_route(self.catalog, 'bUSDC', 'base-mainnet', True)

    def test_both_cli_directions_and_missing_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'catalog.json').write_text(json.dumps(self.catalog))
            def run(script, extra):
                return subprocess.run([sys.executable, str(SCRIPTS/script), '--config', str(root/'catalog.json'),
                    '--asset', 'bUSDC', '--network', 'base-mainnet', '--allow-synthetic',
                    '--evidence', str(root/'evidence.json'), *extra], text=True, capture_output=True)
            (root/'evidence.json').write_text(json.dumps(dict(self.evidence, vault_runtime=self.runtime())))
            result = run('observe-stablecoin-deposit.py', [])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['mint_authorized'])
            (root/'evidence.json').write_text(json.dumps(self.evidence))
            self.assertEqual(run('observe-stablecoin-deposit.py', []).returncode, 1)
            self.evidence['receipt']['logs'] = []
            expected = add_release(self.route, self.evidence)
            (root/'release.json').write_text(json.dumps(expected))
            (root/'evidence.json').write_text(json.dumps(dict(self.evidence, vault_runtime=self.runtime())))
            result = run('inspect-stablecoin-release.py', ['--release', str(root/'release.json')])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['redemption_settled'])

    def test_base_custody_profile_and_legacy_plan_separation(self):
        plan = candidate()
        plan['schema'] = 'postern.custody-deployment-plan.v2'
        plan['source'].update(network='base-mainnet', chain_id='eip155:8453', genesis_hash=BASE_GENESIS,
                              source_domain=BASE_SOURCE_DOMAIN, token_address=BASE_USDC)
        result = validate_custody_deployment_manifest(plan)
        self.assertEqual(result['sourceDomain'], BASE_SOURCE_DOMAIN)
        self.assertEqual(result['custodyThreshold'], 3)
        self.assertFalse(result['activationAuthorized'])
        plan['schema'] = 'postern.custody-deployment-plan.v1'
        with self.assertRaises(ValueError):
            validate_custody_deployment_manifest(plan)
