"""Adversarial bytecode/block binding tests using only synthetic RPC evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from usdt_observer.common import Invalid
from usdt_observer.runtime import collect_runtime, validate_runtime, MAX_CODE
from usdt_observer.stablecoins import select_route
from test_stablecoin_observer import catalog_fixture, evidence_for, configuration_for


class StablecoinRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.catalog = catalog_fixture()
        self.route = select_route(self.catalog, 'bUSDC', 'ethereum-mainnet', True)
        self.evidence = evidence_for(self.route)
        self.runtime = {'block_hash': self.evidence['receipt']['blockHash'],
                        'configuration': configuration_for(self.route),
                        'reserves': {'total_locked': '0x' + (1_000_000).to_bytes(32, 'big').hex(),
                                     'token_balance': '0x' + (1_000_000).to_bytes(32, 'big').hex()},
                        'block_number': self.evidence['receipt']['blockNumber'],
                        'address': self.route['vault_vm_hex'],
                        'code': self.catalog['assets'][1]['manifest']['routes'][0]['deployment']['runtime_code']}

    def test_exact_match_remains_non_authorizing(self):
        before = copy.deepcopy((self.route, self.evidence, self.runtime))
        result = validate_runtime(self.route, self.evidence, self.runtime)
        self.assertTrue(result['vault_runtime_matched'])
        self.assertFalse(result['deployment_verified'])
        self.assertFalse(result['mint_authorized'])
        self.assertEqual(result['block_number'], '100')
        self.assertEqual((self.route, self.evidence, self.runtime), before)

    def test_wrong_code_address_or_block_refused(self):
        for key, value in [('code', '0x60016000fd'), ('address', '0x' + 'aa' * 20),
                           ('block_hash', '0x' + 'ab' * 32), ('block_number', '0x65')]:
            changed = dict(self.runtime, **{key: value})
            with self.subTest(key=key), self.assertRaises(Invalid):
                validate_runtime(self.route, self.evidence, changed)

    def test_empty_malformed_and_oversized_code_refused(self):
        for code in ['0x', '0x00', '0xabc', '60006000fd', '0xgggg', True, None,
                     '0x' + '12' * (MAX_CODE + 1)]:
            with self.subTest(code_type=type(code)), self.assertRaises(Invalid):
                validate_runtime(self.route, self.evidence, dict(self.runtime, code=code))

    def test_missing_and_unknown_fields_refused(self):
        for runtime in [None, {}, dict(self.runtime, extra=1),
                        {k: v for k, v in self.runtime.items() if k != 'address'}]:
            with self.assertRaises(Invalid):
                validate_runtime(self.route, self.evidence, runtime)

    def test_deposit_must_not_precede_deployment(self):
        self.route['vault_deployment_height'] = 101
        with self.assertRaises(Invalid):
            validate_runtime(self.route, self.evidence, self.runtime)
        self.route['vault_deployment_height'] = 100
        validate_runtime(self.route, self.evidence, self.runtime)

    def test_collection_uses_canonical_hash_and_rechecks_block(self):
        source = Mock()
        config = self.runtime['configuration']
        reads = [v for k, v in config.items() if k not in ('signers', 'memberships')]
        for signer, membership in zip(config['signers'], config['memberships']):
            reads.extend([signer, membership])
        reads.extend(self.runtime['reserves'].values())
        source.eth.side_effect = [self.runtime['code'], *reads, self.evidence['canonical_block']]
        self.assertEqual(collect_runtime(self.route, self.evidence, source), self.runtime)
        self.assertEqual(source.eth.call_args_list[0].args, ('eth_getCode', [
            self.route['vault_vm_hex'], {'blockHash': self.runtime['block_hash'], 'requireCanonical': True}]))
        self.assertEqual(source.eth.call_args_list[-1].args,
                         ('eth_getBlockByNumber', ['0x64', False]))
        for call in source.eth.call_args_list[1:-1]:
            self.assertEqual(call.args[0], 'eth_call')
            self.assertEqual(call.args[1][1], {
                'blockHash': self.runtime['block_hash'], 'requireCanonical': True})

    def test_rpc_failure_never_falls_back_to_latest_or_height(self):
        source = Mock()
        source.eth.side_effect = Invalid('unsupported hash selector')
        with self.assertRaises(Invalid):
            collect_runtime(self.route, self.evidence, source)
        self.assertEqual(source.eth.call_count, 1)

    def test_reorg_during_runtime_collection_refused(self):
        source = Mock()
        config = self.runtime['configuration']
        reads = [v for k, v in config.items() if k not in ('signers', 'memberships')]
        for signer, membership in zip(config['signers'], config['memberships']):
            reads.extend([signer, membership])
        reads.extend(self.runtime['reserves'].values())
        source.eth.side_effect = [self.runtime['code'], *reads,
                                  dict(self.evidence['canonical_block'], hash='0x' + 'ab' * 32)]
        with self.assertRaises(Invalid):
            collect_runtime(self.route, self.evidence, source)

    def test_invalid_receipt_refused_before_code_rpc(self):
        source = Mock()
        self.evidence['receipt']['status'] = '0x0'
        with self.assertRaises(Invalid):
            collect_runtime(self.route, self.evidence, source)
        source.eth.assert_not_called()

    def test_cli_missing_or_wrong_runtime_never_creates_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, evidence, journal = root / 'config.json', root / 'evidence.json', root / 'journal.sqlite'
            config.write_text(json.dumps(self.catalog))
            deficit = dict(self.runtime, reserves={
                'total_locked': '0x' + (1_000_000).to_bytes(32, 'big').hex(),
                'token_balance': '0x' + (999_999).to_bytes(32, 'big').hex()})
            missing_reserves = {k: v for k, v in self.runtime.items() if k != 'reserves'}
            for runtime in [None, dict(self.runtime, code='0x60016000fd'), deficit, missing_reserves]:
                captured = copy.deepcopy(self.evidence)
                if runtime is not None:
                    captured['vault_runtime'] = runtime
                evidence.write_text(json.dumps(captured))
                result = subprocess.run([sys.executable, str(SCRIPTS / 'observe-stablecoin-deposit.py'),
                    '--config', str(config), '--asset', 'bUSDC', '--network', 'ethereum-mainnet',
                    '--allow-synthetic', '--evidence', str(evidence), '--journal', str(journal)],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertFalse(json.loads(result.stderr)['mint_authorized'])
                self.assertFalse(journal.exists())
