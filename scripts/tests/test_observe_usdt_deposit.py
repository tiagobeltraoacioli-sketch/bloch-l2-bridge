"""CLI end-to-end tests with actual adapters/ABI and only synthetic evidence."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TESTS = Path(__file__).resolve().parent
SCRIPTS = TESTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))
from usdt_observer.common import MAX_JSON, normalized_route
from test_usdt_ethereum_observer import fixture as ethereum_fixture, append_deposit
from test_usdt_tron_observer import deposit_fixture as tron_fixture, block_id

CLI = SCRIPTS / 'observe-usdt-deposit.py'
spec = importlib.util.spec_from_file_location('observe_usdt_cli_test', CLI)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def manifest_fixture():
    manifest = json.loads((SCRIPTS / 'usdt-routes.synthetic.json').read_text())
    # Use the same synthetic TRON block-ID encoding as the actual adapter fixture.
    genesis = bytes.fromhex(block_id(0))
    route = manifest['routes'][1]
    route['genesis_hash'] = '0x' + genesis.hex()
    route['source_domain'] = '0x' + hashlib.sha256(
        b'BLOCH-USDT-SOURCE-CONFIG-v1\0tron-mainnet\0' + genesis).hexdigest()
    return manifest


def ethereum_evidence(manifest, deposits=((7, 1000000),), tx_byte='66'):
    _, evidence = ethereum_fixture()
    route = normalized_route(manifest, 'ethereum-mainnet', allow_synthetic=True)
    evidence['genesis']['hash'] = route['genesis_hash']
    tx = '0x' + tx_byte * 32
    evidence['receipt']['transactionHash'] = tx
    evidence['canonical_block']['transactions'][1] = tx
    evidence['receipt']['logs'] = []
    for nonce, amount in deposits:
        append_deposit(route, evidence, nonce, amount)
    return evidence


class ObserveDepositCliTest(unittest.TestCase):
    def test_public_json_preserves_uint64_without_browser_number_rounding(self):
        nonce = (1 << 53) + 1
        evidence = ethereum_evidence(self.manifest, deposits=((nonce, 1000000),))
        result = self.invoke('ethereum-mainnet', evidence)
        self.assertEqual(result.returncode, 0, result.stderr)
        observation = json.loads(result.stdout)['observations'][0]
        self.assertEqual(observation['nonce'], str(nonce))
        self.assertEqual(observation['amount'], '1000000')
        self.assertIsInstance(observation['block_number'], str)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = manifest_fixture()
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps(self.manifest))
        self.evidence = self.root / 'evidence.json'
        self.journal = self.root / 'observations.sqlite'

    def args(self, network, extra=()):
        return ['--config', str(self.config), '--network', network, '--allow-synthetic',
                '--evidence', str(self.evidence), *extra]

    def invoke(self, network, evidence, extra=()):
        self.evidence.write_text(json.dumps(evidence))
        return subprocess.run([sys.executable, str(CLI), *self.args(network, extra)],
                              capture_output=True, text=True, timeout=15, check=False)

    def refused(self, result):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        report = json.loads(result.stderr)
        self.assertEqual(report['error'], 'observation-refused')
        self.assertFalse(report['source_policy_satisfied'])
        self.assertFalse(report['mint_authorized'])
        self.assertFalse(report['bridge_ready'])

    def test_offline_both_networks_report_observations_without_readiness(self):
        for network, evidence in [('ethereum-mainnet', ethereum_evidence(self.manifest)),
                                  ('tron-mainnet', tron_fixture()[1])]:
            with self.subTest(network=network):
                result = self.invoke(network, evidence)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, '')
                report = json.loads(result.stdout)
                self.assertEqual(report['network'], network)
                self.assertTrue(report['synthetic'])
                self.assertTrue(report['source_policy_satisfied'])
                self.assertEqual(report['validation'], 'source-rpc-consistency-only')
                self.assertEqual(len(report['observations']), 1)
                self.assertEqual(len(report['evidence_sha256']), 64)
                for flag in ('deployment_verified', 'finality_verified', 'mint_authorized',
                             'native_execution_performed', 'bridge_ready'):
                    self.assertIs(report[flag], False)
                self.assertNotIn('journal', report)
        self.assertFalse(self.journal.exists())

    def test_optional_journal_replay_is_idempotent_across_processes(self):
        evidence = ethereum_evidence(self.manifest)
        arguments = ('--journal', str(self.journal))
        first = self.invoke('ethereum-mainnet', evidence, arguments)
        second = self.invoke('ethereum-mainnet', evidence, arguments)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(first.stdout)['journal']['new_observations'], 1)
        self.assertEqual(json.loads(second.stdout)['journal']['new_observations'], 0)
        self.assertEqual(json.loads(second.stdout)['journal']['duplicate_observations'], 1)
        with sqlite3.connect(self.journal) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM observations').fetchone()[0], 1)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)

    def test_conflicting_batch_rolls_back_earlier_new_observation(self):
        arguments = ('--journal', str(self.journal))
        initial = ethereum_evidence(self.manifest, ((7, 1000000),))
        first = self.invoke('ethereum-mainnet', initial, arguments)
        self.assertEqual(first.returncode, 0, first.stderr)
        # Nonce 6 is new and inserts first; nonce 7 conflicts with the existing row.
        conflicting = ethereum_evidence(self.manifest, ((6, 1000000), (7, 2000000)), tx_byte='77')
        result = self.invoke('ethereum-mainnet', conflicting, arguments)
        self.refused(result)
        with sqlite3.connect(self.journal) as db:
            rows = db.execute('SELECT observation_json FROM observations').fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0][0])['nonce'], 7)
        self.assertEqual(json.loads(rows[0][0])['amount'], 1000000)

    def test_wrong_expected_transaction_refuses_both_networks_before_journal(self):
        for network, evidence in [('ethereum-mainnet', ethereum_evidence(self.manifest)),
                                  ('tron-mainnet', tron_fixture()[1])]:
            result = self.invoke(network, evidence, ('--tx-hash', '0x' + 'ff' * 32,
                                                    '--journal', str(self.journal)))
            self.refused(result)
            self.assertFalse(self.journal.exists())

    def test_correct_expected_transaction_is_bound_on_both_networks(self):
        for network, evidence in [('ethereum-mainnet', ethereum_evidence(self.manifest)),
                                  ('tron-mainnet', tron_fixture()[1])]:
            txid = (evidence['receipt']['transactionHash'] if network == 'ethereum-mainnet'
                    else '0x' + evidence['transaction_info']['id'])
            result = self.invoke(network, evidence, ('--tx-hash', txid))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['observations'][0]['tx_hash'], txid)

    def test_malformed_duplicate_and_oversized_json_are_redacted(self):
        for raw in (b'{"private_marker":"do-not-echo",', b'{"receipt":{},"receipt":{}}',
                    b' ' * (MAX_JSON + 1), b'{"nonce":NaN}'):
            self.evidence.write_bytes(raw)
            result = subprocess.run([sys.executable, str(CLI), *self.args('ethereum-mainnet')],
                                    capture_output=True, text=True, timeout=15, check=False)
            self.refused(result)
            self.assertNotIn('do-not-echo', result.stderr)
        self.config.write_bytes(b'{"synthetic":true,"synthetic":false}')
        self.refused(self.invoke('ethereum-mainnet', ethereum_evidence(self.manifest)))

    def test_synthetic_remote_endpoint_is_rejected_before_any_http(self):
        args = ['--config', str(self.config), '--network', 'ethereum-mainnet', '--allow-synthetic',
                '--endpoint', 'https://must-not-contact.invalid/rpc', '--tx-hash', '0x' + '66' * 32]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch('usdt_observer.collect.HttpSource.post', side_effect=AssertionError('outbound HTTP forbidden')) as post:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = cli.main(args)
            post.assert_not_called()
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(json.loads(stderr.getvalue())['error'], 'observation-refused')

    def test_synthetic_opt_in_is_required(self):
        evidence = ethereum_evidence(self.manifest)
        self.evidence.write_text(json.dumps(evidence))
        args = [arg for arg in self.args('ethereum-mainnet') if arg != '--allow-synthetic']
        result = subprocess.run([sys.executable, str(CLI), *args], capture_output=True,
                                text=True, timeout=15, check=False)
        self.refused(result)


if __name__ == '__main__':
    unittest.main()
