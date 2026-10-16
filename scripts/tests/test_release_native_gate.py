"""CLI native review gate ordering and conservative success semantics."""
import contextlib
import importlib.util
import io
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_release_journal import fixture
from test_stablecoin_observer import catalog_fixture

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_cli_native_gate', SCRIPTS / 'inspect-stablecoin-release.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class ReleaseNativeGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _, self.captured, expected = fixture()
        for name, value in [('config', catalog_fixture()), ('release', expected),
                            ('evidence', self.captured), ('trust', {}), ('certificate', {})]:
            (self.root / name).write_text(json.dumps(value))
        self.base = ['--config', str(self.root / 'config'), '--asset', 'bUSDC',
                     '--release', str(self.root / 'release'), '--allow-synthetic']
        self.native = ['--native-verifier', sys.executable, '--native-trust', str(self.root / 'trust'),
                       '--native-certificate', str(self.root / 'certificate')]

    def invoke(self, extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(self.base + extra)
        return code, out.getvalue(), err.getvalue()

    def test_required_review_and_partial_inputs_refuse_before_rpc_or_tracking(self):
        for options in [[], self.native[:2], self.native[2:4], self.native[4:], self.native[:4]]:
            with self.subTest(options=options), patch.object(cli, 'HttpSource') as rpc, \
                    patch('usdt_observer.release_tracking.refresh') as refresh:
                code, out, err = self.invoke(['--require-native-review', '--endpoint', 'http://127.0.0.1:1',
                    '--tx-hash', self.captured['receipt']['transactionHash'],
                    '--tracking', str(self.root / 'tracking')] + options)
                self.assertEqual(code, 1)
                self.assertEqual(out, '')
                self.assertFalse(json.loads(err)['bridge_ready'])
                rpc.assert_not_called()
                refresh.assert_not_called()
                self.assertFalse((self.root / 'tracking').exists())

    def test_bad_certificate_does_not_open_source_or_mutate_existing_journal(self):
        journal = self.root / 'journal'
        journal.write_bytes(b'existing-state')
        with patch('usdt_observer.native_review.verify_review', side_effect=ValueError('bad certificate')), \
                patch.object(cli, 'HttpSource') as rpc, \
                patch('usdt_observer.release_journal.record') as record:
            code, out, _ = self.invoke(['--require-native-review', '--endpoint', 'http://127.0.0.1:1',
                '--tx-hash', self.captured['receipt']['transactionHash'], '--journal', str(journal)] + self.native)
            self.assertEqual((code, out), (1, ''))
            rpc.assert_not_called()
            record.assert_not_called()
            self.assertEqual(journal.read_bytes(), b'existing-state')

    def test_attestation_does_not_skip_source_validation(self):
        captured = dict(self.captured)
        del captured['vault_runtime']
        (self.root / 'evidence').write_text(json.dumps(captured))
        with patch('usdt_observer.native_review.verify_review', return_value={'attestation_verified': True}):
            code, out, _ = self.invoke(['--require-native-review', '--evidence', str(self.root / 'evidence')] + self.native)
            self.assertEqual((code, out), (1, ''))

    def test_success_keeps_finality_and_settlement_false(self):
        from usdt_observer.releases import match_release
        route, captured, expected = fixture()
        release_id = match_release(route, {k: v for k, v in captured.items() if k != 'vault_runtime'}, expected)['observation']['release_id']
        review = {'attestation_verified': True, 'redemption_settled': False, 'finality_verified': False,
                  'release_id': release_id}
        with patch('usdt_observer.native_review.verify_review', return_value=review) as verify:
            code, out, err = self.invoke(['--require-native-review', '--evidence', str(self.root / 'evidence')] + self.native)
            self.assertEqual((code, err), (0, ''))
            output = json.loads(out)
            self.assertEqual(output['native_review'], review)
            for field in ['native_release_authenticated', 'finality_verified', 'redemption_settled', 'bridge_ready']:
                self.assertIs(output[field], False)
            verify.assert_called_once()
            context = {key: output[key] for key in ['native_review', 'observation', 'evidence_sha256']}
            digest = hashlib.sha256(b'BLOCH-REVIEW-EVIDENCE-v1\0' + json.dumps(
                context, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
            self.assertEqual(output['review_evidence_sha256'], digest)


    def test_wrong_review_release_refuses_before_journal_write(self):
        with patch('usdt_observer.native_review.verify_review', return_value={
                'attestation_verified': True, 'release_id': '0x'+'00'*32}), \
                patch('usdt_observer.release_journal.record') as record:
            code, out, _ = self.invoke(['--require-native-review', '--evidence', str(self.root / 'evidence'),
                                       '--journal', str(self.root / 'journal')] + self.native)
            self.assertEqual((code, out), (1, ''))
            record.assert_not_called()
