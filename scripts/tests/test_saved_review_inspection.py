"""Saved certificates must pass current verification before fresh source collection."""
import json
import unittest
from unittest.mock import patch
import test_release_native_gate as gate
from usdt_observer.releases import match_release
from test_release_journal import fixture


class SavedReviewInspectionTest(unittest.TestCase):
    def setUp(self):
        self.fixture = gate.ReleaseNativeGateTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        route, captured, expected = fixture()
        observation = match_release(route, {k: v for k, v in captured.items() if k != 'vault_runtime'}, expected)['observation']
        self.review = {'release_id': observation['release_id'], 'commitment': '0x'+'aa'*32,
                       'attestation_verified': True}
        self.audit = {'audit': {'observation': observation, 'native_review': self.review,
                               'certificate': {'public': 'saved'}, 'trust': {'do_not_use': True}}}
        self.options = self.fixture.native[:4] + ['--native-audit-id', '11'*32,
                       '--native-audit-journal', str(self.fixture.root / 'old-journal')]
        self.online = ['--endpoint', 'http://127.0.0.1:1', '--tx-hash', captured['receipt']['transactionHash']]

    def test_saved_certificate_uses_current_trust_and_collects_again(self):
        with patch('usdt_observer.release_journal.read_review', return_value=self.audit), \
                patch('usdt_observer.native_review.verify_review', return_value=self.review) as verify, \
                patch.object(gate.cli, 'HttpSource') as rpc, \
                patch.object(gate.cli, 'collect', return_value={k: v for k, v in self.fixture.captured.items() if k != 'vault_runtime'}) as collect, \
                patch.object(gate.cli, 'collect_runtime', return_value=self.fixture.captured['vault_runtime']) as runtime:
            rpc.return_value.loopback = True
            code, out, err = self.fixture.invoke(self.online + self.options)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(verify.call_args.args[3], {})  # Explicit current trust file.
        self.assertEqual(verify.call_args.args[4], {'public': 'saved'})
        collect.assert_called_once()
        runtime.assert_called_once()
        result = json.loads(out)
        self.assertEqual(result['reused_native_audit_id'], '11'*32)
        self.assertFalse(result['redemption_settled'])
        self.assertFalse(result['bridge_ready'])

    def test_current_verification_failure_never_collects(self):
        with patch('usdt_observer.release_journal.read_review', return_value=self.audit), \
                patch('usdt_observer.native_review.verify_review', side_effect=ValueError('expired')), \
                patch.object(gate.cli, 'HttpSource') as rpc:
            code, out, _ = self.fixture.invoke(self.online + self.options)
        self.assertEqual((code, out), (1, ''))
        rpc.assert_not_called()

    def test_incomplete_saved_source_refuses(self):
        with patch('usdt_observer.release_journal.read_review') as read:
            for options in [self.options[:-2], ['--native-audit-journal', 'missing']]:
                code, out, _ = self.fixture.invoke(self.online + options)
                self.assertEqual((code, out), (1, ''))
            read.assert_not_called()

    def test_changed_saved_commitment_refuses_before_rpc(self):
        review = dict(self.review, commitment='0x'+'bb'*32)
        with patch('usdt_observer.release_journal.read_review', return_value=self.audit), \
                patch('usdt_observer.native_review.verify_review', return_value=review), \
                patch.object(gate.cli, 'HttpSource') as rpc:
            code, out, _ = self.fixture.invoke(self.online + self.options)
        self.assertEqual((code, out), (1, ''))
        rpc.assert_not_called()
