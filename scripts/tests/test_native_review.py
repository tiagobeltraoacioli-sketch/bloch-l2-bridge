"""Observer trust separation and verifier process failures."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.native_review import verify_review
from test_release_journal import fixture


class NativeReviewTest(unittest.TestCase):
    def setUp(self):
        self.route, _, self.expected = fixture()
        self.trust = dict(checkpoint_height='4', checkpoint_root='0x'+'11'*32,
                          current_height='5', authority='0x1234',
                          max_checkpoint_age='1', max_certificate_lifetime='10')
        self.cert = dict(valid_until='14', signature='0x5678', preimage='0xaabb')
        self.digest = hashlib.sha3_256(bytes.fromhex('aabb')).hexdigest()

    def verify(self):
        return verify_review(Path(sys.executable), self.route, self.expected, self.trust, self.cert)

    @patch('usdt_observer.native_review.run_verifier')
    def test_process_protocol_and_no_settlement(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, (self.digest+'\n').encode())
        result = self.verify()
        self.assertTrue(result['attestation_verified'])
        self.assertEqual(result['authority_sha256'], hashlib.sha256(bytes.fromhex('1234')).hexdigest())
        self.assertEqual(result['signature_sha256'], hashlib.sha256(bytes.fromhex('5678')).hexdigest())
        self.assertEqual(result['route_id'], self.expected['route_id'])
        self.assertEqual(result['native_asset'], self.expected['native_asset'])
        self.assertFalse(result['redemption_settled'])
        self.assertFalse(result['finality_verified'])
        wire = run.call_args.kwargs['input']
        self.assertTrue(wire.startswith(b'BLOCH-REVIEW-VERIFY-v2\0'+struct.pack('>Q', 4)+bytes.fromhex('11'*32)))
        self.assertTrue(wire.endswith(bytes.fromhex('00000002123400000002567800000002aabb')))
        self.assertEqual(run.call_args.args[0], [sys.executable])
        self.assertEqual(run.call_args.kwargs['timeout'], 10)

    @patch('usdt_observer.native_review.run_verifier')
    def test_failure_wrong_output_timeout_and_spawn_failure(self, run):
        for code, output in [(1, (self.digest+'\n').encode()), (0, b'00\n'), (0, b''),
                             (0, (self.digest+'\nextra').encode())]:
            run.return_value = subprocess.CompletedProcess([], code, output)
            with self.assertRaises(ValueError): self.verify()
        for error in [OSError(), subprocess.TimeoutExpired('verifier', 10)]:
            run.side_effect = error
            with self.assertRaises(ValueError): self.verify()

    @patch('usdt_observer.native_review.run_verifier')
    def test_malformed_or_embedded_trust_never_spawns(self, run):
        for field, value in [('valid_until', '01'), ('valid_until', True),
                             ('signature', '0x12 4'), ('preimage', '0x'+'00'*8193),
                             ('authority', '0x1234')]:
            with self.subTest(field=field, value=str(value)[:20]):
                original = dict(self.cert)
                self.cert[field] = value
                with self.assertRaises(ValueError): self.verify()
                self.cert = original
        self.expected['amount'] = '0'
        with self.assertRaises(ValueError): self.verify()
        run.assert_not_called()


    @patch('usdt_observer.native_review.run_verifier')
    def test_policy_boundaries_are_inclusive(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, (self.digest+'\n').encode())
        self.assertTrue(self.verify()['attestation_verified'])
        self.trust.update(current_height='14', max_checkpoint_age='10')
        self.assertTrue(self.verify()['attestation_verified'])
        self.trust.update(current_height='4', max_checkpoint_age='0', max_certificate_lifetime='0')
        self.cert['valid_until'] = '4'
        self.assertTrue(self.verify()['attestation_verified'])

    @patch('usdt_observer.native_review.run_verifier')
    def test_stale_future_expired_and_excessive_lifetime_never_spawn(self, run):
        for field, value in [('current_height', '6'), ('current_height', '3'),
                             ('current_height', '15'), ('max_certificate_lifetime', '9'),
                             ('max_checkpoint_age', '0')]:
            with self.subTest(field=field, value=value):
                original = dict(self.trust)
                self.trust[field] = value
                with self.assertRaises(ValueError): self.verify()
                self.trust = original
        run.assert_not_called()

    @patch('usdt_observer.native_review.run_verifier')
    def test_policy_must_be_present_canonical_and_operator_supplied(self, run):
        for field in ['max_checkpoint_age', 'max_certificate_lifetime']:
            original = dict(self.trust)
            del self.trust[field]
            with self.assertRaises(ValueError): self.verify()
            self.trust = original.copy()
            for value in [True, 1, '-1', '01', '18446744073709551616']:
                self.trust[field] = value
                with self.assertRaises(ValueError): self.verify()
            self.trust = original.copy()
            self.cert[field] = '18446744073709551615'
            with self.assertRaises(ValueError): self.verify()
            del self.cert[field]
        self.trust['checkpoint_root'] = '0x' + '00' * 32
        with self.assertRaises(ValueError): self.verify()
        run.assert_not_called()
