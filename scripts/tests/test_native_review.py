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
                          current_height='5', authority='0x1234')
        self.cert = dict(valid_until='14', signature='0x5678', preimage='0xaabb')
        self.digest = hashlib.sha3_256(bytes.fromhex('aabb')).hexdigest()

    def verify(self):
        return verify_review(Path(sys.executable), self.route, self.expected, self.trust, self.cert)

    @patch('usdt_observer.native_review.subprocess.run')
    def test_process_protocol_and_no_settlement(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, (self.digest+'\n').encode())
        result = self.verify()
        self.assertTrue(result['attestation_verified'])
        self.assertFalse(result['redemption_settled'])
        self.assertFalse(result['finality_verified'])
        wire = run.call_args.kwargs['input']
        self.assertTrue(wire.startswith(b'BLOCH-REVIEW-VERIFY-v1\0'+struct.pack('>Q', 4)+bytes.fromhex('11'*32)))
        self.assertTrue(wire.endswith(bytes.fromhex('00000002123400000002567800000002aabb')))
        self.assertEqual(run.call_args.args[0], [sys.executable])
        self.assertEqual(run.call_args.kwargs['timeout'], 10)

    @patch('usdt_observer.native_review.subprocess.run')
    def test_failure_wrong_output_timeout_and_spawn_failure(self, run):
        for code, output in [(1, (self.digest+'\n').encode()), (0, b'00\n'), (0, b''),
                             (0, (self.digest+'\nextra').encode())]:
            run.return_value = subprocess.CompletedProcess([], code, output)
            with self.assertRaises(ValueError): self.verify()
        for error in [OSError(), subprocess.TimeoutExpired('verifier', 10)]:
            run.side_effect = error
            with self.assertRaises(ValueError): self.verify()

    @patch('usdt_observer.native_review.subprocess.run')
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
