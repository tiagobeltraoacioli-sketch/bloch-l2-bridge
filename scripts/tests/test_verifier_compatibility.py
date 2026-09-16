"""Compatibility must not be confused with cryptographic or deployment readiness."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.verifier_compatibility import check_verifier


class VerifierCompatibilityTest(unittest.TestCase):
    @patch('usdt_observer.verifier_compatibility.run_verifier')
    def test_exact_protocol_only(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, b'BLOCH-REVIEW-VERIFY-v2\n')
        result = check_verifier(sys.executable)
        self.assertTrue(result['protocol_compatible'])
        for key in ['cryptography_tested', 'native_state_authenticated', 'redemption_settled', 'bridge_ready']:
            self.assertFalse(result[key])
        run.assert_called_once_with([sys.executable, '--protocol'], input=b'', timeout=3)

    @patch('usdt_observer.verifier_compatibility.run_verifier')
    def test_mismatch_nonzero_extra_output_and_timeout_refuse(self, run):
        for code, output in [(0, b'BLOCH-REVIEW-VERIFY-v1\n'), (1, b'BLOCH-REVIEW-VERIFY-v2\n'),
                             (0, b'BLOCH-REVIEW-VERIFY-v2\nextra'), (0, b'')]:
            run.return_value = subprocess.CompletedProcess([], code, output)
            with self.assertRaises(ValueError): check_verifier(sys.executable)
        run.side_effect = subprocess.TimeoutExpired('verifier', 3)
        with self.assertRaises(ValueError): check_verifier(sys.executable)

    def test_missing_and_relative_executables_refuse(self):
        for path in ['verifier', '/nonexistent/native-verifier']:
            with self.assertRaises(ValueError): check_verifier(path)
