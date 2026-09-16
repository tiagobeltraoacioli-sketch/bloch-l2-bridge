"""Real child processes exercise bounded reads, backpressure and deadlines."""
from pathlib import Path
import subprocess
import sys
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.verifier_process import run_verifier


class VerifierProcessTest(unittest.TestCase):
    def run_child(self, code, payload=b'x', timeout=2):
        return run_verifier([sys.executable, '-c', code], input=payload, timeout=timeout)

    def test_full_input_and_exact_output(self):
        result = self.run_child("import sys; data=sys.stdin.buffer.read(); assert len(data)==65536; print('a'*64)", b'x'*65536)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'a'*64+b'\n')

    def test_output_before_input_does_not_deadlock(self):
        result = self.run_child("import sys; print('a'*64, flush=True); sys.stdin.buffer.read()", b'x'*65536)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 65)

    def test_output_flood_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'excessive'):
            self.run_child("import os; os.write(1,b'a'*1000000)")

    def test_stall_and_closed_stdout_still_obey_deadline(self):
        for code in ["import time; time.sleep(30)", "import os,time; os.close(1); time.sleep(30)"]:
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_child(code, b'x'*65536, timeout=0.2)
            self.assertLess(time.monotonic()-started, 3)

    def test_empty_input_and_nonzero_exit(self):
        result = self.run_child("import sys; assert not sys.stdin.buffer.read(); sys.exit(7)", b'')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b'')

    def test_oversize_input_never_launches(self):
        with self.assertRaises(ValueError):
            run_verifier(['/nonexistent'], input=b'x'*65537)
