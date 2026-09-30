"""Real child processes exercise bounded reads, backpressure and deadlines."""
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_explicit_larger_input_budget_is_bounded_and_default_is_unchanged(self):
        payload = b'x' * (1024 * 1024)
        result = run_verifier([sys.executable, '-c',
                              "import sys; assert len(sys.stdin.buffer.read())==1048576; print('a'*64)"],
                              input=payload, max_input_bytes=len(payload))
        self.assertEqual(result.returncode, 0)
        for bound in (True, 0, -1, 1024 * 1024 + 1, 1.5):
            with self.assertRaises(ValueError):
                run_verifier(['/nonexistent'], input=b'x', max_input_bytes=bound)
        with self.assertRaises(ValueError):
            run_verifier(['/nonexistent'], input=payload)

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
        for payload, timeout in [(bytearray(b'x'), 1), (b'x', True), (b'x', 0), (b'x', 61),
                                 (b'x', float('nan'))]:
            with self.assertRaises(ValueError):
                run_verifier(['/nonexistent'], input=payload, timeout=timeout)

    def test_timeout_terminates_descendants_holding_verifier_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'descendant-survived'
            descendant = "import pathlib,time;time.sleep(.5);pathlib.Path({!r}).write_text('bad')".format(str(marker))
            parent = "import subprocess,sys;subprocess.Popen([sys.executable,'-c',{!r}])".format(descendant)
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_child(parent, timeout=0.1)
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    def test_success_terminates_descendants_that_closed_verifier_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'daemon-survived'
            descendant = "import pathlib,time;time.sleep(.5);pathlib.Path({!r}).write_text('bad')".format(str(marker))
            parent = ("import subprocess,sys;subprocess.Popen([sys.executable,'-c',{!r}],"
                      "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                      "print('a'*64)".format(descendant))
            result = self.run_child(parent, timeout=1)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'a'*64+b'\n')
            time.sleep(0.7)
            self.assertFalse(marker.exists())
