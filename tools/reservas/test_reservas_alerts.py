"""alert_command escalation of reservas.py: once per start and clear, never per round; a stuck surplus after its wait."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reservas  # noqa: E402


class Escalation(unittest.TestCase):
    def make(self, statuses, **cfg):
        d = Path(tempfile.mkdtemp())
        m = reservas.Monitor.__new__(reservas.Monitor)
        m.cfg = {'bridges': [{'name': 'b'}], 'alert_command': ['x'], 'health_file': str(d / 'h.json'), **cfg}
        m.log = lambda **kv: None
        calls = []
        m.notify = lambda pid, detail: calls.append(pid)
        it = iter(statuses)
        m.check = lambda b: (lambda s: (_ for _ in ()).throw(reservas.Unverifiable('down')) if s == 'error' else s)(next(it))
        return m, calls, d / 'h.json'

    def test_deficit_once_and_resolved(self):
        m, calls, h = self.make(['ok', 'deficit', 'deficit', 'deficit', 'ok'])
        for _ in range(5):
            m.round()
        self.assertEqual(calls, ['b:deficit', 'b:deficit:resolved'])
        self.assertTrue(json.loads(h.read_text())['healthy'])

    def test_stuck_surplus_after_wait(self):
        m, calls, h = self.make(['surplus'] * 3, surplus_alert_s=100)
        with mock.patch.object(reservas.time, 'time', side_effect=[0, 50, 150]):
            for _ in range(3):
                m.round()
        self.assertEqual(calls, ['b:surplus-stuck'])
        self.assertFalse(json.loads(h.read_text())['healthy'])

    def test_unverifiable_rounds(self):
        m, calls, h = self.make(['error'] * 5)
        for _ in range(5):
            m.round()
        self.assertEqual(calls, ['b:unverifiable'])

    def test_read_error_does_not_clear_deficit(self):
        m, calls, h = self.make(['deficit', 'error', 'deficit'])
        for _ in range(3):
            m.round()
        self.assertEqual(calls, ['b:deficit'])


if __name__ == '__main__':
    unittest.main()
