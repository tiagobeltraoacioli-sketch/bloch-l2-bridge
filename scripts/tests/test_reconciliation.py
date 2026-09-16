"""Reconciliation identities survive uncertainty, retries and competing workers."""
from concurrent.futures import ThreadPoolExecutor
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest
from test_release_journal import fixture
from usdt_observer import reconciliation as r
from usdt_observer.common import Invalid

class ReconciliationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'reconciliation.sqlite'
        self.route, _, self.expected = fixture()
        r.register(self.path, self.route, self.expected)

    def move(self, revision, status, number=1, **kw):
        return r.transition(self.path, self.route, self.expected, revision=revision,
                            operation='0x' + f'{number:064x}', status=status, **kw)

    def test_retry_and_stale_completion(self):
        self.move(1, 'reconciling')
        self.move(2, 'unavailable', 2)
        self.assertEqual(self.move(1, 'reconciling')['status'], 'unavailable')
        with self.assertRaises(Invalid):
            self.move(2, 'observed', 3, transaction='0x'+'aa'*32, evidence_sha256='0x'+'bb'*32)
        with self.assertRaises(Invalid):
            self.move(1, 'frozen')

    def test_uncertainty_never_releases_identity(self):
        self.move(1, 'reconciling')
        self.move(2, 'unavailable', 2)
        changed = copy.deepcopy(self.expected)
        changed['recipient'] = '0x' + 'ab'*20
        with self.assertRaises(Invalid):
            r.register(self.path, self.route, changed)
        changed = copy.deepcopy(self.expected)
        changed['native_burn'] = '0x' + 'ac'*32
        with self.assertRaises(Invalid):
            r.register(self.path, self.route, changed)
        self.assertEqual(r.register(self.path, self.route, self.expected)['revision'], 3)

    def test_reorg_freezes_without_settlement_or_new_identity(self):
        self.move(1, 'reconciling')
        self.move(2, 'observed', 2, transaction='0x'+'aa'*32, evidence_sha256='0x'+'bb'*32)
        self.move(3, 'reconciling', 3)
        state = self.move(4, 'frozen', 4)
        for key in ('payment_authorized', 'finality_verified', 'redemption_settled', 'bridge_ready'):
            self.assertFalse(state[key])
        with self.assertRaises(Invalid):
            self.move(5, 'reconciling', 5)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM history').fetchone()[0], 5)

    def test_competing_workers_one_wins(self):
        def attempt(n):
            try:
                self.move(1, 'reconciling', n)
                return True
            except Invalid:
                return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt, range(1, 5))), 1)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM history').fetchone()[0], 2)

    def test_restart_and_foreign_database(self):
        self.move(1, 'reconciling')
        self.assertEqual(r.read_state(self.path, self.route, self.expected)['status'], 'reconciling')
        other = self.path.parent / 'other.sqlite'
        other.touch(mode=0o600)
        with self.assertRaises(Invalid):
            r.register(other, self.route, self.expected)

    def test_observed_needs_identifiers_and_flags_are_not_inputs(self):
        self.move(1, 'reconciling')
        with self.assertRaises(Invalid):
            self.move(2, 'observed', 2)
        with self.assertRaises(TypeError):
            self.move(2, 'observed', 2, payment_authorized=True)
        self.assertEqual(r.read_state(self.path, self.route, self.expected)['revision'], 2)

    def test_first_creator_window_fails_closed_then_retry_succeeds(self):
        from unittest.mock import patch
        path = self.path.parent / 'first.sqlite'
        original = sqlite3.connect
        intercepted = False

        def connect(*args, **kwargs):
            nonlocal intercepted
            if not intercepted:
                intercepted = True
                # The creator has made the empty file but not begun schema setup.
                with self.assertRaises(Invalid):
                    r.register(path, self.route, self.expected)
                with original(path) as db:
                    self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0], 0)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0], 0)
            return original(*args, **kwargs)

        with patch.object(r.sqlite3, 'connect', side_effect=connect):
            self.assertEqual(r.register(path, self.route, self.expected)['revision'], 1)
        self.assertTrue(intercepted)
        self.assertEqual(r.register(path, self.route, self.expected)['revision'], 1)
        with original(path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM claims').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM history').fetchone()[0], 1)

    def test_interruption_before_schema_commit_leaves_refused_file(self):
        path = self.path.parent / 'interrupted.sqlite'
        class SimulatedInterruption(BaseException):
            pass
        with self.assertRaises(SimulatedInterruption):
            with r.database(path, write=True) as db:
                self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0], r.APPLICATION_ID)
                raise SimulatedInterruption()
        self.assertTrue(path.exists())
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0], 0)
        before = path.read_bytes()
        with self.assertRaises(Invalid):
            r.register(path, self.route, self.expected)
        self.assertEqual(path.read_bytes(), before)
