"""Reconciliation identities survive uncertainty, retries and competing workers."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
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

    def test_route_nonce_identity_survives_weakened_table_constraints(self):
        with sqlite3.connect(self.path) as db:
            db.execute('ALTER TABLE claims RENAME TO claims_original')
            db.execute('''CREATE TABLE claims (
                burn TEXT, route_nonce TEXT, facts TEXT, revision INTEGER, status TEXT)''')
            db.execute('INSERT INTO claims SELECT * FROM claims_original')
            db.execute('DROP TABLE claims_original')
        changed = copy.deepcopy(self.expected)
        changed['native_burn'] = '0x' + 'ac' * 32
        with self.assertRaisesRegex(Invalid, 'identity already assigned'):
            r.register(self.path, self.route, changed)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM claims').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM history').fetchone()[0], 1)

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

    def test_silent_transition_mutation_is_detected_and_rolled_back(self):
        self.move(1, 'reconciling')
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TRIGGER undo_claim_status AFTER UPDATE OF status ON claims
                          BEGIN UPDATE claims SET status='reconciling' WHERE burn=NEW.burn; END''')
        with self.assertRaises(Invalid):
            self.move(2, 'observed', 2, transaction='0x'+'aa'*32, evidence_sha256='0x'+'bb'*32)
        state = r.read_state(self.path, self.route, self.expected)
        self.assertEqual((state['revision'], state['status']), (2, 'reconciling'))

    def test_oversized_claim_mutation_is_rejected_before_decode_and_rolled_back(self):
        self.move(1, 'reconciling')
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TRIGGER enlarge_reconciliation_claim
                          AFTER UPDATE OF status ON claims
                          BEGIN UPDATE claims SET facts=CAST(zeroblob(4097) AS TEXT)
                          WHERE burn=NEW.burn; END''')
        with self.assertRaises(Invalid):
            self.move(2, 'unavailable', 2)
        state = r.read_state(self.path, self.route, self.expected)
        self.assertEqual((state['revision'], state['status']), (2, 'reconciling'))

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
        with self.assertRaises(Invalid):
            self.move(2, 'observed', 2, transaction='0x'+'00'*32,
                      evidence_sha256='0x'+'bb'*32)
        with self.assertRaises(TypeError):
            self.move(2, 'observed', 2, payment_authorized=True)
        self.assertEqual(r.read_state(self.path, self.route, self.expected)['revision'], 2)

    def test_reads_and_mutations_refuse_corrupt_transition_history(self):
        self.move(1, 'reconciling')
        self.move(2, 'observed', 2, transaction='0x'+'aa'*32, evidence_sha256='0x'+'bb'*32)
        with sqlite3.connect(self.path) as db:
            claim = db.execute('SELECT * FROM claims').fetchone()
            history = db.execute('SELECT * FROM history ORDER BY revision').fetchall()

        def restore():
            with sqlite3.connect(self.path) as db:
                db.execute('DELETE FROM history')
                db.executemany('INSERT INTO history VALUES (?,?,?,?,?)', history)
                db.execute('UPDATE claims SET route_nonce=?, facts=?, revision=?, status=? WHERE burn=?',
                           (claim[1], claim[2], claim[3], claim[4], claim[0]))

        payload = json.loads(history[2][3])
        mutations = (
            ('claim status', "UPDATE claims SET status='unavailable'", ()),
            ('claim revision', 'UPDATE claims SET revision=2', ()),
            ('route nonce', "UPDATE claims SET route_nonce='foreign:7'", ()),
            ('missing revision', 'DELETE FROM history WHERE revision=2', ()),
            ('history status', "UPDATE history SET status='frozen' WHERE revision=2", ()),
            ('duplicate payload', 'UPDATE history SET payload=? WHERE revision=2',
             ('{"status":"reconciling","status":"frozen"}',)),
            ('wrong previous revision', 'UPDATE history SET payload=? WHERE revision=3',
             (json.dumps(dict(payload, previous_revision=1), sort_keys=True, separators=(',', ':')),)),
            ('missing observed hash', 'UPDATE history SET payload=? WHERE revision=3',
             (json.dumps(dict(payload, transaction=None), sort_keys=True, separators=(',', ':')),)),
            ('invalid operation', "UPDATE history SET operation='xyz' WHERE revision=2", ()),
        )
        for name, statement, parameters in mutations:
            with self.subTest(name=name):
                restore()
                with sqlite3.connect(self.path) as db:
                    db.execute(statement, parameters)
                with self.assertRaises(Invalid):
                    r.read_state(self.path, self.route, self.expected)
                with self.assertRaises(Invalid):
                    r.register(self.path, self.route, self.expected)
                with self.assertRaises(Invalid):
                    self.move(3, 'reconciling', 99)
        restore()
        self.assertEqual(r.read_state(self.path, self.route, self.expected)['status'], 'observed')

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
