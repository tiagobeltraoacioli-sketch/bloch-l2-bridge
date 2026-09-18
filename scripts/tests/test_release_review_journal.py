"""Atomic historical attestation persistence; never settlement authorization."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.release_journal import record, read_review
from usdt_observer.releases import match_release
from test_release_journal import fixture


class ReviewJournalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'journal'
        self.route, self.captured, self.expected = fixture()
        evidence = {k: v for k, v in self.captured.items() if k != 'vault_runtime'}
        release_id = match_release(self.route, evidence, self.expected)['observation']['release_id']
        self.review = {'release_id': release_id, 'attestation_verified': True,
                       'redemption_settled': False, 'finality_verified': False}
        self.inputs = {'executable': Path(sys.executable), 'trust': {'test': 'public-trust'},
                       'certificate': {'test': 'public-certificate'}}

    def record(self):
        return record(self.path, self.route, self.captured, self.expected, native_verification=self.inputs)

    def rows(self):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT * FROM native_review_observations ORDER BY audit_id').fetchall()

    def test_persist_retry_and_append_preserve_history(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review) as verify:
            result = self.record()
            self.assertEqual(result['new_native_reviews'], 1)
            self.assertFalse(result['redemption_settled'])
            rows = self.rows()
            audit = json.loads(rows[0][2])
            self.assertEqual(audit['certificate'], self.inputs['certificate'])
            self.assertEqual(audit['trust'], self.inputs['trust'])
            self.assertEqual(audit['native_review'], self.review)
            self.assertEqual(self.record()['new_native_reviews'], 0)
            self.assertEqual(self.rows(), rows)
            self.inputs['certificate']['test'] = 'another-public-certificate'
            self.assertEqual(self.record()['new_native_reviews'], 1)
            self.assertEqual(len(self.rows()), 2)
            self.assertIn(rows[0], self.rows())
            self.assertEqual(verify.call_count, 3)

    def test_refused_verification_creates_no_file(self):
        with patch('usdt_observer.native_review.verify_review', side_effect=ValueError('refused')):
            with self.assertRaises(ValueError): self.record()
        self.assertFalse(self.path.exists())

    def test_source_only_journal_accepts_additive_review(self):
        record(self.path, self.route, self.captured, self.expected)
        with sqlite3.connect(self.path) as db:
            before = db.execute('SELECT * FROM release_observations').fetchall()
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            result = self.record()
        self.assertEqual(result['duplicate_observations'], 1)
        self.assertEqual(result['new_native_reviews'], 1)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT * FROM release_observations').fetchall(), before)
        record(self.path, self.route, self.captured, self.expected)
        self.assertEqual(len(self.rows()), 1)

    def test_review_capacity_failure_preserves_history(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            self.record()
            self.inputs['certificate']['test'] = 'second'
            # Existing source observation permits retry while review capacity is full.
            with patch('usdt_observer.release_journal.MAX_ROWS', 1):
                with self.assertRaises(ValueError): self.record()
        self.assertEqual(len(self.rows()), 1)

    def test_mismatched_review_cannot_change_existing_database(self):
        record(self.path, self.route, self.captured, self.expected)
        before = self.path.read_bytes()
        with patch('usdt_observer.native_review.verify_review', return_value={'release_id': 'wrong'}):
            with self.assertRaises(ValueError): self.record()
        self.assertEqual(self.path.read_bytes(), before)


    def test_audit_insert_failure_rolls_back_new_source_observation(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            self.record()
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TRIGGER refuse_audit BEFORE INSERT ON native_review_observations BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        self.route, self.captured, self.expected = fixture(nonce=8, burn='0x'+'cc'*32, tx='0x'+'dd'*32)
        evidence = {k: v for k, v in self.captured.items() if k != 'vault_runtime'}
        self.review['release_id'] = match_release(self.route, evidence, self.expected)['observation']['release_id']
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            with self.assertRaises(ValueError): self.record()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM release_observations').fetchone()[0], 1)
        self.assertEqual(len(self.rows()), 1)

    def test_silent_audit_insert_loss_is_detected(self):
        record(self.path, self.route, self.captured, self.expected)
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TABLE native_review_observations (
                audit_id TEXT PRIMARY KEY, release_id TEXT NOT NULL, audit TEXT NOT NULL)''')
            db.execute('''CREATE TRIGGER discard_new_audit AFTER INSERT ON native_review_observations
                          BEGIN DELETE FROM native_review_observations WHERE audit_id=NEW.audit_id; END''')
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            with self.assertRaisesRegex(ValueError, 'readback mismatch'):
                self.record()
        self.assertEqual(self.rows(), [])


    def test_read_is_historical_and_preserves_database_bytes(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            result = self.record()
        before = self.path.read_bytes()
        output = read_review(self.path, result['native_review_audit_id'])
        self.assertEqual(output['audit']['certificate'], self.inputs['certificate'])
        self.assertFalse(output['attestation_reverified'])
        self.assertFalse(output['redemption_settled'])
        self.assertTrue(output['requires_fresh_evidence'])
        self.assertEqual(self.path.read_bytes(), before)

    def test_read_refuses_missing_corrupt_and_oversize_audits(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            result = self.record()
        with self.assertRaises(ValueError): read_review(self.path, '00'*32)
        for value in ['{}', 'x'*131073]:
            with sqlite3.connect(self.path) as db:
                db.execute('UPDATE native_review_observations SET audit=?', (value,))
            with self.assertRaises(ValueError): read_review(self.path, result['native_review_audit_id'])

    def test_read_refuses_changed_source_facts(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            result = self.record()
        with sqlite3.connect(self.path) as db:
            facts = json.loads(db.execute('SELECT facts FROM release_observations').fetchone()[0])
            facts['amount'] = '123'
            db.execute('UPDATE release_observations SET facts=?', (json.dumps(facts),))
        with self.assertRaises(ValueError): read_review(self.path, result['native_review_audit_id'])

    def test_read_refuses_changed_source_identity_columns(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            result = self.record()
        original = self.path.read_bytes()
        for column, value in [('source_event', '00' * 32), ('transfer_event', '11' * 32),
                              ('route_nonce', 'wrong:7'), ('native_burn', '22' * 32),
                              ('first_evidence_sha256', 'bad')]:
            self.path.write_bytes(original)
            with sqlite3.connect(self.path) as db:
                db.execute(f'UPDATE release_observations SET {column}=?', (value,))
            with self.subTest(column=column), self.assertRaises(ValueError):
                read_review(self.path, result['native_review_audit_id'])

    def test_read_missing_file_does_not_create_it(self):
        with self.assertRaises(OSError): read_review(self.path, '00'*32)
        self.assertFalse(self.path.exists())


    def test_reader_cli_reports_history_and_refuses_unknown_id(self):
        with patch('usdt_observer.native_review.verify_review', return_value=self.review):
            result = self.record()
        command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'read-stablecoin-review.py'),
                   '--journal', str(self.path), '--audit-id']
        output = subprocess.run(command + [result['native_review_audit_id']], capture_output=True, timeout=5)
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertFalse(json.loads(output.stdout)['attestation_reverified'])
        refused = subprocess.run(command + ['00'*32], capture_output=True, timeout=5)
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(refused.stdout, b'')
        self.assertFalse(json.loads(refused.stderr)['redemption_settled'])
