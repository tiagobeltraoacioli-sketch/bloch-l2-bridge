"""Atomic historical attestation persistence; never settlement authorization."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.release_journal import record
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
