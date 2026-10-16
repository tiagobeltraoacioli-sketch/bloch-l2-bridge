"""Current trust must never be inferred from a historical audit."""
import copy
import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.review_revalidation import revalidate_review
import test_release_review_journal as journal_tests


class ReviewRevalidationTest(unittest.TestCase):
    def setUp(self):
        self.fixture = journal_tests.ReviewJournalTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.review['commitment'] = '0x'+'aa'*32
        with patch('usdt_observer.native_review.verify_review', return_value=self.fixture.review):
            self.audit_id = self.fixture.record()['native_review_audit_id']
        self.trust = {'current': 'independently supplied'}

    def revalidate(self):
        f = self.fixture
        return revalidate_review(f.path, self.audit_id, Path(sys.executable), f.route, f.expected, self.trust)

    def test_explicit_trust_and_historical_source_semantics(self):
        before = self.fixture.path.read_bytes()
        with patch('usdt_observer.review_revalidation.verify_review', return_value=self.fixture.review) as verify:
            result = self.revalidate()
        self.assertIs(verify.call_args.args[3], self.trust)
        self.assertNotEqual(verify.call_args.args[3], self.fixture.inputs['trust'])
        self.assertEqual(verify.call_args.args[4], self.fixture.inputs['certificate'])
        self.assertTrue(result['attestation_reverified'])
        self.assertTrue(result['requires_fresh_evidence'])
        for field in ['finality_verified', 'redemption_settled', 'bridge_ready', 'native_release_authenticated']:
            self.assertFalse(result[field])
        self.assertEqual(self.fixture.path.read_bytes(), before)

    def test_revoked_authority_or_expired_certificate_does_not_change_journal(self):
        before = self.fixture.path.read_bytes()
        with patch('usdt_observer.review_revalidation.verify_review', side_effect=ValueError('refused')):
            with self.assertRaises(ValueError): self.revalidate()
        self.assertEqual(self.fixture.path.read_bytes(), before)

    def test_wrong_expected_release_refuses_before_verifier(self):
        self.fixture.expected['native_burn'] = '0x'+'cc'*32
        with patch('usdt_observer.review_revalidation.verify_review') as verify:
            with self.assertRaises(ValueError): self.revalidate()
            verify.assert_not_called()

    def test_changed_commitment_refuses(self):
        review = copy.deepcopy(self.fixture.review)
        review['commitment'] = '0x'+'bb'*32
        with patch('usdt_observer.review_revalidation.verify_review', return_value=review):
            with self.assertRaises(ValueError): self.revalidate()
