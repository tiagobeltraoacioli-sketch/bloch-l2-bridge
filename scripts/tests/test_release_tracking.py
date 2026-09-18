"""Durable invalidation, superseded refresh and restart-only reads."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from usdt_observer.common import Invalid
from usdt_observer import release_tracking as tracking
from test_release_journal import fixture
from test_stablecoin_observer import catalog_fixture


class ReleaseTrackingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'tracking.sqlite'
        self.route, self.captured, self.expected = fixture()
        self.tx = self.captured['receipt']['transactionHash']

    def refresh(self, fetch=None):
        return tracking.refresh(self.path, self.route, self.expected, self.tx,
                                fetch or (lambda: self.captured))

    def state(self):
        return tracking.read_state(self.path, self.route, self.expected)

    def test_refresh_invalidates_old_evidence_before_collection(self):
        self.refresh()
        def fetch():
            state = self.state()
            self.assertEqual((state['revision'], state['last_refresh_status']), (2, 'refreshing'))
            with sqlite3.connect(self.path) as db:
                self.assertIsNone(db.execute('SELECT observation FROM release_tracking').fetchone()[0])
            return self.captured
        self.refresh(fetch)
        self.assertEqual(self.state()['last_refresh_status'], 'observed')
        for flag in ['redemption_settled', 'native_release_authenticated', 'bridge_ready']:
            self.assertFalse(self.state()[flag])
        self.assertTrue(self.state()['requires_fresh_evidence'])

    def test_rpc_failure_clears_success_and_retry_uses_new_revision(self):
        self.refresh()
        with self.assertRaises(OSError): self.refresh(Mock(side_effect=OSError('offline')))
        self.assertEqual(self.state()['last_refresh_status'], 'unavailable')
        self.refresh()
        self.assertEqual(self.state()['revision'], 3)

    def test_validation_failure_and_wrong_requested_tx_invalidate(self):
        self.refresh()
        changed = copy.deepcopy(self.captured)
        changed['receipt']['status'] = '0x0'
        with self.assertRaises(Invalid): self.refresh(lambda: changed)
        self.assertEqual(self.state()['last_refresh_status'], 'unavailable')
        with self.assertRaises(Invalid):
            tracking.refresh(self.path, self.route, self.expected, '0x' + 'ad' * 32,
                             lambda: self.captured)
        self.assertEqual(self.state()['last_refresh_status'], 'unavailable')

    def test_process_interruption_leaves_pending_not_previous_success(self):
        self.refresh()
        with self.assertRaises(KeyboardInterrupt):
            self.refresh(Mock(side_effect=KeyboardInterrupt()))
        self.assertEqual(self.state()['last_refresh_status'], 'refreshing')
        self.assertFalse(self.state()['redemption_settled'])

    def test_late_success_and_failure_cannot_overwrite_newer_refresh(self):
        for fail in [False, True]:
            def older():
                self.refresh()
                if fail: raise OSError('old response failed')
                return self.captured
            with self.assertRaisesRegex(Invalid, 'superseded'): self.refresh(older)
            self.assertEqual(self.state()['last_refresh_status'], 'observed')
        self.assertEqual(self.state()['revision'], 4)

    def test_remined_payment_can_be_freshly_observed_without_settlement(self):
        self.refresh()
        changed = copy.deepcopy(self.captured)
        block = '0x' + 'bc' * 32
        changed['receipt']['blockHash'] = block
        changed['canonical_block']['hash'] = block
        changed['vault_runtime']['block_hash'] = block
        for log in changed['receipt']['logs']: log['blockHash'] = block
        captured, report = self.refresh(lambda: changed)
        self.assertEqual(captured['receipt']['blockHash'], block)
        self.assertEqual(report['revision'], 2)
        self.assertFalse(report['redemption_settled'])

    def test_conflicting_expected_release_refused_before_rpc_or_read(self):
        self.refresh()
        expected = dict(self.expected, amount='999999')
        fetch = Mock()
        with self.assertRaises(Invalid):
            tracking.refresh(self.path, self.route, expected, self.tx, fetch)
        fetch.assert_not_called()
        with self.assertRaises(Invalid): tracking.read_state(self.path, self.route, expected)
        self.assertEqual(self.state()['revision'], 1)

    def test_read_refuses_contradictory_or_cross_release_observation(self):
        self.refresh()
        with sqlite3.connect(self.path) as db:
            original = db.execute('SELECT status, observation FROM release_tracking').fetchone()
        observation = json.loads(original[1])
        mutations = (
            ('observed', None),
            ('refreshing', original[1]),
            ('unavailable', original[1]),
            ('observed', '[]'),
            ('observed', '{"route_id":"one","route_id":"two"}'),
            ('observed', '{"amount":NaN}'),
            ('observed', original[1] + ' '),
            ('observed', json.dumps(dict(observation, amount='999999'))),
            ('observed', json.dumps(dict(observation, release_id='0x' + 'cd' * 32))),
            ('observed', json.dumps(dict(observation, tx_hash='0x' + '00' * 32))),
            ('observed', json.dumps(dict(observation, transfer_log_index=observation['log_index']))),
        )
        for status, encoded in mutations:
            with self.subTest(status=status, encoded=encoded):
                with sqlite3.connect(self.path) as db:
                    db.execute('UPDATE release_tracking SET status=?, observation=?', (status, encoded))
                with self.assertRaises(Invalid):
                    self.state()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE release_tracking SET status=?, observation=?', original)
        self.assertEqual(self.state()['last_refresh_status'], 'observed')

    def test_missing_read_creates_nothing_and_foreign_db_is_unchanged(self):
        with self.assertRaises(OSError): self.state()
        self.assertFalse(self.path.exists())
        with sqlite3.connect(self.path) as db: db.execute('CREATE TABLE unrelated (value TEXT)')
        self.path.chmod(0o600)
        before = self.path.read_bytes()
        with self.assertRaises(Invalid): self.refresh()
        self.assertEqual(self.path.read_bytes(), before)

    def test_capacity_and_revision_exhaustion_stop_before_network(self):
        fetch = Mock()
        with patch.object(tracking, 'MAX_ROWS', 0), self.assertRaises(Invalid): self.refresh(fetch)
        fetch.assert_not_called()
        # A failed initial transaction intentionally leaves an uninitialized file.
        self.path.unlink()
        self.refresh()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE release_tracking SET revision=?', (tracking.MAX_REVISION,))
        with self.assertRaises(Invalid): self.refresh(fetch)
        fetch.assert_not_called()

    def test_cli_invalid_endpoint_invalidates_before_transport_creation(self):
        self.refresh()
        config, expected = self.root / 'config.json', self.root / 'release.json'
        config.write_text(json.dumps(catalog_fixture()))
        expected.write_text(json.dumps(self.expected))
        spec = importlib.util.spec_from_file_location('tracked_release_cli', SCRIPTS / 'inspect-stablecoin-release.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with contextlib.redirect_stderr(io.StringIO()):
            result = cli.main(['--config', str(config), '--release', str(expected), '--asset', 'bUSDC',
                               '--allow-synthetic', '--endpoint', 'not-an-endpoint', '--tx-hash', self.tx,
                               '--tracking', str(self.path)])
        self.assertEqual(result, 1)
        self.assertEqual(self.state()['last_refresh_status'], 'unavailable')

    def test_silent_result_mutation_is_detected_and_rolled_back(self):
        self.refresh()
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TRIGGER erase_release_result AFTER UPDATE OF status ON release_tracking
                          WHEN NEW.status != 'refreshing'
                          BEGIN UPDATE release_tracking SET status='refreshing', observation=NULL
                          WHERE burn=NEW.burn; END''')
        with self.assertRaisesRegex(Invalid, 'readback mismatch'):
            self.refresh()
        state = self.state()
        self.assertEqual(state['last_refresh_status'], 'refreshing')
        self.assertEqual(state['revision'], 2)

    def test_silent_identity_mutation_during_result_write_is_rolled_back(self):
        self.refresh()
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TRIGGER corrupt_release_identity AFTER UPDATE OF status ON release_tracking
                          WHEN NEW.status != 'refreshing'
                          BEGIN UPDATE release_tracking SET facts='{}' WHERE burn=NEW.burn; END''')
        with self.assertRaisesRegex(Invalid, 'readback mismatch'):
            self.refresh()
        state = self.state()
        self.assertEqual(state['last_refresh_status'], 'refreshing')
        self.assertEqual(state['revision'], 2)

    def test_oversized_invalidation_mutation_rolls_back_before_collection(self):
        self.refresh()
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TRIGGER enlarge_release_invalidation
                          AFTER UPDATE OF status ON release_tracking
                          WHEN NEW.status = 'refreshing'
                          BEGIN UPDATE release_tracking SET facts=CAST(zeroblob(4097) AS TEXT)
                          WHERE burn=NEW.burn; END''')
        fetch = Mock()
        with self.assertRaisesRegex(Invalid, 'invalidation readback mismatch'):
            self.refresh(fetch)
        fetch.assert_not_called()
        state = self.state()
        self.assertEqual(state['last_refresh_status'], 'observed')
        self.assertEqual(state['revision'], 1)

    def test_oversized_result_mutation_is_rolled_back_before_decode(self):
        self.refresh()
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TRIGGER enlarge_release_result
                          AFTER UPDATE OF status ON release_tracking
                          WHEN NEW.status = 'observed'
                          BEGIN UPDATE release_tracking
                          SET observation=CAST(zeroblob(16385) AS TEXT)
                          WHERE burn=NEW.burn; END''')
        with self.assertRaisesRegex(Invalid, 'result readback mismatch'):
            self.refresh()
        state = self.state()
        self.assertEqual(state['last_refresh_status'], 'refreshing')
        self.assertEqual(state['revision'], 2)
