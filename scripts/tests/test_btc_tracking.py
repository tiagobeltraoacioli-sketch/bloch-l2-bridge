"""Persistence, crash and concurrent refresh regressions; no state authorizes minting."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from btc_observer import tracking
from btc_observer.chain import assess_status
from btc_observer.journal import record
from btc_observer.transaction import Invalid
from test_btc_chain import Node


class BitcoinTrackingTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'tracking.sqlite'
        self.node = Node()
        self.key = 'bitcoin-regtest:' + self.node.deposit['expected_txid'] + ':0'

    def refresh(self, node=None, rpc=None, threshold=6):
        node = self.node if node is None else node
        return tracking.refresh(self.path, rpc or node, node.deposit, node.proof,
                                expected_block_hash=node.block_hash, min_confirmations=threshold)

    def state(self):
        result = tracking.read_state(self.path, self.key)
        self.assertIs(result['requires_refresh_for_action'], True)
        for flag in ('confirmation_policy_met', 'inclusion_verified', 'finality_verified',
                     'custody_verified', 'mint_authorized', 'bridge_ready'):
            self.assertIs(result[flag], False)
        return result

    def test_policy_change_and_restart_reads_never_restore_authorization(self):
        self.assertTrue(self.refresh()['chain']['confirmation_policy_met'])
        first = self.state()
        self.assertEqual(first['last_refresh_status'], 'observed')
        self.assertEqual(first['revision'], 1)
        before = self.path.read_bytes()
        self.assertEqual(self.state(), first)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(self.refresh(threshold=7)['chain']['confirmation_policy_met'])
        state = self.state()
        self.assertEqual((state['revision'], state['last_refresh_status']), (2, 'below_threshold'))
        self.assertEqual(state['required_confirmations'], 7)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_confirmation_loss_changes_status(self):
        self.refresh()
        node = Node()
        node.info.update(blocks=103, headers=103, bestblockhash='cd' * 32)
        node.metadata['confirmations'] = 4
        self.assertFalse(self.refresh(node)['chain']['confirmation_policy_met'])
        self.assertEqual(self.state()['last_refresh_status'], 'below_threshold')

    def test_orphan_and_remined_block_keep_one_identity(self):
        self.refresh()
        node = Node()
        node.metadata['confirmations'] = -1
        node.active = 'ff' * 32
        result = self.refresh(node)
        self.assertFalse(result['chain']['node_active_chain_observed'])
        self.assertEqual(result['chain']['confirmations'], 0)
        self.assertEqual(self.state()['last_refresh_status'], 'orphaned')
        node = Node()
        from btc_observer.transaction import digest
        node.proof['header'] = node.proof['header'][:76] + b'\x01\0\0\0'
        node.block_hash = digest(node.proof['header'])
        node.metadata['hash'] = node.block_hash
        node.header, node.active = node.proof['header'].hex(), node.block_hash
        self.refresh(node)
        state = self.state()
        self.assertEqual((state['revision'], state['last_refresh_status']), (3, 'observed'))
        self.assertEqual(state['historical_evidence']['block_hash'], node.block_hash)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM btc_tracking').fetchone()[0], 1)

    def test_orphan_above_tip_and_inconsistent_orphan_claim(self):
        node = Node()
        node.metadata.update(height=106, confirmations=-1)
        result = self.refresh(node)
        self.assertEqual(result['tracking']['last_refresh_status'], 'orphaned')
        self.assertNotIn(('getblockhash', [106]), node.calls)
        for confirmations, active in ((-1, self.node.block_hash), (0, 'ff' * 32), (6, 'ff' * 32)):
            node = Node()
            node.metadata['confirmations'], node.active = confirmations, active
            with self.assertRaises(Invalid):
                self.refresh(node)
            self.assertEqual(self.state()['last_refresh_status'], 'unavailable')

    def test_rpc_failure_and_bad_proof_clear_previous_evidence(self):
        self.refresh()
        def failing(*_):
            pending = self.state()
            self.assertEqual(pending['last_refresh_status'], 'refreshing')
            self.assertIsNone(pending['historical_evidence'])
            raise Invalid('Source unavailable')
        with self.assertRaises(Invalid):
            self.refresh(rpc=failing)
        state = self.state()
        self.assertEqual((state['revision'], state['last_refresh_status']), (2, 'unavailable'))
        self.assertIsNone(state['historical_evidence'])
        self.node.proof['siblings'] = []
        with self.assertRaises(Invalid):
            self.refresh()
        self.assertEqual(self.state()['last_refresh_status'], 'unavailable')

    def test_tip_change_is_unavailable_not_an_orphan_assertion(self):
        node = Node()
        node.after = dict(node.info, bestblockhash='cd' * 32)
        with self.assertRaises(Invalid):
            self.refresh(node)
        self.assertEqual(self.state()['last_refresh_status'], 'unavailable')

    def test_interrupted_refresh_remains_pending_and_recovers_with_new_revision(self):
        class Interrupted(BaseException):
            pass
        self.refresh()
        def interrupted(*_):
            raise Interrupted()
        with self.assertRaises(Interrupted):
            self.refresh(rpc=interrupted)
        state = self.state()
        self.assertEqual((state['revision'], state['last_refresh_status']), (2, 'refreshing'))
        self.assertIsNone(state['historical_evidence'])
        self.refresh(Node())
        self.assertEqual((self.state()['revision'], self.state()['last_refresh_status']), (3, 'observed'))

    def test_late_success_or_failure_cannot_overwrite_newer_refresh(self):
        self.refresh()
        for fail in (False, True):
            entered, resume = threading.Event(), threading.Event()
            older = Node()
            def slow(method, params):
                if not entered.is_set():
                    entered.set()
                    if not resume.wait(5):
                        raise Invalid('Test synchronization timed out')
                if fail:
                    raise Invalid('Old request failed')
                return older(method, params)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.refresh, older, slow)
                try:
                    self.assertTrue(entered.wait(5))
                    newer = self.refresh(Node(), threshold=7)
                    revision = newer['tracking']['revision']
                finally:
                    resume.set()
                with self.assertRaisesRegex(Invalid, 'superseded'):
                    future.result(timeout=5)
            state = self.state()
            self.assertEqual((state['revision'], state['last_refresh_status']), (revision, 'below_threshold'))

    def test_input_containers_are_frozen_during_rpc(self):
        original_proof = copy.deepcopy(self.node.proof)
        def mutate(method, params):
            self.node.deposit['expected_txid'] = 'ff' * 32
            self.node.proof['siblings'].clear()
            return self.node(method, params)
        result = self.refresh(rpc=mutate)
        self.assertEqual(result['outpoint_key'], self.key)
        self.assertEqual(result['proof']['tx_count'], original_proof['tx_count'])
        self.assertEqual(self.state()['last_refresh_status'], 'observed')

    def test_foreign_journal_and_unsafe_files_remain_untouched(self):
        record(self.path, [self.node.deposit])
        before = self.path.read_bytes()
        with self.assertRaisesRegex(Invalid, 'Not a BTC tracking'):
            self.refresh()
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(Invalid):
            self.state()
        self.path.unlink()
        target = Path(self.directory.name) / 'target'
        target.write_bytes(b'keep')
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(Invalid):
            self.refresh()
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(Invalid):
            self.refresh()
        self.path.unlink()
        Path(self.directory.name).chmod(0o755)
        with self.assertRaises(Invalid):
            self.refresh()
        self.assertEqual(target.read_bytes(), b'keep')

    def test_capacity_revision_exhaustion_and_invalid_input_fail_before_rpc(self):
        with patch.object(tracking, 'MAX_ROWS', 0), self.assertRaises(Invalid):
            self.refresh()
        self.assertEqual(self.node.calls, [])
        # Failed creation is not silently reset. Use a separate fresh test file.
        self.path = Path(self.directory.name) / 'fresh.sqlite'
        self.refresh()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE btc_tracking SET revision=?', (tracking.MAX_REVISION,))
        self.node.calls.clear()
        with self.assertRaises(Invalid):
            self.refresh()
        self.assertEqual(self.node.calls, [])
        self.assertEqual(self.state()['revision'], tracking.MAX_REVISION)
        with self.assertRaises(Invalid):
            self.refresh(threshold=True)

    def test_read_missing_file_does_not_create_it(self):
        with self.assertRaises(OSError):
            self.state()
        self.assertFalse(self.path.exists())

    def test_read_refuses_cross_revision_and_contradictory_evidence(self):
        self.refresh()
        with sqlite3.connect(self.path) as db:
            original = db.execute('SELECT status, evidence FROM btc_tracking').fetchone()
        status, encoded = original
        evidence = json.loads(encoded)
        mutations = (
            ('observed', None),
            ('observed', dict(evidence, block_hash='ff' * 32)),
            ('observed', dict(evidence, required_confirmations=7)),
            ('observed', dict(evidence, confirmations=5)),
            ('observed', dict(evidence, tip_chainwork='00' * 32)),
            ('observed', dict(evidence, node_active_chain_observed=False)),
            ('below_threshold', evidence),
            ('orphaned', dict(evidence, confirmations=0, node_active_chain_observed=True)),
            ('refreshing', evidence),
            ('unavailable', evidence),
        )
        for corrupt_status, corrupt_evidence in mutations:
            with self.subTest(status=corrupt_status, evidence=corrupt_evidence):
                with sqlite3.connect(self.path) as db:
                    db.execute('UPDATE btc_tracking SET status=?, evidence=?',
                               (corrupt_status, json.dumps(corrupt_evidence)))
                with self.assertRaises(Invalid):
                    self.state()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE btc_tracking SET status=?, evidence=?', original)
        self.assertEqual(self.state()['last_refresh_status'], status)

    def test_post_commit_sync_failure_leaves_only_pending_state(self):
        with patch.object(tracking.os, 'fsync', side_effect=OSError('Injected sync failure')):
            with self.assertRaises(OSError):
                self.refresh()
        self.assertEqual(self.node.calls, [])
        self.assertEqual(self.state()['last_refresh_status'], 'refreshing')
        self.refresh()
        self.assertEqual((self.state()['revision'], self.state()['last_refresh_status']), (2, 'observed'))


if __name__ == '__main__':
    unittest.main()
