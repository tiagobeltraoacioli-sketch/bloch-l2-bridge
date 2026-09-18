"""Persistent release identities, crash retries and fail-closed storage tests."""
from concurrent.futures import ThreadPoolExecutor
import copy
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.common import Invalid
from usdt_observer import release_journal
from usdt_observer.stablecoins import select_route
from test_stablecoin_observer import catalog_fixture, evidence_for, configuration_for
from test_stablecoin_releases import add_release
from test_usdt_ethereum_observer import abi


def fixture(symbol='bUSDC', nonce=7, burn='0x' + 'bb' * 32, tx=None):
    catalog = catalog_fixture()
    route = select_route(catalog, symbol, 'ethereum-mainnet', True)
    captured = evidence_for(route)
    if tx:
        captured['receipt']['transactionHash'] = tx
        captured['canonical_block']['transactions'][1] = tx
    captured['receipt']['logs'] = []
    expected = add_release(route, captured, nonce, burn)
    manifest = next(x['manifest'] for x in catalog['assets'] if x['symbol'] == symbol)
    captured['vault_runtime'] = {
        'block_hash': captured['receipt']['blockHash'], 'block_number': captured['receipt']['blockNumber'],
        'address': route['vault_vm_hex'], 'code': manifest['routes'][0]['deployment']['runtime_code'],
        'configuration': configuration_for(route),
        'reserves': {'total_locked': '0x' + abi(0).hex(), 'token_balance': '0x' + abi(0).hex()}}
    return route, captured, expected


class ReleaseJournalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'release.sqlite'
        self.route, self.captured, self.expected = fixture()

    def record(self, args=None):
        return release_journal.record(self.path, *(args or (self.route, self.captured, self.expected)))

    def rows(self):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT * FROM release_observations ORDER BY release_id').fetchall()

    def test_retry_is_idempotent_and_remains_historical(self):
        self.assertEqual(self.record()['new_observations'], 1)
        before = self.rows()
        result = self.record()
        self.assertEqual(result['duplicate_observations'], 1)
        self.assertEqual(result['new_observations'], 0)
        self.assertTrue(result['requires_fresh_evidence'])
        for flag in ['native_release_authenticated', 'redemption_settled', 'mint_authorized', 'bridge_ready']:
            self.assertFalse(result[flag])
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_retry_revalidates_all_persisted_identity_columns(self):
        self.record()
        original = self.path.read_bytes()
        mutations = [
            ("UPDATE release_observations SET source_event=?", ('00' * 32,)),
            ("UPDATE release_observations SET transfer_event=?", ('11' * 32,)),
            ("UPDATE release_observations SET route_nonce=?", ('unbound:7',)),
            ("UPDATE release_observations SET native_burn=?", ('22' * 32,)),
            ("UPDATE release_observations SET first_evidence_sha256=?", ('bad',)),
        ]
        for statement, parameters in mutations:
            self.path.write_bytes(original)
            with sqlite3.connect(self.path) as db:
                db.execute(statement, parameters)
            with self.subTest(statement=statement), self.assertRaises(Invalid):
                self.record()

    def test_same_burn_cannot_be_reassigned_to_other_asset_or_nonce(self):
        self.record()
        before = self.rows()
        for args in [fixture(nonce=8, tx='0x' + 'ad' * 32), fixture('bUSDT')]:
            with self.assertRaises(Invalid): self.record(args)
            self.assertEqual(self.rows(), before)

    def test_same_nonce_cannot_name_new_burn(self):
        self.record()
        with self.assertRaises(Invalid):
            self.record(fixture(burn='0x' + 'bc' * 32, tx='0x' + 'ad' * 32))
        self.assertEqual(len(self.rows()), 1)

    def test_same_source_event_cannot_pay_another_claim(self):
        self.record()
        with self.assertRaises(Invalid):
            self.record(fixture(nonce=8, burn='0x' + 'bc' * 32))
        self.assertEqual(len(self.rows()), 1)

    def test_reorg_does_not_overwrite_old_block(self):
        self.record()
        before = self.rows()
        changed = copy.deepcopy(self.captured)
        block = '0x' + 'ba' * 32
        changed['receipt']['blockHash'] = block
        changed['canonical_block']['hash'] = block
        changed['vault_runtime']['block_hash'] = block
        for log in changed['receipt']['logs']: log['blockHash'] = block
        with self.assertRaises(Invalid): self.record((self.route, changed, self.expected))
        self.assertEqual(self.rows(), before)

    def test_transfer_log_cannot_be_reused_or_replace_a_release_log(self):
        self.record()
        before = self.rows()
        for reuse_transfer in [True, False]:
            route, captured, expected = fixture(nonce=8, burn='0x' + 'bc' * 32)
            logs = captured['receipt']['logs']
            if reuse_transfer:
                unrelated = copy.deepcopy(logs[0])
                unrelated.update(address='0x' + 'cd' * 20, topics=[], data='0x', logIndex='0x12')
                logs.insert(1, unrelated)
                logs[2]['logIndex'] = '0x13'
            else:
                logs[0]['logIndex'] = '0x12'
                logs[1]['logIndex'] = '0x13'
            with self.assertRaises(Invalid): self.record((route, captured, expected))
            self.assertEqual(self.rows(), before)

    def test_distinct_assets_and_claims_coexist(self):
        self.record()
        result = self.record(fixture('bUSDT', burn='0x' + 'bc' * 32))
        self.assertEqual(result['new_observations'], 1)
        self.assertEqual(len(self.rows()), 2)

    def test_invalid_evidence_cannot_create_or_mutate_database(self):
        changed = copy.deepcopy(self.captured)
        changed['vault_runtime']['reserves']['total_locked'] = '0x' + abi(1).hex()
        with self.assertRaises(Invalid): self.record((self.route, changed, self.expected))
        self.assertFalse(self.path.exists())
        self.record()
        before = self.rows()
        with self.assertRaises(Invalid): self.record((self.route, changed, self.expected))
        self.assertEqual(self.rows(), before)

    def test_capacity_still_allows_exact_retry(self):
        self.record()
        with patch.object(release_journal, 'MAX_ROWS', 1):
            self.assertEqual(self.record()['duplicate_observations'], 1)
            with self.assertRaises(Invalid):
                self.record(fixture(nonce=8, burn='0x' + 'bc' * 32, tx='0x' + 'ad' * 32))
        self.assertEqual(len(self.rows()), 1)

    def test_concurrent_retries_of_initialized_journal_do_not_duplicate(self):
        self.record()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.record(), range(8)))
        self.assertTrue(all(r['duplicate_observations'] == 1 for r in results))
        self.assertEqual(len(self.rows()), 1)

    def test_silent_insert_loss_is_detected_and_rolled_back(self):
        self.record()
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TRIGGER discard_new_release AFTER INSERT ON release_observations
                          BEGIN DELETE FROM release_observations WHERE release_id=NEW.release_id; END''')
        before = self.rows()
        with self.assertRaisesRegex(Invalid, 'readback mismatch'):
            self.record(fixture(nonce=8, burn='0x' + 'bc' * 32, tx='0x' + 'ad' * 32))
        self.assertEqual(self.rows(), before)

    def test_post_commit_fsync_failure_is_recoverable_by_exact_retry(self):
        with patch.object(release_journal.os, 'fsync', side_effect=OSError('simulated')):
            with self.assertRaises(OSError): self.record()
        self.assertEqual(self.record()['duplicate_observations'], 1)

    def test_foreign_database_and_file_permissions_fail_closed(self):
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE unrelated (value TEXT)')
        self.path.chmod(0o600)
        before = self.path.read_bytes()
        with self.assertRaises(Invalid): self.record()
        self.assertEqual(self.path.read_bytes(), before)
        self.path.unlink()
        self.record()
        self.path.chmod(0o644)
        with self.assertRaises(Invalid): self.record()
        self.path.chmod(0o600)
        alias = self.root / 'hardlink'
        os.link(self.path, alias)
        with self.assertRaises(Invalid): self.record()
        alias.unlink()
        link = self.root / 'symlink'
        link.symlink_to(self.path)
        with self.assertRaises(Invalid):
            release_journal.record(link, self.route, self.captured, self.expected)
