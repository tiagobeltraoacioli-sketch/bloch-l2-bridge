"""Persistent observation deduplication; none of these records authorize minting."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from btc_observer import journal
from btc_observer.transaction import decode, Invalid
from test_btc_transaction import SCRIPT, tx


def deposit(raw=None, index=0, network='bitcoin-regtest'):
    raw = tx() if raw is None else raw
    return dict(raw=raw, network=network, expected_txid=decode(raw).txid, vout=index, script_pubkey=SCRIPT)


class BitcoinJournalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'btc.sqlite'

    def rows(self):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT * FROM btc_outputs ORDER BY outpoint').fetchall()

    def test_restart_duplicate_and_distinct_outputs(self):
        result = journal.record(self.path, [deposit()])
        self.assertEqual((result['inserted'], result['duplicates'], result['total']), (1, 0, 1))
        self.assertIs(result['mint_authorized'], False)
        self.assertIs(result['bridge_ready'], False)
        result = journal.record(self.path, [deposit(), deposit(index=1)])
        self.assertEqual((result['inserted'], result['duplicates'], result['total']), (1, 1, 2))
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_witness_variants_do_not_create_new_deposits_or_replace_evidence(self):
        one, two = tx(b'\x01\x02ab'), tx(b'\x01\x02cd')
        journal.record(self.path, [deposit(one)])
        before = self.rows()
        result = journal.record(self.path, [deposit(two), deposit(one)])
        self.assertEqual((result['inserted'], result['duplicates']), (0, 2))
        self.assertEqual(self.rows(), before)
        self.assertEqual(before[0][2], decode(one).wtxid)

    def test_network_context_separates_observations(self):
        result = journal.record(self.path, [deposit(), deposit(network='bitcoin-mainnet')])
        self.assertEqual(result['inserted'], 2)

    def test_all_raw_inputs_are_revalidated_before_creating_file(self):
        bad = deposit()
        bad['expected_txid'] = '00' * 32
        with self.assertRaises(Invalid):
            journal.record(self.path, [deposit(), bad])
        self.assertFalse(self.path.exists())
        bad = deposit()
        bad['mint_authorized'] = True
        with self.assertRaises(Invalid):
            journal.record(self.path, [bad])
        self.assertFalse(self.path.exists())

    def test_conflicting_persisted_facts_fail_the_entire_batch(self):
        journal.record(self.path, [deposit()])
        with sqlite3.connect(self.path) as db:
            row = db.execute('SELECT outpoint, facts FROM btc_outputs').fetchone()
            facts = json.loads(row[1])
            facts['amount_sats'] = '999'
            db.execute('UPDATE btc_outputs SET facts=? WHERE outpoint=?', (json.dumps(facts), row[0]))
        before = self.rows()
        with self.assertRaisesRegex(Invalid, 'Conflicting'):
            journal.record(self.path, [deposit(index=1), deposit()])
        self.assertEqual(self.rows(), before)

    def test_row_limit_rolls_back_new_rows_but_allows_duplicates(self):
        raw = tx(amounts=(1, 2, 3))
        journal.record(self.path, [deposit(raw)])
        before = self.rows()
        with patch.object(journal, 'MAX_ROWS', 2):
            with self.assertRaisesRegex(Invalid, 'row limit'):
                journal.record(self.path, [deposit(raw, 1), deposit(raw, 2)])
            self.assertEqual(self.rows(), before)
            journal.record(self.path, [deposit(raw, 1)])
            self.assertEqual(journal.record(self.path, [deposit(raw)])['duplicates'], 1)

    def test_batch_limits_reject_before_creating_file(self):
        for batch in ([], [deposit()] * 129):
            with self.assertRaises(Invalid):
                journal.record(self.path, batch)
        with patch.object(journal, 'MAX_BATCH_BYTES', 1):
            with self.assertRaisesRegex(Invalid, 'byte limit'):
                journal.record(self.path, [deposit()])
        self.assertFalse(self.path.exists())

    def test_foreign_database_is_not_modified(self):
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE other (value TEXT)')
        self.path.chmod(0o600)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(Invalid, 'Not a BTC'):
            journal.record(self.path, [deposit()])
        self.assertEqual(self.path.read_bytes(), before)

    def test_unsafe_paths_and_permissions_are_refused(self):
        target = Path(self.temp.name) / 'target'
        target.write_bytes(b'keep')
        self.path.symlink_to(target)
        with self.assertRaises(Invalid):
            journal.record(self.path, [deposit()])
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(Invalid):
            journal.record(self.path, [deposit()])
        self.path.unlink()
        Path(self.temp.name).chmod(0o755)
        with self.assertRaisesRegex(Invalid, 'private directory'):
            journal.record(self.path, [deposit()])
        self.assertFalse(self.path.exists())
        self.assertEqual(target.read_bytes(), b'keep')

    def test_concurrent_writers_insert_once(self):
        journal.record(self.path, [deposit()])
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: journal.record(self.path, [deposit(index=1)]), range(4)))
        self.assertEqual(sum(r['inserted'] for r in results), 1)
        self.assertEqual(sum(r['duplicates'] for r in results), 3)
        self.assertEqual(len(self.rows()), 2)

    def test_post_commit_sync_failure_is_safe_to_retry(self):
        with patch.object(journal.os, 'fsync', side_effect=OSError('injected directory sync failure')):
            with self.assertRaises(OSError):
                journal.record(self.path, [deposit()])
        result = journal.record(self.path, [deposit()])
        self.assertEqual((result['inserted'], result['duplicates']), (0, 1))


if __name__ == '__main__':
    unittest.main()
