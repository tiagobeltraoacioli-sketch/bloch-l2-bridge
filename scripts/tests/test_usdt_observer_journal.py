"""Local journal durability and conflict regressions; no keys or mint authority."""
import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer import ethereum, journal
from usdt_observer.common import Invalid, deposit_digest
from test_usdt_ethereum_observer import fixture, tagged

DIGEST = '12' * 32


def observation_fixture():
    route, evidence = fixture()
    return route, ethereum.validate(route, evidence)[0]


def changed_observation(observation, **changes):
    value = dict(observation, **changes)
    value['deposit_id'] = '0x' + deposit_digest(
        bytes.fromhex(value['route_id'][2:]), value['nonce'], bytes.fromhex(value['sender'][2:]),
        value['amount'], bytes.fromhex(value['pq_recipient_hash'][2:])).hex()
    return value


def changed_route(route, **changes):
    value = dict(route, **changes)
    value['route_id'] = tagged('BLOCH-USDT-ROUTE-v1', value['source_domain'], value['native_domain'],
                               value['native_asset'], value['token_vm_hex'], value['vault_vm_hex'], 6, value['cap'])
    return value


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)
        self.path = self.directory / 'observations.sqlite'
        self.route, self.observation = observation_fixture()

    def record(self, observations=None, route=None, path=None, digest=DIGEST):
        return journal.record(path or self.path, route or self.route,
                              [self.observation] if observations is None else observations, digest)

    def rows(self):
        with sqlite3.connect(self.path) as connection:
            return connection.execute('SELECT observation_json,evidence_sha256 FROM observations ORDER BY deposit_id').fetchall()

    def test_roundtrip_idempotence_case_normalization_and_no_mint_authority(self):
        result = self.record()
        self.assertEqual(result, {'new_observations': 1, 'duplicate_observations': 0,
                                  'mint_authorized': False, 'native_execution_performed': False})
        upper = {k: '0x' + v[2:].upper() if isinstance(v, str) and v.startswith('0x') else v
                 for k, v in self.observation.items()}
        repeat = self.record([upper], digest='34' * 32)
        self.assertEqual(repeat['duplicate_observations'], 1)
        self.assertEqual(repeat['new_observations'], 0)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0][0]), self.observation)
        self.assertEqual(rows[0][1], DIGEST)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_changed_block_and_reused_route_nonce_refuse_entire_batch(self):
        self.record()
        original = self.rows()
        mutations = [dict(self.observation, block_hash='0x' + 'ef' * 32),
                     changed_observation(self.observation, amount=self.observation['amount'] + 1,
                                         tx_hash='0x' + 'ef' * 32)]
        for altered in mutations:
            with self.subTest(altered=altered), self.assertRaises(Invalid):
                self.record([altered])
            self.assertEqual(self.rows(), original)

    def test_source_event_alias_is_rejected_within_and_across_routes(self):
        self.record()
        alias = changed_observation(self.observation, nonce=1)
        with self.assertRaises(Invalid):
            self.record([alias])
        other_route = changed_route(self.route, vault_vm_hex='0x' + 'cd' * 20)
        alias = changed_observation(self.observation, route_id=other_route['route_id'])
        with self.assertRaises(Invalid):
            self.record([alias], route=other_route)
        self.assertEqual(len(self.rows()), 1)
        # A distinct event on the second route remains valid despite nonce zero.
        distinct = changed_observation(alias, tx_hash='0x' + 'ef' * 32)
        self.assertEqual(self.record([distinct], route=other_route)['new_observations'], 1)

    def test_mid_batch_conflict_rolls_back_prior_insertions(self):
        self.record()
        baseline = self.rows()
        new = changed_observation(self.observation, nonce=1, tx_hash='0x' + 'ef' * 32)
        conflict = dict(self.observation, block_hash='0x' + 'cd' * 32)
        with self.assertRaises(Invalid):
            self.record([new, conflict])
        self.assertEqual(self.rows(), baseline)
        self.assertEqual(self.record([new])['new_observations'], 1)

    def test_failed_initial_transaction_leaves_no_unusable_empty_database(self):
        alias = changed_observation(self.observation, nonce=1)
        with self.assertRaises(Invalid):
            self.record([self.observation, alias])
        self.assertFalse(self.path.exists())
        self.assertEqual(self.record()['new_observations'], 1)

    def test_initial_connection_failure_is_cleaned_and_retry_succeeds(self):
        with patch.object(journal.sqlite3, 'connect', side_effect=sqlite3.OperationalError('synthetic open failure')):
            with self.assertRaises((Invalid, sqlite3.OperationalError)):
                self.record()
        self.assertFalse(self.path.exists(), 'failed open must not leave an unclaimable empty database')
        self.assertEqual(self.record()['new_observations'], 1)

    def test_full_unsigned_values_are_persisted_without_sqlite_integer_overflow(self):
        route = changed_route(self.route, cap=(1 << 64) - 1)
        observation = changed_observation(self.observation, route_id=route['route_id'],
                                          amount=(1 << 64) - 1, nonce=(1 << 64) - 2,
                                          block_number=(1 << 63) + 7)
        self.assertEqual(self.record([observation], route=route)['new_observations'], 1)
        self.assertEqual(json.loads(self.rows()[0][0]), observation)

    def test_invalid_observation_is_refused_before_file_creation(self):
        for observation in [dict(self.observation, amount=True), dict(self.observation, unexpected='field'),
                            dict(self.observation, block_hash='0x' + '00' * 32),
                            dict(self.observation, network='tron-mainnet'),
                            dict(self.observation, transfer_log_index=self.observation['log_index'])]:
            with self.assertRaises(Invalid):
                self.record([observation])
            self.assertFalse(self.path.exists())
        with self.assertRaises(Invalid):
            self.record(digest='not a digest')

    def test_private_directory_and_regular_file_are_required(self):
        self.directory.chmod(0o755)
        try:
            with self.assertRaises(Invalid):
                self.record()
            self.assertFalse(self.path.exists())
        finally:
            self.directory.chmod(0o700)
        self.record()
        self.path.chmod(0o644)
        with self.assertRaises(Invalid):
            self.record()

    def test_file_and_parent_symlinks_preserve_their_targets(self):
        unrelated = self.directory / 'operator-evidence'
        unrelated.write_bytes(b'preserve this evidence')
        self.path.symlink_to(unrelated)
        with self.assertRaises(Invalid):
            self.record()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(unrelated.read_bytes(), b'preserve this evidence')
        parent_link = self.directory / 'parent-link'
        parent_link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(Invalid):
            self.record(path=parent_link / 'other.sqlite')
        self.assertFalse((self.directory / 'other.sqlite').exists())

    def test_unrelated_private_sqlite_file_is_unchanged(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute('CREATE TABLE operator_evidence (value TEXT)')
            connection.execute("INSERT INTO operator_evidence VALUES ('keep')")
        self.path.chmod(0o600)
        original = self.path.read_bytes()
        with self.assertRaises(Invalid):
            self.record()
        self.assertEqual(self.path.read_bytes(), original)

    def test_capacity_is_atomic_but_idempotent_replay_still_works(self):
        new = changed_observation(self.observation, nonce=1, tx_hash='0x' + 'ef' * 32)
        with patch.object(journal, 'MAX_ROWS', 1):
            with self.assertRaises(Invalid):
                self.record([self.observation, new])
            self.assertFalse(self.path.exists())
            self.record()
            with self.assertRaises(Invalid):
                self.record([new])
            self.assertEqual(self.record()['duplicate_observations'], 1)
            self.assertEqual(len(self.rows()), 1)

    def test_disk_space_and_database_size_limits_preserve_existing_file(self):
        with patch.object(journal.shutil, 'disk_usage', return_value=type('Space', (), {'free': 0})()):
            with self.assertRaises(Invalid):
                self.record()
        self.assertFalse(self.path.exists())
        self.record()
        original = self.path.read_bytes()
        with patch.object(journal, 'MAX_DB_BYTES', 1):
            with self.assertRaises(Invalid):
                self.record()
        self.assertEqual(self.path.read_bytes(), original)

    def test_directory_fsync_failure_after_commit_is_safe_to_retry(self):
        # SQLite has already committed durably; an error reporting directory
        # persistence must not delete that file or cause a duplicate insertion.
        with patch.object(journal.os, 'fsync', side_effect=OSError('synthetic directory sync failure')):
            with self.assertRaises(Invalid):
                self.record()
        self.assertTrue(self.path.exists())
        self.assertEqual(self.record()['duplicate_observations'], 1)
        self.assertEqual(len(self.rows()), 1)


if __name__ == '__main__':
    unittest.main()
