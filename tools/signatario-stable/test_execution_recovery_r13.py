"""Shared completion files cannot hide rolled-back or never-executed bridge mints."""
import json
import os
from pathlib import Path
import unittest
from unittest import mock

import test_relayer_review as review
import test_relayer_r11 as r11
from test_relayer_review import Base, dep_id, word
from test_relayer_r11 import Chain, ScanBase, deposit_log


class SharedMarkers(Base):
    def test_unordered_relay_rechecks_a_forged_execution_marker(self):
        v = self.vigia(provenance=False)
        directory = review.OrderedMints.setup_slots(self, v, [0], 0)[0]
        (directory / 'executed').write_text('done\n')
        v.signatario = lambda *args: (0, {'call': ['mint()']})
        v.backup_due = lambda *args: True
        sent = []
        v.send = lambda *args: sent.append(args) or '0x' + '12' * 32
        v.relay_mint(directory)
        self.assertEqual(len(sent), 1)
        self.assertFalse((directory / 'executed').exists())

    def test_ordered_relay_rechecks_markers_and_preserves_slot_order(self):
        v = self.vigia()
        directories = review.OrderedMints.setup_slots(self, v, [0, 1], 0)
        for directory in directories:
            (directory / 'executed').write_text('done\n')
        sent = []
        v.send_mint = lambda d, dep, sigs, nonce, fixed: sent.append((nonce, fixed))
        v.relay_mints_in_order(directories)
        self.assertEqual(sent, [(0, False), (1, True)])

    def test_marker_cannot_skip_a_queued_execution_after_rollback(self):
        for ordered in (False, True):
            with self.subTest(ordered=ordered):
                v = self.vigia(provenance=ordered)
                directory = self.d / ('ordered' if ordered else 'unordered') / dep_id(0)[2:]
                directory.mkdir(parents=True)
                (directory / 'executed').write_text('done\n')
                v.minted = lambda dep: True
                v.execute_if_queued = mock.Mock()
                if ordered:
                    v.relay_mints_in_order([directory])
                else:
                    v.relay_mint(directory)
                v.execute_if_queued.assert_called_once_with(directory, dep_id(0))


class ExecutionCheckpoints(ScanBase):
    def prepared(self):
        chain = Chain(100, [])
        v = self.vigia_on(Chain(100, []), chain)
        values = {'minted(bytes32)': '0x' + word(1), 'pendingMints(bytes32)': '0x' + word(0) * 3,
                  'mintCancels(bytes32)': '0x' + word(0), 'lastRemint(bytes32)': '0x' + word(0)}
        v.call_at = lambda url, to, signature, tag, *args: values[signature]
        v.remember_execution(dep_id(0))
        self.assertIn(dep_id(0), v.finished()['executed'])
        return v, chain, values

    def test_execution_cache_is_revalidated_after_reorg(self):
        v, chain, _ = self.prepared()
        chain.salt = 'b'
        v.new_pass()
        self.assertEqual(v.finished()['executed'], set())

    def test_execution_cache_is_revalidated_after_rollback_or_contract_switch(self):
        for mutation in ('height', 'token'):
            with self.subTest(mutation=mutation):
                v, chain, _ = self.prepared()
                if mutation == 'height':
                    chain.head = 99
                else:
                    v.token = '0x' + 'ab' * 20
                v.new_pass()
                self.assertEqual(v.finished()['executed'], set())

    def test_execution_cache_never_restores_shared_records_after_restart(self):
        self.prepared()
        v = self.vigia_on(Chain(100, []), Chain(100, []))
        self.assertEqual(v.finished()['executed'], set())

    def test_queued_or_cancelled_generations_are_not_final_executions(self):
        for change in ('queued', 'cancelled', 'unminted', 'bad-abi', 'unavailable'):
            with self.subTest(change=change):
                v, _, values = self.prepared()
                item = dep_id(1)
                if change == 'queued':
                    values['pendingMints(bytes32)'] = '0x' + word(0) + word(10) + word(99)
                elif change == 'cancelled':
                    values['mintCancels(bytes32)'] = '0x' + word(1)
                elif change == 'unminted':
                    values['minted(bytes32)'] = '0x' + word(0)
                elif change == 'bad-abi':
                    values['pendingMints(bytes32)'] = '0x'
                else:
                    v.call_at = mock.Mock(side_effect=RuntimeError('rate limited'))
                v.remember_execution(item)
                self.assertNotIn(item, v.finished()['executed'])


class SharedScanState(ScanBase):
    def test_replacing_published_bytes_cannot_change_the_trusted_digest(self):
        chain = Chain(100, [deposit_log(0, 50)])
        v = self.vigia_on(chain)
        replace = Path.replace

        def swap_after_publish(source, target):
            result = replace(source, target)
            if Path(target) == v.scan_file('deposits'):
                forged = json.loads(Path(target).read_bytes())
                forged['logs'] = []
                Path(target).write_text(json.dumps(forged))
            return result

        with mock.patch.object(Path, 'replace', swap_after_publish):
            self.assertEqual(v.deposits(), [dep_id(0)])
        chain.get_logs.clear()
        self.assertEqual(v.deposits(), [dep_id(0)])
        self.assertEqual(chain.get_logs, [(0, 100)])

    def test_cache_write_does_not_follow_a_shared_temporary_symlink(self):
        v = self.vigia_on(Chain(100, []))
        path = v.scan_file('deposits')
        path.parent.mkdir(parents=True)
        victim = self.d / 'private-config'
        victim.write_text('keep private configuration\n')
        path.with_name(f'.{path.name}.{os.getpid()}.tmp').symlink_to(victim)
        v.scan_save('deposits', {'observed': True})
        self.assertEqual(victim.read_text(), 'keep private configuration\n')
        self.assertEqual(v.scan_load('deposits'), {'observed': True})

    def test_forged_matching_cursor_cannot_omit_real_deposits(self):
        chain = Chain(100, [deposit_log(0, 50)])
        v = self.vigia_on(chain)
        self.assertEqual(v.deposits(), [dep_id(0)])
        path = v.scan_file('deposits')
        record = json.loads(path.read_text())
        record['logs'] = []  # all chain/height/hash/context fields still match
        path.write_text(json.dumps(record))
        chain.get_logs.clear()
        self.assertEqual(v.deposits(), [dep_id(0)])
        self.assertEqual(chain.get_logs, [(0, 100)])

    def test_restart_rebuilds_finished_flags_instead_of_trusting_shared_ids(self):
        v = r11.Finished.feed_vigia(self)
        v.sync([dep_id(0)], [])
        v = r11.Finished.feed_vigia(self)
        v.minted = lambda dep: self.reads.append(('minted', dep)) or False
        v.sync([dep_id(0)], [])
        self.assertEqual(self.reads, [('minted', dep_id(0))])
        self.assertEqual(v.open_deps, [dep_id(0)])
        self.assertEqual(v.feed.retired, [])


if __name__ == '__main__':
    unittest.main()
