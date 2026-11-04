"""Adversarial recovery of the persisted discovery and finished-item caches."""
import json
import time
import unittest
from unittest import mock

import vigia
import test_relayer_r11 as r11
from test_relayer_r11 import Chain, ScanBase, deposit_log
from test_relayer_review import dep_id


class ScanRecovery(ScanBase):
    def prepared(self, **config):
        chain = Chain(100, [deposit_log(0, 50)])
        daemon = self.vigia_on(chain, **config)
        daemon.deposits()
        daemon.finish('release', dep_id(1), daemon.final_anchor(chain.block(100)))
        return chain, daemon

    def test_periodic_rescan_still_invalidates_reorganized_finished_items(self):
        chain, daemon = self.prepared(scan_full_every_s=60)
        chain.salt = 'b'
        with mock.patch.object(vigia.time, 'time', return_value=time.time() + 61):
            daemon.deposits()
        self.assertEqual(daemon.finished()['release'], set())

    def test_rollback_below_deployment_height_invalidates_finished_items(self):
        chain, daemon = self.prepared(vault_from_block=40)
        chain.head = 30
        self.assertEqual(daemon.deposits(), [])
        self.assertEqual(daemon.finished()['release'], set())

    def test_changed_contract_invalidates_finished_items(self):
        _, daemon = self.prepared()
        daemon.vault = '0x' + 'ef' * 20
        daemon.deposits()
        self.assertEqual(daemon.finished()['release'], set())

    def test_missing_or_corrupt_cursor_cannot_preserve_finished_items(self):
        for mutation in ('missing', 'invalid-json', 'missing-hash', 'negative-height', 'nan-time'):
            with self.subTest(mutation=mutation):
                _, daemon = self.prepared()
                path = daemon.scan_file('deposits')
                if mutation == 'missing':
                    path.unlink()
                elif mutation == 'invalid-json':
                    path.write_text('{')
                else:
                    record = json.loads(path.read_text())
                    if mutation == 'missing-hash':
                        record.pop('hash')
                    elif mutation == 'negative-height':
                        record['to'] = -1
                    else:
                        record['full_t'] = float('nan')
                    path.write_text(json.dumps(record))
                daemon.deposits()
                self.assertEqual(daemon.finished()['release'], set())

    def test_reorg_during_log_walk_does_not_publish_mixed_branch_cursor(self):
        chain, daemon = self.prepared()
        before = daemon.scan_file('deposits').read_bytes()
        chain.head = 101
        original = chain.answer

        def reorg(method, params):
            result = original(method, params)
            if method == 'eth_getLogs':
                chain.salt = 'b'
            return result

        chain.answer = reorg
        with self.assertRaisesRegex(RuntimeError, 'changed during log scan'):
            daemon.deposits()
        self.assertEqual(daemon.scan_file('deposits').read_bytes(), before)
        self.assertEqual(daemon.finished()['release'], set())


class FinishedCheckpoints(ScanBase):
    feed_vigia, burns = r11.Finished.feed_vigia, r11.Finished.burns

    def test_reorg_above_discovery_cursor_invalidates_a_later_completion(self):
        chain = Chain(100, [])
        daemon = self.feed_vigia(eth=chain)
        daemon.deposits()
        original = chain.block
        chain.head = 101
        daemon.sync([], self.burns(1))
        self.assertEqual(len(daemon.finished()['release']), 1)
        chain.block = lambda number: (dict(original(number), hash='0x' + 'b1' * 32)
                                      if number == 101 else original(number))
        daemon = self.feed_vigia(eth=chain)
        daemon.deposits()  # The block at cursor 100 has not changed.
        daemon.sync([], self.burns(1))
        self.assertEqual(self.reads, [('released', self.burns(1)[0]['burn_id'])])

    def test_restart_with_changed_contract_or_endpoint_rechecks_flags(self):
        for field in ('token', 'source_vault', 'l2_rpc', 'eth_rpc'):
            with self.subTest(field=field):
                daemon = self.feed_vigia()
                daemon.sync([dep_id(1)], self.burns(1))
                daemon = self.feed_vigia()
                if field == 'token':
                    daemon.token = '0x' + 'de' * 20
                elif field == 'source_vault':
                    daemon.vault = '0x' + 'ef' * 20
                else:
                    daemon.cfg[field] += '/different-source'
                daemon.sync([dep_id(1)], self.burns(1))
                expected = ('minted', dep_id(1)) if field in ('token', 'l2_rpc') else ('released', self.burns(1)[0]['burn_id'])
                self.assertIn(expected, self.reads)

    def test_legacy_finished_ids_are_observations_to_recheck(self):
        daemon = self.feed_vigia()
        daemon.scan_save('finished', {'mint': [dep_id(1)], 'release': [self.burns(1)[0]['burn_id']]})
        daemon.sync([dep_id(1)], self.burns(1))
        self.assertEqual(len(self.reads), 2)
        self.assertEqual(daemon.scan_load('finished')['schema'], 2)

    def test_hash_bound_read_and_recheck_reject_a_mid_call_reorg(self):
        chain = Chain(100, [])
        daemon = self.feed_vigia(eth=chain)
        expected = {'blockHash': chain.block(100)['hash'], 'requireCanonical': True}

        def reorganize(url, to, signature, tag, *args):
            self.assertEqual(tag, expected)
            chain.salt = 'b'
            return '0x1'

        daemon.call_at = reorganize
        daemon.sync([], self.burns(1))
        self.assertEqual(daemon.finished()['release'], set())

    def test_unavailable_finality_clears_cache_and_never_records_latest_only(self):
        chain = Chain(100, [])
        daemon = self.feed_vigia(eth=chain)
        daemon.sync([], self.burns(1))
        original = daemon.rpc

        def unavailable(url, method, params):
            if method == 'eth_getBlockByNumber' and params[0] == 'finalized':
                raise vigia.LevelClosed('finality unavailable')
            return original(url, method, params)

        daemon.rpc = unavailable
        daemon.new_pass()
        self.reads.clear()
        daemon.sync([], self.burns(1))
        self.assertEqual(len(self.reads), 1)
        self.assertEqual(daemon.finished()['release'], set())

    def test_unsupported_hash_selector_keeps_uncached_item_reads(self):
        daemon = self.feed_vigia()
        daemon.call_at = mock.Mock(side_effect=RuntimeError('hash selectors unsupported'))
        daemon.sync([], self.burns(1))
        self.assertEqual(daemon.finished()['release'], set())
        daemon.sync([], self.burns(1))
        self.assertEqual(len(self.reads), 2)

    def test_each_new_pass_rechecks_a_live_process_checkpoint_once_per_chain(self):
        chain = Chain(100, [])
        daemon = self.feed_vigia(eth=chain)
        daemon.sync([], self.burns(50))
        daemon.new_pass()
        self.reads.clear()
        with mock.patch.object(chain, 'answer', wraps=chain.answer) as rpc:
            daemon.sync([], self.burns(50))
            daemon.sync([], self.burns(50))
            self.assertEqual(rpc.call_count, 1)
        self.assertEqual(self.reads, [])
        chain.salt = 'b'
        daemon.new_pass()
        daemon.sync([], self.burns(50))
        self.assertEqual(len(self.reads), 50)

    def test_corrupt_finished_records_cannot_skip_real_state_reads(self):
        for mutation in ('nested-item', 'boolean-number', 'missing-context', 'negative-number'):
            with self.subTest(mutation=mutation):
                daemon = self.feed_vigia()
                daemon.sync([], self.burns(1))
                record = daemon.scan_load('finished')
                if mutation == 'nested-item':
                    record['release']['items'] = [{}]
                elif mutation == 'boolean-number':
                    record['release']['anchor']['number'] = True
                elif mutation == 'negative-number':
                    record['release']['anchor']['number'] = -1
                else:
                    record['release'].pop('context')
                daemon.scan_save('finished', record)
                daemon = self.feed_vigia()
                daemon.sync([], self.burns(1))
                self.assertEqual(len(self.reads), 1)


if __name__ == '__main__':
    unittest.main()
