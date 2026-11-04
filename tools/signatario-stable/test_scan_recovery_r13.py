"""Adversarial recovery of the persisted discovery and finished-item caches."""
import json
import time
import unittest
from unittest import mock

import vigia
from test_relayer_r11 import Chain, ScanBase, deposit_log
from test_relayer_review import dep_id


class ScanRecovery(ScanBase):
    def prepared(self, **config):
        chain = Chain(100, [deposit_log(0, 50)])
        daemon = self.vigia_on(chain, **config)
        daemon.deposits()
        daemon.finish('release', dep_id(1))
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


if __name__ == '__main__':
    unittest.main()
