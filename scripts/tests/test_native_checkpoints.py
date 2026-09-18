"""Finalized block identity is distinct from head and native DEX state."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.native_checkpoints import compare_checkpoints


def reports():
    info = {'height': 96, 'slot': 101, 'epoch': 10, 'slots_per_epoch': 10,
            'finalized_height': 80, 'finalized': {'epoch': 8, 'root': '0x'+'ab'*32},
            'state_root': '0x'+'cd'*32, 'block_id': '0x'+'ef'*32}
    return [{'source': source, 'chaininfo': copy.deepcopy(info)} for source in ['node-a', 'node-b']]


class NativeCheckpointsTest(unittest.TestCase):
    def test_matching_checkpoint_allows_different_heads_but_not_credit(self):
        value = reports()
        value[1]['chaininfo'].update(height=97, slot=102, state_root='0x'+'dd'*32, block_id='0x'+'ee'*32)
        result = compare_checkpoints(value)
        self.assertTrue(result['node_report_agreement'])
        for flag in ['reports_authenticated', 'reports_fresh', 'operator_independence_verified',
                     'native_dex_state_bound', 'finality_verified', 'mint_authorized', 'bridge_ready']:
            self.assertFalse(result[flag])
        self.assertEqual(result['finalized_block_root'], '0x'+'ab'*32)

    def test_same_epoch_different_root_refuses(self):
        value = reports()
        value[1]['chaininfo']['finalized']['root'] = '0x'+'bc'*32
        with self.assertRaises(ValueError): compare_checkpoints(value)

    def test_different_epoch_height_or_epoch_length_refuses(self):
        for field, replacement in [('finalized_height', 79), ('slots_per_epoch', 9)]:
            value = reports()
            value[1]['chaininfo'][field] = replacement
            with self.assertRaises(ValueError): compare_checkpoints(value)
        value = reports()
        value[1]['chaininfo']['finalized']['epoch'] = 7
        with self.assertRaises(ValueError): compare_checkpoints(value)

    def test_missing_or_invalid_finalized_height_refuses(self):
        for invalid in [None, True, '80', -1, 97, 2**64]:
            value = reports()
            value[0]['chaininfo']['finalized_height'] = invalid
            with self.assertRaises(ValueError): compare_checkpoints(value)

    def test_source_labels_and_report_count_are_bounded(self):
        for value in [reports()[:1], reports()*9, [reports()[0], reports()[0]]]:
            with self.assertRaises(ValueError): compare_checkpoints(value)

    def test_future_or_zero_checkpoint_refuses(self):
        for key, value in [('epoch', 11), ('root', '0x'+'00'*32)]:
            items = reports()
            items[0]['chaininfo']['finalized'][key] = value
            with self.assertRaises(ValueError): compare_checkpoints(items)

    def test_zero_head_identities_refuse_even_when_checkpoint_matches(self):
        for field in ('state_root', 'block_id'):
            items = reports()
            items[0]['chaininfo'][field] = '0x' + '00' * 32
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare_checkpoints(items)
