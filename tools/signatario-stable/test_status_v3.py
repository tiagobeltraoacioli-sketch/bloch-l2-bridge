#!/usr/bin/env python3
"""The signer reads a v3 follower status as the v2 shape its checks use, and refuses a log that differs from it.
  python3 test_status_v3.py"""
import json
import tempfile
import unittest
from pathlib import Path

import l2_finality as F


def entry(n):
    return {'l2_number': n, 'l2_hash': f'{n:064x}', 'l2_state_root': 'ab' * 32, 'native_slot': 1000 + n}


class StatusV3(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'status.json'
        self.log = self.path.with_name('status.settlements.jsonl')

    def write(self, count, **over):
        entries = [entry(n) for n in range(1, count + 1)]
        text = b''.join(json.dumps(e, separators=(',', ':'), sort_keys=True).encode() + b'\n' for e in entries)
        self.log.write_bytes(text)
        doc = {'schema': F.STATUS_SCHEMA_V3, 'network': 'n', 'finalized_settlements_count': count,
               'finalized_settlements_recent': entries[-64:],
               'settlement_log': {'file': self.log.name, 'entries': count, 'bytes': len(text), 'digest': '00'}}
        doc.update(over)
        self.path.write_text(json.dumps(doc))
        return entries

    def test_v2_is_returned_as_it_is(self):
        doc = {'schema': F.STATUS_SCHEMA_V2, 'finalized_settlements': [entry(1)]}
        self.path.write_text(json.dumps(doc))
        self.assertEqual(F.load_status(self.path), doc)

    def test_v3_becomes_the_v2_shape(self):
        entries = self.write(100)
        doc = F.load_status(self.path)
        self.assertEqual(doc['schema'], F.STATUS_SCHEMA_V2)
        self.assertEqual(doc['finalized_settlements'], entries)
        for gone in ('settlement_log', 'finalized_settlements_recent', 'finalized_settlements_count'):
            self.assertNotIn(gone, doc)
        self.assertEqual(F.covering_settlement(doc, 50)['l2_number'], 50)

    def test_empty_log(self):
        self.write(0)
        self.log.unlink()
        self.assertEqual(F.load_status(self.path)['finalized_settlements'], [])

    def test_a_status_with_no_recent_entries_and_a_log_is_refused(self):
        self.write(3, finalized_settlements_recent=[])
        with self.assertRaises(F.NotFinal):
            F.load_status(self.path)

    def test_a_short_or_torn_log_is_refused(self):
        self.write(10)
        whole = self.log.read_bytes()
        self.log.write_bytes(whole[:-5])
        with self.assertRaises(F.NotFinal):
            F.load_status(self.path)

    def test_a_log_longer_than_the_status_names_is_read_up_to_the_status(self):
        entries = self.write(10)
        with open(self.log, 'ab') as f:
            f.write(b'{"torn')
        self.assertEqual(F.load_status(self.path)['finalized_settlements'], entries)

    def test_a_log_with_another_tip_is_refused(self):
        self.write(10)
        doc = json.loads(self.path.read_text())
        doc['finalized_settlements_recent'][-1]['l2_hash'] = 'ee' * 32
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(F.NotFinal):
            F.load_status(self.path)

    def test_a_log_name_outside_the_folder_is_refused(self):
        self.write(1, settlement_log={'file': '../x', 'entries': 1, 'bytes': 1, 'digest': ''})
        with self.assertRaises(F.NotFinal):
            F.load_status(self.path)

    def test_a_missing_log_is_an_unreadable_status(self):
        self.write(1)
        self.log.unlink()
        with self.assertRaises(OSError):
            F.load_status(self.path)

    def test_check_status_still_refuses_a_v3_document_that_was_not_loaded(self):
        with self.assertRaises(F.NotFinal):
            F.check_status({'schema': F.STATUS_SCHEMA_V3}, {}, 0, 0)


if __name__ == '__main__':
    unittest.main()
