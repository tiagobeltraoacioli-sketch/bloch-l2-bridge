"""Round 18 (agent 370): review 342's TRON fixes that have no test elsewhere.

  Prices        R342-TRX-4: the TRX price at the creation is two fresh readings from two sources that agree; the higher
                is used; a stale, single, mistyped, non-ASCII or far-moved price is refused; the node must be in sync.
  SharedStorage R342-TRX-2: an index directory on a network or FUSE filesystem is refused; the LOCK names pid and host.

Run: python3 -m unittest test_tron_r18   (standard library only)
"""
import os
import socket
import tempfile
import unittest

import tron_deploy as d
import tron_log_index as li

NOW = 1_794_891_000
BASIS = 305_400


def refused(f, *args):
    try:
        f(*args)
    except d.Refuse as e:
        return str(e)
    return ''


class Prices(unittest.TestCase):
    def test_two_fresh_agreeing_sources_give_the_higher_price(self):
        price, rec = d.prices_now([f'binance=0.3057@{NOW - 60}', f'coingecko=0.3055@{NOW - 300}'], BASIS, NOW)
        self.assertEqual(price, 305_700)
        self.assertEqual(([r['source'] for r in rec['readings']], rec['used'], rec['basis']), (['binance', 'coingecko'], 305_700, BASIS))

    def test_one_source_twice_a_single_reading_or_a_plain_price_is_refused(self):
        self.assertIn('two different sources', refused(d.prices_now, [f'binance=0.3057@{NOW}'], BASIS, NOW))
        self.assertIn('twice', refused(d.prices_now, [f'binance=0.3057@{NOW}', f'binance=0.3056@{NOW}'], BASIS, NOW))
        self.assertIn('SOURCE=PRICE@UNIX_SECONDS', refused(d.prices_now, ['0.3057', '0.3056'], BASIS, NOW))
        self.assertIn('SOURCE=PRICE@UNIX_SECONDS', refused(d.prices_now, ['--help=0.3@1', f'b=0.3@{NOW}'], BASIS, NOW))

    def test_stale_or_future_readings_are_refused(self):
        self.assertIn('at most 900 s old', refused(d.prices_now, [f'a=0.3057@{NOW - 901}', f'b=0.3057@{NOW}'], BASIS, NOW))
        self.assertIn('never in the future', refused(d.prices_now, [f'a=0.3057@{NOW + 61}', f'b=0.3057@{NOW}'], BASIS, NOW))

    def test_sources_that_disagree_or_a_price_far_from_the_basis_are_refused(self):
        self.assertIn('disagree', refused(d.prices_now, [f'a=0.3000@{NOW}', f'b=0.3070@{NOW}'], BASIS, NOW))   # 2.3%
        self.assertEqual(d.prices_now([f'a=0.3000@{NOW}', f'b=0.3060@{NOW}'], BASIS, NOW)[0], 306_000)          # 2.0%
        # the reviewer's mistyped price: 0.03054 (a tenth) in both readings
        self.assertIn('from the recorded basis', refused(d.prices_now, [f'a=0.03054@{NOW}', f'b=0.03054@{NOW}'], BASIS, NOW))
        self.assertIn('from the recorded basis', refused(d.prices_now, [f'a=0.45@{NOW}', f'b=0.45@{NOW}'], BASIS, NOW))
        price, rec = d.prices_now([f'a=0.45@{NOW}', f'b=0.45@{NOW}'], BASIS, NOW, True)                       # accepted on purpose
        self.assertEqual((price, rec['movedFromBasisBps']), (450_000, 4734))

    def test_prices_are_ascii_digits_and_above_zero(self):
        for bad in ('٣', '0.٣', '0.000000', '0', '1.', '.5', '1e3', '-1', None):
            self.assertNotEqual(refused(d.price_micro, bad), '', bad)
        self.assertEqual(d.price_micro('0.000001'), 1)
        self.assertNotEqual(refused(d.prices_now, [f'a=0.3057@{NOW}', f'b=0.3057@١٧٩٤٨٩١٠٠٠'], BASIS, NOW), '')

    def test_a_node_whose_head_is_old_is_refused(self):
        class Node:
            def __init__(self, age):
                self.age = age

            def head(self):
                return {'number': 7, 'timestamp_ms': (NOW - self.age) * 1000}
        self.assertEqual(d.node_in_sync(Node(5), NOW)['number'], 7)
        self.assertIn('not in sync', refused(d.node_in_sync, Node(61), NOW))


class SharedStorage(unittest.TestCase):
    MOUNTS = ('/dev/vda1 / ext4 rw 0 0\n'
              'srv:/export /mnt/idx nfs4 rw,local_lock=flock 0 0\n'
              'sshfs#u@h: /mnt/fuse fuse.sshfs rw 0 0\n'
              '/dev/vdb1 /mnt/idx/local xfs rw 0 0\n')

    def test_the_longest_mount_point_decides(self):
        self.assertEqual(li.filesystem_type('/home/ubuntu/x', self.MOUNTS), 'ext4')
        self.assertEqual(li.filesystem_type('/mnt/idx/a', self.MOUNTS), 'nfs4')
        self.assertEqual(li.filesystem_type('/mnt/idx/local/a', self.MOUNTS), 'xfs')
        self.assertEqual(li.filesystem_type('/mnt/idxx', self.MOUNTS), 'ext4')     # a prefix of a name is not a mount

    def test_network_and_fuse_directories_are_refused_local_ones_are_not(self):
        for path in ('/mnt/idx/a', '/mnt/fuse/a'):
            with self.assertRaises(SystemExit) as e:
                li.refuse_shared_storage(path, self.MOUNTS)
            self.assertIn('local disk only', str(e.exception))
        self.assertEqual(li.refuse_shared_storage('/mnt/idx/local/a', self.MOUNTS), 'xfs')

    def test_the_lock_names_the_pid_and_the_host(self):
        with tempfile.TemporaryDirectory() as t:
            key = li.lock_directory(t)
            try:
                self.assertEqual(open(os.path.join(t, 'LOCK')).read().strip(), f'pid {os.getpid()} host {socket.gethostname()}')
            finally:
                li.unlock_directory(key)


if __name__ == '__main__':
    unittest.main()
