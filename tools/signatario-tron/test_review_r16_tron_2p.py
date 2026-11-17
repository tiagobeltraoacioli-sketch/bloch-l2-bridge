"""Reviewer 325 (round 16), second pass on the TRON tools at 639abb9.
Run: python3 -m unittest test_review_r16_tron_2p -v   (in tools/signatario-tron)."""
import collections
import tempfile
import unittest

import tron_log_index as li

VAULT = '0x' + '11' * 20
ROUTE = '22' * 32


class Chain:
    """A solidified TRON chain of `height` blocks; the vault's deposits sit in the blocks named in `deposits`."""

    def __init__(self, height, deposits=()):
        self.height, self.deposits = height, sorted(deposits)
        self.requests = collections.Counter()

    def _block(self, n):
        return {'number': n, 'id': f'{n:016x}' + 'ab' * 24, 'timestamp_ms': 3000 * n, 'parent': '00' * 32}

    def solidified(self):
        self.requests['getnowblock'] += 1
        return self._block(self.height)

    def block(self, n, solid=False):
        self.requests['getblockbynum'] += 1
        return self._block(n) if n <= self.height else None

    def block_infos(self, n, solid=False):
        self.requests['gettransactioninfobyblocknum'] += 1
        if n not in self.deposits:
            return []
        nonce = self.deposits.index(n)
        data = f'{nonce:064x}' + '00' * 12 + '33' * 20 + f'{5_000_000:064x}' + '00' * 12 + '44' * 20
        return [{'id': f'{n:064x}', 'blockNumber': n, 'receipt': {'result': 'SUCCESS'},
                 'log': [{'address': VAULT[2:], 'topics': [li.DEPOSITED[2:], f'{nonce:016x}' + 'cd' * 24, ROUTE], 'data': data}]}]

    def tx_info(self, tx, solid=False):
        self.requests['gettransactioninfobyid'] += 1
        n = int(tx, 16)
        return self.block_infos(n)[0] if n in self.deposits else None

    def call(self, contract, data, solid=False, sender=None):
        self.requests['triggerconstantcontract'] += 1
        if data[2:10] == li.SEL_DEPOSIT_COUNT:
            return '0x' + f'{sum(1 for d in self.deposits if d <= self.height):064x}'
        return '0x' + f'{1:064x}'  # depositMatches


def index(chain, directory):
    return li.LogIndex(chain, VAULT, 1, directory, 728126428, workers=1, grace_s=0)


class ReviewR16Tron2P(unittest.TestCase):
    def test_trx1_restated_history_is_read_once_and_queries_cost_nothing(self):
        """R325-TRX-1, restated for the indexed shim. First pass: every attestation re-read the vault's whole history
        (57,605 node requests for a one-day-old vault, each time). Now: the history is read once, one request per
        block, and a query is answered from memory."""
        chain = Chain(28_800, deposits=[100, 20_000])
        with tempfile.TemporaryDirectory() as d:
            idx = index(chain, d)
            while idx.verified < chain.height:
                idx.advance(4000)
            catch_up = sum(chain.requests.values())
            before = sum(chain.requests.values())
            found = idx.query(1, chain.height, [li.DEPOSITED, '0x' + f'{1:016x}' + 'cd' * 24])
            per_query = sum(chain.requests.values()) - before
            print(f'\ncatch-up of one day: {catch_up} node requests, once; one query: {per_query}')
            self.assertEqual(len(found), 1)
            self.assertEqual(per_query, 0)
            self.assertLess(catch_up, 28_800 * 1.1)

    def test_trx2p1_two_shims_on_one_index_directory_do_not_corrupt_it(self):
        """R325-TRX-2P-1. The index directory has no lock. Two shims started on the same directory (a restart that
        overlaps the old process, a copied unit file) append to the same file, each with its own cursor. After the next
        restart the index holds one deposit twice and lacks another, while it still calls itself verified."""
        chain = Chain(60, deposits=[10, 40])
        with tempfile.TemporaryDirectory() as d:
            a, b = index(chain, d), index(chain, d)     # both start from the same (empty) directory
            chain.height = 20
            a.advance(4000)                             # A indexes deposit 0
            chain.height = 60
            b.advance(4000)                             # B, unaware, indexes deposits 0 and 1 into the same file
            c = index(chain, d)                         # the next restart
            c.advance(4000)
            nonces = [int(l['data'][2:66], 16) for l in c.logs if l['topics'][:1] == [li.DEPOSITED]]
            self.assertEqual((nonces, c.verified), ([0, 1], 60),
                             f'after the restart the index holds deposits {nonces}, counts {c.deposits} and is "verified" to {c.verified}')


if __name__ == '__main__':
    unittest.main()
