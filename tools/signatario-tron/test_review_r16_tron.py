"""Reviewer 325 (round 16): demonstrations against the TRON tools at 6b4a7fe. Each test states the needed property and
FAILS on the reviewed code. Run: python3 -m unittest test_review_r16_tron -v   (in tools/signatario-tron)."""
import unittest

import tron_rpc_shim
import tronlib

VAULT = '0x' + '11' * 20
DEPOSITED = '0x' + 'ab' * 32


class CountingNode:
    """A TRON node whose solidified chain is `height` blocks of other people's transactions; counts every request."""

    def __init__(self, height):
        self.height, self.requests = height, 0

    def _block(self, n):
        self.requests += 1
        return {'number': n, 'id': f'{n:016x}' + '00' * 24, 'timestamp_ms': 3000 * n, 'parent': '00' * 32}

    def block(self, n, solid=False):
        return self._block(n)

    def head(self):
        return self._block(self.height + 19)

    def solidified(self):
        return self._block(self.height)

    def block_infos(self, n, solid=False):
        self.requests += 1
        return []


class ReviewR16Tron(unittest.TestCase):
    def test_trx1_one_deposit_attestation_costs_a_bounded_number_of_node_requests(self):
        """R325-TRX-1. `eth_half.py deposit` (unchanged, tools/signatario-stable/eth_half.py:196-199) asks for the
        `Deposited` log of ONE deposit id over every block from `vault_from_block` to `finalized`, in `log_chunk`
        (default 10,000) block queries, each under a 60 s client timeout (eth_half.py:146). The shim answers each query
        with two node requests per block, whatever the address and topic filter. One day of TRON is 28,800 blocks."""
        node = CountingNode(height=28_800)                      # the vault is one day old
        shim = tron_rpc_shim.Shim.__new__(tron_rpc_shim.Shim)
        shim.node, shim.chain_id = node, 728126428
        requests_per_query = []
        for lo in range(0, node.height + 1, 10_000):            # eth_half.py's own loop, default log_chunk
            before = node.requests
            shim.get_logs({'address': VAULT, 'topics': [DEPOSITED, '0x' + 'cd' * 32], 'fromBlock': hex(lo),
                           'toBlock': hex(min(lo + 9_999, node.height))})
            requests_per_query.append(node.requests - before)
        total = sum(requests_per_query)
        # A mainnet block answers these two requests with about 240 KB + 85 KB of JSON (read on 2026-11-17, block
        # 88,063,136, 229 transactions). 20,000 requests inside one 60 s timeout is 3 ms each, parse included.
        self.assertLessEqual(max(requests_per_query), 200,
                             f'one eth_getLogs query made {max(requests_per_query)} node requests; one attestation of a '
                             f'one-day-old vault made {total}')

    def test_trx4_the_tools_refuse_a_node_that_is_not_the_operators_own(self):
        """R325-TRX-4. Every signer safety property rests on `/walletsolidity/*` of the operator's OWN node. The
        Bitcoin tools refuse a non-loopback endpoint; here a remote plain-http gateway is accepted silently."""
        with self.assertRaises(tronlib.TronError):
            tronlib.Node('http://203.0.113.7:8090')


if __name__ == '__main__':
    unittest.main()
