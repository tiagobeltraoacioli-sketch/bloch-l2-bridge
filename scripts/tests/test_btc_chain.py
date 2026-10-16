"""Synthetic trusted-node responses exercise consistency, not Bitcoin consensus."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from btc_observer.chain import assess_deposit, CHAINS, SIGNET_CHALLENGE
from btc_observer.transaction import Invalid, decode
from test_btc_proof import fixture
from test_btc_transaction import SCRIPT


class Node:
    def __init__(self, network='bitcoin-regtest'):
        self.raw, self.proof = fixture()
        self.block_hash = self.proof.pop('expected_block_hash')
        self.deposit = dict(raw=self.raw, network=network, expected_txid=decode(self.raw).txid,
                            vout=0, script_pubkey=SCRIPT)
        self.info = dict(chain=CHAINS[network][0], blocks=105, headers=105, bestblockhash='ab' * 32,
                         initialblockdownload=False, warnings=[], chainwork='00' * 31 + 'ff')
        if network == 'bitcoin-signet':
            self.info['signet_challenge'] = SIGNET_CHALLENGE
        self.metadata = dict(hash=self.block_hash, height=100, confirmations=6,
                             nTx=self.proof['tx_count'], merkleroot=self.proof['header'][36:68][::-1].hex())
        self.genesis = CHAINS[network][1]
        self.header = self.proof['header'].hex()
        self.active = self.block_hash
        self.tip_active = self.info['bestblockhash']
        self.calls = []
        self.after = None

    def __call__(self, method, params):
        self.calls.append((method, params))
        if method == 'getblockchaininfo':
            return copy.deepcopy(self.after if len(self.calls) > 1 and self.after is not None else self.info)
        if method == 'getblockhash':
            return self.genesis if params == [0] else self.tip_active if params == [self.info['blocks']] else self.active
        if method == 'getblockheader':
            return copy.deepcopy(self.metadata) if params[1] else self.header
        raise AssertionError('Unexpected RPC method')

    def assess(self, confirmations=6):
        return assess_deposit(self, self.deposit, self.proof,
                              expected_block_hash=self.block_hash, min_confirmations=confirmations)


class BitcoinChainTest(unittest.TestCase):
    def test_all_networks_match_genesis_and_explicit_policy(self):
        for network in CHAINS:
            node = Node(network)
            result = node.assess()
            self.assertTrue(result['chain']['confirmation_policy_met'])
            self.assertTrue(result['chain']['node_active_chain_observed'])
            self.assertEqual(result['chain']['confirmations'], 6)
            self.assertEqual(result['outpoint_key'], network + ':' + decode(node.raw).txid + ':0')
            self.assertEqual([method for method, _ in node.calls], [
                'getblockchaininfo', 'getblockhash', 'getblockhash', 'getblockheader',
                'getblockheader', 'getblockhash', 'getblockchaininfo', 'getblockhash'])
            for section in (result, result['proof'], result['chain']):
                for flag in ('inclusion_verified', 'finality_verified', 'custody_verified',
                             'mint_authorized', 'bridge_ready'):
                    self.assertIs(section[flag], False)

    def test_below_threshold_is_observed_without_authorization(self):
        node = Node()
        self.assertFalse(node.assess(7)['chain']['confirmation_policy_met'])
        self.assertTrue(Node().assess(1)['chain']['confirmation_policy_met'])

    def test_wrong_network_genesis_and_custom_signet_refused(self):
        for field, value in (('chain', 'main'), ('chain', 'test')):
            node = Node()
            node.info[field] = value
            with self.assertRaises(Invalid):
                node.assess()
        node = Node()
        node.genesis = 'ff' * 32
        with self.assertRaisesRegex(Invalid, 'genesis'):
            node.assess()
        for challenge in ('51', None):
            node = Node('bitcoin-signet')
            node.info['signet_challenge'] = challenge
            with self.assertRaisesRegex(Invalid, 'signet'):
                node.assess()

    def test_synchronizing_malformed_and_warning_nodes_refused(self):
        for key, value in (('blocks', True), ('blocks', -1), ('headers', 106), ('headers', 105.0),
                           ('initialblockdownload', True), ('initialblockdownload', 0),
                           ('warnings', ['warning']), ('warnings', None),
                           ('bestblockhash', 'ab'), ('chainwork', '00' * 32), ('chainwork', None)):
            node = Node()
            node.info[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Invalid):
                node.assess()

    def test_header_metadata_and_count_are_bound_to_proof(self):
        for key, value in (('hash', 'ff' * 32), ('height', 106), ('height', 0), ('height', True),
                           ('confirmations', -1), ('confirmations', 0), ('confirmations', 7),
                           ('confirmations', 6.0), ('nTx', 0), ('nTx', 4), ('nTx', True),
                           ('merkleroot', 'ff' * 32)):
            node = Node()
            node.metadata[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Invalid):
                node.assess()
        node = Node()
        node.header = '00' * 80
        with self.assertRaisesRegex(Invalid, 'header differs'):
            node.assess()

    def test_orphan_reorg_and_tip_extension_refused(self):
        node = Node()
        node.active = 'ff' * 32
        with self.assertRaisesRegex(Invalid, 'active chain'):
            node.assess()
        for changes in ({'bestblockhash': 'cd' * 32}, {'blocks': 106, 'headers': 106},
                        {'chainwork': '01' * 32}, {'initialblockdownload': True}):
            node = Node()
            node.after = dict(node.info, **changes)
            with self.subTest(changes=changes), self.assertRaises(Invalid):
                node.assess()

    def test_best_block_hash_is_pinned_to_active_height(self):
        node = Node()
        node.tip_active = 'ff' * 32
        with self.assertRaisesRegex(Invalid, 'Best block hash'):
            node.assess()
        self.assertEqual(node.calls, [('getblockchaininfo', []), ('getblockhash', [105])])

    def test_invalid_local_inputs_make_no_rpc_requests(self):
        for value in (0, -1, True, 1.0, 100001):
            node = Node()
            with self.assertRaises(Invalid):
                node.assess(value)
            self.assertEqual(node.calls, [])
        node = Node()
        node.deposit['script_pubkey'] = b'\x51'
        with self.assertRaises(Invalid):
            node.assess()
        self.assertEqual(node.calls, [])
        node = Node()
        node.proof['siblings'] = []
        with self.assertRaises(Invalid):
            node.assess()
        self.assertEqual(node.calls, [])

    def test_missing_fields_and_source_failures_never_return_success(self):
        for attribute in ('info', 'metadata'):
            for key in list(getattr(Node(), attribute)):
                node = Node()
                del getattr(node, attribute)[key]
                with self.subTest(attribute=attribute, key=key), self.assertRaises(Invalid):
                    node.assess()
        node = Node()
        def failed(*_):
            raise Invalid('Unavailable node')
        with self.assertRaises(Invalid):
            assess_deposit(failed, node.deposit, node.proof,
                           expected_block_hash=node.block_hash, min_confirmations=6)


if __name__ == '__main__':
    unittest.main()
