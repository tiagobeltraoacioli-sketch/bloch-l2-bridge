"""Several routes on one network (round 20, agent 411): what the registry must accept and what it must still refuse.

  python3 -m unittest test_registry_multi        (from tools/allnets; offline)

Coordinator decisions of 2026-11-19: a further route has the id `<network>-<asset>` and lives in
`deployments/<route-id>/bridge.network.json` with the SAME `network.id` and chain id as the network's first route and
another asset. The registry accepts that and nothing weaker: it refuses two routes with one (network, asset) pair, two
routes that share a custody address, two L2 tokens with one symbol, and an asset address listed under two routes; and
it keeps refusing what it refused before (two NETWORKS with one chain id or one source-domain label, a foreign fee
recipient, another token, a weaker committee). Every refusal is shown on a tree mutated to break exactly that rule.
The identities of the routes that existed before round 20 are pinned here field by field: none may move.
"""
import copy
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import registry  # noqa: E402

NEW = {'ethereum-usdt': ('ethereum', '1', 'bUSDT', 'Bloch Bridged USDT'),
       'arbitrum-one-usdt': ('arbitrum-one', '42161', 'bUSDT.arb', 'Bloch Bridged USDT (Arbitrum)'),
       'op-mainnet-usdt': ('op-mainnet', '10', 'bUSDT.op', 'Bloch Bridged USDT (OP Mainnet)')}
TOKEN = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
FROZEN_VAULT = 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault'
# route id -> (network id, kind, source chain id, asset symbol, asset id, L2 symbol, L2 name, source domain, custody contract)
# as bloch-l2-bridge `main` 135bdba generated them. Decision 1: none of these may move.
BEFORE = {
    'ethereum': ('ethereum', 'evm', '1', 'USDC', '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'bUSDC', 'Bloch Bridged USDC',
                 'ethereum-mainnet', FROZEN_VAULT),
    'arbitrum-one': ('arbitrum-one', 'evm', '42161', 'USDC', '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', 'bUSDC.arb',
                     'Bloch Bridged USDC (Arbitrum)', 'arbitrum-one', FROZEN_VAULT),
    'op-mainnet': ('op-mainnet', 'evm', '10', 'USDC', '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', 'bUSDC.op',
                   'Bloch Bridged USDC (OP Mainnet)', 'op-mainnet', FROZEN_VAULT),
    'linea': ('linea', 'evm', '59144', 'USDC', '0x176211869cA2b568f2A7D4EE941E073a821EE1ff', 'bUSDC.linea',
              'Bloch Bridged USDC (Linea)', 'linea-mainnet', FROZEN_VAULT),
    'tron': ('tron', 'tvm', '728126428', 'USDT', 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', 'bUSDT.trx', 'Bloch Bridged USDT (Tron)',
             'tron-mainnet', 'contracts/tron/TronSourceVault.sol:TronSourceVault'),
}
BEFORE_IDS = ['ethereum', 'arbitrum-one', 'base', 'bitcoin', 'bnb', 'linea', 'op-mainnet', 'solana', 'stellar', 'tron']


class MultiRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg, cls.errors = registry.build()
        cls.routes = {r['id']: {k: v for k, v in r.items() if k != 'id'} for r in cls.reg['routes']}
        cls.findings = json.loads(registry.FINDINGS.read_text())['findings']

    def mutated(self, fn):
        out = copy.deepcopy(self.routes)
        fn(out)
        return registry.cross_checks(out, self.findings)

    def refused(self, code, fn):
        errs = self.mutated(fn)
        self.assertTrue(any(e.startswith(code) for e in errs), errs)
        return errs

    # ── accepted ─────────────────────────────────────────────────────────────
    def test_the_tree_with_three_further_routes_passes_every_check(self):
        self.assertEqual(self.errors, [])
        self.assertEqual(sorted(self.routes), sorted(BEFORE_IDS + list(NEW)))

    def test_a_further_route_shares_its_network_s_id_and_chain_id_and_nothing_else(self):
        for rid, (net, chain, symbol, name) in NEW.items():
            r, first = self.routes[rid], self.routes[net]
            with self.subTest(route=rid):
                self.assertEqual((r['network']['id'], r['sourceChainId']), (net, chain))
                self.assertEqual(r['network'], first['network'] if net != 'ethereum' else r['network'])
                self.assertEqual(r['sourceDomain'], first['sourceDomain'])
                self.assertEqual((r['l2']['symbol'], r['l2']['name']), (symbol, name))
                self.assertEqual(r['route'], {'id': rid, 'asset': 'usdt'})
                self.assertNotEqual(r['asset']['id'].lower(), first['asset']['id'].lower())
                self.assertNotEqual(r['l2']['symbol'], first['l2']['symbol'])
                self.assertEqual(r['l2']['creationCodeKeccak'], TOKEN)
                self.assertEqual(r['sources'], [f'deployments/{rid}/bridge.network.json'])

    def test_every_further_route_is_held_and_cannot_be_offered(self):
        for rid in NEW:
            l = self.routes[rid]['launch']
            with self.subTest(route=rid):
                self.assertEqual((l['v1'], l['state'], l['sourceState'], l['source']), (False, 'held', 'held', 'asset-route-registry'))
                self.assertIn('independent review, external audit and the owner\'s key ceremony are pending', l['reason'])

    def test_fees_follow_the_usdc_route_of_the_network_and_limits_the_rule_of_2026_11_19(self):
        want = {'ethereum-usdt': (5, 10, '101000000', '100000000', '500000000000', '50000000000'),
                'arbitrum-one-usdt': (5, 5, '21000000', '20000000', '250000000000', '25000000000'),
                'op-mainnet-usdt': (5, 5, '21000000', '20000000', '250000000000', '25000000000')}
        for rid, (dep, rel, mind, minb, cap, window) in want.items():
            r, first = self.routes[rid], self.routes[NEW[rid][0]]
            with self.subTest(route=rid):
                self.assertEqual((r['fee']['depositBps'], r['fee']['releaseBps']), (dep, rel))
                self.assertEqual((r['fee']['depositBps'], r['fee']['releaseBps'], r['limits']['minDeposit'], r['limits']['l2MinBurn']),
                                 (first['fee']['depositBps'], first['fee']['releaseBps'], first['limits']['minDeposit'], first['limits']['l2MinBurn']))
                self.assertEqual((r['limits']['minDeposit'], r['limits']['l2MinBurn'], r['limits']['cap'], r['limits']['window'],
                                  r['limits']['windowSeconds']), (mind, minb, cap, window, 86400))
                self.assertEqual(r['fee']['recipient'], '0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544')
                self.assertEqual(r['committee'], first['committee'])

    def test_linea_base_and_bnb_have_no_usdt_route(self):
        for rid in ('linea-usdt', 'base-usdt', 'bnb-usdt'):
            self.assertNotIn(rid, self.routes)
            self.assertFalse((registry.ROOT / 'deployments' / rid).exists())

    # ── the identities that existed before round 20 ─────────────────────────────
    def test_no_identity_of_an_earlier_route_moved(self):
        for rid, want in BEFORE.items():
            r = self.routes[rid]
            got = (r['network']['id'], r['network']['kind'], r['sourceChainId'], r['asset']['symbol'], r['asset']['id'], r['l2']['symbol'],
                   r['l2']['name'], r['sourceDomain'], r['custody']['contract'])
            with self.subTest(route=rid):
                self.assertEqual(got, want)
                self.assertNotIn('route', r)
        self.assertEqual(self.reg['tokenCreationCodeKeccak'], TOKEN)
        self.assertEqual([r['id'] for r in self.reg['routes'] if r['id'] not in NEW], BEFORE_IDS)
        for rid in BEFORE_IDS:
            self.assertEqual(self.routes[rid]['l2'].get('creationCodeKeccak'), TOKEN, rid)

    def test_no_file_of_an_earlier_route_names_a_route_block(self):
        for rid in BEFORE_IDS[1:]:
            doc = json.loads((registry.ROOT / 'deployments' / rid / 'bridge.network.json').read_text())
            self.assertNotIn('route', doc, rid)
            self.assertEqual(doc['network']['id'], rid)

    # ── still refused, or refused anew ───────────────────────────────────────
    def test_two_routes_with_the_same_network_and_asset_are_refused(self):
        def same_pair(o):
            o['arbitrum-one-usdt']['route']['asset'] = 'usdc'
            o['arbitrum-one-usdt']['asset']['symbol'] = 'USDC'
        errs = self.refused('C10', same_pair)
        self.assertTrue(any('arbitrum-one' in e and 'usdc' in e for e in errs), errs)

    def test_the_asset_key_compare_ignores_case(self):
        self.refused('C10', lambda o: o['op-mainnet-usdt']['route'].__setitem__('asset', 'USDC'))

    def test_an_asset_address_listed_under_two_routes_is_refused(self):
        def same_asset(o):
            o['op-mainnet-usdt']['asset']['id'] = o['op-mainnet']['asset']['id'].lower()
        errs = self.refused('C10', same_asset)
        self.assertTrue(any('asset address' in e for e in errs), errs)

    def test_two_routes_sharing_a_custody_address_are_refused(self):
        vault = '0x' + '5a' * 20

        def shared(o):
            o['ethereum']['custody']['address'] = vault
            o['ethereum-usdt']['custody']['address'] = vault.upper().replace('0X', '0x')
        errs = self.refused('C9', shared)
        self.assertTrue(any('custody address' in e for e in errs), errs)

    def test_a_custody_address_shared_across_networks_is_refused_too(self):
        vault = '0x' + '5b' * 20

        def shared(o):
            o['linea']['custody']['address'] = vault
            o['op-mainnet-usdt']['custody']['address'] = vault
        self.refused('C9', shared)

    def test_undecided_custody_addresses_do_not_collide(self):
        self.assertEqual({r['custody']['address'] for r in self.routes.values()}, {'TBD-deploy'})
        self.assertEqual(self.mutated(lambda o: None), [])

    def test_two_l2_tokens_with_the_same_symbol_are_refused(self):
        self.refused('C2 L2 symbol', lambda o: o['arbitrum-one-usdt']['l2'].__setitem__('symbol', 'bUSDC.arb'))
        self.refused('C2 L2 symbol', lambda o: o['ethereum-usdt']['l2'].__setitem__('symbol', 'busdt.TRX'))
        self.refused('C2 L2 name', lambda o: o['op-mainnet-usdt']['l2'].__setitem__('name', 'Bloch Bridged USDC (OP Mainnet)'))

    def test_two_l2_tokens_at_one_address_are_refused(self):
        token = '0x' + '70' * 20

        def shared(o):
            o['ethereum']['l2']['token'] = token
            o['ethereum-usdt']['l2']['token'] = token
        errs = self.refused('C9', shared)
        self.assertTrue(any('L2 token address' in e for e in errs), errs)

    def test_two_networks_with_one_chain_id_are_still_refused(self):
        # the round-18 check C3, unchanged in strength: another NETWORK may not take a chain id
        self.refused('C3', lambda o: o['linea'].__setitem__('sourceChainId', '42161'))
        self.refused('C3', lambda o: o['linea'].__setitem__('sourceChainId', '1'))

    def test_a_further_route_under_another_network_s_chain_id_is_refused(self):
        self.refused('C3', lambda o: o['op-mainnet-usdt'].__setitem__('sourceChainId', '42161'))

    def test_one_network_with_two_chain_ids_is_refused(self):
        self.refused('C3', lambda o: o['arbitrum-one-usdt'].__setitem__('sourceChainId', '421614'))

    def test_two_networks_with_one_source_domain_label_are_still_refused(self):
        self.refused('C4', lambda o: o['tron'].__setitem__('sourceDomain', 'ethereum-mainnet'))
        self.refused('C4', lambda o: o['linea'].__setitem__('sourceDomain', 'op-mainnet'))

    def test_routes_of_one_network_with_two_labels_are_refused(self):
        self.refused('C4', lambda o: o['ethereum-usdt'].__setitem__('sourceDomain', 'ethereum-mainnet-usdt'))

    def test_a_route_id_that_is_not_network_and_asset_is_refused(self):
        def renamed(o):
            o['ethereum-tether'] = o.pop('ethereum-usdt')
        self.refused('C1', renamed)

    def test_a_further_route_without_a_first_route_of_its_network_is_refused(self):
        def orphan(o):
            o['op-mainnet-usdt']['network']['id'] = 'optimism'
            o['optimism-usdt'] = o.pop('op-mainnet-usdt')
            o['optimism-usdt']['route']['id'] = 'optimism-usdt'
            o['optimism-usdt']['sourceChainId'] = '11'
            o['optimism-usdt']['sourceDomain'] = 'optimism'
        self.refused('C1', orphan)

    def test_a_further_route_of_a_kind_other_than_its_network_s_is_refused(self):
        self.refused('C1', lambda o: o['ethereum-usdt']['network'].__setitem__('kind', 'tvm'))

    def test_the_other_checks_cover_the_further_routes(self):
        self.refused('C5 ethereum-usdt', lambda o: o['ethereum-usdt']['l2'].__setitem__('creationCodeKeccak', '0x' + '11' * 32))
        self.refused('C6 arbitrum-one-usdt', lambda o: o['arbitrum-one-usdt']['fee'].__setitem__('recipient', '0x' + '22' * 20))
        self.refused('C7 op-mainnet-usdt', lambda o: o['op-mainnet-usdt']['committee'].__setitem__('threshold', 4))

    def test_a_finding_can_name_a_further_route_and_never_raises_it(self):
        bad = self.findings + [{'id': 'X', 'routes': ['ethereum-usdt'], 'severity': 'Medium', 'state': 'open', 'owner': 0}]
        self.assertEqual(registry.cross_checks(copy.deepcopy(self.routes), bad), [])
        for rid in NEW:
            self.assertFalse(self.routes[rid]['launch']['v1'])

    def test_the_readme_table_has_a_row_per_route(self):
        table = registry.readme_table(self.reg)
        for rid, (_, _, symbol, _) in NEW.items():
            self.assertIn(f'| {rid} | {symbol} | held |', table)


if __name__ == '__main__':
    unittest.main()
