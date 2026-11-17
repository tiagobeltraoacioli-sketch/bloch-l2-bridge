#!/usr/bin/env python3
"""Integration of the bridge lines (agent 355, round 17): one deploy tool for every route.

  python3 tools/deploy-pontes/test_routes.py

What the single lines could not test: deploy_pontes.py, as merged from the Ethereum freeze, the shared-tools fix, the
EVM networks, Stellar and the data rule for TRON, validates the committed token config of EVERY route it deploys
natively (filled with throwaway values), keeps one token per source chain, and opens no chain by a flag or a file.
"""
import contextlib
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import deploy_pontes  # noqa: E402
import launch_fixture as fx  # noqa: E402
import routes  # noqa: E402

NATIVE_ETH_SECTION = ('ethereum', 'arbitrum-one', 'op-mainnet', 'linea', 'tron')


def filled(net):
    """The committed token config of a route whose config has an `ethereum` section, with throwaway values."""
    cfg = json.loads((ROOT / routes.ROUTES[net]['config']).read_text())
    cfg['source']['revision'] = '1' * 40
    cfg['deployer']['address'] = fx.fresh(1)
    cfg['deployer']['fundedBy']['safe'] = fx.fresh(2)
    cfg['signers']['set'] = [{'operator': f'op{i}', 'address': fx.fresh(10 + i)} for i in range(7)]
    cfg['guardians']['set'] = [{'operator': f'guard{i}', 'address': fx.fresh(20 + i)} for i in range(3)]
    eth = cfg['ethereum']
    eth.update(vault=fx.fresh(30), route='0x' + '7e' * 32, vaultCodeHash='0x' + 'c0' * 32, vaultCap=cfg['limits']['supplyCap'])
    eth['vaultGuard']['guardians'] = sorted((fx.fresh(40 + i) for i in range(3)), key=lambda a: int(a, 16))
    cfg['tx']['maxGasPriceWei'] = 10**9
    return cfg


def verdict(cfg, rehearsal=False):
    try:
        deploy_pontes.validate(copy.deepcopy(cfg), rehearsal)
        return None
    except deploy_pontes.Refused as e:
        return str(e)


@contextlib.contextmanager
def tron_launchable():
    """deployments/ copied, with the TRON route's `launch` block set to launchable, for the ACCEPT path of the data
    rule. Since 12ec904 the committed TRON file says `held`, so the committed tree refuses TRON (asserted separately
    in test_the_committed_tron_route_is_held_and_refused); the accept path is exercised on this copy only."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        shutil.copytree(ROOT / 'deployments', tmp / 'deployments')
        path = tmp / 'deployments/tron/bridge.network.json'
        doc = json.loads(path.read_text())
        doc['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'test copy: the accept path of the data rule'}
        path.write_text(json.dumps(doc))
        real = routes.DEPLOYMENTS, routes.ROOT
        routes.DEPLOYMENTS, routes.ROOT = tmp / 'deployments', tmp
        try:
            yield tmp
        finally:
            routes.DEPLOYMENTS, routes.ROOT = real


class OneTool(unittest.TestCase):
    def test_every_native_route_config_validates(self):
        with tron_launchable():
            for net in NATIVE_ETH_SECTION:
                with self.subTest(net):
                    self.assertIsNone(verdict(filled(net)))

    def test_the_committed_tron_route_is_held_and_refused(self):
        """Round 18: 370's launch block (12ec904) says held; the deploy tool must then refuse the TRON token, by the
        data rule, with the route's own reason."""
        doc = json.loads((ROOT / 'deployments/tron/bridge.network.json').read_text())
        self.assertIs(doc['launch']['v1'], False)
        why = verdict(filled('tron'))
        self.assertIsNotNone(why)
        self.assertIn('not launchable in v1', why)
        self.assertIn('deployments/tron/bridge.network.json', why)

    def test_the_table_names_every_route_directory_and_nothing_else(self):
        rows, extra = routes.table()
        self.assertEqual(extra, [])
        self.assertEqual(sorted(r['network'] for r in rows),
                         sorted(['ethereum'] + [p.parent.name for p in (ROOT / 'deployments').glob('*/bridge.network.json')
                                                if p.parent.name != 'ethereum']))
        for r in rows:
            if r['path'] != 'refused':
                self.assertTrue((ROOT / r['tool']).is_file(), r)
                self.assertTrue((ROOT / r['config']).is_file(), r)
                self.assertTrue((ROOT / r['document']).is_file(), r)

    def test_l2_symbols_are_distinct_and_one_per_source_chain(self):
        rows, _ = routes.table()
        symbols = [r['l2Symbol'] for r in rows]
        self.assertEqual(len(set(symbols)), len(symbols), symbols)
        chains = [str(filled(n)['ethereum']['chainId']) for n in NATIVE_ETH_SECTION]
        self.assertEqual(len(set(chains)), len(chains))

    def test_a_route_token_under_another_routes_chain_id_is_refused(self):
        """Every pair (config of route A, source chain id of route B) is refused: one token per source chain."""
        for a in NATIVE_ETH_SECTION:
            for b in NATIVE_ETH_SECTION:
                if a == b:
                    continue
                cfg = filled(a)
                cfg['ethereum']['chainId'] = filled(b)['ethereum']['chainId']
                with self.subTest(config=a, chain=b):
                    self.assertIsNotNone(verdict(cfg))

    def test_tron_is_accepted_only_under_its_own_token(self):
        with tron_launchable():
            self._tron_own_token()

    def _tron_own_token(self):
        cfg = filled('tron')
        self.assertEqual(cfg['ethereum']['chainId'], 728126428)
        self.assertIsNone(verdict(cfg))
        other = copy.deepcopy(cfg)
        other['token']['symbol'] = 'bUSDC'
        self.assertIn('one token per network', verdict(other))
        other = copy.deepcopy(cfg)
        other['token']['name'] = 'Bloch Bridged USDC'
        self.assertIn('one token per network', verdict(other))

    def test_an_unknown_source_chain_is_refused_and_names_what_was_looked_for(self):
        cfg = filled('tron')
        cfg['ethereum']['chainId'] = 728126429
        why = verdict(cfg)
        self.assertIn('ethereum.chainId must be 1', why)
        self.assertIn('no deployments/<network>/bridge.network.json has network.chainId "728126429"', why)

    def test_base_and_bnb_are_refused_whatever_the_config_and_the_route_command_says_why(self):
        for chain in (8453, 56):
            for net in NATIVE_ETH_SECTION:
                cfg = filled(net)
                cfg['ethereum']['chainId'] = chain
                for rehearsal in (False, True):
                    if rehearsal:
                        cfg = fx.rehearsal(cfg)
                    with self.subTest(chain=chain, config=net, rehearsal=rehearsal):
                        self.assertIn('not launchable in bridge v1', verdict(cfg, rehearsal))
        for net in ('base', 'bnb'):
            with self.assertRaises(deploy_pontes.Refused) as e:
                deploy_pontes.main(['route', net, 'validate'])
            self.assertIn('not launchable in v1', str(e.exception))

    def test_a_data_file_cannot_open_an_evm_network_or_a_route_that_says_it_is_not_launchable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            shutil.copytree(ROOT / 'deployments', tmp / 'deployments')
            real = routes.DEPLOYMENTS
            routes.DEPLOYMENTS = tmp / 'deployments'
            real_root, routes.ROOT = routes.ROOT, tmp
            try:
                # (1) an EVM network typed into a new directory, declared launchable by its own file
                doc = json.loads((tmp / 'deployments/op-mainnet/bridge.network.json').read_text())
                doc['network'].update(id='zora', chainId='7777777')
                (tmp / 'deployments/zora').mkdir()
                (tmp / 'deployments/zora/bridge.network.json').write_text(json.dumps(doc))
                self.assertIn('not opened by a data file', routes.source_refusal(7777777, doc['l2']['name'], doc['l2']['symbol']))
                # (2) the TRON route once its own file says it is held
                path = tmp / 'deployments/tron/bridge.network.json'
                tron = json.loads(path.read_text())
                # the committed file says held since 12ec904; start this copy from launchable to see the switch
                tron['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'test copy: the accept path of the data rule'}
                path.write_text(json.dumps(tron))
                self.assertIsNone(routes.source_refusal(728126428, tron['l2']['name'], tron['l2']['symbol']))
                tron['launch'] = {'v1': False, 'state': 'held', 'reason': 'a reason of at least twenty characters'}
                path.write_text(json.dumps(tron))
                self.assertIn('not launchable in v1', routes.source_refusal(728126428, tron['l2']['name'], tron['l2']['symbol']))
                # (3) a file that fails the schema check opens nothing
                del tron['launch']
                tron['surprise'] = 1
                path.write_text(json.dumps(tron))
                self.assertIn('fails the schema check', routes.source_refusal(728126428, tron['l2']['name'], tron['l2']['symbol']))
                # (4) two routes naming one chain id: refused
                del tron['surprise']
                path.write_text(json.dumps(tron))
                twin = copy.deepcopy(tron)
                twin['network']['id'] = 'tron2'
                (tmp / 'deployments/tron2').mkdir()
                (tmp / 'deployments/tron2/bridge.network.json').write_text(json.dumps(twin))
                self.assertIn('more than one route', routes.source_refusal(728126428, tron['l2']['name'], tron['l2']['symbol']))
            finally:
                routes.DEPLOYMENTS, routes.ROOT = real, real_root

    def test_the_ethereum_route_never_reaches_the_data_rule(self):
        called = []
        real = routes.source_refusal
        routes.source_refusal = lambda *a: called.append(a) or 'reached'
        try:
            for net in ('ethereum', 'arbitrum-one', 'op-mainnet', 'linea'):
                self.assertIsNone(verdict(filled(net)))
            self.assertEqual(called, [])
            self.assertIn('reached', verdict(filled('tron')))
        finally:
            routes.source_refusal = real

    def test_the_stellar_config_takes_its_own_path(self):
        cfg = json.loads((ROOT / routes.ROUTES['stellar']['config']).read_text())
        self.assertIn('stellar', cfg)
        self.assertNotIn('ethereum', cfg)
        self.assertTrue((HERE / 'source_stellar.py').is_file())


if __name__ == '__main__':
    unittest.main(verbosity=1)
