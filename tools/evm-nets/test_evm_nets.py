#!/usr/bin/env python3
"""Offline tests of the EVM-network tooling (no chain, no key): python3 -m unittest test_evm_nets  (in tools/evm-nets).

Needs `cast` only for the vault-config tests (FOUNDRY_BIN or ~/.foundry/bin); they are skipped without it.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tools/signatario-stable'))
sys.path.insert(0, str(ROOT / 'tools/deploy-pontes'))
import evm_anchor  # noqa: E402
import evm_nets  # noqa: E402
import network_json  # noqa: E402

REGISTRY = json.loads((HERE / 'networks.json').read_text())
NETS = REGISTRY['networks']
# Round 17: only launchable networks have deployment files (tools/evm-nets/launch.py; tests in test_launch_r17.py).
LIVE = {n: s for n, s in NETS.items() if s['launch']['v1']}
CAST = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin')) / 'cast'


def addr(label):
    return '0x' + hashlib.sha256(label.encode()).hexdigest()[:40]


class Registry(unittest.TestCase):
    def test_five_networks_distinct_ids_labels_and_symbols(self):
        self.assertEqual(sorted(NETS), ['arbitrum-one', 'base', 'bnb', 'linea', 'op-mainnet'])
        for field in (lambda s: s['chainId'], lambda s: s['sourceDomainLabel'], lambda s: s['l2']['symbol'],
                      lambda s: s['asset']['address'].lower()):
            self.assertEqual(len({field(s) for s in NETS.values()}), 5)
        self.assertNotIn(1, [s['chainId'] for s in NETS.values()])

    def test_l2_symbols_are_the_decided_names_and_fit_the_token_tool(self):
        want = {'arbitrum-one': 'bUSDC.arb', 'base': 'bUSDC.base', 'op-mainnet': 'bUSDC.op', 'linea': 'bUSDC.linea', 'bnb': 'bUSDC.bnb'}
        for name, spec in NETS.items():
            self.assertEqual(spec['l2']['symbol'], want[name])
            self.assertRegex(spec['l2']['symbol'], r'^[A-Za-z0-9.]{1,11}$')
            # One storage word: a longer name costs creation gas the L2's 5,000,000 limit has little room for.
            self.assertLessEqual(len(spec['l2']['name'].encode()), 31, name)

    def test_the_fee_recipient_is_the_owner_address_with_its_checksum(self):
        self.assertEqual(REGISTRY['feeRecipient'], '0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544')

    def test_signer_settings_fit_the_frozen_vault_window(self):
        for name, spec in NETS.items():
            s = spec['signer']
            self.assertNotIn('anchor_window', s, name)
            self.assertNotIn('vaultContract', spec, name)
            self.assertLess(s['anchor_max_age'], 256, name)
            self.assertIn(s['anchor_policy'], ('finalized', 'probe'), name)
            if s['anchor_policy'] == 'finalized':
                # The finalized block must sit inside the window the signer may use, in blocks.
                lag_blocks = spec['measured']['finalizedLagSeconds'] / spec['measured']['blockTimeSeconds']
                self.assertLess(lag_blocks, s['anchor_max_age'], name)
            else:
                self.assertLess(s['anchor_depth'], 16, name)


class SignerRules(unittest.TestCase):
    def test_probe_is_refused_on_ethereum_by_code(self):
        # R325-EVM-3. A stub node that only says "chain 1": eth_half.py must refuse before anything else.
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['content-length']))
                body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': '0x1'}).encode()
                self.send_response(200)
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            for policy, refused in (('probe', True), (None, False)):
                with tempfile.TemporaryDirectory() as tmp:
                    cfg = {'eth_rpc': f'http://127.0.0.1:{srv.server_port}', 'eth_chain_id': 1, 'vault': '0x' + '11' * 20,
                           'vault_code_keccak': '0x' + '22' * 32, 'keystore': 'k', 'password_file': 'p', 'db': str(Path(tmp) / 'db.json')}
                    if policy:
                        cfg['anchor_policy'] = policy
                    (Path(tmp) / 'c.json').write_text(json.dumps(cfg))
                    done = subprocess.run([sys.executable, str(ROOT / 'tools/signatario-stable/eth_half.py'), '--config',
                                           str(Path(tmp) / 'c.json'), 'release', '--intent', str(Path(tmp) / 'none.json')],
                                          capture_output=True, text=True)
                    self.assertEqual('probe is not allowed on Ethereum' in done.stdout, refused, done.stdout + done.stderr)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_every_network_sets_and_justifies_an_anchor_depth_and_uses_the_deposit_cursor(self):
        for name, spec in NETS.items():
            s = spec['signer']
            self.assertTrue(s.get('why'), name)
            self.assertIs(s.get('deposit_cursor'), True, name)
            if s['anchor_policy'] == 'probe':
                self.assertGreaterEqual(s['anchor_depth'], 2, name)
                # the depth must cost at most 5% of the 256-block window
                self.assertLessEqual(s['anchor_depth'], 12, name)

    def test_bnb_is_marked_not_in_v1_and_its_unit_token_is_unpinned(self):
        self.assertEqual((NETS['bnb']['launch']['v1'], NETS['bnb']['launch']['state']), (False, 'out'))
        self.assertNotIn('v1', NETS['bnb'])
        self.assertIsNone(NETS['bnb']['asset']['unit']['address'])
        doc = json.loads((ROOT / 'deployments/bnb/bridge.network.json').read_text())
        self.assertTrue(doc['notes'][0].startswith('NOT LAUNCHABLE IN V1 (out)'))
        self.assertEqual(doc['launch'], NETS['bnb']['launch'])
        self.assertTrue(any('unwrap' in n for n in doc['release']['notes']))


class OutsideValues(unittest.TestCase):
    def test_code_read_from_a_node_cannot_become_a_cast_option(self):
        # Agent 374's class (R332 / review 331 High): `cast keccak -h...` exits 0 with the help text. `verify-unit`
        # hashes the code a node returns; anything but 0x-hex is refused before `cast` runs (round 18, agent 372).
        for bad in ('-h' + 'a' * 130, '--help', '0x12zz', '', 'deadbeef', '0x' + 'ab' * 3 + ' --help'):
            with self.assertRaises(SystemExit, msg=bad) as e:
                evm_nets.keccak(bad)
            self.assertIn('not 0x-prefixed hex', str(e.exception))


class Generated(unittest.TestCase):
    def test_committed_files_are_what_the_generator_derives(self):
        files, absent = evm_nets.derive()
        for path, text in files.items():
            self.assertTrue(path.exists(), path)
            self.assertEqual(path.read_text(), text, f'{path} is stale: run evm_nets.py write')
        for path in absent:
            self.assertFalse(path.exists(), f'{path}: a network that is not launchable has no deployment file')

    def test_every_bridge_network_json_is_valid(self):
        for name in NETS:
            self.assertEqual(network_json.check(ROOT / 'deployments' / name / 'bridge.network.json'), [], name)

    def test_the_checker_refuses_wrong_files(self):
        good = json.loads((ROOT / 'deployments/op-mainnet/bridge.network.json').read_text())
        cases = {'a number as an amount': lambda d: d['limits'].__setitem__('cap', 100),
                 'an unknown top-level key': lambda d: d.__setitem__('extra', 1),
                 'a missing fee': lambda d: d.pop('fee'),
                 'another L2 chain': lambda d: d['l2'].__setitem__('chainId', 1),
                 'a symbol the token tool refuses': lambda d: d['l2'].__setitem__('symbol', 'bUSDC-op'),
                 'a fee paid elsewhere': lambda d: d['fee'].__setitem__('paidOn', 'l2')}
        for what, change in cases.items():
            doc = copy.deepcopy(good)
            change(doc)
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp) / 'op-mainnet'
                d.mkdir()
                (d / 'bridge.network.json').write_text(json.dumps(doc))
                self.assertTrue(network_json.check(d / 'bridge.network.json'), what)
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / 'elsewhere'
            d.mkdir()
            (d / 'bridge.network.json').write_text(json.dumps(good))
            self.assertTrue(network_json.check(d / 'bridge.network.json'), 'directory name')

    def test_optional_properties_added_for_other_bridges_are_accepted_and_typed(self):
        good = json.loads((ROOT / 'deployments/op-mainnet/bridge.network.json').read_text())
        for value, ok in ((1800, True), ('1800', False), (-1, False)):
            doc = copy.deepcopy(good)
            doc['limits']['releaseDelaySeconds'] = value
            doc['committee']['guardianCancelQuorum'] = 2
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp) / 'op-mainnet'
                d.mkdir()
                (d / 'bridge.network.json').write_text(json.dumps(doc))
                self.assertEqual(network_json.check(d / 'bridge.network.json') == [], ok, value)

    def test_every_config_keeps_the_ethereum_limits_fee_and_committee_shape(self):
        eth = json.loads((ROOT / 'deployments/mainnet/busdc-vault-mainnet.config.json').read_text())['vault']
        for name in LIVE:
            v = json.loads((ROOT / 'deployments' / name / 'busdc-vault.config.json').read_text())['vault']
            spec = NETS[name]
            for key in ('cap', 'transferMode'):
                self.assertEqual(v[key], eth[key], (name, key))
            # limits (window, switch) are the Ethereum ones; the minimums and the fee rates are the network's own
            # (fee schedule of 2026-11-17, tools/evm-nets/networks.json)
            for key in ('windowLimit', 'windowSeconds', 'switchThreshold', 'switchDelay'):
                self.assertEqual(v['policy'][key], eth['policy'][key], (name, key))
            self.assertEqual((v['policy']['minDeposit'], v['policy']['l2MinBurn']), (spec['minDeposit'], spec['l2MinBurn']), name)
            self.assertEqual({k: v['provenance'][k] for k in ('mode', 'releaseDelay', 'mintVerifier')},
                             {k: eth['provenance'][k] for k in ('mode', 'releaseDelay', 'mintVerifier')})
            self.assertEqual(v['signers']['threshold'], 5)
            self.assertEqual(len(v['signers']['set']), 7)
            self.assertEqual(len(v['guard']['guardians']), 3)
            self.assertEqual(v['provenance']['fees'], {'recipient': REGISTRY['feeRecipient'], 'depositBps': spec['feeBps']['deposit'],
                                                       'releaseBps': spec['feeBps']['release']})

    def test_no_generated_file_holds_a_decided_key_or_deployer(self):
        for name in LIVE:
            v = json.loads((ROOT / 'deployments' / name / 'busdc-vault.config.json').read_text())
            self.assertIsNone(v['deployer']['address'])
            self.assertTrue(all(s['address'] is None for s in v['vault']['signers']['set']))
            self.assertTrue(all(g['address'] is None for g in v['vault']['guard']['guardians']))


class Anchor(unittest.TestCase):
    def test_probe_code(self):
        # NUMBER; mstore(0); number-1 BLOCKHASH; mstore(0x20); CHAINID; mstore(0x40); return(0, 0x60)
        self.assertEqual(evm_anchor._code(), '0x4360005260014303406020524660405260606000f3')
        self.assertEqual(evm_anchor._code(5), '0x43600052' + '7f' + f'{5:064x}' + '40602052' + '46604052' + '60606000f3')

    def test_view_and_history_decode(self):
        answer = '0x' + f'{100:064x}' + 'ab' * 32 + f'{10:064x}'
        self.assertEqual(evm_anchor.evm_view(lambda m, p: answer, 'latest'), (100, '0x' + 'ab' * 32, 10))
        with self.assertRaises(ValueError):
            evm_anchor.evm_view(lambda m, p: '0x', 'latest')


@unittest.skipUnless(CAST.exists(), 'cast not found')
class VaultConfigs(unittest.TestCase):
    def tool(self, *args):
        done = subprocess.run([sys.executable, str(ROOT / 'tools/deploy-pontes/vault_pontes.py'), *[str(a) for a in args]],
                              capture_output=True, text=True, env={**os.environ, 'FOUNDRY_BIN': str(CAST.parent)})
        return done.returncode, json.loads(done.stdout)

    def filled(self, name):
        c = json.loads((ROOT / 'deployments' / name / 'busdc-vault.config.json').read_text())
        c['source']['revision'] = 'ab' * 20
        c['deployer'] = {'address': addr('deployer'), 'fundedBy': {'entity': 'test', 'safe': addr('safe')}}
        c['vault']['signers']['set'] = [{'operator': f'op{i}', 'address': addr(f's{i}')} for i in range(7)]
        c['vault']['guard']['guardians'] = [{'operator': f'gop{i}', 'address': addr(f'g{i}')} for i in range(3)]
        if c['vault']['token'] is None:
            c['vault']['token'] = addr('unit-token')
        return c

    def run_cfg(self, cfg, command='validate'):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'c.json'
            p.write_text(json.dumps(cfg))
            return self.tool(command, '--config', p)

    def test_committed_templates_are_refused_as_undecided(self):
        for name in LIVE:
            rc, r = self.tool('validate', '--config', ROOT / 'deployments' / name / 'busdc-vault.config.json')
            self.assertEqual((rc, r['decision']), (1, 'refused'), name)
            self.assertIn('undecided', r['reason'])

    def test_filled_configs_validate_and_give_eleven_arguments(self):
        for name, spec in LIVE.items():
            rc, r = self.run_cfg(self.filled(name))
            self.assertEqual((rc, r.get('decision')), (0, 'config-valid'), (name, r))
            rc, a = self.run_cfg(self.filled(name), 'args')
            self.assertEqual(len(a['constructorArgs']), 11, name)
            self.assertIn(REGISTRY['feeRecipient'].lower(), a['constructorArgs'][10])
            self.assertEqual(a['forge'][4], 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', name)

    def test_network_policy_refusals(self):
        c = self.filled('arbitrum-one')
        c['vault']['token'] = NETS['base']['asset']['address']
        self.assertIn('vault.token on chain 42161', self.run_cfg(c)[1]['reason'])
        c = self.filled('op-mainnet')
        c['vault']['sourceDomainLabel'] = 'ethereum-mainnet'
        self.assertIn('labels', self.run_cfg(c)[1]['reason'])
        c = self.filled('op-mainnet')
        c['vault']['contract'] = 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault'
        c['vault'].pop('provenance')
        self.assertIn('vault.contract on chain 10', self.run_cfg(c)[1]['reason'])
        c = self.filled('linea')
        c['ethereum']['chainId'] = 5
        self.assertIn('chainId must be 1, or a source network', self.run_cfg(c)[1]['reason'])
        c = self.filled('linea')
        c['vault']['provenance']['fees'] = {'recipient': None, 'depositBps': 0, 'releaseBps': 0}
        self.assertIn('revenue', self.run_cfg(c)[1]['reason'])

    def test_the_ethereum_config_is_still_ethereum_only(self):
        c = json.loads((ROOT / 'deployments/mainnet/busdc-vault-mainnet.config.json').read_text())
        c['source']['revision'] = 'ab' * 20
        c['deployer'] = {'address': addr('deployer'), 'fundedBy': {'entity': 'test', 'safe': addr('safe')}}
        c['vault']['signers']['set'] = [{'operator': f'op{i}', 'address': addr(f's{i}')} for i in range(7)]
        c['vault']['guard']['guardians'] = [{'operator': f'gop{i}', 'address': addr(f'g{i}')} for i in range(3)]
        self.assertEqual(self.run_cfg(c)[1].get('decision'), 'config-valid')
        c['vault']['token'] = NETS['base']['asset']['address']
        self.assertIn('canonical USDC', self.run_cfg(c)[1]['reason'])


if __name__ == '__main__':
    unittest.main()
