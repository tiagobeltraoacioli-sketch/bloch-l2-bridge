#!/usr/bin/env python3
"""Round 17 tests of the EVM-network tooling (reviews R329-EVM-1 to -6): python3 -m unittest test_launch_r17  (in tools/evm-nets).

No chain and no key: the nodes are stubs that answer a chain id. `cast` (FOUNDRY_BIN or ~/.foundry/bin) is needed
for the deploy-tool classes; they are skipped without it.

  Launch        the registry and the decision recorded in launch.py; what a hand-edited or missing registry does
  DeployGate    vault_pontes.py and deploy_pontes.py refuse Base and BNB Smart Chain whatever is typed in (the cases of
                the reviewer's demonstration r329_demo_deploy_gate.py); fee recipient, rates and token symbol are pinned
  SignerGate    eth_half.py, signatario.py and vigia.py (sign and relay) refuse a network that is not launchable; no
                flag, environment variable or operator key lifts it
  AnchorPolicy  the anchor settings come from the registry by chain id; a contradicting file is refused at start, a
                missing key is filled; an --interval longer than the network's is refused
  Timing        the signer's work measurements, the hold, the alerts, and the monitor signer_timing.py
  Generator     evm_nets.py writes no deployment file for a network that is not launchable; preflight --network
"""
import contextlib
import copy
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
STABLE = ROOT / 'tools/signatario-stable'
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(STABLE))
sys.path.insert(0, str(ROOT / 'tools/deploy-pontes'))
import evm_nets  # noqa: E402
import launch  # noqa: E402
import signer_timing  # noqa: E402

REGISTRY = json.loads((HERE / 'networks.json').read_text())
NETS = REGISTRY['networks']
CAST = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin')) / 'cast'
ENV = {**os.environ, 'FOUNDRY_BIN': str(CAST.parent)}
OVERRIDE_ATTEMPTS = {'BLOCH_ALLOW_BASE': '1', 'EVMNETS_LAUNCH': 'all', 'LAUNCH_OVERRIDE': '1', 'V1': 'true', 'FORCE': '1',
                     'REHEARSAL': '1', 'EVMNETS_FROM_FORK_BLOCK': '1'}


def addr(label):
    return '0x' + hashlib.sha256(('r17-' + label).encode()).hexdigest()[:40]


def registry_keys(chain, tool):
    """The keys an operator file of this network must state (round 18: a missing one is refused at start)."""
    settings = launch.signer_settings(chain) or {}
    return {k: settings[k] for k in launch.SHARED_BY[tool] if k in settings}


@contextlib.contextmanager
def stub_node(chain_id):
    """A JSON-RPC stub that answers every request with the chain id (enough for the checks made before any real read)."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['content-length']))
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': hex(chain_id)}).encode()
            self.send_response(200)
            self.send_header('content-length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f'http://127.0.0.1:{srv.server_port}'
    finally:
        srv.shutdown()
        srv.server_close()


def filled_vault(name, like='op-mainnet'):
    """A vault config for `name` with every decision filled by throwaway addresses. For a network that has no committed
    config (not launchable) it is built by hand from another network's, as an operator determined to deploy would."""
    spec = NETS[name]
    path = ROOT / 'deployments' / name / 'busdc-vault.config.json'
    c = json.loads((path if path.exists() else ROOT / 'deployments' / like / 'busdc-vault.config.json').read_text())
    c['ethereum']['chainId'] = spec['chainId']
    c['vault']['sourceDomainLabel'], c['vault']['assetLabel'] = spec['sourceDomainLabel'], spec['assetLabel']
    c['vault']['token'] = spec['asset']['address'] if spec['asset']['decimals'] == 6 else addr('unit-token')
    c['source']['revision'] = 'ab' * 20
    c['deployer'] = {'address': addr('deployer'), 'fundedBy': {'entity': 'test', 'safe': addr('safe')}}
    c['vault']['signers']['set'] = [{'operator': f'op{i}', 'address': addr(f's{i}')} for i in range(7)]
    c['vault']['guard']['guardians'] = [{'operator': f'gop{i}', 'address': addr(f'g{i}')} for i in range(3)]
    return c


def filled_token(name):
    """The Ethereum token config with every decision filled (the Ethereum suites' own fixture), renamed and pointed at
    `name` as its source network: what evm_nets.py derives for a launchable network, and what an operator would type
    for one that is not."""
    import launch_fixture
    spec = NETS[name]
    c = launch_fixture.filled()
    c['token']['name'], c['token']['symbol'] = spec['l2']['name'], spec['l2']['symbol']
    c['ethereum']['chainId'] = spec['chainId']
    return c


class Launch(unittest.TestCase):
    def test_the_registry_agrees_with_the_decision_in_code(self):
        self.assertEqual(sorted(launch.launchable()), ['arbitrum-one', 'linea', 'op-mainnet'])
        self.assertEqual({s['chainId']: (n, s['launch']['v1']) for n, s in NETS.items()}, launch.DECIDED)
        for name in ('arbitrum-one', 'op-mainnet', 'linea'):
            self.assertIsNone(launch.refusal(NETS[name]['chainId']))
        self.assertIsNone(launch.refusal(1))        # Ethereum is not this module's business
        self.assertIsNone(launch.refusal(31337))    # nor a local rehearsal chain

    def test_base_is_held_with_the_measured_numbers_and_bnb_is_out(self):
        base, bnb = launch.refusal(8453), launch.refusal(56)
        for text in ('held', '256-block window', '31.6 s of 49 s', '4 s of work', 'not paid in 300 s with 12 s',
                     'not paid in 301 s with 26 s', 'No flag, environment variable or operator file'):
            self.assertIn(text, base)
        self.assertIn('out', bnb)
        self.assertIn('Out of bridge v1', bnb)
        self.assertEqual(NETS['base']['launch']['state'], 'held')
        self.assertEqual(NETS['bnb']['launch']['state'], 'out')

    def edited(self, change):
        reg = copy.deepcopy(REGISTRY)
        change(reg)
        tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        json.dump(reg, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_a_registry_edited_by_hand_lifts_nothing_and_closes_every_network(self):
        def flip(reg):
            reg['networks']['base']['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'typed in by an operator, no review'}
        def drop_launch(reg):
            del reg['networks']['bnb']['launch']
        def old_note(reg):
            reg['networks']['bnb']['v1'] = True
        def remove_base(reg):
            del reg['networks']['base']
        def renumber(reg):
            reg['networks']['base']['chainId'] = 84530
        def add_net(reg):
            reg['networks']['other'] = {**copy.deepcopy(reg['networks']['linea']), 'chainId': 777}
        for change in (flip, drop_launch, old_note, remove_base, renumber, add_net):
            path = self.edited(change)
            with self.assertRaises(launch.LaunchError, msg=change.__name__):
                launch.registry(path)
            for chain in launch.DECIDED:  # launchable ones included: an untrusted registry closes all of them
                self.assertIn('cannot be trusted', launch.refusal(chain, path), (change.__name__, chain))
            self.assertIsNone(launch.refusal(1, path))

    def test_a_missing_or_broken_registry_closes_every_network(self):
        missing = str(Path(tempfile.gettempdir()) / 'r17-no-such-registry.json')
        broken = self.edited(lambda reg: None)
        Path(broken).write_text('{not json')
        for path in (missing, broken):
            for chain in launch.DECIDED:
                self.assertIn('cannot be trusted', launch.refusal(chain, path))

    def test_no_environment_variable_is_read(self):
        source = (HERE / 'launch.py').read_text()
        # the module reads no environment and its CLI takes a mode, nothing that could select or lift a network
        self.assertFalse('os.environ' in source or 'getenv' in source or 'import os' in source or 'argv[2' in source)
        old = dict(os.environ)
        os.environ.update(OVERRIDE_ATTEMPTS)
        try:
            self.assertIsNotNone(launch.refusal(8453))
            self.assertIsNotNone(launch.refusal(56))
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_a_rehearsal_chain_id_is_outside_every_real_network(self):
        for chain in launch.DECIDED:
            r = launch.rehearsal_chain_id(chain)
            self.assertNotIn(r, launch.DECIDED)
            self.assertNotEqual(r, 1)
            self.assertIsNone(launch.signer_settings(r))


@unittest.skipUnless(CAST.exists(), 'cast not found')
class DeployGate(unittest.TestCase):
    def vault(self, cfg, command='validate', *extra, env=None, token_cfg=None):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'c.json'
            p.write_text(json.dumps(cfg))
            more = []
            if token_cfg is not None:
                (Path(tmp) / 't.json').write_text(json.dumps(token_cfg))
                more = ['--token-config', str(Path(tmp) / 't.json')]
            done = subprocess.run([sys.executable, str(ROOT / 'tools/deploy-pontes/vault_pontes.py'), command, '--config', str(p),
                                   *more, *extra], capture_output=True, text=True, env=env or ENV)
        return done.returncode, json.loads(done.stdout)

    def token(self, cfg, *extra):
        import deploy_pontes
        try:
            deploy_pontes.validate(cfg, '--rehearsal' in extra)
            return None
        except deploy_pontes.Refused as e:
            return str(e)

    # ── the reviewer's demonstration (r329_demo_deploy_gate.py), now as assertions ──
    def test_r329_base_config_with_the_committee_filled_is_refused(self):
        for command in ('validate', 'args'):
            rc, r = self.vault(filled_vault('base'), command)
            self.assertEqual((rc, r['decision']), (1, 'refused'), command)
            self.assertIn('Base (chain 8453) is not launchable in bridge v1 (held)', r['reason'])
            self.assertNotIn('constructorArgs', r)
            self.assertNotIn('forge', r)

    def test_r329_op_mainnet_control_still_validates(self):
        rc, r = self.vault(filled_vault('op-mainnet'))
        self.assertEqual((rc, r['decision']), (0, 'config-valid'), r)

    def test_r329_bnb_is_refused_with_and_without_a_pinned_unit_token(self):
        rc, r = self.vault(filled_vault('bnb'))
        self.assertEqual(rc, 1)
        self.assertIn('BNB Smart Chain (chain 56) is not launchable in bridge v1 (out)', r['reason'])
        # "an address pinned by hand": the registry edit the reviewer made. It no longer opens the network: with the
        # address typed into networks.json the launch block still says out, and the answer is the same refusal.
        path = HERE / 'networks.json'
        orig = path.read_text()
        try:
            reg = json.loads(orig)
            reg['networks']['bnb']['asset']['unit']['address'] = addr('unit-token')
            path.write_text(json.dumps(reg, indent=2) + '\n')
            rc, r = self.vault(filled_vault('bnb'))
            self.assertEqual(rc, 1)
            self.assertIn('not launchable in bridge v1 (out)', r['reason'])
            # ... and flipping `launch.v1` by hand in the registry closes every network instead of opening this one
            reg['networks']['bnb']['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'typed in by hand, never reviewed'}
            path.write_text(json.dumps(reg, indent=2) + '\n')
            for name in ('bnb', 'base', 'op-mainnet'):
                rc, r = self.vault(filled_vault(name))
                self.assertEqual(rc, 1, name)
                self.assertIn('cannot be trusted', r['reason'], name)
        finally:
            path.write_text(orig)

    def test_r329_a_stranger_as_fee_recipient_is_refused(self):
        for name in ('op-mainnet', 'arbitrum-one', 'linea'):
            c = filled_vault(name)
            c['vault']['provenance']['fees']['recipient'] = addr('stranger')
            rc, r = self.vault(c)
            self.assertEqual(rc, 1, name)
            self.assertIn(f'must be recipient 0x775a993f09bd80aecf8f8c2ade0c84158e3a0544, depositBps 5, releaseBps '
                          f'{NETS[name]["feeBps"]["release"]}', r['reason'])

    def test_fee_rates_other_than_the_decided_ones_are_refused(self):
        for name, want in (('linea', 'depositBps 5, releaseBps 15'), ('op-mainnet', 'depositBps 5, releaseBps 5')):
            for dep, rel in ((5, 4), (0, 5), (30, 30), (6, 5), (5, 10), (15, 5)):
                c = filled_vault(name)
                c['vault']['provenance']['fees'].update(depositBps=dep, releaseBps=rel)
                self.assertIn(want, self.vault(c)[1]['reason'], (name, dep, rel))
        self.assertEqual(REGISTRY['feeRecipient'], '0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544')
        self.assertNotIn('feeBps', REGISTRY)

    # ── the fee schedule of 2026-11-17 (coordinator; agents/347-fee-economics-r17.md) ──
    def test_the_decided_schedule_is_in_the_registry_and_in_every_generated_file(self):
        want = {'arbitrum-one': (5, 5, 21, 20, 0.5), 'op-mainnet': (5, 5, 21, 20, 0.5), 'base': (5, 5, 21, 20, 0.5), 'linea': (5, 15, 601, 600, 2)}
        for name, (dep, rel, min_dep, min_burn, ceiling) in want.items():
            spec = NETS[name]
            self.assertEqual((spec['feeBps']['deposit'], spec['feeBps']['release'], spec['minDeposit'], spec['l2MinBurn'],
                              spec['relay']['gasCeilingGwei']), (dep, rel, min_dep * 10**6, min_burn * 10**6, ceiling), name)
            doc = json.loads((ROOT / 'deployments' / name / 'bridge.network.json').read_text())
            self.assertEqual((doc['fee']['depositBps'], doc['fee']['releaseBps'], doc['limits']['minDeposit'], doc['limits']['l2MinBurn'],
                              doc['release']['gasCeilingGwei']), (dep, rel, str(min_dep * 10**6), str(min_burn * 10**6), f'{ceiling:g}'), name)
            self.assertTrue(any('a release waits' in n for n in doc['release']['notes']), name)
            if spec['launch']['v1']:
                v = json.loads((ROOT / 'deployments' / name / 'busdc-vault.config.json').read_text())['vault']
                t = json.loads((ROOT / 'deployments' / name / 'busdc-token.config.json').read_text())
                r = json.loads((ROOT / 'deployments' / name / 'ops/relayer.template.json').read_text())
                self.assertEqual((v['provenance']['fees']['depositBps'], v['provenance']['fees']['releaseBps'], v['policy']['minDeposit'],
                                  v['policy']['l2MinBurn'], t['limits']['minBurn'], r['eth_max_gas_price_gwei']),
                                 (dep, rel, min_dep * 10**6, min_burn * 10**6, min_burn * 10**6, ceiling), name)
                # the constructor's own rule: the smallest deposit, less its fee, is at least the smallest burn
                self.assertGreaterEqual(min_dep * 10**6 - min_dep * 10**6 * dep // 10_000, min_burn * 10**6, name)
        eth_v = json.loads((ROOT / 'deployments/mainnet/busdc-vault-mainnet.config.json').read_text())['vault']
        eth_t = json.loads((ROOT / 'deployments/mainnet/busdc-mainnet.config.json').read_text())
        eth_r = json.loads((ROOT / 'deployments/mainnet/busdc-ops/relayer.template.json').read_text())
        e = REGISTRY['relayCost']['ethereum']
        self.assertEqual((eth_v['provenance']['fees']['depositBps'], eth_v['provenance']['fees']['releaseBps'], eth_v['policy']['minDeposit'],
                          eth_v['policy']['l2MinBurn'], eth_t['limits']['minBurn'], eth_r['eth_max_gas_price_gwei']),
                         (5, 10, 101_000_000, 100_000_000, 100_000_000, 2))
        self.assertEqual((e['feeBps'], e['minDeposit'], e['l2MinBurn'], e['gasCeilingGwei']),
                         ({'deposit': 5, 'release': 10}, 101_000_000, 100_000_000, 2))
        # windows and caps are NOT part of this schedule (an owner decision still open): unchanged
        self.assertEqual((eth_v['cap'], eth_v['policy']['windowLimit']), (100_000_000_000, 10_000_000_000))

    def test_the_minimum_burn_floor_is_the_stated_formula(self):
        usd = REGISTRY['relayCost']['nativeUsd']
        import math
        for chain, gas, ceiling, bps in ((1, 207000, 2, 10), (59144, 210269, 2, 15), (42161, 206932, 0.5, 5), (10, 206968, 0.5, 5)):
            want = math.ceil(gas * ceiling * 1e-9 * usd * 1e6 / (1 - bps / 10_000))
            got = launch.min_burn_floor(chain, bps)
            self.assertLessEqual(abs(got - want), 1, (chain, got, want))
        self.assertEqual(launch.min_burn_floor(1, 10), 752761)       # 0.752761 dollars on Ethereum at 2 gwei and 1,816.445 USD
        self.assertEqual(launch.min_burn_floor(59144, 15), 765032)   # 0.765032 on Linea
        self.assertGreater(launch.min_burn_floor(1, 9999), 7 * 10**9)  # the complement: a 99.99% fee would need a 7,520 dollar minimum
        self.assertIsNone(launch.min_burn_floor(31337, 5))           # a rehearsal chain has no recorded relayer cost
        self.assertIsNone(launch.min_burn_floor(56, 5))              # nor a network out of v1
        for name in ('arbitrum-one', 'op-mainnet', 'linea'):
            self.assertGreaterEqual(NETS[name]['l2MinBurn'], launch.min_burn_floor(NETS[name]['chainId'], NETS[name]['feeBps']['release']))

    def test_a_minimum_burn_below_the_relayer_cost_is_refused_by_both_tools(self):
        import launch_fixture
        for name in ('linea', 'op-mainnet'):
            spec = NETS[name]
            floor = launch.min_burn_floor(spec['chainId'], spec['feeBps']['release'])
            for burn, ok in ((floor - 1, False), (floor, True)):
                c = filled_vault(name)
                c['vault']['policy'].update(l2MinBurn=burn, minDeposit=burn + 1000)
                rc, r = self.vault(c)
                self.assertEqual(rc == 0, ok, (name, burn, r))
                if not ok:
                    self.assertIn(f'is below {floor}', r['reason'])
                    self.assertIn('(1 - releaseBps / 10000)', r['reason'])
                t = filled_token(name)
                t['limits']['minBurn'] = burn
                why = self.token(t)
                self.assertEqual(why is None, ok, (name, burn, why))
                if not ok:
                    self.assertIn(f'is below {floor}', why)
        # the Ethereum route (chain 1): the same floor from relayCost.ethereum, and the decided config passes
        floor = launch.min_burn_floor(1, 10)
        eth = launch_fixture.filled()
        self.assertIsNone(self.token(eth))
        eth['limits']['minBurn'] = floor - 1
        self.assertIn(f'is below {floor}', self.token(eth))
        v = launch_fixture.filled_vault(launch_fixture.filled())
        self.assertEqual(self.vault(v)[1].get('decision'), 'config-valid')
        v['vault']['policy'].update(l2MinBurn=floor - 1, minDeposit=floor + 1000)
        self.assertIn(f'is below {floor}', self.vault(v)[1]['reason'])
        v = launch_fixture.filled_vault(launch_fixture.filled())
        v['vault']['policy'].update(l2MinBurn=10_000_000, minDeposit=11_000_000)   # the values before the schedule still pass the FLOOR
        self.assertEqual(self.vault(v)[1].get('decision'), 'config-valid')         # (it is a floor, not the schedule: chain 1 is not pinned)

    def test_no_flag_or_environment_variable_lifts_the_vault_tool(self):
        c = filled_vault('base')
        for extra in ([], ['--rehearsal'], ['--force'], ['--allow-held'], ['--network', 'op-mainnet'], ['--v1']):
            rc, r = self.vault(c, 'validate', *extra)
            self.assertEqual((rc, r['decision']), (1, 'refused'), extra)
        c2 = copy.deepcopy(c)
        c2['ethereum']['rehearsal'] = True  # a rehearsal config is only ever chain 31337
        rc, r = self.vault(c2, 'validate', '--rehearsal')
        self.assertEqual(rc, 1)
        self.assertIn('chainId must be 31337', r['reason'])
        rc, r = self.vault(c, 'validate', env={**ENV, **OVERRIDE_ATTEMPTS})
        self.assertEqual(rc, 1)
        rc, r = self.vault(c, 'verify', '--rpc', 'http://127.0.0.1:9', '--address', addr('vault'))
        self.assertEqual(rc, 1)
        self.assertIn('not launchable', r['reason'])  # refused before the node is ever asked

    def test_the_token_tool_refuses_base_and_bnb_as_a_source_with_or_without_rehearsal(self):
        import deploy_pontes
        import launch_fixture
        for name in ('base', 'bnb'):
            for extra in ((), ('--rehearsal',)):
                c = filled_token(name)
                if extra:
                    c = launch_fixture.rehearsal(c)
                    c['ethereum']['chainId'] = NETS[name]['chainId']
                why = self.token(c, *extra)
                self.assertIsNotNone(why, (name, extra))
                self.assertIn('not launchable in bridge v1', why, (name, extra))
        self.assertTrue(hasattr(deploy_pontes, 'evm_launch'))
        # controls: the launchable networks pass under their own name and symbol, and Ethereum is as it was
        for name in ('op-mainnet', 'arbitrum-one', 'linea'):
            self.assertIsNone(self.token(filled_token(name)), name)
        self.assertIsNone(self.token(launch_fixture.filled()))

    def test_the_token_symbol_and_name_are_pinned_per_source_chain(self):
        src = (ROOT / 'tools/deploy-pontes/deploy_pontes.py').read_text()
        self.assertIn("refuse((name, symbol) == (want['name'], want['symbol'])", src)
        for name, wrong in (('op-mainnet', ('Bloch Bridged USDC (Base)', 'bUSDC.base')), ('op-mainnet', ('Bloch Bridged USDC', 'bUSDC')),
                            ('linea', ('Bloch Bridged USDC (Linea)', 'bUSDC.op'))):
            c = filled_token(name)
            c['token']['name'], c['token']['symbol'] = wrong
            why = self.token(c)
            self.assertIsNotNone(why)
            self.assertIn('one token per network', why)
            self.assertIn(NETS[name]['l2']['symbol'], why)
        # chain 1 keeps its own rule and name: the registry is not consulted for it
        c = __import__('launch_fixture').filled()
        self.assertEqual((c['ethereum']['chainId'], c['token']['symbol']), (1, 'bUSDC'))
        self.assertIsNone(self.token(c))
        c['ethereum']['chainId'] = 5
        self.assertIn('must be 1 or one of [10, 42161, 59144]', self.token(c))


class SignerGate(unittest.TestCase):
    def run_tool(self, argv, env=None):
        return subprocess.run([sys.executable, *[str(a) for a in argv]], capture_output=True, text=True, env=env or ENV)

    def eth_half_cfg(self, tmp, url, chain, **more):
        cfg = {'eth_rpc': url, 'eth_chain_id': chain, 'vault': '0x' + '11' * 20, 'vault_code_keccak': '0x' + '22' * 32, 'keystore': 'k',
               'password_file': 'p', 'db': str(Path(tmp) / 'db.json'), 'provenance': True, **registry_keys(chain, 'eth_half'), **more}
        (Path(tmp) / 'eth.json').write_text(json.dumps(cfg))
        return Path(tmp) / 'eth.json'

    def signer_cfg(self, tmp, url, chain, **more):
        cfg = {'signer': 1, 'l2_rpc': url, 'l2_chain_id': 700771, 'token': '0x' + '33' * 20, 'token_code_keccak': '0x' + '44' * 32,
               'source_chain_id': chain, 'source_vault': '0x' + '11' * 20, 'source_route': '0x' + '55' * 32, 'threshold': 5,
               'vault_threshold': 5, 'keystore': 'k', 'password_file': 'p', 'eth_signer': '0x' + '66' * 20,
               'db': str(Path(tmp) / 'db.json'), 'l2_source': 'rpc', 'work_dir': str(tmp), 'provenance': True,
               'eth_half_deposit': ['false'], 'eth_half_release': ['false'], 'shared_dir': str(Path(tmp) / 'shared'),
               'eth_rpc': url, 'eth_chain_id': chain, 'vault_from_block': 1, 'l2_relayer_key': 'x', 'eth_relayer_key': 'x',
               **registry_keys(chain, 'vigia'), **more}
        (Path(tmp) / 'cfg.json').write_text(json.dumps(cfg))
        return Path(tmp) / 'cfg.json'

    def test_eth_half_refuses_base_and_bnb_for_deposit_and_release(self):
        for chain, word in ((8453, 'held'), (56, 'out')):
            with stub_node(chain) as url, tempfile.TemporaryDirectory() as tmp:
                for command in (['deposit', '--deposit-id', '0x' + '77' * 32], ['release', '--intent', str(Path(tmp) / 'none.json')]):
                    for more in ({}, {'anchor_policy': 'probe', 'anchor_depth': 5, 'anchor_max_age': 250}, {'v1': True, 'launch': 'yes',
                                 'rehearsal': True, 'force': True}):
                        done = self.run_tool([STABLE / 'eth_half.py', '--config', self.eth_half_cfg(tmp, url, chain, **more), *command],
                                             env={**ENV, **OVERRIDE_ATTEMPTS})
                        out = json.loads(done.stdout)
                        self.assertEqual((done.returncode, out['ok']), (1, False), (chain, command))
                        self.assertEqual(out['reason'], 'this network is not launchable: nothing is attested or signed for it')
                        self.assertIn(f'({word})', out['why'])

    def test_eth_half_cannot_be_pointed_at_a_held_network_under_another_configured_id(self):
        # The node decides the chain id, not the file: a config that says 10 over a Base node stops at the first check.
        with stub_node(8453) as url, tempfile.TemporaryDirectory() as tmp:
            done = self.run_tool([STABLE / 'eth_half.py', '--config', self.eth_half_cfg(tmp, url, 10), 'release', '--intent', 'x'])
            self.assertIn('serves another chain', done.stdout)

    def test_signatario_refuses_every_command_for_base_and_bnb(self):
        for chain in (8453, 56):
            with stub_node(chain) as url, tempfile.TemporaryDirectory() as tmp:
                cfg = self.signer_cfg(tmp, url, chain)
                for command in (['mint', '--deposit-id', '0x' + '77' * 32, '--out', Path(tmp) / 'o'],
                                ['remint', '--deposit-id', '0x' + '77' * 32, '--out', Path(tmp) / 'o'],
                                ['release', '--burn-tx', '0x' + '88' * 32, '--out', Path(tmp) / 'o'],
                                ['combine', '--sig', 'a', '--out', Path(tmp) / 'o'], ['measure', '--timing', Path(tmp) / 't']):
                    done = self.run_tool([STABLE / 'signatario.py', '--config', cfg, *command], env={**ENV, **OVERRIDE_ATTEMPTS})
                    self.assertEqual(done.returncode, 1, command)
                    self.assertIn('this network is not launchable: nothing is signed or combined for it', done.stdout, command)
                    self.assertFalse((Path(tmp) / 'o').exists())

    def test_vigia_refuses_to_sign_or_relay_for_base_and_bnb(self):
        for chain in (8453, 56):
            with stub_node(chain) as url, tempfile.TemporaryDirectory() as tmp:
                for mode in ('sign', 'relay'):
                    for extra in ([], ['--interval', '5'], ['--rehearsal'], ['--force']):
                        done = self.run_tool([STABLE / 'vigia.py', '--config', self.signer_cfg(tmp, url, chain), mode, '--once', *extra],
                                             env={**ENV, **OVERRIDE_ATTEMPTS})
                        self.assertNotEqual(done.returncode, 0, (chain, mode))
                        self.assertIn('refusing to sign or relay', done.stderr, (chain, mode))
                        self.assertIn('not launchable in bridge v1', done.stderr)
                        self.assertEqual(done.stdout.strip(), '', 'nothing may run before the refusal')

    def test_vigia_refuses_when_only_one_of_the_two_chain_id_keys_names_a_held_network(self):
        with stub_node(8453) as url, tempfile.TemporaryDirectory() as tmp:
            for ids in ({'source_chain_id': 8453, 'eth_chain_id': 10}, {'source_chain_id': 10, 'eth_chain_id': 8453},
                        {'source_chain_id': 1, 'eth_chain_id': 8453}):
                cfg = self.signer_cfg(tmp, url, 10, **ids)
                done = self.run_tool([STABLE / 'vigia.py', '--config', cfg, 'sign', '--once'])
                self.assertIn('refusing to sign or relay', done.stderr, ids)

    def test_ethereum_configs_never_load_the_launch_module(self):
        # Neutrality of the Ethereum bridge: with chain id 1 the three daemons do not import tools/evm-nets at all.
        code = ('import sys, json, pathlib, tempfile\n'
                f'sys.path.insert(0, {str(STABLE)!r})\n'
                'import vigia\n'
                'd = pathlib.Path(tempfile.mkdtemp())\n'
                'cfg = {"shared_dir": str(d), "token": "0x" + "33" * 20, "source_vault": "0x" + "11" * 20, "source_route": "0x" + "55" * 32,\n'
                '       "threshold": 5, "source_chain_id": 1, "eth_chain_id": 1, "signer": 1}\n'
                '(d / "c.json").write_text(json.dumps(cfg))\n'
                'v = vigia.Vigia(d / "c.json")\n'
                'assert v.timing is None and v.pace is None and v.timing_args() == [] and v.window_allows({"burn_id": "0x"}) is True\n'
                'assert "launch" not in sys.modules and "evm_anchor" not in sys.modules, sorted(sys.modules)\n'
                'print("neutral")\n')
        done = self.run_tool(['-c', code])
        self.assertEqual(done.stdout.strip(), 'neutral', done.stderr)
        for name in ('eth_half.py', 'signatario.py'):
            src = (STABLE / name).read_text()
            self.assertIn('!= 1:', src)
        self.assertIn("if chain != 1:\n            c = self.cfg = self.network_settings(chain, c)", (STABLE / 'eth_half.py').read_text())
        self.assertIn('if self.source_chain_id != 1:', (STABLE / 'signatario.py').read_text())


class AnchorPolicy(unittest.TestCase):
    def vigia(self, chain, fill=True, **more):
        import vigia
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(d, ignore_errors=True))
        cfg = {'shared_dir': str(d), 'token': '0x' + '33' * 20, 'source_vault': '0x' + '11' * 20, 'source_route': '0x' + '55' * 32,
               'threshold': 5, 'source_chain_id': chain, 'eth_chain_id': chain, 'signer': 1,
               **(registry_keys(chain, 'vigia') if fill else {}), **more}
        (d / 'c.json').write_text(json.dumps(cfg))
        return vigia.Vigia(d / 'c.json')

    def test_a_missing_key_is_refused_at_start(self):
        # R329-EVM-3: on Arbitrum One a signer file without `anchor_policy` took the Ethereum branch and no round ever fit.
        # Round 17 filled the key from the registry; round 18 (coordinator: "missing key refused at start") refuses the
        # file instead, so an operator file always states the network's settings and never takes the Ethereum branch.
        for name in launch.launchable():
            spec = NETS[name]
            full = {k: spec['signer'][k] for k in launch.SHARED_BY['vigia']}
            for key in full:
                more = {k: v for k, v in full.items() if k != key}
                with self.assertRaises(SystemExit) as e:
                    self.vigia(spec['chainId'], fill=False, **more)
                self.assertIn('missing', str(e.exception), (name, key))
                self.assertIn(key, str(e.exception), (name, key))

    def test_the_registry_values_are_taken_by_chain_id(self):
        # The property the round-17 test asserted (the registry's values are the ones in force) stays covered.
        for name in launch.launchable():
            spec = NETS[name]
            v = self.vigia(spec['chainId'], fill=False, **{k: spec['signer'][k] for k in launch.SHARED_BY['vigia']})
            self.assertEqual(v.cfg['anchor_policy'], spec['signer']['anchor_policy'], name)
            self.assertEqual(v.anchor_max_age, spec['signer']['anchor_max_age'], name)
            self.assertEqual((v.signs_per_hour, v.refused_retry), (spec['signer']['max_release_signs_per_hour'], spec['signer']['refused_retry']))
            self.assertEqual(v.pace['interval_s'], spec['signer']['interval_s'])
            self.assertEqual(v.timing['window_s'], spec['signer']['anchor_max_age'] * spec['timing']['anchorBlockSeconds'])

    def test_a_contradicting_signer_file_is_refused_at_start(self):
        for more in ({'anchor_policy': 'finalized'}, {'anchor_max_age': 160}, {'anchor_max_age': '250'}, {'anchor_policy': 'probe', 'anchor_max_age': 251}):
            with self.assertRaises(SystemExit) as e:
                self.vigia(42161, **more)
            self.assertIn('contradicts the network registry', str(e.exception), more)
        self.vigia(42161, anchor_policy='probe', anchor_max_age=200)  # the registry's own values are accepted

    def test_budgets_may_be_set_by_the_operator_and_default_to_the_network(self):
        v = self.vigia(59144, max_release_signs_per_hour=3, refused_retry=7)
        self.assertEqual((v.signs_per_hour, v.refused_retry), (3, 7))

    def test_a_rehearsal_chain_keeps_its_own_keys(self):
        v = self.vigia(31337, anchor_policy='probe', anchor_max_age=99)
        self.assertEqual((v.cfg['anchor_policy'], v.anchor_max_age, v.timing, v.pace), ('probe', 99, None, None))
        v = self.vigia(launch.rehearsal_chain_id(8453), anchor_policy='probe', anchor_max_age=250, rehearsal_network='base')
        self.assertEqual((v.timing['network'], v.timing['window_s'], v.pace['interval_s']), ('base', 50.0, 5))
        # `rehearsal_network` does nothing on any other chain id, a real one least of all
        v = self.vigia(31337, rehearsal_network='base')
        self.assertIsNone(v.timing)
        with self.assertRaises(SystemExit):
            self.vigia(8453, rehearsal_network='base')

    def test_eth_half_takes_the_registry_values_and_refuses_a_contradiction(self):
        with stub_node(10) as url, tempfile.TemporaryDirectory() as tmp:
            def run(fill=True, **more):
                cfg = {'eth_rpc': url, 'eth_chain_id': 10, 'vault': '0x' + '11' * 20, 'vault_code_keccak': '0x' + '22' * 32, 'keystore': 'k',
                       'password_file': 'p', 'db': str(Path(tmp) / 'db.json'), **more}
                if fill:
                    cfg = {**registry_keys(10, 'eth_half'), **cfg}
                (Path(tmp) / 'c.json').write_text(json.dumps(cfg))
                done = subprocess.run([sys.executable, str(STABLE / 'eth_half.py'), '--config', str(Path(tmp) / 'c.json'), 'release',
                                       '--intent', str(Path(tmp) / 'none.json')], capture_output=True, text=True, env=ENV)
                return done.stdout + done.stderr
            for more in ({'anchor_policy': 'finalized'}, {'anchor_depth': 0}, {'anchor_max_age': 160}, {'finalized_margin': 5}):
                out = run(**more)
                self.assertIn('config contradicts the network registry', out, more)
                self.assertIn(next(iter(more)), out)
            # Round 18: a file that omits a key the registry sets is refused at start (it was filled in round 17).
            full = {'anchor_policy': 'probe', 'anchor_depth': 2, 'anchor_max_age': 250, 'finalized_margin': 0}
            for key in ('',) + tuple(full):
                out = run(fill=False, **{k: v for k, v in full.items() if k != key})
                if key:
                    self.assertIn('config misses keys the network registry sets', out, key)
                    self.assertIn(key, out)
                else:
                    # The registry's own values get past the start (they stop at the missing intent file).
                    self.assertNotIn('contradicts', out)
                    self.assertNotIn('misses', out)
                    self.assertIn('none.json', out)

    def test_an_interval_longer_than_the_network_allows_is_refused(self):
        with stub_node(10) as url, tempfile.TemporaryDirectory() as tmp:
            cfg = {'shared_dir': str(Path(tmp) / 's'), 'token': '0x' + '33' * 20, 'source_vault': '0x' + '11' * 20,
                   'source_route': '0x' + '55' * 32, 'threshold': 5, 'source_chain_id': 10, 'eth_chain_id': 10, 'signer': 1,
                   'l2_rpc': url, 'eth_rpc': url, **registry_keys(10, 'vigia')}
            (Path(tmp) / 'c.json').write_text(json.dumps(cfg))
            done = subprocess.run([sys.executable, str(STABLE / 'vigia.py'), '--config', str(Path(tmp) / 'c.json'), 'sign', '--once',
                                   '--interval', '60'], capture_output=True, text=True, env=ENV)
            self.assertIn('--interval 60 is longer than this network allows (20 s', done.stderr)

    def test_the_registry_pacing_fits_each_window(self):
        for name, spec in NETS.items():
            t = launch.timing(spec['chainId']) if spec['launch']['v1'] else None
            window = spec['signer']['anchor_max_age'] * spec['timing']['anchorBlockSeconds']
            # one discovery pass and one relay pass must leave room for the work the hold still allows
            self.assertLessEqual(2 * spec['signer']['interval_s'] + spec['timing']['holdFraction'] * window, window, name)
            self.assertLessEqual(2 * spec['signer']['interval_s'], 0.4 * window, name)
            self.assertLess(spec['timing']['alertFraction'], spec['timing']['holdFraction'], name)
            self.assertLessEqual(spec['signer']['refused_retry'], max(12, window / 4) + 1e-9, name)
            self.assertTrue(spec['signer']['pacing_why'], name)
            if t:
                self.assertEqual(t['window_s'], window)


class Timing(unittest.TestCase):
    def signer(self, chain=10, samples=()):
        import vigia
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(d, ignore_errors=True))
        cfg = {'shared_dir': str(d), 'token': '0x' + '33' * 20, 'source_vault': '0x' + '11' * 20, 'source_route': '0x' + '55' * 32,
               'threshold': 5, 'source_chain_id': chain, 'eth_chain_id': chain, 'signer': 1, 'eth_rpc': 'http://127.0.0.1:9',
               **registry_keys(chain, 'vigia')}
        (d / 'c.json').write_text(json.dumps(cfg))
        v = vigia.Vigia(d / 'c.json')
        v.timing_samples = [dict(s) for s in samples]
        v.calls = []

        def fake(*args):  # stands in for signatario.py: writes what the real one writes with --timing
            v.calls.append(args[0])
            Path(args[args.index('--timing') + 1]).write_text(json.dumps(v.next_sample))
            return 0, {'measured': True}
        v.signatario = fake
        return v

    def logs(self, call):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = call()
        return result, [json.loads(l) for l in buf.getvalue().splitlines() if l.startswith('{')]

    def sample(self, total, age=0, mode='join', **more):
        return {'t': int(time.time()), 'mode': mode, 'signed': mode != 'measure', 'ok': True, 'total_s': total, 'rebuild_s': max(0, total - 1),
                **({} if mode == 'measure' else {'source_half_s': 1.0}), 'anchor_age_s': age, **more}

    def test_no_measurement_yet_measures_first_and_then_decides(self):
        v = self.signer()
        v.next_sample = self.sample(4.0, mode='measure')
        ok, lines = self.logs(lambda: v.window_allows({'burn_id': '0xb', 'nonce': 1}))
        self.assertTrue(ok)
        self.assertEqual(v.calls, ['measure'])
        self.assertEqual(v.recent_work(), 4.0)
        self.assertTrue(any(l.get('kind') == 'timing' and l.get('mode') == 'measure' for l in lines))
        doc = json.loads(v.timing_path.read_text())
        self.assertEqual((doc['network'], doc['recent_work_s'], doc['held']), ('op-mainnet', 4.0, False))

    def test_a_measurement_that_did_not_complete_is_not_a_measurement(self):
        v = self.signer()
        v.next_sample = {**self.sample(0.2, mode='measure'), 'ok': False}  # e.g. the follower was stale: refused at once
        ok, lines = self.logs(lambda: v.window_allows({'burn_id': '0xb', 'nonce': 1}))
        self.assertFalse(ok)
        self.assertIsNone(v.recent_work())
        self.assertTrue(any(l.get('held') and 'no measurement' in l.get('reason', '') for l in lines))

    def test_a_signer_too_slow_for_the_window_holds_and_alerts(self):
        # OP Mainnet: window 500 s, hold above 250 s. Nothing is opened or joined, and the alert is critical.
        v = self.signer(samples=[self.sample(260.0)])
        v.last_measure = time.time()  # measured a moment ago: no new measurement yet
        ok, lines = self.logs(lambda: v.window_allows({'burn_id': '0xb', 'nonce': 1}))
        self.assertFalse(ok)
        self.assertEqual(v.calls, [])
        alert = [l for l in lines if l.get('kind') == 'alert']
        self.assertEqual([(a['id'], a['severity']) for a in alert], [('release-window-hold', 'critical')])
        self.assertEqual((alert[0]['hold_s'], alert[0]['window_s'], alert[0]['recent_work_s']), (250.0, 500.0, 260.0))
        self.assertTrue(json.loads(v.timing_path.read_text())['held'])

    def test_a_held_signer_measures_again_and_resumes_only_on_its_measurements(self):
        v = self.signer(samples=[self.sample(260.0)])
        v.last_measure = time.time() - 301  # remeasureSeconds is 300
        v.next_sample = self.sample(30.0, mode='measure')
        ok, _ = self.logs(lambda: v.window_allows({'burn_id': '0xb', 'nonce': 1}))
        self.assertEqual(v.calls, ['measure'])
        self.assertFalse(ok, 'one fast measurement does not outweigh the slow one among the recent three')
        v.timing_samples += [self.sample(30.0, mode='measure'), self.sample(30.0, mode='measure')]
        ok, _ = self.logs(lambda: v.window_allows({'burn_id': '0xb', 'nonce': 1}))
        self.assertTrue(ok)

    def test_a_round_that_cannot_be_finished_inside_the_window_is_not_joined(self):
        import vigia
        v = self.signer(samples=[self.sample(100.0)])  # 100 s of work per signature, window 500 s
        prop = v.shared / 'cert.json'
        prop.write_text(json.dumps({'context': {'sourceAnchorNumber': 1000}}))
        import evm_anchor
        real = evm_anchor.evm_view
        self.addCleanup(lambda: setattr(evm_anchor, 'evm_view', real))
        for now_number, allowed in ((1100, True), (1200, True), (1201, False), (1250, False)):  # 2 s a block: 200, 400, 402, 500 s old
            evm_anchor.evm_view = lambda rpc, block, number, n=now_number: (n, '0x' + 'ab' * 32, 10)
            ok, lines = self.logs(lambda: v.window_allows({'burn_id': '0xb', 'nonce': 1}, prop))
            self.assertEqual(ok, allowed, now_number)
            if not allowed:
                self.assertTrue(any('cannot be joined inside the window' in str(l.get('reason')) for l in lines))
        self.assertEqual(v.calls, [], 'no rebuild was spent on a round that could not be joined')
        self.assertIsNotNone(vigia)

    def test_the_alert_fires_at_the_stated_fraction_of_the_window(self):
        for total, age, alerted in ((99.0, 0, False), (100.0, 0, True), (20.0, 100.0, True), (20.0, 98.0, False)):
            v = self.signer()
            v.timing_path.parent.mkdir(parents=True, exist_ok=True)
            v.timing_path.with_name(f'.last-{v.me}.json').write_text(json.dumps(self.sample(total)))
            res = {'eth': {'anchor_evm_number': 1000 + int(age / 2), 'eth_head_number': 5}, 'context': {'sourceAnchorNumber': 1000}}
            _, lines = self.logs(lambda: v.take_timing('0xb', 'r-1', res))
            alerts = [l for l in lines if l.get('kind') == 'alert']
            self.assertEqual(bool(alerts), alerted, (total, age))
            if alerts:
                self.assertEqual((alerts[0]['id'], alerts[0]['severity'], alerts[0]['alert_s']), ('release-window-budget', 'warning', 100.0))
            timing = [l for l in lines if l.get('kind') == 'timing'][0]
            self.assertEqual((timing['total_s'], timing['anchor_age_s'], timing['window_s']), (total, float(int(age / 2) * 2), 500.0))

    def test_signatario_writes_the_timing_file_only_when_asked(self):
        with stub_node(31337) as url, tempfile.TemporaryDirectory() as tmp:
            cfg = {'signer': 1, 'l2_rpc': url, 'l2_chain_id': 700771, 'token': '0x' + '33' * 20, 'token_code_keccak': '0x' + '44' * 32,
                   'source_chain_id': 31337, 'source_vault': '0x' + '11' * 20, 'source_route': '0x' + '55' * 32, 'threshold': 5,
                   'db': str(Path(tmp) / 'db.json'), 'l2_source': 'rpc', 'work_dir': str(Path(tmp) / 'w')}
            (Path(tmp) / 'c.json').write_text(json.dumps(cfg))
            run = lambda *a: subprocess.run([sys.executable, str(STABLE / 'signatario.py'), '--config', str(Path(tmp) / 'c.json'), *a],  # noqa: E731
                                            capture_output=True, text=True, env=ENV)
            done = run('measure', '--timing', str(Path(tmp) / 't.json'))
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            doc = json.loads((Path(tmp) / 't.json').read_text())
            self.assertEqual((doc['mode'], doc['signed'], doc['ok'], doc['l2_source']), ('measure', False, True, 'rpc'))
            self.assertGreaterEqual(doc['total_s'], 0)
            # a release that is refused still reports how long it took; without --timing nothing is written
            done = run('release', '--burn-tx', '0x' + '88' * 32, '--out', str(Path(tmp) / 'o.json'), '--timing', str(Path(tmp) / 't2.json'))
            self.assertEqual(done.returncode, 1)
            self.assertEqual([json.loads((Path(tmp) / 't2.json').read_text())[k] for k in ('signed', 'ok')], [False, False])
            before = sorted(p.name for p in Path(tmp).iterdir())
            run('release', '--burn-tx', '0x' + '88' * 32, '--out', str(Path(tmp) / 'o.json'))
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), before)

    def test_the_monitor_alerts_from_the_exported_file_with_the_registry_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            def findings(samples, network='linea', **more):
                p = Path(tmp) / 'timing.json'
                # the file's own copy of the limits is a lie on purpose: the monitor must take them from the registry
                p.write_text(json.dumps({'signer': 's1', 'network': network, 'window_s': 10**9, 'alert_s': 10**9, 'hold_s': 10**9,
                                         'updated': int(time.time()), 'held': False, 'samples': samples, **more}))
                return signer_timing.findings(p, max_age=3600)
            self.assertEqual(findings([self.sample(10.0)]), [])
            f = findings([self.sample(50.0)])
            self.assertEqual([(x['id'], x['severity']) for x in f], [('release-window-budget', 'warning')])  # Linea: 20% of 250 s
            f = findings([self.sample(10.0, age=60.0)])
            self.assertEqual(f[0]['id'], 'release-window-budget')
            f = findings([self.sample(126.0)])
            self.assertEqual([(x['id'], x['severity']) for x in f], [('release-window-hold', 'critical')])
            self.assertEqual(findings([self.sample(10.0)], held=True)[0]['id'], 'release-window-hold')
            self.assertEqual(findings([self.sample(10.0)], updated=int(time.time()) - 7200)[0]['id'], 'timing-stale')
            self.assertEqual(findings([self.sample(10.0)], network='base')[0]['id'], 'timing-unreadable')
            self.assertEqual(signer_timing.findings(Path(tmp) / 'absent.json')[0]['id'], 'timing-unreadable')
            old = [{**self.sample(500.0), 't': int(time.time()) - 22000}]  # older than measurementTtlSeconds: not recent
            self.assertEqual(findings(old), [])
            (Path(tmp) / 'ok.json').write_text(json.dumps({'signer': 's1', 'network': 'linea', 'updated': int(time.time()), 'samples': [self.sample(126.0)]}))
            done = subprocess.run([sys.executable, str(HERE / 'signer_timing.py'), 'check', '--timing', str(Path(tmp) / 'ok.json')],
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 2)
            self.assertIn('release-window-hold', done.stdout)


class Generator(unittest.TestCase):
    def test_no_deployment_or_operator_file_exists_for_base_or_bnb(self):
        for name in ('base', 'bnb'):
            self.assertEqual(sorted(p.name for p in (ROOT / 'deployments' / name).iterdir()), ['bridge.network.json'], name)
            doc = json.loads((ROOT / 'deployments' / name / 'bridge.network.json').read_text())
            self.assertIs(doc['launch']['v1'], False)
            self.assertTrue(doc['notes'][0].startswith('NOT LAUNCHABLE IN V1'))
        files, absent = evm_nets.derive()
        self.assertEqual(len(absent), 10)
        self.assertFalse(any('/base/busdc' in str(p) or '/bnb/busdc' in str(p) or '/base/ops' in str(p) or '/bnb/ops' in str(p) for p in files))

    def test_a_deployment_file_typed_in_for_base_fails_the_check(self):
        path = ROOT / 'deployments/base/busdc-vault.config.json'
        self.assertFalse(path.exists())
        try:
            path.write_text(json.dumps(filled_vault('base')))
            done = subprocess.run([sys.executable, str(HERE / 'evm_nets.py'), 'check'], capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn('not launchable', done.stderr)
        finally:
            path.unlink()

    def test_launchable_networks_carry_the_launch_block_and_the_three_operator_templates(self):
        for name, spec in launch.launchable().items():
            doc = json.loads((ROOT / 'deployments' / name / 'bridge.network.json').read_text())
            self.assertEqual(doc['launch'], spec['launch'])
            ops = ROOT / 'deployments' / name / 'ops'
            self.assertEqual(sorted(p.name for p in ops.iterdir()), ['eth-half.template.json', 'relayer.template.json', 'signer.template.json'])
            signer, relayer, half = (json.loads((ops / f'{n}.template.json').read_text()) for n in ('signer', 'relayer', 'eth-half'))
            for c in (signer, relayer):
                self.assertEqual((c['source_chain_id'], c['eth_chain_id']), (spec['chainId'], spec['chainId']))
                self.assertEqual(launch.config_conflicts(spec['chainId'], c, 'vigia'), [])
                self.assertEqual((c['l2_chain_id'], c['l2_pins'], c['provenance']), (700770, 'mainnet-v2', True))
            self.assertEqual(launch.config_conflicts(spec['chainId'], half, 'eth_half'), [])
            self.assertEqual(signer['l2_source'], 'rebuild')
            self.assertEqual((signer['max_release_signs_per_hour'], signer['refused_retry']),
                             (spec['signer']['max_release_signs_per_hour'], spec['signer']['refused_retry']))
            self.assertIn(name, signer['timing_state'])
            self.assertNotIn('bloch-busdc-signer', json.dumps(signer))  # no file shared with the Ethereum bridge's daemons

    def test_verify_unit_is_refused_for_bnb(self):
        done = subprocess.run([sys.executable, str(HERE / 'evm_nets.py'), 'verify-unit', 'bnb', '--rpc', 'http://127.0.0.1:9', '--address',
                               addr('unit')], capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('not launchable in bridge v1 (out)', done.stderr)

    def test_the_schema_accepts_the_launch_block_and_the_two_requested_optional_fields(self):
        import network_json
        doc = json.loads((ROOT / 'deployments/op-mainnet/bridge.network.json').read_text())
        for change, ok in ((lambda d: d['launch'].update(state='held', v1=False), True), (lambda d: d.pop('launch'), True),
                           (lambda d: d['launch'].update(state='maybe'), False), (lambda d: d['launch'].pop('reason'), False),
                           (lambda d: d['launch'].update(v1='yes'), False), (lambda d: d['release'].update(router='TBD-deploy'), True),
                           (lambda d: d['fee'].update(releaseFlat='8000000'), True), (lambda d: d['fee'].update(releaseFlat=8), False)):
            d = copy.deepcopy(doc)
            change(d)
            with tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp) / 'op-mainnet'
                p.mkdir()
                (p / 'bridge.network.json').write_text(json.dumps(d))
                self.assertEqual(network_json.check(p / 'bridge.network.json') == [], ok)

    def test_preflight_refuses_a_network_that_is_not_launchable_and_a_contradicting_file(self):
        import preflight_signer
        with tempfile.TemporaryDirectory() as tmp:
            signer = json.loads((ROOT / 'deployments/op-mainnet/ops/signer.template.json').read_text())
            (Path(tmp) / 's.json').write_text(json.dumps(signer))
            for name in ('base', 'bnb', 'nowhere'):
                report = preflight_signer.run(['--config', str(Path(tmp) / 's.json'), '--network', name, '--skip-dry-release', '--skip-binaries'])
                self.assertEqual(preflight_signer.outcome(report, False), (1, 'fail'), name)
                self.assertEqual({r['group'] for r in report.failed}, {'network'}, name)
            report = preflight_signer.run(['--config', str(Path(tmp) / 's.json'), '--network', 'op-mainnet', '--skip-dry-release', '--skip-binaries'])
            names = [r['check'] for r in report.failed]
            self.assertFalse(any('chain_id' in n for n in names), names)   # chain 10 is the decided value for this network
            self.assertFalse(any(r['group'] == 'network' for r in report.failed))
            signer['anchor_policy'] = 'finalized'
            (Path(tmp) / 's.json').write_text(json.dumps(signer))
            report = preflight_signer.run(['--config', str(Path(tmp) / 's.json'), '--network', 'op-mainnet', '--skip-dry-release', '--skip-binaries'])
            self.assertTrue(any(r['group'] == 'network' and 'anchor_policy' in r['detail'] for r in report.failed))
            # Round 18: a file that omits a key the registry sets fails the preflight too, as the daemons refuse it at start.
            del signer['anchor_policy']
            (Path(tmp) / 's.json').write_text(json.dumps(signer))
            report = preflight_signer.run(['--config', str(Path(tmp) / 's.json'), '--network', 'op-mainnet', '--skip-dry-release', '--skip-binaries'])
            self.assertTrue(any(r['group'] == 'network' and 'states every anchor setting' in r['check'] and 'anchor_policy' in r['detail']
                                for r in report.failed), [r for r in report.failed if r['group'] == 'network'])


if __name__ == '__main__':
    unittest.main()
