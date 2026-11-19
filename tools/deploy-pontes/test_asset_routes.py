#!/usr/bin/env python3
"""Further asset routes of a network in the deploy tools (round 20, agent 411).

  python3 -m unittest test_asset_routes        (from tools/deploy-pontes; needs `cast` only for the constructor arguments)

What is shown, each on the committed tree and on a copy of the registry in which a route is LIFTED (both records of
the decision changed together, as a reviewed commit would):

  * held: vault_pontes.py and deploy_pontes.py refuse a USDT vault or a bUSDT token on chain 1, 42161 and 10 with the
    ROUTE's reason (not with "the token must be USDC"), with and without every other field right, and no flag helps;
  * lifted: the files `asset_routes.py write` would generate validate once the owner's values are filled in, and each
    single deviation from the route (another vault contract, transfer mode, cap, window, fee, flat fee, token,
    label, L2 name or symbol, limits) is refused;
  * the two records: a file that disagrees with the code refuses every decided pair and leaves USDC alone;
  * nothing of the first routes moved: the committed USDC configs validate as before and still refuse the Tether shape.
"""
import contextlib
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tools/evm-nets'))
import asset_routes as AR  # noqa: E402
import deploy_pontes  # noqa: E402
import launch_fixture as fx  # noqa: E402
import vault_pontes  # noqa: E402

ROUTES = ('ethereum-usdt', 'arbitrum-one-usdt', 'op-mainnet-usdt')
USDC = {1: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 42161: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
        10: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85'}
HELD = 'independent review, external audit and the owner\'s key ceremony are pending'


@contextlib.contextmanager
def lifted(*rids, edit=None, code=True):
    """The registry with `rids` launchable: a copy of asset-routes.json (optionally edited) and, with `code`, the
    matching DECIDED entries. `code=False` is the file edited by hand alone."""
    reg = json.loads(AR.REGISTRY.read_text())
    for rid in rids:
        reg['routes'][rid]['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'test: lifted in a copy of the registry'}
    if edit:
        edit(reg)
    decided = dict(AR.DECIDED)
    if code:
        for key, (rid, _) in AR.DECIDED.items():
            if rid in rids:
                decided[key] = (rid, True)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'asset-routes.json'
        path.write_text(json.dumps(reg))
        with mock.patch.object(AR, 'REGISTRY', path), mock.patch.dict(AR.DECIDED, decided, clear=True):
            yield reg


def generated(rid):
    """The vault and token configs `asset_routes.py write` derives for a route (as of the registry in force), with the
    owner's values filled by throwaway ones."""
    files, _ = AR.derive()
    by = {p.name: json.loads(t) for p, t in files.items() if p.parent.name == rid}
    tok = by.get('busdt-token.config.json')
    vault = by.get('busdt-vault.config.json')
    if tok is None or vault is None:
        return None, None
    tok['source']['revision'] = '1' * 40
    tok['deployer']['address'] = fx.fresh(1)
    tok['deployer']['fundedBy']['safe'] = fx.fresh(2)
    tok['signers']['set'] = [{'operator': f'op{i}', 'address': fx.fresh(10 + i)} for i in range(7)]
    tok['guardians']['set'] = [{'operator': f'guard{i}', 'address': fx.fresh(20 + i)} for i in range(3)]
    tok['ethereum'].update(vault=fx.fresh(30), route='0x' + '7e' * 32, vaultCodeHash='0x' + 'c0' * 32, vaultCap=tok['limits']['supplyCap'])
    tok['ethereum']['vaultGuard']['guardians'] = sorted((fx.fresh(40 + i) for i in range(3)), key=lambda a: int(a, 16))
    tok['tx']['maxGasPriceWei'] = 10**9
    vault['source']['revision'] = '1' * 40
    vault['deployer']['address'] = fx.fresh(3)
    vault['deployer']['fundedBy']['safe'] = fx.fresh(2)
    vault['vault']['signers']['set'] = [{'operator': f'rel{i}', 'address': fx.fresh(50 + i)} for i in range(7)]
    vault['vault']['guard']['guardians'] = [{'operator': f'guard{i}', 'address': a}
                                            for i, a in enumerate(tok['ethereum']['vaultGuard']['guardians'])]
    return vault, tok


def hand_made(rid):
    """What an operator would write by hand for a route today: the lifted registry's files, read while lifted."""
    with lifted(rid):
        return generated(rid)


def vault_verdict(cfg, token_cfg=None, rehearsal=False):
    try:
        vault_pontes.validate(copy.deepcopy(cfg), rehearsal, copy.deepcopy(token_cfg))
        return None
    except vault_pontes.Refused as e:
        return str(e)


def token_verdict(cfg, rehearsal=False):
    try:
        deploy_pontes.validate(copy.deepcopy(cfg), rehearsal)
        return None
    except deploy_pontes.Refused as e:
        return str(e)


class Held(unittest.TestCase):
    def test_every_route_is_held_in_both_records(self):
        reg = AR.registry()
        self.assertEqual(sorted(reg['routes']), sorted(ROUTES))
        for (chain, token), (rid, v1) in AR.DECIDED.items():
            self.assertFalse(v1, rid)
            self.assertEqual(reg['routes'][rid]['launch']['state'], 'held')
            self.assertIn(HELD, AR.refusal(chain, token))
            self.assertIn(HELD, AR.refusal(str(chain), token.upper().replace('0X', '0x')))
        self.assertEqual(AR.launchable(), {})

    def test_usdc_and_unknown_tokens_are_not_this_file_s_business(self):
        for chain, token in USDC.items():
            self.assertIsNone(AR.refusal(chain, token))
            self.assertIsNone(AR.decided(chain, token))
        self.assertIsNone(AR.refusal(1, '0x' + '12' * 20))
        self.assertIsNone(AR.refusal(59144, '0xdAC17F958D2ee523a2206206994597C13D831ec7'))  # USDT's address, another chain
        for bad in (True, 1.0, '0x1', None, -1):
            self.assertIsNone(AR.decided(bad, '0xdAC17F958D2ee523a2206206994597C13D831ec7'))

    def test_a_held_route_has_a_network_file_and_nothing_else(self):
        files, absent = AR.derive()
        self.assertEqual(sorted(str(p.relative_to(ROOT)) for p in files), sorted(f'deployments/{r}/bridge.network.json' for r in ROUTES))
        self.assertEqual(len(absent), 15)
        for rid in ROUTES:
            self.assertEqual(sorted(p.name for p in (ROOT / 'deployments' / rid).iterdir()), ['bridge.network.json'])

    def test_check_fails_while_a_held_route_has_a_deployment_file(self):
        stray = ROOT / 'deployments/op-mainnet-usdt/busdt-vault.config.json'
        self.assertFalse(stray.exists())
        try:
            stray.write_text('{}\n')
            with self.assertRaises(SystemExit) as e:
                AR.main(['check'])
            self.assertIn('files of a route that is not launchable', str(e.exception))
        finally:
            stray.unlink()
        self.assertEqual(AR.main(['check']), 0)

    def test_the_vault_tool_refuses_each_route_with_the_route_s_reason(self):
        for rid in ROUTES:
            vault, tok = hand_made(rid)
            for rehearsal_flag in (False,):
                why = vault_verdict(vault, tok, rehearsal_flag)
                with self.subTest(route=rid):
                    self.assertIsNotNone(why)
                    self.assertIn(f'route {rid}', why)
                    self.assertIn(HELD, why)
                    self.assertIn('No flag', why)

    def test_the_vault_tool_refuses_a_held_route_s_token_under_any_shape(self):
        """The USDC route's own committed shape, re-pointed at the held route's asset: still the route's refusal."""
        base = fx.filled_vault(fx.filled())
        for rid in ROUTES:
            spec = AR.registry()['routes'][rid]
            cfg = copy.deepcopy(base)
            cfg['ethereum']['chainId'] = spec['chainId']
            cfg['vault']['token'] = spec['asset']['address']
            why = vault_verdict(cfg)
            with self.subTest(route=rid):
                self.assertIn(f'route {rid}', why or '')
                self.assertIn(HELD, why or '')
            cfg['vault']['token'] = spec['asset']['address'].lower()
            self.assertIn(HELD, vault_verdict(cfg) or '')

    def test_the_token_tool_refuses_each_route_with_the_route_s_reason(self):
        for rid in ROUTES:
            _, tok = hand_made(rid)
            why = token_verdict(tok)
            with self.subTest(route=rid):
                self.assertIn(f'route {rid}', why or '')
                self.assertIn(HELD, why or '')

    def test_the_token_tool_refuses_a_held_route_s_name_or_symbol_alone(self):
        for rid in ROUTES:
            spec = AR.registry()['routes'][rid]
            for field in ('name', 'symbol'):
                cfg = fx.filled()
                cfg['ethereum']['chainId'] = spec['chainId']
                cfg['token'][field] = spec['l2'][field]
                with self.subTest(route=rid, field=field):
                    self.assertIn(f'route {rid}', token_verdict(cfg) or '')

    def test_the_route_command_refuses_and_prints_why(self):
        for rid in ROUTES:
            done = subprocess.run([sys.executable, str(HERE / 'deploy_pontes.py'), 'route', rid, 'validate'], capture_output=True, text=True)
            with self.subTest(route=rid):
                self.assertNotEqual(done.returncode, 0)
                self.assertIn(f'route {rid} is not launchable in v1 (held)', done.stdout + done.stderr)

    def test_no_environment_variable_or_rehearsal_flag_lifts_a_route_on_its_own_chain(self):
        vault, tok = hand_made('ethereum-usdt')
        with mock.patch.dict('os.environ', {'BLOCH_BRIDGE_ALLOW_HELD': '1', 'ASSET_ROUTES_LIFT': 'ethereum-usdt'}):
            self.assertIn(HELD, vault_verdict(vault, tok) or '')
            self.assertIn(HELD, token_verdict(tok) or '')
        # --rehearsal is chain 31337 only: the route's own chain id never validates under it
        v2 = copy.deepcopy(vault)
        v2['ethereum']['rehearsal'] = True
        self.assertIn('chainId must be 31337', vault_verdict(v2, rehearsal=True) or '')


class TwoRecords(unittest.TestCase):
    def test_a_file_lifted_by_hand_refuses_every_decided_pair(self):
        with lifted('arbitrum-one-usdt', code=False):
            with self.assertRaises(AR.RouteError):
                AR.registry()
            for (chain, token), (rid, _) in AR.DECIDED.items():
                why = AR.refusal(chain, token)
                self.assertIn('cannot be trusted', why)
                self.assertIn(rid, why)
            self.assertIsNone(AR.refusal(42161, USDC[42161]))
            vault, tok = hand_made('arbitrum-one-usdt')
        with lifted('arbitrum-one-usdt', code=False):
            self.assertIn('cannot be trusted', vault_verdict(vault, tok) or '')
            self.assertIn('cannot be trusted', token_verdict(tok) or '')
            self.assertIsNone(vault_verdict(fx.filled_vault(fx.filled()), fx.filled()))  # Ethereum USDC: untouched
            self.assertIsNone(token_verdict(fx.filled()))

    def test_every_disagreement_between_the_file_and_the_code_is_refused(self):
        def drop(reg):
            del reg['routes']['op-mainnet-usdt']

        def fee(reg):
            reg['routes']['ethereum-usdt']['feeBps']['release'] = 5

        def minimum(reg):
            reg['routes']['arbitrum-one-usdt']['l2MinBurn'] = 1_000_000

        def cap(reg):
            reg['routes']['op-mainnet-usdt']['limits']['cap'] = 500_000_000_000

        def window(reg):
            reg['routes']['ethereum-usdt']['limits']['window'] = 500_000_000_000

        def creation(reg):
            reg['routes']['ethereum-usdt']['vault']['creationKeccak'] = '0x' + '00' * 32

        def frozen_for_tether(reg):
            reg['routes']['ethereum-usdt']['vault'].update(contract=AR.FROZEN_VAULT, creationKeccak=AR.VAULTS[AR.FROZEN_VAULT][0],
                                                           transferMode=0, releaseFlat=None)

        def mode(reg):
            reg['routes']['arbitrum-one-usdt']['vault']['transferMode'] = 1

        def flat(reg):
            reg['routes']['ethereum-usdt']['vault']['releaseFlat'] = 1_000_000

        def symbol(reg):
            reg['routes']['arbitrum-one-usdt']['l2']['symbol'] = 'bUSDC.arb'

        def twin(reg):
            reg['routes']['op-mainnet-usdt']['l2']['symbol'] = 'bUSDT'

        def asset(reg):
            reg['routes']['op-mainnet-usdt']['asset']['address'] = USDC[10]

        def chain(reg):
            reg['routes']['op-mainnet-usdt']['chainId'] = 42161

        def name(reg):
            reg['routes']['tether-on-ethereum'] = reg['routes'].pop('ethereum-usdt')

        def decimals(reg):
            reg['routes']['ethereum-usdt']['asset']['decimals'] = 18

        def guard_gone(reg):
            reg['routes']['arbitrum-one-usdt']['guard']['codes'] = []

        def guard_other(reg):
            reg['routes']['arbitrum-one-usdt']['guard']['codes'] = [{'address': '0x' + '11' * 20, 'keccak': '0x' + '22' * 32, 'what': 'x'}]

        def guard_call(reg):
            reg['routes']['ethereum-usdt']['guard']['calls'][0]['selector'] = '--help'

        def state(reg):
            reg['routes']['ethereum-usdt']['launch']['state'] = 'launchable'

        for edit in (drop, fee, minimum, cap, window, creation, frozen_for_tether, mode, flat, symbol, twin, asset, chain, name,
                     decimals, guard_gone, guard_other, guard_call, state):
            with self.subTest(edit=edit.__name__), lifted(edit=edit):
                with self.assertRaises(AR.RouteError):
                    AR.registry()
                for (c, token) in AR.DECIDED:
                    self.assertIsNotNone(AR.refusal(c, token))

    def test_a_missing_or_unreadable_file_refuses_every_decided_pair_and_no_other(self):
        with mock.patch.object(AR, 'REGISTRY', Path('/nonexistent/asset-routes.json')):
            for (c, token) in AR.DECIDED:
                self.assertIn('cannot be trusted', AR.refusal(c, token))
            self.assertIsNone(AR.refusal(1, USDC[1]))
            self.assertIsNone(vault_verdict(fx.filled_vault(fx.filled()), fx.filled()))

    def test_an_untrusted_launch_registry_refuses_every_further_route(self):
        import launch
        with mock.patch.object(launch, 'REGISTRY', Path('/nonexistent/networks.json')):
            for (c, token) in AR.DECIDED:
                self.assertIn('cannot be trusted', AR.refusal(c, token))


class Lifted(unittest.TestCase):
    def test_a_lifted_route_gets_its_five_files_and_the_others_none(self):
        with lifted('ethereum-usdt'):
            files, absent = AR.derive()
            names = sorted(str(p.relative_to(ROOT / 'deployments')) for p in files)
            self.assertEqual(names, sorted([
                'arbitrum-one-usdt/bridge.network.json', 'op-mainnet-usdt/bridge.network.json', 'ethereum-usdt/bridge.network.json',
                'ethereum-usdt/busdt-vault.config.json', 'ethereum-usdt/busdt-token.config.json',
                'ethereum-usdt/ops/eth-half.template.json', 'ethereum-usdt/ops/signer.template.json',
                'ethereum-usdt/ops/relayer.template.json']))
            self.assertEqual(len(absent), 10)
            net = json.loads(files[ROOT / 'deployments/ethereum-usdt/bridge.network.json'])
            self.assertEqual(net['launch']['state'], 'launchable')

    def test_the_generated_files_of_each_route_validate_when_lifted(self):
        for rid in ROUTES:
            with lifted(rid):
                vault, tok = generated(rid)
                spec = AR.registry()['routes'][rid]
                with self.subTest(route=rid):
                    self.assertIsNone(vault_verdict(vault, tok))
                    self.assertIsNone(token_verdict(tok))
                    v = vault['vault']
                    self.assertEqual((v['contract'], v['transferMode'], v['token'], v['cap'], v['policy']['windowLimit']),
                                     (spec['vault']['contract'], spec['vault']['transferMode'], spec['asset']['address'],
                                      spec['limits']['cap'], spec['limits']['window']))
                    self.assertEqual((tok['token']['name'], tok['token']['symbol'], tok['ethereum']['chainId']),
                                     (spec['l2']['name'], spec['l2']['symbol'], spec['chainId']))
                    self.assertEqual((tok['limits']['supplyCap'], tok['limits']['bucketCapacity'], tok['limits']['minBurn']),
                                     (spec['limits']['cap'], spec['limits']['window'], spec['l2MinBurn']))
                    self.assertEqual('releaseFlat' in v['provenance']['fees'], rid == 'ethereum-usdt')

    def test_the_constructor_arguments_of_the_tether_vault_carry_the_flat_fee_field(self):
        with lifted('ethereum-usdt'):
            vault, tok = generated('ethereum-usdt')
            norm = vault_pontes.validate(copy.deepcopy(vault), False, tok)
            args = vault_pontes.constructor_args(vault, norm)
        self.assertEqual(args[5], '1')  # transferMode: exact balance deltas are authoritative
        self.assertTrue(args[-1].endswith(',5,10,0))'), args[-1])
        with lifted('op-mainnet-usdt'):
            vault, tok = generated('op-mainnet-usdt')
            norm = vault_pontes.validate(copy.deepcopy(vault), False, tok)
            args = vault_pontes.constructor_args(vault, norm)
        self.assertEqual(args[5], '0')
        self.assertTrue(args[-1].endswith(',5,5))'), args[-1])

    def test_every_single_deviation_of_a_lifted_vault_config_is_refused(self):
        def put(path, value):
            def edit(c):
                d = c
                for k in path[:-1]:
                    d = d[k]
                d[path[-1]] = value
            return edit
        cases = {
            'ethereum-usdt': [
                put(('vault', 'contract'), AR.FROZEN_VAULT), put(('vault', 'transferMode'), 0),
                put(('vault', 'cap'), 100_000_000_000), put(('vault', 'policy', 'windowLimit'), 10_000_000_000),
                put(('vault', 'policy', 'windowSeconds'), 3600), put(('vault', 'provenance', 'fees', 'releaseBps'), 5),
                put(('vault', 'provenance', 'fees', 'releaseFlat'), 1), put(('vault', 'provenance', 'fees', 'recipient'), fx.fresh(77)),
                put(('vault', 'token'), USDC[1]), put(('vault', 'assetLabel'), 'USDC'),
                put(('vault', 'sourceDomainLabel'), 'ethereum-mainnet-usdt'), put(('vault', 'policy', 'minDeposit'), 21_000_000),
                put(('vault', 'policy', 'l2MinBurn'), 20_000_000), put(('vault', 'signers', 'threshold'), 4),
                put(('vault', 'policy', 'switchThreshold'), 5), put(('ethereum', 'chainId'), 10)],
            'arbitrum-one-usdt': [
                put(('vault', 'contract'), AR.TETHER_VAULT), put(('vault', 'transferMode'), 1),
                put(('vault', 'cap'), 500_000_000_000), put(('vault', 'policy', 'windowLimit'), 50_000_000_000),
                put(('vault', 'token'), USDC[42161]), put(('vault', 'assetLabel'), 'USDT'),
                put(('vault', 'provenance', 'fees', 'depositBps'), 0), put(('ethereum', 'chainId'), 1)],
            'op-mainnet-usdt': [
                put(('vault', 'token'), '0xdAC17F958D2ee523a2206206994597C13D831ec7'), put(('vault', 'assetLabel'), 'USDT0'),
                put(('vault', 'cap'), 250_000_000_001), put(('ethereum', 'chainId'), 42161)],
        }
        for rid, edits in cases.items():
            with lifted(rid):
                vault, tok = generated(rid)
                self.assertIsNone(vault_verdict(vault, tok), rid)
                for n, edit in enumerate(edits):
                    bad = copy.deepcopy(vault)
                    edit(bad)
                    with self.subTest(route=rid, case=n):
                        self.assertIsNotNone(vault_verdict(bad, tok), (rid, n))

    def test_every_single_deviation_of_a_lifted_token_config_is_refused(self):
        for rid in ROUTES:
            with lifted(rid):
                _, tok = generated(rid)
                spec = AR.registry()['routes'][rid]
                first = {1: ('Bloch Bridged USDC', 'bUSDC'), 42161: ('Bloch Bridged USDC (Arbitrum)', 'bUSDC.arb'),
                         10: ('Bloch Bridged USDC (OP Mainnet)', 'bUSDC.op')}[spec['chainId']]
                bads = []
                for field, value in (('name', first[0]), ('symbol', first[1]), ('symbol', 'bUSDT.x'), ('name', 'Bloch Bridged USDT (Other)')):
                    c = copy.deepcopy(tok)
                    c['token'][field] = value
                    bads.append(c)
                for key, value in (('supplyCap', spec['limits']['cap'] - 1), ('bucketCapacity', spec['limits']['window'] - 1),
                                   ('minBurn', spec['l2MinBurn'] + 1)):
                    c = copy.deepcopy(tok)
                    c['limits'][key] = value
                    if key == 'supplyCap':
                        c['ethereum']['vaultCap'] = value
                    bads.append(c)
                other = copy.deepcopy(tok)
                other['ethereum']['chainId'] = {1: 10, 42161: 1, 10: 42161}[spec['chainId']]
                bads.append(other)
                for n, c in enumerate(bads):
                    with self.subTest(route=rid, case=n):
                        self.assertIsNotNone(token_verdict(c), (rid, n))

    def test_a_lifted_route_does_not_open_another(self):
        with lifted('ethereum-usdt'):
            for rid in ('arbitrum-one-usdt', 'op-mainnet-usdt'):
                spec = AR.registry()['routes'][rid]
                self.assertIn(HELD, AR.refusal(spec['chainId'], spec['asset']['address']))
        vault, tok = hand_made('op-mainnet-usdt')
        with lifted('ethereum-usdt'):
            self.assertIn(HELD, vault_verdict(vault, tok) or '')
            self.assertIn(HELD, token_verdict(tok) or '')

    def test_the_source_asset_the_token_tool_expects_of_each_vault(self):
        ex = deploy_pontes.expected_source_asset
        self.assertEqual(ex(1, 'Bloch Bridged USDC', 'bUSDC'), USDC[1].lower())
        self.assertEqual(ex(42161, 'Bloch Bridged USDC (Arbitrum)', 'bUSDC.arb'), USDC[42161].lower())
        self.assertEqual(ex(10, 'Bloch Bridged USDC (OP Mainnet)', 'bUSDC.op'), USDC[10].lower())
        with lifted(*ROUTES):
            for rid in ROUTES:
                s = AR.registry()['routes'][rid]
                self.assertEqual(ex(s['chainId'], s['l2']['name'], s['l2']['symbol']), s['asset']['address'].lower())
        self.assertIsNone(ex(31337, 'Anything', 'x'))
        self.assertIsNone(ex(728126428, 'Bloch Bridged USDT (Tron)', 'bUSDT.trx'))


class RouteFiles(unittest.TestCase):
    """The route's bridge.network.json: what the DEX bridge page reads (schema bloch.bridge.network.v1 + `route`)."""
    def setUp(self):
        import network_json
        self.nj = network_json

    def placed(self, doc, directory):
        """The checker's verdict on `doc` written as deployments/<directory>/bridge.network.json of a scratch tree."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / directory / 'bridge.network.json'
            path.parent.mkdir()
            path.write_text(json.dumps(doc))
            return self.nj.check(path)

    def doc(self, rid):
        return json.loads((ROOT / 'deployments' / rid / 'bridge.network.json').read_text())

    def test_the_three_committed_files_are_valid_and_say_held(self):
        for rid in ROUTES:
            d = self.doc(rid)
            spec = AR.registry()['routes'][rid]
            with self.subTest(route=rid):
                self.assertEqual(self.nj.check(ROOT / 'deployments' / rid / 'bridge.network.json'), [])
                self.assertEqual(d['route'], {'id': rid, 'asset': 'usdt'})
                self.assertEqual((d['network']['id'], d['network']['chainId']), (spec['network'], str(spec['chainId'])))
                self.assertEqual((d['launch']['v1'], d['launch']['state']), (False, 'held'))
                self.assertEqual(d['asset']['id'], spec['asset']['address'])
                self.assertEqual(d['custody']['contract'], spec['vault']['contract'])
                self.assertEqual((d['l2']['symbol'], d['l2']['name']), (spec['l2']['symbol'], spec['l2']['name']))
                self.assertEqual(d['custody']['address'], 'TBD-deploy')
                self.assertTrue(d['notes'][0].startswith('NOT LAUNCHABLE IN V1 (held)'))

    def test_the_page_is_told_how_each_token_deviates(self):
        eth, arb, op = (self.doc(r) for r in ROUTES)
        self.assertEqual((eth['asset']['behaviour']['returnsNoValue'], eth['asset']['behaviour']['approveZeroFirst']), (True, True))
        self.assertIn('approve(vault, 0)', eth['deposit']['steps'][0])
        self.assertIn('return no data', eth['deposit']['steps'][1])
        for d in (arb, op):
            self.assertEqual((d['asset']['behaviour']['returnsNoValue'], d['asset']['behaviour']['approveZeroFirst']), (False, False))
            self.assertNotIn('approve(vault, 0)', ' '.join(d['deposit']['steps']))
        self.assertEqual(len(arb['asset']['behaviour']['recipientRefusals']), 1)
        self.assertTrue(any('never name the token contract itself' in n for n in arb['release']['notes']))
        self.assertEqual(arb['asset']['symbol'], 'USD\u20ae0')
        self.assertFalse(arb['asset']['issuerNative'] or op['asset']['issuerNative'])
        self.assertTrue(eth['asset']['issuerNative'])
        for d in (eth, arb, op):
            self.assertIn('admin', d['asset'])
            self.assertIn('contractIs', d['asset'])
            self.assertEqual(len(d['asset']['verified']), 2)

    def test_the_directory_of_a_file_with_a_route_block_is_its_route_id(self):
        d = self.doc('ethereum-usdt')
        self.assertEqual(self.placed(d, 'ethereum-usdt'), [])
        self.assertTrue(any('directory = route.id' in e for e in self.placed(d, 'ethereum')))
        self.assertTrue(any('directory = route.id' in e for e in self.placed(d, 'usdt')))

    def test_a_route_id_must_be_the_network_id_and_the_asset_key(self):
        for edit in (lambda d: d['route'].__setitem__('id', 'ethereum-tether'), lambda d: d['route'].__setitem__('asset', 'usdc'),
                     lambda d: d['network'].__setitem__('id', 'mainnet'), lambda d: d['route'].__setitem__('id', 'Ethereum-usdt'),
                     lambda d: d['route'].__setitem__('asset', 'USDT')):
            d = self.doc('ethereum-usdt')
            edit(d)
            found = self.placed(d, d['route']['id'].lower() if d['route']['id'] != 'Ethereum-usdt' else 'ethereum-usdt')
            self.assertTrue(found, d['route'])

    def test_an_unknown_or_incomplete_route_or_behaviour_block_is_refused(self):
        for edit in (lambda d: d['route'].__setitem__('launch', True), lambda d: d['route'].pop('asset'),
                     lambda d: d.__setitem__('route', 'ethereum-usdt'), lambda d: d['asset']['behaviour'].pop('approveZeroFirst'),
                     lambda d: d['asset']['behaviour'].__setitem__('approveZeroFirst', 'yes'),
                     lambda d: d['asset']['behaviour'].__setitem__('extra', 1),
                     lambda d: d['asset']['behaviour'].__setitem__('recipientRefusals', 'none')):
            d = self.doc('ethereum-usdt')
            edit(d)
            self.assertTrue(self.placed(d, 'ethereum-usdt'), 'accepted a malformed file')

    def test_a_file_without_a_route_block_keeps_the_old_rule(self):
        d = json.loads((ROOT / 'deployments/arbitrum-one/bridge.network.json').read_text())
        self.assertNotIn('route', d)
        self.assertEqual(self.placed(d, 'arbitrum-one'), [])
        self.assertTrue(any('directory = network.id' in e for e in self.placed(d, 'arbitrum-one-usdt')))
        self.assertTrue(any('directory = network.id' in e for e in self.placed(d, 'arbitrum')))


class FirstRoutesUnmoved(unittest.TestCase):
    def test_the_committed_usdc_configs_validate_as_before(self):
        tok = fx.filled()
        self.assertIsNone(token_verdict(tok))
        self.assertIsNone(vault_verdict(fx.filled_vault(tok), tok))
        other = fx.filled_vault(tok)
        other['vault']['transferMode'] = 1
        self.assertIn('transferMode must be 0', vault_verdict(other, tok))
        other = fx.filled_vault(tok)
        other['vault']['contract'] = AR.TETHER_VAULT
        self.assertIsNotNone(vault_verdict(other, tok))


if __name__ == '__main__':
    unittest.main()
