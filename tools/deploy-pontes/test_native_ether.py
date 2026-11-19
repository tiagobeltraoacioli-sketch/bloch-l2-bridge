#!/usr/bin/env python3
"""The native-ether route `ethereum-eth` (bETH) in the deploy tools (agent 412, round 20). Offline: no node, no cast.

  python3 -m unittest test_native_ether        (from tools/deploy-pontes)

What is pinned:
  - the route is HELD and every deployment tool refuses a non-rehearsal config of it with the route's own reason; the
    two launch records (code and route file) must BOTH say launchable before anything is accepted, and every way of
    reading them fails closed;
  - the numbers: minimum burn from the measured worst-case release at the 30 gwei ceiling, minimum deposit from the
    minimum burn through the fee rounded up, cap and window from the USD rule at the recorded price;
  - the three route files and the module state ONE set of values;
  - the Ethereum USDC route is untouched: its committed configs hash and validate as before, and neither vault
    contract can be configured as the other's route.
"""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import deploy_pontes  # noqa: E402
import launch_fixture as fx  # noqa: E402
import vault_pontes  # noqa: E402
sys.path.insert(0, str(ROOT / 'tools/signatario-stable'))
import native_ether as ne  # noqa: E402

ROUTE = ROOT / 'deployments/ethereum-eth'
USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
FROZEN_TOKEN = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
# Canonical SHA-256 of the committed Ethereum USDC configs at main 135bdba (vault_pontes.canonical / config_sha256):
# this route's tool changes must not move them.
USDC_VAULT_SHA = '479e5d22cfd449e37692db4ad4e068e0a9234a23e5337bbe1a2ce77f44f058b2'
USDC_TOKEN_SHA = '0xfee6eb833e913735b7164e12a9ca4b17d3b954eea37965e317ebcf75693e412b'


def filled_token():
    cfg = json.loads((ROUTE / 'beth-token.config.json').read_text())
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


def filled_vault(token_cfg=None):
    cfg = json.loads((ROUTE / 'beth-vault.config.json').read_text())
    cfg['source']['revision'] = '1' * 40
    cfg['deployer']['address'] = fx.fresh(3)
    cfg['deployer']['fundedBy']['safe'] = fx.fresh(2)
    v = cfg['vault']
    v['signers']['set'] = [{'operator': f'rel{i}', 'address': fx.fresh(50 + i)} for i in range(7)]
    guards = (token_cfg or filled_token())['ethereum']['vaultGuard']['guardians']
    v['guard']['guardians'] = [{'operator': f'guard{i}', 'address': a} for i, a in enumerate(guards)]
    return cfg


def rehearsal_vault(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['ethereum'] = {'chainId': 31337, 'rehearsal': True}
    return cfg


def vault_verdict(cfg, rehearsal=False, token_cfg=None):
    try:
        vault_pontes.validate(copy.deepcopy(cfg), rehearsal, token_cfg)
        return None
    except vault_pontes.Refused as e:
        return str(e)


def token_verdict(cfg, rehearsal=False):
    try:
        deploy_pontes.validate(copy.deepcopy(cfg), rehearsal)
        return None
    except deploy_pontes.Refused as e:
        return str(e)


@contextlib.contextmanager
def records(code=None, file=None, drop_file=False, drop_block=False):
    """The two launch records replaced for the duration: `code` replaces native_ether.LAUNCH, `file` the route file's
    `launch` block (on a temporary copy; the committed file is never written)."""
    real_launch, real_file = dict(ne.LAUNCH), ne.ROUTE_FILE
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'bridge.network.json'
        doc = json.loads(real_file.read_text())
        if file is not None:
            doc['launch'] = file
        if drop_block:
            doc.pop('launch', None)
        if not drop_file:
            path.write_text(json.dumps(doc))
        if code is not None:
            ne.LAUNCH.clear()
            ne.LAUNCH.update(code)
        ne.ROUTE_FILE = path
        try:
            yield path
        finally:
            ne.LAUNCH.clear()
            ne.LAUNCH.update(real_launch)
            ne.ROUTE_FILE = real_file


OPEN = {'v1': True, 'state': 'launchable'}
OPEN_FILE = {'v1': True, 'state': 'launchable', 'reason': 'test copy: both records lifted'}


class LaunchGate(unittest.TestCase):
    def test_the_committed_route_is_held_in_both_records(self):
        code, block = ne.launch_records()
        self.assertEqual(code, {'v1': False, 'state': 'held'})
        self.assertEqual((block['v1'], block['state']), (False, 'held'))
        for word in ('independent review', 'external audit', 'key ceremony'):
            self.assertIn(word, block['reason'])
        why = ne.refusal()
        self.assertIn('not launchable in v1 (held)', why)
        self.assertIn('external audit', why)

    def test_only_both_records_launchable_lift_it(self):
        with records(code=OPEN, file=OPEN_FILE):
            self.assertIsNone(ne.refusal())
        with records(code=OPEN):  # the file still says held
            self.assertIn('disagree', ne.refusal())
        with records(file=OPEN_FILE):  # the code still says held
            self.assertIn('disagree', ne.refusal())

    def test_every_broken_reading_is_a_refusal(self):
        with records(code=OPEN, drop_file=True):
            self.assertIn('missing', ne.refusal())
        with records(code=OPEN, drop_block=True):
            self.assertIn('no `launch` block', ne.refusal())
        with records(code=OPEN, file='launchable'):  # not an object
            self.assertIn('no `launch` block', ne.refusal())
        with records(code=OPEN, file={'v1': 'true', 'state': 'launchable', 'reason': 'x'}):  # a string is not true
            self.assertIn('disagree', ne.refusal())
        with records(code=OPEN, file={'v1': True, 'state': 'held', 'reason': 'x'}):
            self.assertIn('disagree', ne.refusal())
        with records(code={'v1': True, 'state': 'held'}, file={'v1': True, 'state': 'held', 'reason': 'x'}):
            self.assertIn('not launchable in v1 (held)', ne.refusal())  # v1 true alone opens nothing
        with records(code={'v1': 1, 'state': 'launchable'}, file={'v1': 1, 'state': 'launchable', 'reason': 'x'}):
            self.assertIsNotNone(ne.refusal())  # 1 is not True
        with records(code=OPEN, file=OPEN_FILE) as path:
            path.write_text('{not json')
            self.assertIn('missing, unreadable', ne.refusal())

    def test_the_signer_gate_reads_the_code_record_alone(self):
        self.assertIn('not launchable in v1 (held)', ne.daemon_refusal(1))
        self.assertIn('nothing is attested or signed', ne.daemon_refusal('1'))
        for chain in (31337, 900_000_001, 700771):  # local rehearsal chains
            self.assertIsNone(ne.daemon_refusal(chain))
        with records(drop_file=True):  # an operator host has no deployments/: still decided, still held
            self.assertIsNotNone(ne.daemon_refusal(1))
        with records(code=OPEN, drop_file=True):
            self.assertIsNone(ne.daemon_refusal(1))
        with records(file=OPEN_FILE):  # the file cannot lift the signer gate
            self.assertIsNotNone(ne.daemon_refusal(1))


class Numbers(unittest.TestCase):
    def test_minimum_burn_pays_the_worst_release_at_the_ceiling(self):
        gas, gwei, bps = ne.RELAY['releaseGasWorst'], ne.RELAY['gasCeilingGwei'], ne.FEE_BPS['release']
        self.assertEqual((gas, gwei, bps), (227_000, 30, 10))
        floor = ne.min_burn_floor()
        self.assertEqual(floor, 6_810_000)  # 6.81 ETH
        cost_wei = gas * gwei * 10**9
        self.assertGreaterEqual(ne.fee_up(floor, bps) * ne.UNIT_WEI, cost_wei)        # the fee pays the relayer
        self.assertLess(ne.fee_up(floor - 1000, bps) * ne.UNIT_WEI, cost_wei)         # and a smaller exit would not
        burn = ne.LIMITS['l2MinBurn']
        self.assertEqual(burn, 7_000_000)
        self.assertGreaterEqual(burn, floor)
        self.assertGreaterEqual(ne.fee_up(burn, bps) * ne.UNIT_WEI, cost_wei)
        self.assertGreater(ne.break_even_gwei(burn, gas), 30)
        self.assertGreaterEqual(ne.RELAY['releaseGasWorst'], ne.RELAY['releaseGasNewAccount'])
        self.assertGreaterEqual(ne.RELAY['releaseGasNewAccount'], ne.RELAY['releaseGasPlain'])

    def test_minimum_deposit_nets_the_minimum_burn(self):
        burn, dep = ne.LIMITS['l2MinBurn'], ne.LIMITS['minDeposit']
        least = ne.min_deposit_for(burn)
        self.assertEqual(least, 7_003_502)
        self.assertEqual(ne.net_of(least), burn)
        self.assertLess(ne.net_of(least - 1), burn)
        self.assertGreaterEqual(dep, least)
        self.assertEqual((dep, ne.net_of(dep)), (7_004_000, 7_000_498))

    def test_fee_rounds_up_and_never_gains_for_the_user(self):
        rng = random.Random(412)
        for _ in range(20_000):
            a, bps = rng.randrange(1, 2**40), rng.choice((1, 5, 10, 30))
            f = ne.fee_up(a, bps)
            self.assertGreaterEqual(f * 10_000, a * bps)
            self.assertLess((f - 1) * 10_000, a * bps)
            b = rng.randrange(1, 2**40)
            self.assertGreaterEqual(ne.fee_up(a, bps) + ne.fee_up(b, bps), ne.fee_up(a + b, bps))
        self.assertEqual([ne.fee_up(x, 5) for x in (10_006, 20_000, 20_001)], [6, 10, 11])
        self.assertEqual(ne.fee_up(10_001, 10), 11)

    def test_limits_follow_the_usd_rule_at_the_recorded_price(self):
        n = ne.numbers()
        self.assertEqual((ne.LIMITS['cap'], ne.LIMITS['windowLimit'], ne.LIMITS['windowSeconds']), (280_000_000, 28_000_000, 86_400))
        self.assertEqual(ne.LIMITS['cap'] % ne.UNITS_PER_ETHER, 0)          # whole ether
        self.assertEqual(ne.LIMITS['windowLimit'] % ne.UNITS_PER_ETHER, 0)
        self.assertLessEqual(n['usd']['cap'], 500_000)
        self.assertLessEqual(n['usd']['window'], 50_000)
        # round numbers: the cap is the largest multiple of 10 ETH inside the rule, the window a tenth of it (as the
        # USD rule's 500,000 / 50,000) and the largest whole number of ether inside its own rule
        self.assertEqual(ne.LIMITS['cap'] % (10 * ne.UNITS_PER_ETHER), 0)
        self.assertGreater((ne.LIMITS['cap'] // ne.UNITS_PER_ETHER + 10) * ne.PRICE['usdPerEther'], 500_000)
        self.assertEqual(ne.LIMITS['cap'], 10 * ne.LIMITS['windowLimit'])
        self.assertGreater((ne.LIMITS['windowLimit'] // ne.UNITS_PER_ETHER + 1) * ne.PRICE['usdPerEther'], 50_000)
        self.assertEqual(n['usd']['capAtDoublePrice'], 2 * n['usd']['cap'])
        self.assertEqual(len(ne.PRICE['sources']) >= 2, True)
        self.assertLess(ne.LIMITS['l2MinBurn'], ne.LIMITS['windowLimit'])
        self.assertLessEqual(ne.LIMITS['minDeposit'], ne.LIMITS['windowLimit'])

    def test_units(self):
        self.assertEqual(ne.UNIT_WEI * ne.UNITS_PER_ETHER, 10**18)
        self.assertEqual(ne.units_of_wei(10**18 + 999_999_999_999), 1_000_000)   # wei below a unit never count
        self.assertEqual(ne.MARKER, '0x' + 'ee' * 20)


class Files(unittest.TestCase):
    def setUp(self):
        self.route = json.loads((ROUTE / 'bridge.network.json').read_text())
        self.vault = json.loads((ROUTE / 'beth-vault.config.json').read_text())
        self.token = json.loads((ROUTE / 'beth-token.config.json').read_text())

    def test_one_set_of_values_in_the_three_files_and_the_module(self):
        v, pol, lim, r = self.vault['vault'], self.vault['vault']['policy'], self.token['limits'], self.route['limits']
        self.assertEqual({'cap': v['cap'], **{k: pol[k] for k in ('windowLimit', 'windowSeconds', 'l2MinBurn', 'minDeposit')}}, ne.LIMITS)
        self.assertEqual((lim['supplyCap'], lim['bucketCapacity'], lim['minBurn']), (v['cap'], pol['windowLimit'], pol['l2MinBurn']))
        self.assertEqual(lim['refillPerSecond'], pol['windowLimit'] // pol['windowSeconds'])
        self.assertEqual((lim['largeMintThreshold'], lim['largeMintDelay']), (0, 43_200))       # T = 0, 12 h
        self.assertEqual((r['cap'], r['window'], r['minDeposit'], r['l2MinBurn'], r['maxDeposit'], r['l2MaxBurn']),
                         tuple(str(x) for x in (v['cap'], pol['windowLimit'], pol['minDeposit'], pol['l2MinBurn'],
                                                pol['windowLimit'], pol['windowLimit'])))
        self.assertEqual((r['windowSeconds'], r['mintDelaySeconds'], r['largeItemThreshold']), (86_400, 43_200, '0'))
        fees = v['provenance']['fees']
        self.assertEqual((fees['recipient'].lower(), fees['depositBps'], fees['releaseBps']), (ne.FEE_RECIPIENT, 5, 10))
        self.assertEqual((self.route['fee']['recipient'], self.route['fee']['depositBps'], self.route['fee']['releaseBps']),
                         ('0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544', 5, 10))
        self.assertEqual(self.route['release']['gasCeilingGwei'], str(ne.RELAY['gasCeilingGwei']))

    def test_identity_of_the_route(self):
        r, v, t = self.route, self.vault['vault'], self.token
        self.assertEqual(r['route'], {'id': 'ethereum-eth', 'asset': 'eth'})
        self.assertEqual((r['network']['id'], r['network']['chainId'], r['network']['kind']), ('ethereum', '1', 'evm'))
        self.assertEqual((r['launch']['v1'], r['launch']['state']), (False, 'held'))
        self.assertEqual(r['status'], 'unaudited-not-deployed')
        self.assertEqual(r['custody']['contract'], ne.CONTRACT)
        self.assertEqual(v['contract'], ne.CONTRACT)
        self.assertTrue((ROOT / ne.CONTRACT.split(':')[0]).is_file())
        self.assertEqual(v['token'].lower(), ne.MARKER)
        self.assertEqual((v['sourceDomainLabel'], v['nativeDomainLabel'], v['assetLabel']),
                         ('ethereum-mainnet', 'bloch-l2-700770', 'ETH'))
        self.assertEqual(v['transferMode'], 0)
        self.assertEqual((v['signers']['threshold'], len(v['signers']['set']), v['policy']['switchThreshold']), (5, 7, 6))
        self.assertEqual((len(v['guard']['guardians']), v['guard']['pauseDuration'], v['guard']['pauseCooldown']), (3, 259_200, 259_200))
        self.assertEqual(v['provenance']['mode'], 1)
        self.assertEqual((v['provenance']['releaseDelay'], v['provenance']['mintVerifier']), (0, None))
        # the L2 token is the frozen contract, isolated for this route, six decimals
        self.assertEqual((r['l2']['name'], r['l2']['symbol'], r['l2']['decimals'], r['l2']['chainId']),
                         ('Bloch Bridged Ether', 'bETH', 6, 700770))
        self.assertEqual(r['l2']['creationCodeKeccak'], FROZEN_TOKEN)
        self.assertTrue(r['l2']['contract'].endswith(':BridgedStablecoinV3'))
        self.assertEqual((t['token']['contract'], t['token']['name'], t['token']['symbol']),
                         ('BridgedStablecoinV3', 'Bloch Bridged Ether', 'bETH'))
        self.assertEqual((t['ethereum']['chainId'], t['network']['chainId'], t['network']['rehearsal']), (1, 700770, False))
        self.assertEqual((r['committee']['threshold'], r['committee']['switchThreshold'], r['committee']['guardianPower'],
                          r['committee']['pauseSeconds'], r['committee']['scheme']), (5, 6, 'pause-only', 259_200, 'secp256k1'))
        # the unit: the page must send amount x 1e12 wei
        self.assertEqual((r['asset']['decimals'], r['asset']['id'], r['asset']['unit']['decimals'],
                          r['asset']['unit']['assetUnitsPerUnit']), (18, 'native', 6, str(ne.UNIT_WEI)))
        self.assertIn('payable', r['deposit']['function'])
        self.assertNotIn('approvalTarget', r['deposit'])
        text = json.dumps(r)
        for word in ('claimFor', 'ReleaseDeferred', 'ValueMismatch', 'DirectTransferRefused', 'SIX decimals'):
            self.assertIn(word, text)

    def test_nothing_is_decided_that_only_the_owner_decides(self):
        v = self.vault
        self.assertIsNone(v['source']['revision'])
        self.assertIsNone(v['deployer']['address'])
        self.assertTrue(all(s == {'operator': None, 'address': None} for s in v['vault']['signers']['set']))
        self.assertTrue(all(g == {'operator': None, 'address': None} for g in v['vault']['guard']['guardians']))
        for key in ('address', 'codeHash', 'route', 'fromBlock'):
            self.assertEqual(self.route['custody'][key], 'TBD-deploy')
        self.assertEqual(self.route['l2']['token'], 'TBD-deploy')
        self.assertIn('undecided', vault_verdict(v))      # the committed template itself validates nowhere
        self.assertIsNotNone(token_verdict(self.token))


class VaultTool(unittest.TestCase):
    def test_a_filled_mainnet_config_is_refused_while_held(self):
        why = vault_verdict(filled_vault())
        self.assertIn('ethereum-eth route is not launchable in v1 (held)', why)
        self.assertIn('external audit', why)

    def test_no_flag_or_field_lifts_the_hold(self):
        cfg = filled_vault()
        cfg['ethereum']['rehearsal'] = True          # the flag in the file alone
        self.assertIn('disagree', vault_verdict(cfg))
        cfg = filled_vault()
        self.assertIn('disagree', vault_verdict(cfg, rehearsal=True))   # the flag on the command line alone
        cfg['ethereum'] = {'chainId': 1, 'rehearsal': True}             # both, on chain id 1
        self.assertIn('chainId must be 31337', vault_verdict(cfg, rehearsal=True))
        with records(file=OPEN_FILE):                # the data file alone
            self.assertIn('disagree', vault_verdict(filled_vault()))
        with records(code=OPEN):                     # the code alone
            self.assertIn('disagree', vault_verdict(filled_vault()))

    def test_with_both_records_lifted_the_decided_config_validates_and_nothing_else(self):
        with records(code=OPEN, file=OPEN_FILE):
            self.assertIsNone(vault_verdict(filled_vault()))
            self.assertIsNone(vault_verdict(filled_vault(), token_cfg=filled_token()))
            cases = {
                'token': lambda c: c['vault'].update(token=USDC),
                'labels': lambda c: c['vault'].update(assetLabel='USDC'),
                'fees must be': lambda c: c['vault']['provenance']['fees'].update(releaseBps=5),
                'fees must be ': lambda c: c['vault']['provenance']['fees'].update(recipient=fx.fresh(99)),
                'limits must be': lambda c: c['vault'].update(cap=281_000_000),
                'limits must be ': lambda c: c['vault']['policy'].update(l2MinBurn=6_000_000, minDeposit=6_004_000),
                'limits must be  ': lambda c: c['vault']['policy'].update(windowLimit=14_000_000),
                'chain id 1 only': lambda c: c['ethereum'].update(chainId=42161),
            }
            for want, change in cases.items():
                cfg = filled_vault()
                change(cfg)
                with self.subTest(want):
                    why = vault_verdict(cfg)
                    self.assertIsNotNone(why)
                    if want.strip() == 'chain id 1 only':
                        continue  # the launch registry of the EVM networks may refuse it first; refused is what counts
                    self.assertIn(want.strip(), why)

    def test_a_minimum_burn_below_the_relayer_floor_is_named(self):
        v = filled_vault()['vault']
        v['policy'].update(l2MinBurn=6_809_000)
        self.assertTrue(any('would not pay the relayer' in b for b in ne.vault_policy_errors(v)))
        v['policy'].update(l2MinBurn=6_810_000)
        self.assertFalse(any('would not pay the relayer' in b for b in ne.vault_policy_errors(v)))

    def test_rehearsal_configs_validate_and_keep_the_contract_rules(self):
        cfg = rehearsal_vault(filled_vault())
        self.assertIsNone(vault_verdict(cfg, rehearsal=True))
        small = copy.deepcopy(cfg)   # a rehearsal may use other limits
        small['vault'].update(cap=1_000_000)
        small['vault']['policy'].update(windowLimit=500_000, minDeposit=10_006, l2MinBurn=10_000)
        self.assertIsNone(vault_verdict(small, rehearsal=True))
        bad = copy.deepcopy(cfg)     # but never another token: the constructor refuses it
        bad['vault']['token'] = USDC
        self.assertIn('native-ether marker', vault_verdict(bad, rehearsal=True))
        bad = copy.deepcopy(cfg)
        bad['vault']['transferMode'] = 1
        self.assertIn('transferMode', vault_verdict(bad, rehearsal=True))
        tight = copy.deepcopy(small)  # the fee is rounded UP: 10,005 nets 9,999 (rounded down it would net 10,000)
        tight['vault']['policy'].update(minDeposit=10_005)
        self.assertIn('rounded up', vault_verdict(tight, rehearsal=True))

    def test_the_two_vault_contracts_cannot_take_each_others_route(self):
        with records(code=OPEN, file=OPEN_FILE):
            # the USDC vault contract under the ether route's values
            cfg = filled_vault()
            cfg['vault']['contract'] = vault_pontes.PROVENANCE_CONTRACT
            self.assertIsNotNone(vault_verdict(cfg))
            # the ether vault contract under the USDC route's values
            usdc = fx.filled_vault(fx.filled())
            usdc['vault']['contract'] = ne.CONTRACT
            self.assertIn('native-ether marker', vault_verdict(usdc))
            # the pairing with the L2 token: bETH with the ether vault and with no other
            self.assertIn('do not pair', vault_verdict(filled_vault(), token_cfg=fx.filled()))
            self.assertIn('do not pair', vault_verdict(fx.filled_vault(fx.filled()), token_cfg=filled_token()))

    def test_the_usdc_route_is_untouched(self):
        self.assertEqual(hashlib.sha256(vault_pontes.canonical(json.loads(fx.VAULT_CFG.read_text())).encode()).hexdigest(), USDC_VAULT_SHA)
        token = fx.filled()
        self.assertIsNone(vault_verdict(fx.filled_vault(token), token_cfg=token))
        self.assertEqual(vault_pontes.PROVENANCE_CONTRACT, 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault')
        self.assertIn(vault_pontes.PROVENANCE_CONTRACT, vault_pontes.PROVENANCE_CONTRACTS)
        nets = vault_pontes.source_networks()
        self.assertEqual(nets[1][:4], ('ethereum-mainnet', 'USDC', USDC.lower(),
                                       (vault_pontes.CONTRACT, vault_pontes.PROVENANCE_CONTRACT)))


class TokenTool(unittest.TestCase):
    def test_a_filled_mainnet_beth_config_is_refused_while_held(self):
        why = token_verdict(filled_token())
        self.assertIn('ethereum-eth route is not launchable in v1 (held)', why)

    def test_beth_is_refused_under_any_other_source_chain(self):
        for chain in (42161, 10, 59144, 8453, 56, 728126428):
            cfg = filled_token()
            cfg['ethereum']['chainId'] = chain
            with self.subTest(chain):
                self.assertIsNotNone(token_verdict(cfg))
        with records(code=OPEN, file=OPEN_FILE):
            cfg = filled_token()
            cfg['ethereum']['chainId'] = 42161
            self.assertIsNotNone(token_verdict(cfg))

    def test_lifting_both_records_still_meets_the_one_token_per_chain_rule(self):
        """What the registry change of round 20 (several routes per network) must open in deploy_pontes.py before this
        route can ever deploy: chain id 1 accepts only the Ethereum bridge's bUSDC today (A375-1)."""
        with records(code=OPEN, file=OPEN_FILE):
            why = token_verdict(filled_token())
            self.assertIn('the L2 token of source chain 1 is bUSDC', why)

    def test_the_rehearsal_config_validates(self):
        cfg = fx.rehearsal(filled_token())
        self.assertIsNone(token_verdict(cfg, rehearsal=True))

    def test_the_usdc_token_config_is_untouched(self):
        self.assertIsNone(token_verdict(fx.filled()))
        self.assertEqual(deploy_pontes.config_sha256(json.loads(fx.TOKEN_CFG.read_text())), USDC_TOKEN_SHA)
        self.assertEqual(deploy_pontes.ETHEREUM_L2_TOKEN, ('Bloch Bridged USDC', 'bUSDC'))


if __name__ == '__main__':
    unittest.main()
