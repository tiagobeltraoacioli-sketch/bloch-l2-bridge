#!/usr/bin/env python3
"""Agent 324 (round 16), agent 338 (round 17, review 331 R331-XLM-2): the Stellar source path of deploy_pontes.py, and
that an Ethereum config does not reach it. The asset contract, every constructor value and the fee account are pinned.

  python3 -m unittest -v test_source_stellar        (offline: no RPC, no cast, no forge, no stellar CLI)
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import deploy_pontes as dp  # noqa: E402
import source_stellar as ss  # noqa: E402
from launch_fixture import ROOT, filled, fresh, rehearsal  # noqa: E402

sn = ss.sn
XLM_CFG = ROOT / 'deployments/stellar/busdc-xlm-token.config.json'
VAULT = sn.strkey_encode('contract', hashlib.sha256(b'a vault').digest())
TOKEN = sn.CIRCLE_USDC['contract']   # the committed config pins Circle's USDC
OTHER_ISSUER = sn.strkey_encode('account', hashlib.sha256(b'a look-alike issuer').digest())
FEE = 'GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA'
PUBLIC_ID = 55527100184162397446267447655670856106844621679976070008664532462234000271737
LABELS = [hashlib.sha256(x).hexdigest() for x in (b'stellar-pubnet', b'bloch-l2-700770', b'USDC')]


def ascending(first, n):
    return sorted((fresh(first + i) for i in range(n)), key=lambda a: int(a, 16))


def route_of(cfg):
    st = cfg['stellar']
    return '0x' + sn.route_id(st['networkPassphrase'], *LABELS, TOKEN, VAULT, st['vaultCap']).hex()


def filled_xlm():
    cfg = json.loads(XLM_CFG.read_text())
    cfg['source']['revision'] = '1' * 40
    cfg['deployer']['address'] = fresh(1)
    cfg['deployer']['fundedBy']['safe'] = fresh(2)
    cfg['signers']['set'] = [{'operator': f'op{i}', 'address': fresh(10 + i)} for i in range(7)]
    cfg['guardians']['set'] = [{'operator': f'guard{i}', 'address': fresh(20 + i)} for i in range(3)]
    st = cfg['stellar']
    st.update(vault=VAULT, vaultWasmHash='0x' + 'c0' * 32, vaultSigners=ascending(50, 7))
    st['vaultGuard']['guardians'] = ascending(40, 3)
    st['route'] = route_of(cfg)
    cfg['tx']['maxGasPriceWei'] = 10**9
    return cfg


def refusal(cfg, rehearsal_flag=False):
    try:
        dp.validate(cfg, rehearsal_flag)
    except dp.Refused as e:
        return str(e)
    return None


def plan_of(cfg):
    """The plan's `sourceVault`, as make_plan builds it (no forge build here)."""
    p = dp.validate(cfg, False)
    sv = {'chainId': p['sourceChainId'], 'address': p['sourceVault'], 'codeHash': p['vaultCodeHash'],
          'route': p['sourceRoute'], 'cap': p['vaultCap'], 'guard': p['vaultGuard'], **p['sourceStellar']}
    return {'sourceVault': sv}, p


def instance(cfg, **state):
    """The vault's instance storage as stellar_net.instance_storage returns it, for the config's vault."""
    st = cfg['stellar']
    route = route_of(cfg)[2:]
    config = {'token': TOKEN, 'source_domain': LABELS[0], 'native_domain': LABELS[1], 'asset': LABELS[2],
              'cap': st['vaultCap'], 'window_limit': st['vaultWindowLimit'], 'window_seconds': 86400,
              'min_deposit': 11_000_000, 'l2_min_burn': cfg['limits']['minBurn'],
              'signers': [a[2:] for a in st['vaultSigners']], 'threshold': st['vaultThreshold'],
              'switch_threshold': st['vaultSwitchThreshold'], 'guardians': [a[2:] for a in st['vaultGuard']['guardians']],
              'pause_duration': st['vaultGuard']['pauseDuration'], 'pause_cooldown': st['vaultGuard']['pauseCooldown'],
              'large_release_threshold': st['largeReleaseThreshold'], 'release_delay': st['releaseDelay'],
              'fee_recipient': st['feeRecipient'], 'deposit_fee_bps': st['depositFeeBps'],
              'release_fee_bps': st['releaseFeeBps']}
    vault_id = sn.strkey_decode(VAULT)[1]
    derived = {'network_id': sn.network_id(st['networkPassphrase']).hex(), 'vault_id': vault_id.hex(),
               'vault20': vault_id[12:].hex(), 'route': route,
               'genesis': sn.genesis(st['networkPassphrase'], VAULT, route).hex()}
    return {'Config': config, 'Derived': derived,
            'State': {'deposit_count': 0, 'total_locked': 0, 'control_nonce': 0, **state}}


class FakeNet:
    storage, wasm, heads = None, 'c0' * 32, {}
    fee_account, fee_trustline = {'account_id': FEE}, {'flags': 1}

    def __init__(self, cfg):
        self.passphrase = cfg['network_passphrase']

    def account(self, g):
        return FakeNet.fee_account if g == FEE else None

    def trustline(self, g, code, issuer):
        return FakeNet.fee_trustline if (g, code, issuer) == (FEE, 'USDC', sn.CIRCLE_USDC['issuer']) else None

    def rpc(self, method, params=None):
        return {'passphrase': FakeNet.passphrase_served}

    def instance_storage(self):
        return copy.deepcopy(FakeNet.storage), FakeNet.wasm, 1_000_000, 4242

    def record_value(self, name, value):
        return ('live', FakeNet.heads[value]) if value in FakeNet.heads else ('absent', None)


class StellarSource(unittest.TestCase):
    def setUp(self):
        self.cfg = filled_xlm()
        FakeNet.storage, FakeNet.wasm, FakeNet.heads = instance(self.cfg), 'c0' * 32, {}
        FakeNet.passphrase_served = self.cfg['stellar']['networkPassphrase']
        FakeNet.fee_account, FakeNet.fee_trustline = {'account_id': FEE}, {'flags': 1}
        patch = mock.patch.object(sn, 'Net', FakeNet)
        patch.start()
        self.addCleanup(patch.stop)

    # ── validate ─────────────────────────────────────────────────────────────
    def test_template_is_refused_until_filled(self):
        self.assertIn('undecided', refusal(json.loads(XLM_CFG.read_text())))

    def test_filled_config_validates_with_the_stellar_source_fields(self):
        p = dp.validate(self.cfg, False)
        self.assertEqual(p['sourceChainId'], PUBLIC_ID)
        self.assertGreater(p['sourceChainId'], 2**64)   # the Stellar network id does not fit 64 bits
        self.assertEqual(p['sourceVault'], '0x' + sn.vault20(VAULT).hex())
        self.assertEqual(p['sourceRoute'], self.cfg['stellar']['route'])
        self.assertEqual(p['sourceStellar']['feeRecipient'], FEE)
        self.assertEqual((p['switchThreshold'], p['contract']), (6, 'BridgedStablecoinV3'))
        # the uint256 goes into the constructor and the immutable as it is
        self.assertIn(str(PUBLIC_ID), dp.constructor_args(p)[1])
        self.assertEqual(int(dp.word(p['sourceChainId']), 16), PUBLIC_ID)

    def test_the_committed_fee_address_and_fee_are_the_owners(self):
        st = json.loads(XLM_CFG.read_text())['stellar']
        self.assertEqual((st['feeRecipient'], st['depositFeeBps'], st['releaseFeeBps']), (FEE, 5, 5))

    def test_refusals(self):
        def with_(path, value):
            cfg = copy.deepcopy(self.cfg)
            node = cfg
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            return refusal(cfg)
        st = self.cfg['stellar']
        cases = [
            (('stellar', 'networkPassphrase'), 'Test SDF Network ; September 2015', 'public network'),
            (('stellar', 'vault'), FEE, 'contract address'),
            (('stellar', 'vault'), 'TBD-deploy', 'not a Stellar address'),
            (('stellar', 'route'), None, 'route is undecided'),
            (('stellar', 'vaultWasmHash'), None, 'vaultWasmHash is undecided'),
            (('stellar', 'vaultCap'), st['vaultCap'] + 1, 'supplyCap must equal'),
            (('stellar', 'vaultWindowLimit'), st['vaultWindowLimit'] - 1, 'bucketCapacity must equal'),
            (('stellar', 'vaultSigners'), list(reversed(st['vaultSigners'])), 'strictly ascending'),
            (('stellar', 'vaultSigners'), st['vaultSigners'][:6], '5-of-7'),
            (('stellar', 'vaultSwitchThreshold'), 5, '5-of-7'),
            (('stellar', 'vaultGuard', 'guardians'), st['vaultGuard']['guardians'][:2], '3 vault guardians'),
            (('stellar', 'vaultGuard', 'guardians'), st['vaultSigners'][:3], 'also a vault guardian'),
            (('stellar', 'releaseDelay'), None, 'releaseDelay is undecided'),
            (('stellar', 'releaseDelay'), 15 * 86400, 'releaseDelay is undecided'),
            (('stellar', 'releaseDelay'), 129601, 'half the vault pauseCooldown'),
            (('stellar', 'feeRecipient'), VAULT, 'must be an account'),
            (('stellar', 'depositFeeBps'), 0, '5 bps'),
            (('token', 'contract'), 'BridgedStablecoinV2', 'BridgedStablecoinV3'),
            # review 331, R331-XLM-2: the asset and the remaining constructor values are pinned
            (('stellar', 'asset', 'issuer'), OTHER_ISSUER, 'is not the Stellar Asset Contract of USDC:' + OTHER_ISSUER),
            (('stellar', 'asset'), {'code': 'USDC', 'issuer': OTHER_ISSUER,
                                    'contract': sn.asset_contract_id(ss.PUBLIC_PASSPHRASE, 'USDC', OTHER_ISSUER)},
             'must be Circle'),
            (('stellar', 'asset', 'contract'), VAULT, 'is not the Stellar Asset Contract'),
            (('stellar', 'asset', 'code'), 'USDT', 'is not the Stellar Asset Contract'),
            (('stellar', 'asset'), None, 'stellar.asset must be an object'),
            (('stellar', 'labels', 'asset'), '0x' + 'ab' * 32, 'stellar.labels must be sha256'),
            (('stellar', 'vaultWindowSeconds'), 1, 'vaultWindowSeconds must be 86400'),
            (('stellar', 'vaultWindowSeconds'), None, 'vaultWindowSeconds is undecided'),
            (('stellar', 'vaultMinDeposit'), None, 'vaultMinDeposit is undecided'),
            (('stellar', 'vaultMinDeposit'), 10_000_000, 'above the token minBurn'),
            (('stellar', 'route'), '0x' + 'ab' * 32, 'does not recompute from the config'),
            (('limits', 'refillPerSecond'), 1, 'refillPerSecond must be'),
            (('mintSwitch', 'threshold'), 5, '6 of 7'),
        ]
        for path, value, expected in cases:
            with self.subTest(path=path, value=value):
                got = with_(path, value)
                self.assertIsNotNone(got)
                self.assertIn(expected, got)

    def test_release_delay_is_a_free_parameter_of_the_reviewed_config(self):
        for delay, threshold in ((0, 0), (7200, 0), (7200, 1_000_000_000), (129600, 5)):
            cfg = copy.deepcopy(self.cfg)
            cfg['stellar'].update(releaseDelay=delay, largeReleaseThreshold=threshold)
            self.assertEqual(dp.validate(cfg, False)['sourceStellar']['releaseDelay'], delay)

    def test_a_rehearsal_never_names_the_public_network(self):
        self.assertIn('never names the public', refusal(rehearsal(self.cfg), True))

    # ── an Ethereum config is untouched ──────────────────────────────────────
    def test_ethereum_config_does_not_reach_the_stellar_path(self):
        eth = filled()
        with mock.patch.object(ss, 'validate_source', side_effect=AssertionError('reached')):
            p = dp.validate(eth, False)
        self.assertNotIn('sourceStellar', p)
        self.assertEqual(p['sourceChainId'], 1)

    def test_a_config_with_both_sections_is_refused_as_before(self):
        cfg = filled()
        cfg['stellar'] = self.cfg['stellar']
        self.assertIn("unexpected ['stellar']", refusal(cfg))
        cfg = copy.deepcopy(self.cfg)
        del cfg['stellar']
        self.assertIn("missing ['ethereum']", refusal(cfg))

    def test_ethereum_plan_vault_checks_do_not_import_the_stellar_module(self):
        plan = {'sourceVault': {'chainId': 1, 'address': fresh(30), 'codeHash': '0x' + 'c0' * 32}}
        with mock.patch.object(ss, 'unused_vault', side_effect=AssertionError('reached')), \
                mock.patch.object(dp, 'Rpc') as rpc:
            rpc.return_value.side_effect = lambda method, params: '0x2'   # another chain: the Ethereum refusal
            with self.assertRaises(dp.Refused) as e:
                dp.unused_vault(plan, 'http://unused')
        self.assertIn('source RPC serves another chain', str(e.exception))

    # ── the vault read back ──────────────────────────────────────────────────
    def test_unused_vault_passes_and_a_used_vault_is_refused(self):
        plan, _ = plan_of(self.cfg)
        self.assertEqual(dp.unused_vault(plan, 'http://stellar'), {'vaultUnused': {'depositCount': 0, 'totalLocked': 0,
                                                                                   'controlNonce': 0}})
        for field in ('deposit_count', 'total_locked', 'control_nonce'):
            FakeNet.storage = instance(self.cfg, **{field: 1})
            with self.assertRaises(dp.Refused) as e:
                dp.unused_vault(plan, 'http://stellar')
            self.assertIn('has been used', str(e.exception))

    def test_every_difference_between_the_vault_and_the_config_is_refused(self):
        plan, _ = plan_of(self.cfg)
        for key, value, expected in (('release_delay', 0, 'releaseDelay'), ('large_release_threshold', 9, 'largeReleaseThreshold'),
                                     ('fee_recipient', sn.strkey_encode('account', b'\x01' * 32), 'feeRecipient'),
                                     ('threshold', 4, 'threshold'), ('switch_threshold', 7, 'switchThreshold'),
                                     ('window_limit', 1, 'windowLimit'), ('deposit_fee_bps', 6, 'depositFeeBps'),
                                     ('pause_duration', 1, 'pause policy'),
                                     ('signers', ['ab' * 20] * 7, 'signers'), ('guardians', ['ab' * 20], 'pause policy'),
                                     # review 331, R331-XLM-2: none of these was compared before
                                     ('token', sn.asset_contract_id(ss.PUBLIC_PASSPHRASE, 'USDC', OTHER_ISSUER),
                                      'the config pins'),
                                     ('window_seconds', 1, 'window_seconds'), ('min_deposit', 1, 'min_deposit'),
                                     ('l2_min_burn', 1, 'l2_min_burn'), ('source_domain', 'ab' * 32, 'source_domain'),
                                     ('native_domain', 'ab' * 32, 'native_domain'), ('asset', 'ab' * 32, 'asset (config'),
                                     ('cap', 5, 'vault cap'), ('release_fee_bps', 6, 'releaseFeeBps')):
            with self.subTest(key=key):
                FakeNet.storage = instance(self.cfg)
                FakeNet.storage['Config'][key] = value
                with self.assertRaises(dp.Refused) as e:
                    dp.unused_vault(plan, 'http://stellar')
                self.assertIn(expected, str(e.exception))
        FakeNet.storage, FakeNet.wasm = instance(self.cfg), 'ee' * 32
        with self.assertRaises(dp.Refused) as e:
            dp.unused_vault(plan, 'http://stellar')
        self.assertIn('Wasm hash', str(e.exception))
        FakeNet.wasm, FakeNet.passphrase_served = 'c0' * 32, 'Test SDF Network ; September 2015'
        with self.assertRaises(dp.Refused) as e:
            dp.unused_vault(plan, 'http://stellar')
        self.assertIn('another Stellar network', str(e.exception))
        # a vault of the same code at another address has another route
        FakeNet.passphrase_served = self.cfg['stellar']['networkPassphrase']
        FakeNet.storage = instance(self.cfg)
        FakeNet.storage['Derived']['route'] = 'ab' * 32
        with self.assertRaises(dp.Refused) as e:
            dp.unused_vault(plan, 'http://stellar')
        self.assertIn('route', str(e.exception))

    def test_a_vault_over_another_asset_is_refused_even_when_it_is_consistent_with_itself(self):
        """R331-XLM-2: a vault deployed over a look-alike asset, whose own route and genesis are consistent."""
        plan, _ = plan_of(self.cfg)
        other = sn.asset_contract_id(ss.PUBLIC_PASSPHRASE, 'USDC', OTHER_ISSUER)
        st = self.cfg['stellar']
        route = sn.route_id(st['networkPassphrase'], *LABELS, other, VAULT, st['vaultCap']).hex()
        FakeNet.storage = instance(self.cfg)
        FakeNet.storage['Config']['token'] = other
        FakeNet.storage['Derived'].update(route=route, genesis=sn.genesis(st['networkPassphrase'], VAULT, route).hex())
        for call in (lambda: dp.unused_vault(plan, 'http://stellar'),
                     lambda: ss.verify(plan, 'http://stellar', {}, None, dp.refuse)):
            with self.assertRaises(dp.Refused) as e:
                call()
            self.assertIn('refusing this vault', str(e.exception))

    def test_a_missing_fee_account_or_trustline_is_refused(self):
        """Owner input 1: the deploy tool refuses while the fee account or its USDC trustline does not exist."""
        plan, _ = plan_of(self.cfg)
        for account, line, expected in ((None, {'flags': 1}, 'does not exist'), ({'account_id': FEE}, None, 'no trustline'),
                                        ({'account_id': FEE}, {'flags': 0}, 'not authorized')):
            FakeNet.fee_account, FakeNet.fee_trustline = account, line
            with self.assertRaises(dp.Refused) as e:
                dp.unused_vault(plan, 'http://stellar')
            self.assertIn(expected, str(e.exception))
            self.assertIn('fee account', str(e.exception))

    def test_the_committed_asset_is_circles_and_its_contract_id_recomputes(self):
        st = json.loads(XLM_CFG.read_text())['stellar']
        self.assertEqual(st['asset'], sn.CIRCLE_USDC)
        self.assertEqual(sn.asset_contract_id(st['networkPassphrase'], 'USDC', st['asset']['issuer']), st['asset']['contract'])
        vault = json.loads((ROOT / 'deployments/stellar/busdc-xlm-vault.config.json').read_text())
        self.assertEqual(vault['vault']['config']['token'], st['asset']['contract'])
        self.assertEqual({k: vault['asset'][k] for k in ('code', 'issuer', 'contract')}, sn.CIRCLE_USDC)
        f = vault['vault']['config']
        self.assertEqual((st['vaultWindowSeconds'], st['vaultMinDeposit'], st['vaultCap'], st['vaultWindowLimit'],
                          st['releaseDelay'], st['largeReleaseThreshold'], st['feeRecipient']),
                         (f['window_seconds'], f['min_deposit'], f['cap'], f['window_limit'], f['release_delay'],
                          f['large_release_threshold'], f['fee_recipient']))
        self.assertEqual([st['labels'][k][2:] for k in ('sourceDomain', 'nativeDomain', 'asset')],
                         [f['source_domain'], f['native_domain'], f['asset']])

    def test_verify_pairs_the_token_mint_chain_with_the_vault_chain(self):
        plan, p = plan_of(self.cfg)
        exp = dict(p['limits'])
        genesis = '0x' + FakeNet.storage['Derived']['genesis']
        token = {'mintCount()': '0', 'mintHead()': genesis}
        get = lambda sig, returns: token[sig]  # noqa: E731
        out = ss.verify(plan, 'http://stellar', exp, get, dp.refuse)
        self.assertEqual(out['mintChain'], {'mintCount': 0, 'mintHead': genesis, 'clean': True})
        self.assertEqual(out['sourceVault']['contract'], VAULT)
        token['mintHead()'] = '0x' + 'ab' * 32
        with self.assertRaises(dp.Refused):
            ss.verify(plan, 'http://stellar', exp, get, dp.refuse)
        # after two credits the token's head must be the vault's head after two deposits
        FakeNet.heads = {2: 'cd' * 32}
        token.update({'mintCount()': '2', 'mintHead()': '0x' + 'cd' * 32})
        self.assertEqual(ss.verify(plan, 'http://stellar', exp, get, dp.refuse)['mintChain']['mintCount'], 2)
        token['mintCount()'] = '3'
        with self.assertRaises(dp.Refused) as e:
            ss.verify(plan, 'http://stellar', exp, get, dp.refuse)
        self.assertIn('absent', str(e.exception))


if __name__ == '__main__':
    unittest.main()
