#!/usr/bin/env python3
"""The owner's ceremony kit on the native-ether route `ethereum-eth` (bETH) (agent 412, round 20).

  FOUNDRY_BIN=<dir of cast 1.7.1> python3 -m unittest test_ceremony_kit_native_ether      (from tools/deploy-pontes)

The ceremony is the same for every route (the same seven signer and three guardian keys, the same records); what is
route-specific in ceremony_kit.py is the decided schedule, the vault's creation-code pin and the vault creation.
Pinned here, with throwaway keys (cast only signs test inputs; no node, no network):
  - `fill` writes a full throwaway inventory into the route's two committed configs, and `key_inventory.py check`
    accepts them; `ethereum` copies a vault verify output into the token config; `sigs` orders a committee's
    signatures for the vault; `handover` names the route and its templates;
  - `schedule` holds the configs and the relayer template to THIS route's decided values and refuses the USDC route's
    values in them (and the reverse: the USDC route's own answer is unchanged);
  - `vault-run` refuses the route while it is held, at its first step, before any node is asked; with both launch
    records lifted (on a copy) it passes that step;
  - the creation-code pin: the audit freeze for the USDC vault, the committed build pin for this vault, a refusal for
    anything else.
"""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import ceremony_kit as ck  # noqa: E402
import test_ceremony_kit as base  # noqa: E402  (its throwaway ceremony: 25 records signed with cast)
import test_native_ether as tn  # noqa: E402  (the launch-record context manager)
import vault_pontes  # noqa: E402

ne = ck.native_ether
ROUTE = ROOT / 'deployments/ethereum-eth'
REV = 'b' * 40


def configs():
    load = lambda f: json.loads((ROUTE / f).read_text())  # noqa: E731
    return load('beth-token.config.json'), load('beth-vault.config.json'), load('beth-ops/relayer.template.json')


class Kit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='ceremony-kit-native-ether-')
        cls.records, cls.keys = base.ceremony(cls.tmp)
        cls.safe = base.key()[1]
        cls.inv, cls.verdict = ck.collect(cls.records, cls.safe)
        token, vault, _ = configs()
        cls.token, cls.vault, cls.check = ck.fill(cls.inv, token, vault, REV, 10**9)

    def test_fill_writes_the_inventory_into_the_routes_configs(self):
        self.assertEqual(self.verdict['keys'], 25)
        v = self.vault['vault']
        release = sorted(self.keys[('eth-release-signer', i)][1] for i in range(1, 8))
        self.assertEqual(sorted(s['address'].lower() for s in v['signers']['set']), release)
        self.assertEqual(sorted(g['address'].lower() for g in v['guard']['guardians']),
                         sorted(self.keys[('eth-vault-guardian', i)][1] for i in range(1, 4)))
        self.assertEqual(sorted(s['address'].lower() for s in self.token['signers']['set']),
                         sorted(self.keys[('l2-mint-signer', i)][1] for i in range(1, 8)))
        self.assertEqual(self.vault['deployer']['address'].lower(), self.keys[('eth-vault-deployer', 1)][1])
        self.assertEqual(self.token['deployer']['address'].lower(), self.keys[('l2-token-deployer', 1)][1])
        self.assertEqual((self.vault['source']['revision'], self.token['source']['revision']), (REV, REV))
        # nothing of the route's own values moved
        self.assertEqual(v['contract'], ne.CONTRACT)
        self.assertEqual(v['token'].lower(), ne.MARKER)
        self.assertEqual({'cap': v['cap'], **{k: v['policy'][k] for k in ('windowLimit', 'windowSeconds', 'l2MinBurn', 'minDeposit')}}, ne.LIMITS)
        self.assertEqual((self.token['token']['name'], self.token['token']['symbol']), ne.L2_TOKEN)

    def test_fill_never_overwrites_a_decided_value(self):
        token, vault, _ = configs()
        vault['vault']['signers']['set'][0] = {'operator': 'someone', 'address': '0x' + '12' * 20}
        with self.assertRaises(ck.Refused):
            ck.fill(self.inv, token, vault, REV, 10**9)

    def test_schedule_is_the_routes_own(self):
        _, _, relayer = configs()
        got = ck.schedule(self.token, self.vault, relayer)
        self.assertEqual((got['decision'], got['route']), ('schedule-ok', 'ethereum-eth'))
        self.assertEqual(got['checked'], {'feeRecipient': ne.FEE_RECIPIENT, 'depositBps': 5, 'releaseBps': 10, 'minDeposit': 7_004_000,
                                          'l2MinBurn': 7_000_000, 'tokenMinBurn': 7_000_000, 'largeMintThreshold': 0,
                                          'relayerEthCeilingGwei': 30})
        self.assertEqual((got['smallestDepositNet'], got['smallestExitPaid'], got['minBurnFloor']), (7_000_498, 6_993_000, 6_690_000))
        self.assertEqual(got['decidedLimits']['vaultCap'], 280_000_000)

    def test_schedule_refuses_any_other_value(self):
        _, _, relayer = configs()
        changes = {
            'releaseBps': lambda t, v, r: v['vault']['provenance']['fees'].update(releaseBps=5),
            'minDeposit': lambda t, v, r: v['vault']['policy'].update(minDeposit=101_000_000),          # the USDC route's
            'l2MinBurn': lambda t, v, r: v['vault']['policy'].update(l2MinBurn=6_900_000),
            'tokenMinBurn': lambda t, v, r: t['limits'].update(minBurn=100_000_000),
            'relayerEthCeilingGwei': lambda t, v, r: r.update(eth_max_gas_price_gwei=300),              # relaying at a loss
            'feeRecipient': lambda t, v, r: v['vault']['provenance']['fees'].update(recipient='0x' + '34' * 20),
            'limits must be': lambda t, v, r: v['vault'].update(cap=500_000_000),
            'supply cap': lambda t, v, r: t['limits'].update(supplyCap=279_000_000),
        }
        for want, change in changes.items():
            t, v, r = copy.deepcopy(self.token), copy.deepcopy(self.vault), copy.deepcopy(relayer)
            change(t, v, r)
            with self.subTest(want):
                with self.assertRaises(ck.Refused) as ctx:
                    ck.schedule(t, v, r)
                self.assertIn(want, str(ctx.exception))

    def test_the_usdc_routes_schedule_is_unchanged(self):
        token, vault, relayer = base.configs()
        t, v, _ = ck.fill(self.inv, token, vault, REV, 10**9)
        got = ck.schedule(t, v, relayer)
        self.assertEqual(set(got), {'decision', 'checked', 'smallestDepositNet', 'smallestExitPaid', 'openOwnerDecision'})
        self.assertEqual(got['checked']['minDeposit'], 101_000_000)
        self.assertEqual(got['checked']['relayerEthCeilingGwei'], 2)
        self.assertEqual(ck.SCHEDULE['l2MinBurn'], 100_000_000)
        # one route's values in the other route's configs
        _, _, eth_relayer = configs()
        with self.assertRaises(ck.Refused):
            ck.schedule(t, v, eth_relayer)                                                   # the 30 gwei ceiling on USDC

    def test_vault_identity(self):
        self.assertEqual(ck.vault_identity(vault_pontes.PROVENANCE_CONTRACT), ck.VAULT_CREATION_KECCAK)
        self.assertEqual(ck.VAULT_CREATION_KECCAK, '0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74')
        pin = json.loads((ROUTE / 'vault-build.pin.json').read_text())
        self.assertEqual(ck.vault_identity(ne.CONTRACT), pin['forge']['creationCodeKeccak'])
        self.assertNotEqual(ck.vault_identity(ne.CONTRACT), ck.VAULT_CREATION_KECCAK)
        for other in (vault_pontes.CONTRACT, 'contracts/tron/TronSourceVault.sol:TronSourceVault', 'x:y'):
            with self.assertRaises(ck.Refused):
                ck.vault_identity(other)

    def test_vault_run_refuses_the_held_route_before_any_node_is_asked(self):
        with self.assertRaises(ck.Refused) as ctx:
            ck.vault_run(self.vault, self.token, 'http://127.0.0.1:1', 30, False, None, None, [])
        self.assertIn('not launchable in v1 (held)', str(ctx.exception))
        with self.assertRaises(ck.Refused) as ctx:      # --broadcast changes nothing
            ck.vault_run(self.vault, self.token, 'http://127.0.0.1:1', 30, True, '0x' + '00' * 32, '/dev/null', [])
        self.assertIn('not launchable in v1 (held)', str(ctx.exception))

    def test_with_both_records_lifted_vault_run_passes_the_gate(self):
        """On a copy of the records only: the creation then stops where the kit checks the checkout (the pinned
        revision of this test does not exist), which is past the launch gate and past the config policy."""
        with tn.records(code=tn.OPEN, file=tn.OPEN_FILE):
            with self.assertRaises(ck.Refused) as ctx:
                ck.vault_run(self.vault, self.token, 'http://127.0.0.1:1', 30, False, None, None, [])
        self.assertNotIn('not launchable', str(ctx.exception))
        self.assertNotIn('vault_pontes validate', str(ctx.exception))

    def test_ethereum_sigs_and_handover(self):
        be = {'chainId': 1, 'vault': base.key()[1], 'route': '0x' + '11' * 32, 'vaultCodeHash': '0x' + '22' * 32,
              'vaultCap': ne.LIMITS['cap'], 'vaultGuard': {
                  'guardians': sorted((g['address'].lower() for g in self.vault['vault']['guard']['guardians']), key=lambda a: int(a, 16)),
                  'pauseDuration': 259_200, 'pauseCooldown': 259_200}}
        verify = {'decision': 'verified', 'block': 100, 'busdcEthereum': be, 'mintChainGenesis': '0x' + '33' * 32}
        token = ck.ethereum(copy.deepcopy(self.token), verify)
        token = token[0] if isinstance(token, tuple) else token
        self.assertEqual(token['ethereum']['vault'], be['vault'])
        wrong = json.loads(json.dumps(verify))
        wrong['busdcEthereum']['vaultCap'] = ne.LIMITS['cap'] - 1                             # a vault that holds less than the supply cap
        with self.assertRaises(ck.Refused):
            ck.ethereum(copy.deepcopy(self.token), wrong)
        # five release signers sign a digest for the vault; the kit orders them by address
        digest = '0x' + 'ab' * 32
        members = sorted((self.keys[('eth-release-signer', i)][1], self.keys[('eth-release-signer', i)][0]) for i in range(1, 8))
        five = [base.cast('wallet', 'sign', '--no-hash', '--private-key', k, digest) for _, k in members[:5]]
        ordered = ck.sigs(digest, self.vault, 5, 'list', list(reversed(five)))
        self.assertEqual(ordered['signers'], [a for a, _ in members[:5]])
        with self.assertRaises(ck.Refused):
            ck.sigs(digest, self.vault, 5, 'list', five[:4])
        outsider = base.cast('wallet', 'sign', '--no-hash', '--private-key', base.key()[0], digest)
        with self.assertRaises(ck.Refused):
            ck.sigs(digest, self.vault, 5, 'list', five[:4] + [outsider])
        record = {'address': base.key()[1], 'runtimeCodeHash': '0x' + '44' * 32, 'blockNumber': 7}
        plan = {'contract': {'address': record['address'], 'runtimeCodeHash': record['runtimeCodeHash']}}
        hand = ck.handover(token, self.vault, verify, record, plan, 90)
        self.assertEqual((hand['route'], hand['unitWei'], hand['templates']), ('ethereum-eth', 10**12, 'deployments/ethereum-eth/beth-ops/'))
        self.assertEqual(hand['feeRecipient'], ne.FEE_RECIPIENT)
        self.assertEqual(hand['thresholds'], {'mint': 5, 'release': 5, 'switch': 6})
        self.assertEqual(len(hand['releaseSigners']), 7)


if __name__ == '__main__':
    unittest.main()
