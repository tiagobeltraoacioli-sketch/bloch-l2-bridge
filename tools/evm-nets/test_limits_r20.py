#!/usr/bin/env python3
"""Round 20: the launch limits decided on 2026-11-19: python3 -m unittest test_limits_r20  (in tools/evm-nets).

Owner, 2026-11-19: the bridge windows and caps are delegated to the coordinator. Coordinator, same day: Ethereum cap
500,000 USDC and window 50,000 USDC per 24 h each way; Arbitrum One, OP Mainnet and Linea cap 250,000 and window
25,000. Every other route keeps its values. The launch runs before the external audit (owner, same day).

No chain and no key. `cast` (FOUNDRY_BIN or ~/.foundry/bin) is needed by the deploy tools' validation.

  Records     the two records of the decision (networks.json `limits`, launch.py LIMITS) agree; a registry whose
              limits were edited closes every network and gives no limit to anyone
  Files       every committed file carries the decided numbers: cap = supplyCap, window = bucket = largest deposit =
              largest burn, refill = floor(window / 86400), cap = 10 windows; Base and BNB are byte-identical to
              what they were; the queue figures stated in the token notes are the computed ones
  Tools       vault_pontes.py and deploy_pontes.py accept the decided configs and refuse every other limit, on chain 1
              and on the three networks, including the values before the decision
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tools/deploy-pontes'))
import evm_nets  # noqa: E402
import launch  # noqa: E402
import deploy_pontes as dp  # noqa: E402
import vault_pontes as vp  # noqa: E402
import launch_fixture  # noqa: E402
from test_launch_r17 import filled_token, filled_vault  # noqa: E402

REGISTRY = json.loads((HERE / 'networks.json').read_text())
NETS = REGISTRY['networks']
U = 10**6
DAY = 86400
# The decision, written out once more here on purpose: (cap, window) in USDC.
DECIDED = {'ethereum': (500_000, 50_000), 'arbitrum-one': (250_000, 25_000), 'op-mainnet': (250_000, 25_000), 'linea': (250_000, 25_000)}
KEPT = {'base': (100_000, 10_000), 'bnb': (100_000, 10_000)}
CHAIN = {'ethereum': 1, 'arbitrum-one': 42161, 'op-mainnet': 10, 'linea': 59144, 'base': 8453, 'bnb': 56}
REFILL = {'ethereum': 578703, 'arbitrum-one': 289351, 'op-mainnet': 289351, 'linea': 289351}
# sha256 of the files of the two networks that were not part of the decision, as at main 135bdba (before round 20).
UNTOUCHED_SHA256 = {
    'deployments/base/bridge.network.json': '4f28f14a2acce100fa04f9b273e0453657cdbd5aae37fdba459b3cab2a8a73e6',
    'deployments/bnb/bridge.network.json': 'e7cbc6fc93ff3c9d59d105fe49322d2acb4b1bb65f1659f6373eecfb6149538f',
}


def vault_file(name):
    return ROOT / ('deployments/mainnet/busdc-vault-mainnet.config.json' if name == 'ethereum' else f'deployments/{name}/busdc-vault.config.json')


def token_file(name):
    return ROOT / ('deployments/mainnet/busdc-mainnet.config.json' if name == 'ethereum' else f'deployments/{name}/busdc-token.config.json')


def a_vault(name):
    """A filled mainnet vault config of a launchable route (throwaway addresses)."""
    if name == 'ethereum':
        return launch_fixture.filled_vault(launch_fixture.filled())
    return filled_vault(name)


def a_token(name):
    return launch_fixture.filled() if name == 'ethereum' else filled_token(name)


class Records(unittest.TestCase):
    def test_the_two_records_agree_and_are_the_decision(self):
        self.assertEqual(launch.LIMITS, {CHAIN[n]: (c * U, w * U) for n, (c, w) in {**DECIDED, **KEPT}.items()})
        self.assertEqual((launch.WINDOWS_PER_CAP, launch.WINDOW_SECONDS), (10, DAY))
        top = REGISTRY['limits']
        self.assertEqual((top['decided'], top['windowsPerCap'], top['windowSeconds']), ('2026-11-19', 10, DAY))
        self.assertEqual(top['ethereum'], {'chainId': 1, 'cap': 500_000 * U, 'windowLimit': 50_000 * U})
        for name, (cap, window) in {**DECIDED, **KEPT}.items():
            if name != 'ethereum':
                self.assertEqual(NETS[name]['limits'], {'cap': cap * U, 'windowLimit': window * U}, name)
            got = launch.limits(CHAIN[name])
            self.assertEqual((got['cap'], got['window_limit'], got['window_seconds'], got['windows_per_cap']), (cap * U, window * U, DAY, 10))
            self.assertEqual((got['supply_cap'], got['bucket_capacity'], got['refill_per_second']), (cap * U, window * U, window * U // DAY))
            self.assertEqual(got['cap'], 10 * got['window_limit'], name)
        # the reasons are part of the record: unaudited launch, the break-even, ten windows against a three-day pause
        for text in ('delegated to the coordinator', 'BEFORE the external audit', 'maximum loss', '60,000', 'ten windows',
                     'three days', 'new vault', '1,250,000 USDC', 'Base (held) and BNB Smart Chain (out'):
            self.assertIn(text, top['decision'], text)
        self.assertEqual(sum(c for c, _ in DECIDED.values()), 1_250_000)

    def test_the_refill_keeps_the_rounding_of_the_earlier_value(self):
        self.assertEqual(10_000 * U // DAY, 115740)  # the value the configs carried before the decision
        for name, want in REFILL.items():
            self.assertEqual(launch.limits(CHAIN[name])['refill_per_second'], want, name)
            # floor: the bucket is never refilled faster than the window, and is full again within 1 s more than 24 h
            self.assertLessEqual(want * DAY, DECIDED[name][1] * U)
            self.assertGreater((want + 1) * DAY, DECIDED[name][1] * U)

    def test_a_rehearsal_chain_has_no_limits_and_only_an_integer_is_a_chain_id(self):
        self.assertIsNone(launch.limits(31337))
        self.assertIsNone(launch.limits(launch.rehearsal_chain_id(8453)))
        for bad in (True, 1.0, '1', None):
            with self.assertRaises(launch.LaunchError):
                launch.limits(bad)

    def edited(self, change):
        reg = copy.deepcopy(REGISTRY)
        change(reg)
        tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        json.dump(reg, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    EDITS = {
        'the earlier Ethereum values': lambda r: r['limits']['ethereum'].update(cap=100_000 * U, windowLimit=10_000 * U),
        'a larger Ethereum cap': lambda r: r['limits']['ethereum'].update(cap=5_000_000 * U),
        'a larger Ethereum window': lambda r: r['limits']['ethereum'].update(windowLimit=500_000 * U),
        'the Ethereum values on Arbitrum One': lambda r: r['networks']['arbitrum-one']['limits'].update(cap=500_000 * U, windowLimit=50_000 * U),
        'one unit more on Linea': lambda r: r['networks']['linea']['limits'].update(cap=250_000 * U + 1),
        'a raised cap on Base': lambda r: r['networks']['base']['limits'].update(cap=250_000 * U, windowLimit=25_000 * U),
        'no limits on OP Mainnet': lambda r: r['networks']['op-mainnet'].pop('limits'),
        'no limits at all': lambda r: r.pop('limits'),
        'no Ethereum record': lambda r: r['limits'].pop('ethereum'),
        'a key added to a record': lambda r: r['networks']['linea']['limits'].update(maxDeposit=1),
        'a key added at the top': lambda r: r['limits'].update(override=True),
        'five windows': lambda r: r['limits'].update(windowsPerCap=5),
        'a 12 hour window': lambda r: r['limits'].update(windowSeconds=43200),
        'a window length as a float': lambda r: r['limits'].update(windowSeconds=86400.0),
        'an amount as text': lambda r: r['limits']['ethereum'].update(cap='500000000000'),
        'an amount as a float': lambda r: r['limits']['ethereum'].update(cap=500000000000.0),
        'an amount as a boolean': lambda r: r['networks']['bnb']['limits'].update(cap=True),
        'another chain id in the Ethereum record': lambda r: r['limits']['ethereum'].update(chainId=10),
        'no reasons': lambda r: r['limits'].update(decision=''),
    }

    def test_limits_edited_in_the_registry_close_every_network_and_give_no_limit(self):
        for what, change in self.EDITS.items():
            path = self.edited(change)
            with self.assertRaises(launch.LaunchError, msg=what):
                launch.registry(path)
            for chain in launch.DECIDED:
                self.assertIn('cannot be trusted', launch.refusal(chain, path), (what, chain))
            for chain in launch.LIMITS:  # chain 1 included: no limit is read from an untrusted registry
                with self.assertRaises(launch.LaunchError, msg=(what, chain)):
                    launch.limits(chain, path)
        # control: the unedited copy is trusted
        path = self.edited(lambda r: None)
        self.assertEqual(launch.limits(1, path)['cap'], 500_000 * U)

    def test_a_decision_that_breaks_the_rule_is_refused_even_when_both_records_agree(self):
        # the ten-window rule and the positive-integer rule hold for the code record too: were LIMITS itself changed
        # together with networks.json, the registry would still be refused
        for what, cap, window, needle in (('eleven windows', 550_000 * U, 50_000 * U, 'is not 10 x windowLimit'),
                                          ('one window', 50_000 * U, 50_000 * U, 'is not 10 x windowLimit'),
                                          ('a zero window', 0, 0, 'must be positive integers')):
            path = self.edited(lambda r: r['limits']['ethereum'].update(cap=cap, windowLimit=window))
            with mock.patch.dict(launch.LIMITS, {1: (cap, window)}):
                with self.assertRaises(launch.LaunchError, msg=what) as e:
                    launch.registry(path)
                self.assertIn(needle, str(e.exception), what)
        path = self.edited(lambda r: r['limits'].update(windowsPerCap=5))
        with mock.patch.object(launch, 'WINDOWS_PER_CAP', 5):  # both records say five windows: the caps no longer fit it
            with self.assertRaises(launch.LaunchError) as e:
                launch.registry(path)
            self.assertIn('is not 5 x windowLimit', str(e.exception))

    def test_the_deploy_tools_refuse_every_route_while_the_registry_limits_are_edited(self):
        path = self.edited(self.EDITS['a larger Ethereum cap'])
        with mock.patch.object(launch, 'REGISTRY', Path(path)):
            for name in DECIDED:
                with self.assertRaises(vp.Refused, msg=name) as e:
                    vp.validate(a_vault(name), False)
                self.assertRegex(str(e.exception), 'cannot be read|cannot be trusted')
                with self.assertRaises(dp.Refused, msg=name) as e:
                    dp.validate(a_token(name), False)
                self.assertRegex(str(e.exception), 'cannot be read|cannot be trusted')
        for name in DECIDED:  # control: with the committed registry the same configs validate
            vp.validate(a_vault(name), False)
            dp.validate(a_token(name), False)


class Files(unittest.TestCase):
    def test_every_committed_file_carries_the_decided_numbers(self):
        for name, (cap, window) in DECIDED.items():
            v = json.loads(vault_file(name).read_text())
            t = json.loads(token_file(name).read_text())
            pol, lim = v['vault']['policy'], t['limits']
            self.assertEqual((v['vault']['cap'], pol['windowLimit'], pol['windowSeconds']), (cap * U, window * U, DAY), name)
            # cap = supplyCap; window = bucket capacity; refill = floor(window / windowSeconds); cap = 10 windows
            self.assertEqual(lim['supplyCap'], v['vault']['cap'], name)
            self.assertEqual(lim['bucketCapacity'], pol['windowLimit'], name)
            self.assertEqual(lim['refillPerSecond'], pol['windowLimit'] // pol['windowSeconds'], name)
            self.assertEqual(lim['refillPerSecond'], REFILL[name], name)
            self.assertEqual(v['vault']['cap'], 10 * pol['windowLimit'], name)
            # the cap empties through the window in ten days, inside the 14 day switch delay and beyond a 3 day pause
            self.assertEqual(v['vault']['cap'] // pol['windowLimit'] * pol['windowSeconds'], 10 * DAY, name)
            self.assertLessEqual(10 * DAY, pol['switchDelay'], name)
            self.assertGreater(10 * DAY, v['vault']['guard']['pauseDuration'] + v['vault']['guard']['pauseCooldown'], name)
            # what the decision did not touch
            self.assertEqual((lim['largeMintThreshold'], lim['largeMintDelay']), (0, 43200), name)
            self.assertEqual((pol['switchThreshold'], pol['switchDelay'], v['vault']['signers']['threshold']), (6, 1209600, 5), name)
            self.assertEqual((v['vault']['guard']['pauseDuration'], v['vault']['guard']['pauseCooldown']), (259200, 259200), name)
            for text in ('2026-11-19', 'before the external audit', 'maximum loss'):
                self.assertIn(text, v['notes']['cap'], (name, text))
                self.assertIn(text, t['notes']['pilot'], (name, text))
            self.assertNotIn('proposed 100,000 USDC,', v['notes']['cap'])
            self.assertNotIn('confirm cap', v['notes']['TBD-owner'])
            if name == 'ethereum':
                continue
            doc = json.loads((ROOT / 'deployments' / name / 'bridge.network.json').read_text())
            dl = doc['limits']
            self.assertEqual((dl['cap'], dl['window'], dl['maxDeposit'], dl['l2MaxBurn'], dl['windowSeconds']),
                             (str(cap * U), str(window * U), str(window * U), str(window * U), DAY), name)
            self.assertEqual((dl['mintDelaySeconds'], dl['largeItemThreshold']), (43200, '0'), name)
            self.assertEqual(doc['status'], 'unaudited-not-deployed')
            note = doc['notes'][0]
            for text in ('UNAUDITED', 'Nothing is deployed', '2026-11-19', f'cap {cap:,} USDC', f'window {window:,} per 24 h',
                         'external audit is done AFTER launch', 'the most this route can lose'):
                self.assertIn(text, note, (name, text))

    def test_the_minimums_and_fees_are_what_they_were(self):
        want = {'ethereum': (101, 100, 5, 10), 'arbitrum-one': (21, 20, 5, 5), 'op-mainnet': (21, 20, 5, 5), 'linea': (601, 600, 5, 15)}
        for name, (min_dep, min_burn, dep, rel) in want.items():
            v = json.loads(vault_file(name).read_text())['vault']
            t = json.loads(token_file(name).read_text())
            self.assertEqual((v['policy']['minDeposit'], v['policy']['l2MinBurn'], t['limits']['minBurn'],
                              v['provenance']['fees']['depositBps'], v['provenance']['fees']['releaseBps']),
                             (min_dep * U, min_burn * U, min_burn * U, dep, rel), name)

    def test_base_and_bnb_are_byte_identical_to_what_they_were(self):
        for rel, want in UNTOUCHED_SHA256.items():
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), want, rel)
        for name, (cap, window) in KEPT.items():
            doc = json.loads((ROOT / 'deployments' / name / 'bridge.network.json').read_text())
            self.assertEqual((doc['limits']['cap'], doc['limits']['window']), (str(cap * U), str(window * U)), name)
            self.assertFalse(doc['launch']['v1'])
            self.assertFalse((ROOT / 'deployments' / name / 'busdc-vault.config.json').exists())
            self.assertFalse((ROOT / 'deployments' / name / 'busdc-token.config.json').exists())
            self.assertNotIn('AFTER launch', json.dumps(doc))

    def test_the_generated_files_are_current(self):
        files, absent = evm_nets.derive()
        self.assertEqual([str(p) for p, text in files.items() if not p.exists() or p.read_text() != text], [])
        self.assertEqual([str(p) for p in absent if p.exists()], [])

    def test_the_queue_figures_in_the_token_notes_are_the_computed_ones(self):
        # (smallest mint, queued at most at the bucket rate, with one more 12 h delay of lag); MAX_PENDING is 2,048
        want = {'ethereum': (100_949_500, 742, 990), 'arbitrum-one': (20_989_500, 1786, 2382), 'op-mainnet': (20_989_500, 1786, 2382),
                'linea': (600_699_500, 62, 83)}
        src = (ROOT / 'contracts/stable/BridgedStablecoinV3.sol').read_text()
        self.assertIn(f'uint256 public constant MAX_PENDING = {evm_nets.MAX_PENDING};', src)
        for name, figures in want.items():
            v = json.loads(vault_file(name).read_text())['vault']
            t = json.loads(token_file(name).read_text())
            lim = launch.limits(CHAIN[name])
            got = evm_nets.queue_figures(lim, v['policy']['minDeposit'], v['provenance']['fees']['depositBps'], t['limits']['largeMintDelay'])
            self.assertEqual(got, figures, name)
            sentence = evm_nets.queue_note(lim, v['policy']['minDeposit'], v['provenance']['fees']['depositBps'], t['limits']['largeMintDelay'])
            self.assertIn(sentence, t['notes']['launchDesign'], name)  # the Ethereum template is hand-written: held to the same text
            self.assertEqual(len(evm_nets.QUEUE_SENTENCE.findall(t['notes']['launchDesign'])), 1, name)
            # at the bucket rate alone the queue always fits; the lag margin is stated as it is, never rounded away
            self.assertLess(figures[1], evm_nets.MAX_PENDING, name)
            self.assertEqual('ABOVE MAX_PENDING' in sentence, figures[2] > evm_nets.MAX_PENDING, name)
            self.assertEqual('under MAX_PENDING' in sentence, figures[2] <= evm_nets.MAX_PENDING, name)
        self.assertIn('lag by about 5.3 h', json.loads(token_file('arbitrum-one').read_text())['notes']['launchDesign'])


class Tools(unittest.TestCase):
    def refused(self, fn, needle):
        with self.assertRaises((dp.Refused, vp.Refused)) as e:
            fn()
        self.assertIn(needle, str(e.exception))

    def test_the_decided_configs_validate_on_every_launchable_route(self):
        for name, (cap, window) in DECIDED.items():
            v, t = a_vault(name), a_token(name)
            self.assertEqual((v['vault']['cap'], v['vault']['policy']['windowLimit']), (cap * U, window * U), name)
            self.assertEqual((t['limits']['supplyCap'], t['limits']['bucketCapacity'], t['limits']['refillPerSecond']),
                             (cap * U, window * U, REFILL[name]), name)
            vp.validate(v, False)
            out = dp.validate(t, False)
            self.assertEqual((out['limits']['supplyCap'], out['limits']['bucketCapacity'], out['limits']['refillPerSecond'],
                              out['vaultCap']), (cap * U, window * U, REFILL[name], cap * U), name)
        tok = launch_fixture.filled()
        vp.validate(launch_fixture.filled_vault(tok), False, tok)  # the pair, as the ceremony validates it

    def test_the_vault_tool_refuses_every_other_cap_and_window(self):
        for name, (cap, window) in DECIDED.items():
            others = {
                'the values before the decision': (100_000 * U, 10_000 * U, DAY),
                'the cap of another route': ((250_000 if name == 'ethereum' else 500_000) * U, window * U, DAY),
                'the limits of another route': ((250_000, 25_000) if name == 'ethereum' else (500_000, 50_000)),
                'ten times the cap': (cap * U * 10, window * U, DAY),
                'one unit more': (cap * U + 1, window * U, DAY),
                'one unit less': (cap * U - 1, window * U, DAY),
                'eleven windows': (cap * U + window * U, window * U, DAY),
                'a window as large as the cap': (cap * U, cap * U, DAY),
                'a smaller window': (cap * U, window * U // 2, DAY),
                'a 12 hour window': (cap * U, window * U, DAY // 2),
                'a 48 hour window': (cap * U, window * U, 2 * DAY),
            }
            others['the limits of another route'] = tuple(x * U for x in others['the limits of another route']) + (DAY,)
            for what, (c, w, s) in others.items():
                cfg = a_vault(name)
                cfg['vault']['cap'] = c
                cfg['vault']['policy'].update(windowLimit=w, windowSeconds=s)
                with self.assertRaises(vp.Refused, msg=(name, what)) as e:
                    vp.validate(cfg, False)
                self.assertIn(f'launch limits of chain {CHAIN[name]} (decided 2026-11-19', str(e.exception), (name, what))
                self.assertIn(f'cap {cap * U}, windowLimit {window * U}, windowSeconds {DAY}', str(e.exception), (name, what))

    def test_the_token_tool_refuses_every_other_supply_cap_bucket_and_refill(self):
        for name, (cap, window) in DECIDED.items():
            others = {
                'the values before the decision': dict(supplyCap=100_000 * U, bucketCapacity=10_000 * U, refillPerSecond=115740),
                'the earlier refill alone': dict(refillPerSecond=115740),
                'a refill one unit faster': dict(refillPerSecond=REFILL[name] + 1),
                'a refill one unit slower': dict(refillPerSecond=REFILL[name] - 1),
                'the whole bucket every second': dict(refillPerSecond=window * U),
                'a larger bucket': dict(bucketCapacity=2 * window * U),
                'a smaller bucket': dict(bucketCapacity=window * U // 2),
                'a larger supply cap': dict(supplyCap=2 * cap * U),
                'a smaller supply cap': dict(supplyCap=cap * U // 2),
            }
            for what, change in others.items():
                t = a_token(name)
                t['limits'].update(change)
                t['ethereum']['vaultCap'] = max(t['ethereum']['vaultCap'], t['limits']['supplyCap'])
                self.refused(lambda: dp.validate(t, False), f'launch limits of source chain {CHAIN[name]} (decided 2026-11-19')
            # the vault cap written into the token config is the supply cap, not merely at least it
            t = a_token(name)
            t['ethereum']['vaultCap'] = cap * U + 1
            self.refused(lambda: dp.validate(t, False), 'are one decided number')
            t['ethereum']['vaultCap'] = cap * U - 1
            self.refused(lambda: dp.validate(t, False), 'supplyCap exceeds the vault cap')

    def test_the_pair_must_agree_cap_supply_window_bucket_refill(self):
        """vault_pontes.py validate --token-config: the values that must agree across the two configs."""
        def pair(change):
            tok = launch_fixture.filled()
            v = launch_fixture.filled_vault(tok)
            change(tok)
            return lambda: vp.validate(v, False, tok)
        pair(lambda t: None)()
        self.refused(pair(lambda t: t['limits'].update(supplyCap=500_000 * U - 1)), 'vault cap differs from the L2 supplyCap')
        self.refused(pair(lambda t: t['limits'].update(supplyCap=500_000 * U + 1)), 'vault cap differs from the L2 supplyCap')
        self.refused(pair(lambda t: t['limits'].update(supplyCap=100_000 * U)), 'vault cap differs from the L2 supplyCap')
        self.refused(pair(lambda t: t['limits'].update(bucketCapacity=10_000 * U)), 'windowLimit differs from the L2 bucketCapacity')
        self.refused(pair(lambda t: t['limits'].update(bucketCapacity=50_000 * U + 1)), 'windowLimit differs from the L2 bucketCapacity')
        for refill in (115740, 578702, 578704, 50_000 * U, 0, None, '578703', 578703.0, True):
            self.refused(pair(lambda t: t['limits'].update(refillPerSecond=refill)), 'refillPerSecond must be floor(windowLimit / windowSeconds) = 578703')

    def test_a_rehearsal_config_is_not_held_to_the_launch_limits(self):
        # a local rehearsal chain (31337) keeps free limits: nothing signed for it is valid on a real network
        t = launch_fixture.rehearsal(launch_fixture.filled())
        t['limits'].update(supplyCap=1_000 * U, bucketCapacity=100 * U, refillPerSecond=1)
        t['ethereum']['vaultCap'] = 2_000 * U
        self.assertEqual(dp.validate(t, True)['limits']['supplyCap'], 1_000 * U)

    def test_no_flag_environment_variable_or_config_key_lifts_the_limits(self):
        source = (HERE / 'launch.py').read_text()
        self.assertFalse('os.environ' in source or 'getenv' in source or 'import os' in source)
        cfg = a_vault('ethereum')
        cfg['vault']['cap'] = 5_000_000 * U
        with mock.patch.dict(os.environ, {'BLOCH_LIMITS': 'free', 'LAUNCH_OVERRIDE': '1', 'FORCE': '1', 'REHEARSAL': '1'}):
            self.refused(lambda: vp.validate(cfg, False), 'launch limits of chain 1')
        cfg['vault']['limitsOverride'] = True
        self.refused(lambda: vp.validate(cfg, False), 'unexpected keys')
        cfg = a_vault('ethereum')
        cfg['vault']['cap'] = 5_000_000 * U
        cfg['ethereum']['rehearsal'] = True  # a rehearsal config is only ever chain 31337
        self.refused(lambda: vp.validate(cfg, True), 'chainId must be 31337')

    def test_the_tools_state_the_rule_in_their_source(self):
        for f, needles in (('vault_pontes.py', ('launch.limits(', 'refillPerSecond must be floor', "vault cap differs from the L2 supplyCap",
                                                'vault windowLimit differs from the L2 bucketCapacity')),
                           ('deploy_pontes.py', ('launch.limits(', 'are one decided number'))):
            text = (ROOT / 'tools/deploy-pontes' / f).read_text()
            for n in needles:
                self.assertIn(n, text, (f, n))
        self.assertTrue(re.search(r'cap != WINDOWS_PER_CAP \* window', (HERE / 'launch.py').read_text()))


if __name__ == '__main__':
    unittest.main()
