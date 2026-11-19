#!/usr/bin/env python3
"""Round 20 (agent 421, finding F410-1): the honest mint queue fits MAX_PENDING on every launchable route, by rule.

  python3 -m unittest test_queue_bound_r20     (in tools/evm-nets; no chain, no key)

The frozen L2 token queues every mint for `largeMintDelay` (12 h; T = 0) and holds at most MAX_PENDING = 2,048 mints
that are queued and not yet executed. Its own comment states the design point: honest mints at the bucket rate queue
at most (bucket + refill x delay) / smallest mint, and (bucket + 2 x refill x delay) / smallest mint when executions
lag by one more delay; with the first values (10 USDC, bucket 10,000) that was 1,500 and 2,000.

The launch limits of 2026-11-19 raised the bucket of Arbitrum One and OP Mainnet to 25,000 USDC while their minimum
deposit stayed 21 USDC: 1,786 and 2,382, above MAX_PENDING (finding F410-1 of agent 410). Coordinator decision of
2026-11-19: minimum deposit 25 USDC on those two networks (1,500 and 2,000 again: the token's design point). The
minimum burn stays 20 USDC.

What is held here, so that a later change of a limit, a minimum, the delay or MAX_PENDING cannot reopen it:
  Rule        launch.queue_bound for chain 1 and every launchable network; the registry is untrusted (every tool
              refuses) when a launchable route breaks the bound; the constants are the frozen token's
  Figures     the decided minimums and the figures of every route, stated once more here
  Files       every generated file carries the minimum deposit; the token notes state the computed figures
  Tools       vault_pontes.py refuses a mainnet vault whose minimum deposit breaks the bound, alone and paired
"""
import copy
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tools/deploy-pontes'))
import evm_nets  # noqa: E402
import launch  # noqa: E402
import vault_pontes as vp  # noqa: E402
import launch_fixture  # noqa: E402
from test_limits_r20 import CHAIN, a_token, a_vault, token_file, vault_file  # noqa: E402

REGISTRY = json.loads((HERE / 'networks.json').read_text())
NETS = REGISTRY['networks']
U = 10**6
MAX_PENDING, DELAY = 2048, 43200
LAUNCHABLE = ('ethereum', 'arbitrum-one', 'op-mainnet', 'linea')
# name: (minimum deposit, minimum burn, deposit fee bps, bucket) in USDC, then (smallest mint in units, queued at the
# bucket rate, queued with one more delay of lag). Written out by hand: the decision and its arithmetic.
DECIDED = {
    'ethereum': ((101, 100, 5, 50_000), (100_949_500, 742, 990)),
    'arbitrum-one': ((25, 20, 5, 25_000), (24_987_500, 1500, 2000)),
    'op-mainnet': ((25, 20, 5, 25_000), (24_987_500, 1500, 2000)),
    'linea': ((601, 600, 5, 25_000), (600_699_500, 62, 83)),
}
HELD = {'base': ((21, 20, 5, 10_000), (20_989_500, 714, 952)), 'bnb': ((11, 10, 5, 10_000), (10_994_500, 1364, 1819))}


def schedule(name):
    return REGISTRY['relayCost']['ethereum'] if name == 'ethereum' else NETS[name]


class Rule(unittest.TestCase):
    def test_the_constants_are_the_frozen_token_s(self):
        src = (ROOT / 'contracts/stable/BridgedStablecoinV3.sol').read_text()
        self.assertIn(f'uint256 public constant MAX_PENDING = {MAX_PENDING};', src)
        self.assertIn('so 1,500 queue at most, and 2,000 with one more delay of lag', src)
        self.assertEqual((launch.MAX_PENDING, launch.MINT_DELAY, launch.QUEUE_LAG_DELAYS), (MAX_PENDING, DELAY, 1))
        self.assertEqual(evm_nets.MAX_PENDING, launch.MAX_PENDING)
        for name in LAUNCHABLE:  # the delay every launch token config carries, and T = 0 (every mint waits it)
            lim = json.loads(token_file(name).read_text())['limits']
            self.assertEqual((lim['largeMintDelay'], lim['largeMintThreshold']), (launch.MINT_DELAY, 0), name)

    def test_the_arithmetic_of_the_bound(self):
        # the token's own example: 10 USDC mints, bucket 10,000, 5,000 refilled per 12 h
        self.assertEqual(launch.queue_figures(10_000 * U, 10_000 * U // 86400, 10 * U, 0), (10 * U, 1499, 1999))
        self.assertEqual(launch.queue_figures(10_000 * U, 115741, 10 * U, 0), (10 * U, 1500, 2000))
        # the finding: 21 USDC with the 25,000 bucket
        self.assertEqual(launch.queue_figures(25_000 * U, 289351, 21 * U, 5), (20_989_500, 1786, 2382))
        # the fee is taken before the mint: the smallest mint is the minimum deposit less its fee, rounded as the vault does
        self.assertEqual(launch.queue_figures(25_000 * U, 289351, 25 * U, 5)[0], 25 * U - 12_500)
        for bad in ((0, 1, 1, 0), (1, 1, 0, 0), (1, 1, 1, 10_000), (1, True, 1, 0), (1.0, 1, 1, 0), (1, 1, 1, -1)):
            with self.assertRaises(launch.LaunchError, msg=bad):
                launch.queue_figures(*bad)

    def test_every_launchable_route_satisfies_the_bound_with_the_decided_figures(self):
        self.assertEqual(sorted([n for n in NETS if NETS[n]['launch']['v1']] + ['ethereum']), sorted(LAUNCHABLE))
        for name, ((min_dep, min_burn, bps, bucket), figures) in DECIDED.items():
            s = schedule(name)
            self.assertEqual((s['minDeposit'], s['l2MinBurn'], s['feeBps']['deposit']), (min_dep * U, min_burn * U, bps), name)
            q = launch.queue_bound(CHAIN[name])
            self.assertEqual((q['smallest_mint'], q['queued'], q['queued_lagged']), figures, name)
            self.assertEqual((q['max_pending'], q['mint_delay'], q['bucket_capacity']), (MAX_PENDING, DELAY, bucket * U), name)
            self.assertLessEqual(q['queued_lagged'], MAX_PENDING, name)
            self.assertTrue(q['ok'], name)
            # the least minimum deposit the rule allows, and the lag a full-rate stream of smallest deposits needs to fill the queue
            self.assertLessEqual(q['min_deposit_floor'], min_dep * U, name)
            self.assertGreater(q['lag_to_fill_s'], DELAY, name)
        self.assertEqual(launch.queue_bound(42161)['min_deposit_floor'], 24_414_319)
        self.assertEqual(launch.queue_bound(42161)['lag_to_fill_s'], 47323)   # 13.1 h of execution lag
        self.assertEqual(launch.queue_bound(1)['lag_to_fill_s'], 227819)      # 63 h

    def test_the_floor_is_exact(self):
        for name in LAUNCHABLE:
            q = launch.queue_bound(CHAIN[name])
            bps = schedule(name)['feeBps']['deposit']
            lim = launch.limits(CHAIN[name])
            at = launch.queue_figures(lim['bucket_capacity'], lim['refill_per_second'], q['min_deposit_floor'], bps)
            below = launch.queue_figures(lim['bucket_capacity'], lim['refill_per_second'], q['min_deposit_floor'] - 1, bps)
            self.assertLessEqual(at[2], MAX_PENDING, name)
            self.assertGreater(below[2], MAX_PENDING, name)

    def test_the_held_networks_would_pass_today_and_a_rehearsal_chain_has_no_bound(self):
        for name, ((min_dep, min_burn, bps, bucket), figures) in HELD.items():
            q = launch.queue_bound(CHAIN[name])
            self.assertEqual((q['smallest_mint'], q['queued'], q['queued_lagged'], q['ok']), figures + (True,), name)
        self.assertIsNone(launch.queue_bound(31337))
        self.assertIsNone(launch.queue_bound(launch.rehearsal_chain_id(10)))

    def edited(self, change):
        reg = copy.deepcopy(REGISTRY)
        change(reg)
        tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        json.dump(reg, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    BREAKS = {
        'the 21 USDC minimum again on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=21 * U),
        'the 21 USDC minimum again on OP Mainnet': lambda r: r['networks']['op-mainnet'].update(minDeposit=21 * U),
        'one unit below the floor on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=24_414_318),
        '20 USDC on Linea': lambda r: r['networks']['linea'].update(minDeposit=20 * U, l2MinBurn=19 * U),
        '48 USDC on Ethereum': lambda r: r['relayCost']['ethereum'].update(minDeposit=48 * U, l2MinBurn=47 * U),
        'a 100% deposit fee on OP Mainnet': lambda r: r['networks']['op-mainnet']['feeBps'].update(deposit=10_000),
        'a minimum deposit that is not an integer': lambda r: r['networks']['linea'].update(minDeposit='601000000'),
        'no minimum deposit on Arbitrum One': lambda r: r['networks']['arbitrum-one'].pop('minDeposit'),
    }

    def test_a_registry_whose_launchable_route_breaks_the_bound_is_untrusted(self):
        for what, change in self.BREAKS.items():
            path = self.edited(change)
            with self.assertRaises(launch.LaunchError, msg=what) as e:
                launch.registry(path)
            if 'integer' not in what and 'no minimum' not in what and '100%' not in what:
                self.assertIn('MAX_PENDING', str(e.exception), what)
            for chain in (42161, 10, 59144):   # every network is refused, not only the edited one
                self.assertIsNotNone(launch.refusal(chain, path), (what, chain))
            for call in (launch.limits, launch.fee_schedule, launch.queue_bound):
                with self.assertRaises(launch.LaunchError, msg=(what, call.__name__)):
                    call(1, path)

    def test_control_edits_that_keep_the_bound_load(self):
        keeps = {
            'the floor itself on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=24_414_319),
            '30 USDC on OP Mainnet': lambda r: r['networks']['op-mainnet'].update(minDeposit=30 * U),
            # a held network is not launchable: its minimum is not judged until somebody makes it launchable
            '5 USDC on Base (held)': lambda r: r['networks']['base'].update(minDeposit=5 * U, l2MinBurn=4 * U),
        }
        for what, change in keeps.items():
            path = self.edited(change)
            self.assertEqual(sorted(launch.registry(path)['networks']), sorted(NETS), what)
        path = self.edited(keeps['5 USDC on Base (held)'])
        self.assertFalse(launch.queue_bound(8453, path)['ok'])   # stated, though not enforced while held

    def test_a_longer_delay_a_smaller_cap_of_the_queue_or_a_second_delay_of_lag_would_break_it(self):
        # what the margin is: the decided values sit on the token's design point, not far inside it
        lim = launch.limits(42161)
        args = (lim['bucket_capacity'], lim['refill_per_second'], 25 * U, 5)
        self.assertLessEqual(launch.queue_figures(*args)[2], MAX_PENDING)
        self.assertGreater(launch.queue_figures(*args, delay=DELAY + 3600)[2], MAX_PENDING)
        self.assertGreater(launch.queue_figures(*args, lag_delays=2)[2], MAX_PENDING)
        self.assertEqual(launch.queue_figures(*args, lag_delays=2)[2], 2501)


class Files(unittest.TestCase):
    def test_every_generated_file_carries_the_decided_minimums(self):
        for name, ((min_dep, min_burn, bps, bucket), _) in DECIDED.items():
            v = json.loads(vault_file(name).read_text())['vault']
            t = json.loads(token_file(name).read_text())
            self.assertEqual((v['policy']['minDeposit'], v['policy']['l2MinBurn'], t['limits']['minBurn'], v['provenance']['fees']['depositBps'],
                              t['limits']['bucketCapacity']), (min_dep * U, min_burn * U, min_burn * U, bps, bucket * U), name)
            if name != 'ethereum':
                doc = json.loads((ROOT / 'deployments' / name / 'bridge.network.json').read_text())
                self.assertEqual((doc['limits']['minDeposit'], doc['limits']['l2MinBurn']), (str(min_dep * U), str(min_burn * U)), name)
            route = json.loads((ROOT / 'deployments/bridges.json').read_text())['routes']
            route = route[name] if isinstance(route, dict) else next(r for r in route if r.get('id') == name)
            self.assertEqual((route['limits']['minDeposit'], route['limits']['l2MinBurn']), (str(min_dep * U), str(min_burn * U)), name)

    def test_the_token_notes_state_the_computed_figures_and_none_is_above_max_pending(self):
        for name, (_, (smallest, queued, lagged)) in DECIDED.items():
            design = json.loads(token_file(name).read_text())['notes']['launchDesign']
            sentence = re.search(r'Honest flow at the bucket rate .*?frozen and unchanged\)', design)
            self.assertIsNotNone(sentence, name)
            self.assertIn(f'queues at most {queued:,} mints, and {lagged:,} with one more delay of lag, under MAX_PENDING', sentence[0], name)
            self.assertNotIn('ABOVE MAX_PENDING', design, name)

    def test_base_and_bnb_are_not_touched(self):
        self.assertEqual((NETS['base']['minDeposit'], NETS['bnb']['minDeposit']), (21 * U, 11 * U))


def a_pair(name):
    """A filled vault and token of a network that pair as the deploy tool requires (the token fixture of the Ethereum
    suites keeps the Ethereum minimum burn; evm_nets.py derives the network's own, as here)."""
    v, t = a_vault(name), a_token(name)
    t['limits']['minBurn'] = NETS[name]['l2MinBurn']
    guard = v['vault']['guard']
    t['ethereum']['vaultGuard'] = {**t['ethereum'].get('vaultGuard', {}), 'pauseDuration': guard['pauseDuration'],
                                   'pauseCooldown': guard['pauseCooldown'],
                                   'guardians': sorted((g['address'].lower() for g in guard['guardians']), key=lambda a: int(a, 16))}
    return v, t


class Tools(unittest.TestCase):
    def test_the_decided_vaults_validate_alone_and_paired(self):
        for name in LAUNCHABLE:
            vp.validate(a_vault(name), False)
        tok = launch_fixture.filled()
        vp.validate(launch_fixture.filled_vault(tok), False, tok)
        for name in ('arbitrum-one', 'op-mainnet', 'linea'):
            v, t = a_pair(name)
            vp.validate(v, False, t)

    def test_a_mainnet_vault_whose_minimum_deposit_breaks_the_bound_is_refused(self):
        for name, low in (('arbitrum-one', 21 * U), ('op-mainnet', 21 * U), ('arbitrum-one', 24_414_318), ('linea', 21 * U), ('ethereum', 48 * U)):
            cfg = a_vault(name)
            cfg['vault']['policy'].update(minDeposit=low, l2MinBurn=min(cfg['vault']['policy']['l2MinBurn'], low - U))
            with self.assertRaises(vp.Refused, msg=(name, low)) as e:
                vp.validate(cfg, False)
            # every one is refused; where the lowered l2MinBurn falls below the relayer cost, that older rule answers first
            self.assertTrue('MAX_PENDING' in str(e.exception) or 'l2MinBurn' in str(e.exception), str(e.exception))
        cfg = a_vault('arbitrum-one')
        cfg['vault']['policy']['minDeposit'] = 21 * U       # the committed value before this round, burn 20 unchanged
        with self.assertRaises(vp.Refused) as e:
            vp.validate(cfg, False)
        self.assertIn('MAX_PENDING', str(e.exception))
        self.assertIn('2382', str(e.exception))
        self.assertIn('24414319', str(e.exception))        # the least minimum deposit the rule allows
        cfg['vault']['policy']['minDeposit'] = 24_414_319
        vp.validate(cfg, False)

    def test_the_pair_is_held_with_the_token_s_own_bucket_and_delay(self):
        v, t = a_pair('op-mainnet')
        vp.validate(v, False, t)
        slow = copy.deepcopy(t)
        slow['limits']['largeMintDelay'] = 2 * DELAY    # a longer mint delay queues more: (25,000 + 2 x 25,000) / 24.9875 = 3,001
        with self.assertRaises(vp.Refused) as e:
            vp.validate(v, False, slow)
        self.assertIn('MAX_PENDING', str(e.exception))
        self.assertIn('3001', str(e.exception))

    def test_control_a_rehearsal_config_is_not_judged(self):
        cfg = a_vault('arbitrum-one')
        cfg['vault']['policy']['minDeposit'] = 21 * U
        cfg['ethereum']['chainId'] = launch.rehearsal_chain_id(42161)
        try:
            vp.validate(cfg, True)
        except vp.Refused as e:   # a rehearsal config may be refused for its own reasons, never for the queue
            self.assertNotIn('MAX_PENDING', str(e))


if __name__ == '__main__':
    unittest.main()
