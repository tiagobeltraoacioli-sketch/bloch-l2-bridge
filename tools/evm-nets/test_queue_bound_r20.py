#!/usr/bin/env python3
"""Round 20 (agent 421, finding F410-1): the honest mint queue fits MAX_PENDING on every launchable route, by rule.

  python3 -m unittest test_queue_bound_r20     (in tools/evm-nets; no chain, no key)

The frozen L2 token queues every mint for `largeMintDelay` (12 h; T = 0) and holds at most MAX_PENDING = 2,048 mints
that are queued and not yet executed. Its own comment states the design point: honest mints at the bucket rate queue
at most (bucket + refill x delay) / smallest mint, and (bucket + 2 x refill x delay) / smallest mint when executions
lag by one more delay; with the first values (10 USDC, bucket 10,000) that was 1,500 and 2,000.

The launch limits of 2026-11-19 raised the bucket of Arbitrum One and OP Mainnet to 25,000 USDC while their minimum
deposit stayed 21 USDC: 1,786 and 2,382, above MAX_PENDING (finding F410-1 of agent 410). The coordinator first decided
25 USDC (1,500 and 2,000: the token's design point) and then, after review 420 (R420-4: at 21 / 20 the four routes
could ask the L2 for about 6,285 transactions a day against a documented capacity of 3,072), replaced it the same day:
**Arbitrum One and OP Mainnet take the Ethereum minimums, deposit 101 USDC and burn 100 USDC** (371 and 495 queued).

A second bound is held with it (class L2Load): the summed worst case of bridge transactions a day on the L2 (a window
of smallest mints, the executions that credit them, a window of smallest burns, on every launchable route) against
the documented L2 capacity, with a stated share left for everything else.

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
    'arbitrum-one': ((101, 100, 5, 25_000), (100_949_500, 371, 495)),
    'op-mainnet': ((101, 100, 5, 25_000), (100_949_500, 371, 495)),
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
        # the first answer to it, 25 USDC: the token's design point exactly
        self.assertEqual(launch.queue_figures(25_000 * U, 289351, 25 * U, 5), (25 * U - 12_500, 1500, 2000))
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
        self.assertEqual(launch.queue_bound(42161)['lag_to_fill_s'], 585075)  # 6.8 days of execution lag (13.1 h at 25 USDC)
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
        'the 21 USDC minimum again on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=21 * U, l2MinBurn=20 * U),
        'the 21 USDC minimum again on OP Mainnet': lambda r: r['networks']['op-mainnet'].update(minDeposit=21 * U, l2MinBurn=20 * U),
        'one unit below the floor on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=24_414_318, l2MinBurn=20 * U),
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
                self.assertIn('MAX_PENDING', str(e.exception), what)   # the queue rule answers before the L2 load rule
            for chain in (42161, 10, 59144):   # every network is refused, not only the edited one
                self.assertIsNotNone(launch.refusal(chain, path), (what, chain))
            for call in (launch.limits, launch.fee_schedule, launch.queue_bound):
                with self.assertRaises(launch.LaunchError, msg=(what, call.__name__)):
                    call(1, path)

    def test_control_edits_that_keep_the_bound_load(self):
        keeps = {
            '102 USDC on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=102 * U),
            '150 / 120 USDC on OP Mainnet': lambda r: r['networks']['op-mainnet'].update(minDeposit=150 * U, l2MinBurn=120 * U),
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
        # what the margin was at 25 USDC (the token's design point, not far inside it), and what it is at 101
        lim = launch.limits(42161)
        args = (lim['bucket_capacity'], lim['refill_per_second'], 25 * U, 5)
        self.assertLessEqual(launch.queue_figures(*args)[2], MAX_PENDING)
        self.assertGreater(launch.queue_figures(*args, delay=DELAY + 3600)[2], MAX_PENDING)
        self.assertEqual(launch.queue_figures(*args, lag_delays=2)[2], 2501)
        now = (lim['bucket_capacity'], lim['refill_per_second'], 101 * U, 5)
        self.assertEqual(launch.queue_figures(*now, lag_delays=13)[2], 1981)    # thirteen more delays of lag still fit
        self.assertLessEqual(launch.queue_figures(*now, delay=4 * DELAY)[2], MAX_PENDING)


class L2Load(unittest.TestCase):
    """The summed worst case of bridge transactions a day on the L2, every launchable route at once, each at its window
    in smallest items: mints = window / smallest mint, executions = one per (1 + MAX_DRAIN) mints, burns = window /
    minimum burn. Against the documented L2 capacity (48 blocks a day at the documented pacing of 1,800 s x 64
    transactions = 3,072: agents/347-fee-economics-r17.md; review 420, R420-4), of which the bridge may take at most
    L2_BRIDGE_SHARE_BPS. What the bound does NOT cover is stated in docs/BRIDGE-ALLNETS.md 7.3 and held below as figures."""

    WANT = {  # route: (mints, executions, burns)
        'ethereum': (495, 55, 500), 'arbitrum-one': (247, 28, 250), 'op-mainnet': (247, 28, 250), 'linea': (41, 5, 41)}

    def test_the_constants_and_their_sources(self):
        self.assertEqual((launch.L2_BLOCKS_PER_DAY, launch.L2_TXS_PER_BLOCK, launch.L2_TX_CAPACITY), (48, 64, 3072))
        self.assertEqual(launch.L2_TX_CAPACITY, launch.L2_BLOCKS_PER_DAY * launch.L2_TXS_PER_BLOCK)
        self.assertEqual((launch.MAX_DRAIN, launch.L2_BRIDGE_SHARE_BPS), (8, 7500))
        self.assertIn('uint256 internal constant MAX_DRAIN = 8;', (ROOT / 'contracts/stable/BridgedStablecoinV3.sol').read_text())

    def test_the_worst_case_of_the_four_routes_fits_with_the_stated_margin(self):
        load = launch.l2_load()
        self.assertEqual(sorted(load['routes']), sorted(LAUNCHABLE))
        for name, (mints, executions, burns) in self.WANT.items():
            r = load['routes'][name]
            self.assertEqual((r['mints'], r['executions'], r['burns'], r['total']), (mints, executions, burns, mints + executions + burns), name)
        self.assertEqual((load['mints'], load['executions'], load['burns'], load['total']), (1030, 116, 1041, 2187))
        self.assertEqual((load['capacity'], load['limit']), (3072, 2304))      # the bridge may ask for at most three quarters
        self.assertLessEqual(load['total'], load['limit'])
        self.assertTrue(load['ok'])
        self.assertEqual(load['margin'], 3072 - 2187)                          # 885 transactions a day left for everything else
        self.assertGreater(load['margin'] * 100, 28 * load['capacity'])        # 28.8% of the documented capacity

    def test_the_figures_before_the_decision_and_the_arithmetic(self):
        # review 420, R420-4: 21 / 20 on Arbitrum One and OP Mainnet (the review rounds executions over the sum: 6,283)
        self.assertEqual(launch.l2_route_load(25_000 * U, 21 * U, 20 * U, 5), {'mints': 1191, 'executions': 133, 'burns': 1250, 'total': 2574})
        self.assertEqual(495 + 55 + 500 + 2 * 2574 + 41 + 5 + 41, 6285)
        # the first decision, 25 / 20: 5,861, still above the capacity
        self.assertEqual(launch.l2_route_load(25_000 * U, 25 * U, 20 * U, 5)['total'], 1000 + 112 + 1250)
        self.assertEqual(495 + 55 + 500 + 2 * 2362 + 87, 5861)
        self.assertEqual(launch.l2_route_load(50_000 * U, 101 * U, 100 * U, 5), {'mints': 495, 'executions': 55, 'burns': 500, 'total': 1050})
        for bad in ((0, 1, 1, 0), (1, 0, 1, 0), (1, 1, 0, 0), (1, 1, 1, 10_000), (1.0, 1, 1, 0), (True, 1, 1, 0)):
            with self.assertRaises(launch.LaunchError, msg=bad):
                launch.l2_route_load(*bad)

    def edited(self, change):
        reg = copy.deepcopy(REGISTRY)
        change(reg)
        tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        json.dump(reg, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_a_registry_whose_routes_together_exceed_the_share_is_untrusted(self):
        breaks = {
            # each keeps the mint queue bound (the other rule) and breaks only the load
            '60 / 50 USDC on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=60 * U, l2MinBurn=50 * U),
            '101 / 30 USDC on OP Mainnet (many small burns)': lambda r: r['networks']['op-mainnet'].update(l2MinBurn=30 * U),
            '90 / 80 USDC on both networks': lambda r: [r['networks'][n].update(minDeposit=90 * U, l2MinBurn=80 * U) for n in ('arbitrum-one', 'op-mainnet')],
        }
        for what, change in breaks.items():
            path = self.edited(change)
            with self.assertRaises(launch.LaunchError, msg=what) as e:
                launch.registry(path)
            self.assertIn('L2 capacity', str(e.exception), what)
            self.assertNotIn('MAX_PENDING', str(e.exception), what)
            for chain in (42161, 10, 59144):
                self.assertIsNotNone(launch.refusal(chain, path), (what, chain))
            with self.assertRaises(launch.LaunchError):
                launch.limits(1, path)
        keeps = {
            '99 / 98 USDC on Arbitrum One': lambda r: r['networks']['arbitrum-one'].update(minDeposit=99 * U, l2MinBurn=98 * U),
            # a held network adds nothing to the sum until it is launchable
            '11 / 10 USDC on Base (held)': lambda r: r['networks']['base'].update(minDeposit=11 * U, l2MinBurn=10 * U),
        }
        for what, change in keeps.items():
            self.assertTrue(launch.l2_load(self.edited(change))['ok'], what)

    def test_what_the_count_bound_does_not_cover_is_stated_as_figures(self):
        load = launch.l2_load()
        # (1) a day that starts with full buckets admits two windows of mints
        self.assertEqual(load['first_day_total'], 2187 + 1030 + 116)
        self.assertGreater(load['first_day_total'], load['capacity'])
        # (2) the relayer sends one executeMint per L2 block and drains behind it, so the credit transactions can be more
        # than one per nine mints: 278, not 116, and the count 2,349. Of the documented 3,072 that is 76.5%, ABOVE the
        # three-quarter line the rule draws with the one-per-nine figure; of the launch configuration's 128 a block
        # (6,144) it is 38%. Stated for the coordinator; the gas rule below uses this larger pattern.
        self.assertEqual((load['transactions_relayer_pattern'], load['tx_capacity_launch_config']), (2349, 6144))
        self.assertGreater(load['transactions_relayer_pattern'], load['limit'])
        self.assertLess(load['transactions_relayer_pattern'], load['capacity'])


class L2Gas(unittest.TestCase):
    """Finding F421-2, closed by measurement (coordinator, 2026-11-19): the summed worst case of DECLARED gas a day of
    the four launchable routes against the L2's block gas a day, refused above the same 75% line. The relayers' limits
    are the gas measured on an L2 replica made by the released binaries (l2-gas-measured-2026-11-19.json) plus 25%."""

    MEASURED = json.loads((HERE / 'l2-gas-measured-2026-11-19.json').read_text())

    def test_the_capacity_is_the_l2_launch_configuration_s(self):
        self.assertEqual((launch.L2_BLOCK_GAS, launch.L2_BLOCKS_PER_DAY, launch.L2_GAS_CAPACITY, launch.L2_GAS_SHARE_BPS),
                         (15_000_000, 48, 720_000_000, 7500))
        self.assertEqual(launch.L2_GAS_SHARE_BPS, launch.L2_BRIDGE_SHARE_BPS)   # the same line as the transaction count

    def test_the_limits_are_the_measured_need_plus_a_quarter_and_the_templates_carry_them(self):
        need, lim = self.MEASURED['need'], self.MEASURED['limits']
        self.assertEqual((launch.RELAYER_MINT_GAS, launch.RELAYER_EXECUTE_GAS, launch.RELAYER_DRAIN_GAS, launch.USER_BURN_GAS),
                         (lim['mint_gas_limit'], lim['execute_gas_limit'], lim['drain_gas_limit'], lim['user_burn_gas_assumed']))
        for limit, needed in ((launch.RELAYER_MINT_GAS, need['mint']), (launch.RELAYER_EXECUTE_GAS, need['executeMint_head_plus_8']),
                              (launch.RELAYER_DRAIN_GAS, need['drain_8_credits'])):
            self.assertGreaterEqual(limit * 4, needed * 5)            # at least 25% above the need
            self.assertLess(limit - 10_000, -(-needed * 5 // 4))      # and no more than the rounding to 10,000
        self.assertGreaterEqual(launch.RELAYER_MINT_GAS, need['mint_first_ever'])   # even the first mint a token sees fits
        self.assertGreaterEqual(launch.USER_BURN_GAS * 2, need['burn'] * 3)
        for name in LAUNCHABLE:
            path = ROOT / ('deployments/mainnet/busdc-ops' if name == 'ethereum' else f'deployments/{name}/ops') / 'relayer.template.json'
            t = json.loads(path.read_text())
            self.assertEqual((t['mint_gas_limit'], t['execute_gas_limit'], t['drain_gas_limit']),
                             (launch.RELAYER_MINT_GAS, launch.RELAYER_EXECUTE_GAS, launch.RELAYER_DRAIN_GAS), name)

    def test_the_measurements_are_what_the_limits_claim(self):
        # the need of each kind is not below anything a run measured (gas used, and the estimates the runs took)
        runs = self.MEASURED['runs']
        need = self.MEASURED['need']
        self.assertEqual(sorted(runs), ['bound1', 'bound2', 'bound3', 'contested1', 'estimates1', 'estimates2', 'estimates3', 'try1'])
        mints = 0
        for name, run in runs.items():
            self.assertEqual(run['creation_keccak'], '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7', name)
            for step, row in run['steps'].items():
                top = row['gas_used_max']
                if step.startswith('mint: first ever'):
                    self.assertLessEqual(top, need['mint_first_ever'], (name, step))
                elif step.startswith('mint:') and 'candidates' not in step and 'must fail safe' not in step and '0..11' not in step:
                    self.assertLessEqual(top, need['mint'], (name, step))
                    mints += row['transactions']
                elif step.startswith('executeMint(head): head + 8'):
                    self.assertLessEqual(top, need['executeMint_head_plus_8'], (name, step))
                elif step.startswith('drain(): 8') or step.startswith('drain(): 5') or step == 'drain(): after the failed one':
                    self.assertLessEqual(top, need['drain_8_credits'], (name, step))
                elif step.startswith('burn:'):
                    self.assertLessEqual(top, need['burn'], (name, step))
                if 'must fail safe' in step and name not in ('estimates3', 'try1'):   # (those two short runs had nothing left to drain)
                    self.assertEqual(row['status'], [0], (name, step))
            est = run.get('estimates') or {}
            if isinstance(est.get('drain() with 8 due'), int):
                self.assertLessEqual(est['drain() with 8 due'], need['drain_8_credits'], name)
            for key in ('estimate_second_mint', 'estimate_first_burn', 'estimate_later_burn'):
                if isinstance(run.get(key), int):
                    self.assertLessEqual(run[key], need['mint'] if 'mint' in key else need['burn'], (name, key))
        self.assertGreater(mints, 6000)   # three runs to MAX_PENDING and the shorter ones
        for name in ('bound1', 'bound2', 'bound3'):
            self.assertEqual((runs[name]['token_max_pending'], runs[name]['pending_at_bound'], runs[name]['pending_after_failures']), (2048, 2048, 2048))
        self.assertEqual(runs['estimates3']['estimates']['executeMint(head) with 8 due behind']['with block 0x7'], 472034)

    def test_the_relayer_s_credit_transactions(self):
        # one executeMint per L2 block with a due mint; a first drain when a block has more than nine; then one per eight
        for mints, want in ((0, (0, 0)), (9, (9, 0)), (41, (41, 0)), (48, (48, 0)), (49, (48, 0)), (57, (48, 1)), (247, (48, 22)),
                            (495, (48, 49)), (480, (48, 48)), (488, (48, 49)), (990, (48, 111))):
            self.assertEqual(launch.relayer_credit_txs(mints), want, mints)
            e, d = want
            self.assertLessEqual(mints, e * 9 + d * 8 if mints > 48 else mints)   # enough credits for every mint
        with self.assertRaises(launch.LaunchError):
            launch.relayer_credit_txs(-1)

    def test_the_worst_case_of_the_four_routes_fits_under_three_quarters_of_the_block_gas(self):
        gas = launch.l2_load()['declared_gas']
        want = {'ethereum': (495, 48, 49, 500, 230_480_000), 'arbitrum-one': (247, 48, 22, 250, 128_090_000),
                'op-mainnet': (247, 48, 22, 250, 128_090_000), 'linea': (41, 41, 0, 41, 38_950_000)}
        for name, (mints, executes, drains, burns, total) in want.items():
            r = gas['routes'][name]
            self.assertEqual((r['mints'], r['executes'], r['drains'], r['burns'], r['gas']), (mints, executes, drains, burns, total), name)
            self.assertEqual(r['gas'], mints * 250_000 + executes * 600_000 + drains * 570_000 + burns * 100_000, name)
        self.assertEqual((gas['mints'], gas['executes'], gas['drains'], gas['burns'], gas['transactions']), (1030, 185, 93, 1041, 2349))
        self.assertEqual((gas['total'], gas['capacity'], gas['limit']), (525_610_000, 720_000_000, 540_000_000))
        self.assertTrue(gas['ok'])
        self.assertEqual(gas['margin'], 194_390_000)                 # 27.0% of the day's block gas is left
        self.assertLess(gas['limit'] - gas['total'], 15_000_000)     # and under the 75% line by less than one block: stated
        # per block: one drain, even at the worst measured for an incident (2.25 million), is far below one block
        self.assertEqual(gas['one_block_fits'], {'relayer_mints': 60, 'drains': 26})
        self.assertLess(2_250_000 * 6, launch.L2_BLOCK_GAS)
        # stated, not rules: the first day with full buckets; every supply burned at once by its holders
        self.assertEqual(gas['first_day_total'], 855_140_000)
        self.assertGreater(gas['first_day_total'], gas['capacity'])
        supply_burns = 500_000 * U // (100 * U) + 2 * (250_000 * U // (100 * U)) + 250_000 * U // (600 * U)
        self.assertEqual(supply_burns, 10_416)
        self.assertGreater(supply_burns * launch.USER_BURN_GAS, gas['capacity'])

    def edited(self, change):
        reg = copy.deepcopy(REGISTRY)
        change(reg)
        tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        json.dump(reg, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_a_registry_whose_routes_together_declare_more_gas_is_untrusted(self):
        # a minimum deposit of 80 USDC on one network keeps the queue bound and the transaction-count rule (2,259 of 2,304)
        # and breaks only the gas (65 more mints and 7 more drains a day: 545.9 million)
        path = self.edited(lambda r: r['networks']['arbitrum-one'].update(minDeposit=80 * U))
        with self.assertRaises(launch.LaunchError) as e:
            launch.registry(path)
        self.assertIn('gas a day on the L2', str(e.exception))
        self.assertNotIn('MAX_PENDING', str(e.exception))
        self.assertNotIn('transactions a day', str(e.exception))
        for chain in (42161, 10, 59144):
            self.assertIsNotNone(launch.refusal(chain, path))
        with self.assertRaises(launch.LaunchError):
            launch.limits(1, path)
        self.assertTrue(launch.l2_load(self.edited(lambda r: r['networks']['arbitrum-one'].update(minDeposit=102 * U)))['declared_gas']['ok'])

    def test_a_larger_limit_or_a_smaller_block_breaks_it(self):
        from unittest import mock
        for name, value in (('RELAYER_MINT_GAS', 300_000), ('RELAYER_DRAIN_GAS', 2_000_000), ('USER_BURN_GAS', 150_000),
                            ('L2_GAS_CAPACITY', 48 * 12_000_000)):
            with mock.patch.object(launch, name, value):
                with self.assertRaises(launch.LaunchError, msg=name):
                    launch.registry()
        launch.registry()


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

    def test_the_two_networks_carry_the_ethereum_minimums(self):
        eth = REGISTRY['relayCost']['ethereum']
        for name in ('arbitrum-one', 'op-mainnet'):
            self.assertEqual((NETS[name]['minDeposit'], NETS[name]['l2MinBurn']), (eth['minDeposit'], eth['l2MinBurn']), name)
            self.assertEqual((NETS[name]['minDeposit'], NETS[name]['l2MinBurn']), (101 * U, 100 * U), name)
            for text in ('2026-11-19', '101', '100', 'R420-4', 'F410-1', '21', '25'):
                self.assertIn(text, NETS[name]['minDepositDecision'], (name, text))
            self.assertGreaterEqual(NETS[name]['l2MinBurn'], launch.min_burn_floor(NETS[name]['chainId'], NETS[name]['feeBps']['release']))
        self.assertEqual((NETS['linea']['minDeposit'], NETS['linea']['l2MinBurn']), (601 * U, 600 * U))

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
            cfg['vault']['policy'].update(minDeposit=low, l2MinBurn=min(cfg['vault']['policy']['l2MinBurn'], low - U, 20 * U))
            with self.assertRaises(vp.Refused, msg=(name, low)) as e:
                vp.validate(cfg, False)
            # every one is refused; where the lowered l2MinBurn falls below the relayer cost, that older rule answers first
            self.assertTrue('MAX_PENDING' in str(e.exception) or 'l2MinBurn' in str(e.exception), str(e.exception))
        cfg = a_vault('arbitrum-one')
        cfg['vault']['policy'].update(minDeposit=21 * U, l2MinBurn=20 * U)    # the committed values before this round
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
        slow['limits']['largeMintDelay'] = 8 * DELAY    # a longer mint delay queues more: (25,000 + 2 x 100,000) / 100.9495 = 2,228
        with self.assertRaises(vp.Refused) as e:
            vp.validate(v, False, slow)
        self.assertIn('MAX_PENDING', str(e.exception))
        self.assertIn('2228', str(e.exception))

    def test_control_a_rehearsal_config_is_not_judged(self):
        cfg = a_vault('arbitrum-one')
        cfg['vault']['policy'].update(minDeposit=21 * U, l2MinBurn=20 * U)
        cfg['ethereum']['chainId'] = launch.rehearsal_chain_id(42161)
        try:
            vp.validate(cfg, True)
        except vp.Refused as e:   # a rehearsal config may be refused for its own reasons, never for the queue
            self.assertNotIn('MAX_PENDING', str(e))


if __name__ == '__main__':
    unittest.main()
