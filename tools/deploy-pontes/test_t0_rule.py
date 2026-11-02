#!/usr/bin/env python3
"""Agent 194, owner decision item 1 (2026-11-02): T = 0 as a hard rule in the deploy tool (agents 171 F171-5, 175).

  python3 -m unittest -v test_t0_rule        (offline: no RPC, no cast, no forge)

`deploy_pontes.py validate` (and therefore plan, run, record and verify, which all validate first) refuses
largeMintThreshold != 0 for BridgedStablecoinV3 on every network and for any stable token on mainnet, and refuses a
non-zero instant capacity (10 x T, or the whole bucket below 10 units).
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deploy_pontes as dp  # noqa: E402
from launch_fixture import filled, rehearsal  # noqa: E402


class TZeroRule(unittest.TestCase):
    def refused(self, cfg, needle, reh=False):
        with self.assertRaises(dp.Refused) as e:
            dp.validate(cfg, reh)
        self.assertIn(needle, str(e.exception))

    def test_control_filled_mainnet_config_validates(self):
        p = dp.validate(filled(), False)
        self.assertEqual(p['limits']['largeMintThreshold'], 0)
        self.assertEqual(dp.instant_capacity(p['limits']), 0)

    def test_mainnet_refuses_T_above_zero(self):
        for t in (1, 100 * 10**6, 1_000 * 10**6):
            cfg = filled()
            cfg['limits']['largeMintThreshold'] = t
            self.refused(cfg, 'largeMintThreshold must be 0')

    def test_mainnet_refuses_T_max_no_delay(self):
        cfg = filled()
        cfg['limits']['largeMintThreshold'] = dp.UINT256_MAX
        with self.assertRaises(dp.Refused):
            dp.validate(cfg, False)

    def test_rehearsal_V3_refuses_T_above_zero(self):
        cfg = rehearsal(filled())
        cfg['limits']['largeMintThreshold'] = 100 * 10**6
        self.refused(cfg, 'largeMintThreshold must be 0', reh=True)

    def test_mainnet_V2_refuses_T_above_zero(self):
        cfg = filled()
        cfg['token']['contract'] = 'BridgedStablecoinV2'
        cfg['limits']['largeMintThreshold'] = 100 * 10**6
        self.refused(cfg, 'largeMintThreshold must be 0')

    def test_control_rehearsal_V2_may_still_use_T_above_zero(self):
        cfg = rehearsal(filled())
        cfg['token']['contract'] = 'BridgedStablecoinV2'
        cfg['limits']['largeMintThreshold'] = 100 * 10**6
        dp.validate(cfg, True)

    def test_refuses_nonzero_instant_capacity(self):
        """T = 0 with a bucket below INSTANT_MINTS units: the constructor makes the whole bucket instant."""
        cfg = rehearsal(filled())
        cfg['limits'].update(supplyCap=9, bucketCapacity=9, refillPerSecond=1, minBurn=1)
        cfg['ethereum']['vaultCap'] = 9
        self.refused(cfg, 'instant capacity must be 0', reh=True)

    def test_instant_capacity_matches_the_constructor(self):
        lim = {'bucketCapacity': 10_000 * 10**6, 'largeMintThreshold': 0}
        self.assertEqual(dp.instant_capacity(lim), 0)
        self.assertEqual(dp.instant_capacity(dict(lim, largeMintThreshold=100 * 10**6)), 1_000 * 10**6)
        self.assertEqual(dp.instant_capacity(dict(lim, largeMintThreshold=1_000 * 10**6)), 10_000 * 10**6)


if __name__ == '__main__':
    unittest.main()
