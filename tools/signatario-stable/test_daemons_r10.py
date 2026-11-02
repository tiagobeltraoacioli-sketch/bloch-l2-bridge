#!/usr/bin/env python3
"""Bridge daemons review, round 10 (agents/173): signer side. No chain and no key material.

  python3 -m unittest -v test_daemons_r10

A FAILURE IS THE REPRODUCTION of a finding; tests named `test_control_...` pass on the reviewed tip (5fb9cf0).
"""
from pathlib import Path
import shutil
import tempfile
import unittest

import l2_finality

# agents/PINS-NEXT.md (agent 65, kit f1c8033, build 17383fe, signing target 116bfaba...): the L2 deposit-only launch build.
# TODO(launch-build re-pin): agent 195 moves the settled-RPC hash (and the signing target); use the FINAL build's hashes.
LAUNCH_BUILD = {
    'follower': 'cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2',
    'produce': 'e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69',
    'settled_rpc': 'e5754d05a1d6b217374a652d6959acf1fcd9323703d82226e07aa1d77a1754e8',
}


class R10S1SignerPins(unittest.TestCase):
    """`deployments/mainnet/busdc-ops/signer.template.json` sets `"l2_pins": "mainnet-v2"`, which is l2_finality.MAINNET_V2:
    the v2.1 binaries (c18752fd, fb0d5313, 18be911a). An operator who installs the launch build fails every release
    certificate with "the follower binary is not the pinned build"; one who installs v2.1 to satisfy the pins rebuilds the
    L2 with a producer the launch did not ship."""

    # TODO(launch-build re-pin, l2_finality.py): an expected failure until the follow-up commit pins the final launch build.
    # unittest counts an unexpected success as a failure, so that commit must update LAUNCH_BUILD and drop both decorators.
    @unittest.expectedFailure
    def test_the_mainnet_pins_name_the_launch_build(self):
        self.assertEqual(l2_finality.MAINNET_V2['binaries'], LAUNCH_BUILD)

    def test_control_the_binary_check_refuses_another_build(self):
        d = Path(tempfile.mkdtemp(prefix='a173-s-'))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = d / 'follower'
        p.write_bytes(b'x')
        with self.assertRaises(l2_finality.NotFinal):
            l2_finality.check_binaries({'follower': str(p)}, {'binaries': {'follower': '00' * 32}})

    @unittest.expectedFailure  # TODO(launch-build re-pin), as above
    def test_the_pins_are_no_longer_provisional(self):
        self.assertFalse(l2_finality.SETTLED_RPC_PIN_PROVISIONAL,
                         'l2_finality.py: "Do not deploy signers while this is True"')


if __name__ == '__main__':
    unittest.main()
