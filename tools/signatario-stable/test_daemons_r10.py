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

# The FINAL L2 deposit-only launch build (agents/201-kit-final.md, two-host rebuild at 01:47 UTC 2026-11-03): release
# bloch-l2-2026-11-03-next-native-78d4921c, build commit 926d2cf, signing target (SHA256SUMS) 6d3bd628...
# Only the settled RPC moved from 17383fe (e5754d05, signing target 116bfaba).
LAUNCH_BUILD = {
    'follower': 'cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2',
    'produce': 'e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69',
    'settled_rpc': '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d',
}


class R10S1SignerPins(unittest.TestCase):
    """`deployments/mainnet/busdc-ops/signer.template.json` sets `"l2_pins": "mainnet-v2"`, which is l2_finality.MAINNET_V2:
    the v2.1 binaries (c18752fd, fb0d5313, 18be911a). An operator who installs the launch build fails every release
    certificate with "the follower binary is not the pinned build"; one who installs v2.1 to satisfy the pins rebuilds the
    L2 with a producer the launch did not ship."""

    def test_the_mainnet_pins_name_the_launch_build(self):
        self.assertEqual(l2_finality.MAINNET_V2['binaries'], LAUNCH_BUILD)

    def test_round20_the_template_pins_name_the_build_that_is_live(self):
        """Round 20 (agent 421, F410-2): the same finding again, one release later. The template named the 2026-11-03 build
        while the L2 went live with the release of 2026-11-17 (follower d4d2b99a, producer 598873ae). The template now names
        the current pin set, which is that release; MAINNET_V2 above stays as the record of the earlier build."""
        import json
        template = json.loads((Path(__file__).resolve().parents[2] / 'deployments/mainnet/busdc-ops/signer.template.json').read_text())
        self.assertEqual(l2_finality.pins_from_config(template)['binaries'], {
            'follower': 'd4d2b99a20f6093cbaf2b9cebead41b3c6b4bf5aad37f2a091752746a659fe96',
            'produce': '598873aef6770002297a710387969218dd7d684ea8e9d8bdcf067d43123b37db',
            'settled_rpc': '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d'})

    def test_control_the_binary_check_refuses_another_build(self):
        d = Path(tempfile.mkdtemp(prefix='a173-s-'))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = d / 'follower'
        p.write_bytes(b'x')
        with self.assertRaises(l2_finality.NotFinal):
            l2_finality.check_binaries({'follower': str(p)}, {'binaries': {'follower': '00' * 32}})

    def test_the_pins_are_no_longer_provisional(self):
        self.assertFalse(l2_finality.SETTLED_RPC_PIN_PROVISIONAL,
                         'l2_finality.py: "Do not deploy signers while this is True"')


if __name__ == '__main__':
    unittest.main()
