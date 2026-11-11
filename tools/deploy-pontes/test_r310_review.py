"""Round 15 review finding R310-2 (agent 310), fixed by agent 314: the reviewer's demonstration (dded5c2) with the
last assertion turned around.

  python3 -m unittest -v test_r310_review
"""
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import legacy_digests  # noqa: E402
import vault_pontes as vp  # noqa: E402
from launch_fixture import filled, filled_vault, stand_in_retired  # noqa: E402


class R310FeeRecipientNotRefused(unittest.TestCase):
    """R310-2: the refusal list ("refused in every role") covers the vault's immutable fee recipient too."""

    def test_R310_2_a_refused_address_is_refused_as_the_immutable_fee_treasury(self):
        addrs, env = stand_in_retired()
        os.environ['BLOCH_BRIDGE_REFUSE_SHA256'] = env
        self.addCleanup(os.environ.pop, 'BLOCH_BRIDGE_REFUSE_SHA256', None)
        self.assertTrue(legacy_digests.is_legacy(addrs[0]))
        tok = filled()
        control = filled_vault(tok)
        control['vault']['signers']['set'][6]['address'] = addrs[0]
        with self.assertRaises(vp.Refused):                 # control: the same address as a signer is refused
            vp.validate(control, False, tok)
        cfg = filled_vault(tok)
        cfg['vault']['provenance']['fees']['recipient'] = addrs[0]
        with self.assertRaisesRegex(vp.Refused, 'no recorded holder'):   # ... and as the fee treasury
            vp.validate(cfg, False, tok)
        cfg['vault']['provenance']['fees']['recipient'] = '0x' + '7e' * 20
        vp.validate(cfg, False, tok)                        # a fresh treasury passes


if __name__ == '__main__':
    unittest.main()
