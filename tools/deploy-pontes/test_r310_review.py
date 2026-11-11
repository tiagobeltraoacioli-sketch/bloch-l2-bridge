"""Round 15 independent review (agent 310): deploy-tool demonstrations against 1aef47c.
Each test PASSES while the defect exists.

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
    """R310-2: the refusal list ("refused in every role") does not cover the vault's immutable fee recipient."""

    def test_R310_2_a_refused_address_is_accepted_as_the_immutable_fee_treasury(self):
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
        vp.validate(cfg, False, tok)                        # ... but passes mainnet validation as the fee treasury


if __name__ == '__main__':
    unittest.main()
