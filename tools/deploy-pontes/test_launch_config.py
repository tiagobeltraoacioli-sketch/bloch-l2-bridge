#!/usr/bin/env python3
"""Agent 194, owner decision item 2 (2026-11-02): the launch configuration as refusals of the deploy tools.

  python3 -m unittest -v test_launch_config        (offline: no RPC, no cast, no forge)

Unpause, switch and locked remint 6 of 7 on the token (mintSwitch.threshold) and the vault (switchThreshold) on
mainnet; 3 L2 token guardians and 3 Ethereum vault guardians (BR-6); the 22 addresses committed on 2026-10-14 (agent
174's list) are refused in every role and are gone from the committed templates; the operator templates keep
`vault_pause_on_mint` true and `release_hold` false.
"""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import deploy_pontes as dp  # noqa: E402
import vault_pontes as vp  # noqa: E402
from launch_fixture import ROOT, TOKEN_CFG, VAULT_CFG, WGNB_CFG, filled, filled_vault, fresh, rehearsal  # noqa: E402


class LaunchConfig(unittest.TestCase):
    def refused(self, fn, needle):
        with self.assertRaises((dp.Refused, vp.Refused)) as e:
            fn()
        self.assertIn(needle, str(e.exception))

    def test_the_legacy_list_is_agent_174s(self):
        self.assertEqual(len(dp.LEGACY_ADDRESSES), 22)
        self.assertIn('0x703a12b45fa13892ed8d03995218b2ea9d7f0f3b', dp.LEGACY_ADDRESSES)
        inv = HERE / 'key_inventory.py'
        if inv.exists():  # present once agent 174's branch is merged
            ns = {}
            exec(compile(inv.read_text().split('class Refused')[0], str(inv), 'exec'), ns)
            self.assertEqual(set(ns['LEGACY']), set(dp.LEGACY_ADDRESSES))

    def test_no_committed_address_is_left_in_the_mainnet_configs(self):
        for f in (TOKEN_CFG, VAULT_CFG, WGNB_CFG):
            text = f.read_text().lower()
            self.assertEqual([a for a in dp.LEGACY_ADDRESSES if a in text], [], f.name)

    def test_the_committed_templates_are_refused_until_the_owner_fills_them(self):
        for f in (TOKEN_CFG, WGNB_CFG):
            with self.assertRaises(dp.Refused):
                dp.validate(json.loads(f.read_text()), False)
        with self.assertRaises(vp.Refused):
            vp.validate(json.loads(VAULT_CFG.read_text()), False)

    def test_every_legacy_address_is_refused_in_every_role(self):
        for a in sorted(dp.LEGACY_ADDRESSES):
            for role in ('deployer', 'safe', 'signer', 'guardian', 'vaultGuard'):
                cfg = filled()
                if role == 'deployer':
                    cfg['deployer']['address'] = a
                elif role == 'safe':
                    cfg['deployer']['fundedBy']['safe'] = a
                elif role == 'signer':
                    cfg['signers']['set'][3]['address'] = a
                elif role == 'guardian':
                    cfg['guardians']['set'][1]['address'] = a
                else:
                    g = cfg['ethereum']['vaultGuard']['guardians']
                    g[1] = a
                    g.sort(key=lambda x: int(x, 16))
                self.refused(lambda: dp.validate(cfg, False), 'committed 2026-10-14')
            r = rehearsal(filled())
            r['signers']['set'][0]['address'] = a
            self.refused(lambda: dp.validate(r, True), 'committed 2026-10-14')

    def test_token_unpause_quorum_is_six_of_seven_on_mainnet(self):
        for t in (5, 7):
            cfg = filled()
            cfg['mintSwitch']['threshold'] = t
            self.refused(lambda: dp.validate(cfg, False), 'need 6 of 7')
        self.assertEqual(dp.validate(filled(), False)['switchThreshold'], 6)

    def test_three_token_guardians_and_three_vault_guardians_on_mainnet(self):
        for n in (2, 4):
            cfg = filled()
            cfg['guardians']['set'] = [{'operator': f'guard{i}', 'address': fresh(20 + i)} for i in range(n)]
            self.refused(lambda: dp.validate(cfg, False), 'L2 token guardians')
            cfg = filled()
            cfg['ethereum']['vaultGuard']['guardians'] = sorted((fresh(40 + i) for i in range(n)), key=lambda a: int(a, 16))
            self.refused(lambda: dp.validate(cfg, False), 'Ethereum vault guardians')

    def test_vault_validate_six_of_seven_three_guardians_no_legacy(self):
        tok = filled()
        norm = vp.validate(filled_vault(tok), False, tok)
        self.assertEqual(len(norm['guardians']), 3)
        for t in (5, 7):
            cfg = filled_vault(tok)
            cfg['vault']['policy']['switchThreshold'] = t
            self.refused(lambda: vp.validate(cfg, False, tok), 'need 6 of 7')
        cfg = filled_vault(tok)
        cfg['vault']['guard']['guardians'] = cfg['vault']['guard']['guardians'][:2]
        self.refused(lambda: vp.validate(cfg, False), '3 vault guardians')
        for a in sorted(dp.LEGACY_ADDRESSES)[:3]:
            cfg = filled_vault(tok)
            cfg['vault']['signers']['set'][6]['address'] = a
            self.refused(lambda: vp.validate(cfg, False), 'committed 2026-10-14')

    def test_operator_templates_carry_the_pause_and_hold_decisions(self):
        """validate refuses a mainnet config while guardiao's template turns vault_pause_on_mint off or eth-half's
        turns release_hold on. The templates are copied to a temporary root; the committed ones are not touched."""
        for name, key, bad in (('guardiao.template.json', 'vault_pause_on_mint', False),
                               ('eth-half.template.json', 'release_hold', True)):
            with tempfile.TemporaryDirectory() as tmp:
                ops = Path(tmp) / 'deployments/mainnet/busdc-ops'
                shutil.copytree(ROOT / 'deployments/mainnet/busdc-ops', ops)
                t = json.loads((ops / name).read_text())
                t[key] = bad
                (ops / name).write_text(json.dumps(t))
                saved, dp.ROOT = dp.ROOT, Path(tmp)
                try:
                    self.refused(lambda: dp.validate(filled(), False), f'"{key}" must be {str(not bad).lower()}')
                finally:
                    dp.ROOT = saved


if __name__ == '__main__':
    unittest.main()
