#!/usr/bin/env python3
"""Agent 194, owner decision item 2 (2026-11-02): the launch configuration as refusals of the deploy tools.

  python3 -m unittest -v test_launch_config        (offline: no RPC, no cast, no forge)

Unpause, switch and locked remint 6 of 7 on the token (mintSwitch.threshold) and the vault (switchThreshold) on
mainnet; 3 L2 token guardians and 3 Ethereum vault guardians (BR-6); the 22 addresses committed on 2026-10-14 (agent
174's list) are refused in every role and are gone from the committed templates; the operator templates keep
`vault_pause_on_mint` true and `release_hold` false.
"""
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import deploy_pontes as dp  # noqa: E402
import vault_pontes as vp  # noqa: E402
import legacy_digests as ld  # noqa: E402
from launch_fixture import (ROOT, TOKEN_CFG, VAULT_CFG, WGNB_CFG, filled, filled_vault, fresh, private_retired,  # noqa: E402
                            rehearsal, stand_in_retired)

# The refusal tests run over the real retired addresses where the private list is present, and always over throwaway
# stand-ins whose digests are added through BLOCH_BRIDGE_REFUSE_SHA256 (the same code path).
PRIVATE = private_retired()
STAND_INS, STAND_IN_ENV = stand_in_retired()
LEGACY_SAMPLES = PRIVATE + STAND_INS


class LaunchConfig(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.dict(os.environ, {'BLOCH_BRIDGE_REFUSE_SHA256': STAND_IN_ENV})
        patch.start()
        self.addCleanup(patch.stop)

    def refused(self, fn, needle):
        with self.assertRaises((dp.Refused, vp.Refused)) as e:
            fn()
        self.assertIn(needle, str(e.exception))

    def test_the_legacy_list_holds_22_digests_and_no_address(self):
        self.assertEqual(len(ld.LEGACY_ADDRESS_SHA256), 22)
        for d in ld.LEGACY_ADDRESS_SHA256:
            self.assertRegex(d, r'^[0-9a-f]{64}$')
        for f in ('legacy_digests.py', 'deploy_pontes.py', 'vault_pontes.py', 'key_inventory.py'):
            text = (HERE / f).read_text()
            for a in set(re.findall(r'0x[0-9a-fA-F]{40}', text)):
                self.assertFalse(ld.is_legacy(a), f'{f} still holds a refused address')

    def test_the_digest_list_refuses_exactly_the_private_list(self):
        """Before and after: with the private list of the 22 addresses (never committed), every one is refused and
        the digests are exactly theirs. Skipped where the private list is absent."""
        if not PRIVATE:
            self.skipTest('private list of the retired addresses not present (BLOCH_RETIRED_ADDRESSES_FILE)')
        self.assertEqual(len(PRIVATE), 22)
        self.assertEqual({ld.address_digest(a) for a in PRIVATE}, set(ld.LEGACY_ADDRESS_SHA256))
        self.assertEqual(ld.legacy_among(PRIVATE + [fresh(1), fresh(2)]), sorted(a.lower() for a in PRIVATE))
        self.assertTrue(all(ld.is_legacy(a.upper().replace('0X', '0x')) for a in PRIVATE))

    def test_the_environment_only_adds_refusals(self):
        a = fresh(77)
        with mock.patch.dict(os.environ, {'BLOCH_BRIDGE_REFUSE_SHA256': ''}):
            self.assertFalse(ld.is_legacy(a))
            self.assertEqual(ld.refused_digests(), ld.LEGACY_ADDRESS_SHA256)
        with mock.patch.dict(os.environ, {'BLOCH_BRIDGE_REFUSE_SHA256': ld.address_digest(a)}):
            self.assertTrue(ld.is_legacy(a))
            self.assertTrue(set(ld.LEGACY_ADDRESS_SHA256) < set(ld.refused_digests()))
        with mock.patch.dict(os.environ, {'BLOCH_BRIDGE_REFUSE_SHA256': 'not-a-digest'}):
            with self.assertRaises(ValueError):
                ld.is_legacy(a)

    def test_no_committed_address_is_left_in_the_mainnet_configs(self):
        for f in (TOKEN_CFG, VAULT_CFG, WGNB_CFG):
            found = set(re.findall(r'0x[0-9a-fA-F]{40}', f.read_text()))
            self.assertEqual(ld.legacy_among(found), [], f.name)

    def test_the_committed_templates_are_refused_until_the_owner_fills_them(self):
        for f in (TOKEN_CFG, WGNB_CFG):
            with self.assertRaises(dp.Refused):
                dp.validate(json.loads(f.read_text()), False)
        with self.assertRaises(vp.Refused):
            vp.validate(json.loads(VAULT_CFG.read_text()), False)

    def test_every_legacy_address_is_refused_in_every_role(self):
        for a in LEGACY_SAMPLES:
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
        for a in LEGACY_SAMPLES[:3]:
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
