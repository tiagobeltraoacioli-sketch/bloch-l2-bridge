#!/usr/bin/env python3
"""Tests for key_inventory.py. Offline. Signature checks run only when `cast` is found (FOUNDRY_BIN), with throwaway
keys that live in a temporary directory and are deleted at the end."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import key_inventory as ki
from launch_fixture import private_retired, stand_in_retired

ROLES = [('l2-mint-signer', 7, 'hot-keystore', 'signer-op'), ('eth-release-signer', 7, 'hot-keystore', 'signer-op'),
         ('l2-token-guardian', 3, 'hot-keystore', 'guard-op'), ('eth-vault-guardian', 3, 'hot-keystore', 'guard-op'),
         ('eth-vault-deployer', 1, 'hardware-wallet', 'owner'), ('l2-token-deployer', 1, 'hardware-wallet', 'owner'),
         ('l2-relayer-gas', 1, 'hot-keystore', 'relayer'), ('eth-relayer-gas', 1, 'hot-keystore', 'relayer'),
         ('bloch-inc-safe', 1, 'safe', 'bloch-inc')]
HAVE_CAST = Path(ki.CAST).exists()


def inventory(addr):
    keys, n = [], 0
    for role, count, custody, op in ROLES:
        for i in range(1, count + 1):
            n += 1
            keys.append({'role': role, 'index': i, 'operator': f'{op}{i}' if count > 1 else op,
                         'address': addr(n), 'custody': custody, 'date': '2026-11-02', 'attestation': None})
    return {'domain': ki.DOMAIN, 'keys': keys}


def configs(inv):
    by = lambda r: [k for k in inv['keys'] if k['role'] == r]
    pair = lambda ks: [{'operator': k['operator'], 'address': k['address']} for k in ks]
    safe = by('bloch-inc-safe')[0]['address']
    tok = {'signers': {'set': pair(by('l2-mint-signer'))}, 'guardians': {'set': pair(by('l2-token-guardian'))},
           'deployer': {'address': by('l2-token-deployer')[0]['address'], 'fundedBy': {'safe': safe}},
           'ethereum': {'vaultGuard': {'guardians': sorted((k['address'] for k in by('eth-vault-guardian')),
                                                           key=lambda a: int(a, 16))}}}
    vau = {'vault': {'signers': {'set': pair(by('eth-release-signer'))}, 'guard': {'guardians': pair(by('eth-vault-guardian'))}},
           'deployer': {'address': by('eth-vault-deployer')[0]['address'], 'fundedBy': {'safe': safe}}}
    return tok, vau


class Offline(unittest.TestCase):
    def setUp(self):
        self.inv = inventory(lambda n: '0x' + f'{n:040x}')
        self.tok, self.vau = configs(self.inv)

    def ok(self, inv=None, tok=None, vau=None, allow=()):
        return ki.check(inv or self.inv, tok or self.tok, vau or self.vau, allow, skip_signatures=True)

    def refused(self, text, **kw):
        with self.assertRaises(ki.Refused) as cm:
            self.ok(**kw)
        self.assertIn(text, str(cm.exception))

    def role(self, inv, r):
        return [k for k in inv['keys'] if k['role'] == r]

    def test_accepts(self):
        out = self.ok()
        self.assertEqual(out['decision'], 'ok')
        self.assertEqual(out['keys'], 25)
        self.assertFalse(out['signaturesChecked'])

    def test_message_binds_every_field(self):
        m = ki.message('l2-mint-signer', 3, 'op3', '0x' + 'aB' * 20, '2026-11-02')
        self.assertIn('role=l2-mint-signer index=3 operator=op3 address=0x' + 'ab' * 20 + ' date=2026-11-02', m)

    def test_legacy(self):
        samples = private_retired()[:2] + stand_in_retired(1)[0]
        with mock.patch.dict(os.environ, {'BLOCH_BRIDGE_REFUSE_SHA256': stand_in_retired(1)[1]}):
            for a in samples:
                inv = copy.deepcopy(self.inv)
                self.role(inv, 'l2-token-deployer')[0]['address'] = '0x' + a[2:].upper()
                self.refused('committed 2026-10-14', inv=inv, tok=configs(inv)[0], vau=configs(inv)[1])
                tok, vau = configs(inv)
                self.assertEqual(self.ok(inv=inv, tok=tok, vau=vau, allow=[a])['decision'], 'ok')

    def test_reuse_across_roles(self):
        inv = copy.deepcopy(self.inv)
        self.role(inv, 'eth-release-signer')[0]['address'] = self.role(inv, 'l2-mint-signer')[0]['address']
        self.refused('holds two roles', inv=inv)

    def test_guardian_operator_independent(self):
        inv = copy.deepcopy(self.inv)
        self.role(inv, 'eth-vault-guardian')[0]['operator'] = 'signer-op1'
        self.refused('guardian operators also run a signer', inv=inv)

    def test_counts(self):
        inv = copy.deepcopy(self.inv)
        inv['keys'] = [k for k in inv['keys'] if not (k['role'] == 'eth-vault-guardian' and k['index'] == 3)]
        self.refused('eth-vault-guardian: 2 keys', inv=inv)

    def test_custody(self):
        inv = copy.deepcopy(self.inv)
        self.role(inv, 'eth-vault-deployer')[0]['custody'] = 'hot-keystore'
        self.refused('custody hot-keystore not allowed', inv=inv)

    def test_release_operators_match_mint(self):
        inv = copy.deepcopy(self.inv)
        self.role(inv, 'eth-release-signer')[6]['operator'] = 'other-op'
        self.refused('release-signer operators must be the 7 mint-signer operators', inv=inv)

    def test_config_mismatch(self):
        tok = copy.deepcopy(self.tok)
        tok['guardians']['set'][0]['address'] = '0x' + '77' * 20
        self.refused('token guardians.set addresses differ', tok=tok)
        vau = copy.deepcopy(self.vau)
        vau['vault']['signers']['set'][0]['operator'] = 'someone'
        self.refused('vault signers.set operators differ', vau=vau)
        tok = copy.deepcopy(self.tok)
        tok['ethereum']['vaultGuard']['guardians'].reverse()
        self.refused('vaultGuard.guardians differ', tok=tok)

    def test_recovery_owner_not_signer(self):
        inv = copy.deepcopy(self.inv)
        inv['keys'].append({'role': 'recovery-authority-owner', 'index': 1, 'operator': 'signer-op4',
                            'address': '0x' + '99' * 20, 'custody': 'hardware-wallet', 'date': '2026-11-02',
                            'attestation': None})
        self.refused('recovery-authority owner also runs a signer', inv=inv)


@unittest.skipUnless(HAVE_CAST, 'cast not found (FOUNDRY_BIN)')
class Signatures(unittest.TestCase):
    """Throwaway keys only, in a temporary directory deleted by the context manager."""

    def test_attestations(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o700)
            wallets = json.loads(subprocess.run([ki.CAST, 'wallet', 'new', '--json', '--number', '25'],
                                                capture_output=True, text=True, check=True).stdout)
            inv = inventory(lambda n: wallets[n - 1]['address'])
            for k, w in zip(inv['keys'], wallets):
                if k['role'] == 'bloch-inc-safe':
                    continue
                text = ki.message(k['role'], k['index'], k['operator'], k['address'], k['date'])
                k['attestation'] = subprocess.run([ki.CAST, 'wallet', 'sign', '--private-key', w['private_key'], text],
                                                  capture_output=True, text=True, check=True).stdout.strip()
            del wallets
            tok, vau = configs(inv)
            out = ki.check(inv, tok, vau)
            self.assertTrue(out['signaturesChecked'])
            bad = copy.deepcopy(inv)
            ms = [k for k in bad['keys'] if k['role'] == 'l2-mint-signer']
            ms[0]['attestation'] = ms[1]['attestation']
            with self.assertRaises(ki.Refused):
                ki.check(bad, tok, vau)
            bad = copy.deepcopy(inv)
            [k for k in bad['keys'] if k['role'] == 'l2-mint-signer'][0]['index'] = 1
            [k for k in bad['keys'] if k['role'] == 'l2-mint-signer'][0]['date'] = '2026-11-03'
            with self.assertRaises(ki.Refused):
                ki.check(bad, tok, vau)
            self.assertTrue(Path(tmp).exists())
        self.assertFalse(Path(tmp).exists())


if __name__ == '__main__':
    unittest.main()
