#!/usr/bin/env python3
"""Offline tests of btc_deploy.py: key recovery from ceremony attestations, vault config refusals.  python3 -m unittest test_btc_deploy"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'deploy-pontes'))
import btc_core as c  # noqa: E402
import btc_deploy  # noqa: E402
import btc_policy as pol  # noqa: E402
import key_inventory  # noqa: E402

PRIVS = [int.from_bytes(hashlib.sha256(b'throwaway-ceremony-%d' % i).digest(), 'big') % c.N for i in range(7)]
OWNER = 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk'


def run(*args):
    done = subprocess.run([sys.executable, str(HERE / 'btc_deploy.py'), *map(str, args)], capture_output=True, text=True)
    return done.returncode, json.loads(done.stdout)


class Deploy(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='btc-deploy-test-'))

    def inventory(self, tamper=None, role='eth-release-signer'):
        keys = []
        for i, priv in enumerate(PRIVS):
            pub = c.pubkey(priv)
            address = c.eth_address(pub)
            text = btc_deploy.attestation_text(key_inventory, role, i + 1, f'signer-op{i + 1}', address, '2026-11-16')
            r, s, v = c.sign(btc_deploy.personal_digest(text), priv)
            sig = '0x' + (r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + v])).hex()
            keys.append({'role': role, 'index': i + 1, 'operator': f'signer-op{i + 1}', 'address': address,
                         'custody': 'hot-keystore', 'date': '2026-11-16', 'attestation': sig})
        if tamper:
            tamper(keys)
        path = self.dir / 'inventory.json'
        path.write_text(json.dumps({'domain': 'bloch.bridge.key-inventory.v1', 'keys': keys}))
        return path

    def test_keys_are_recovered_from_the_ceremony_attestations(self):
        rc, out = run('keys', '--inventory', self.inventory())
        self.assertEqual(rc, 0, out)
        self.assertEqual([k['pubkey'] for k in out['keys']], [c.pubkey(p).hex() for p in PRIVS])

    def test_separate_bitcoin_keys_have_their_own_role_and_text(self):
        path = self.inventory(role='btc-vault-signer')
        other = self.dir / 'busdc.json'
        other.write_text(json.dumps({'keys': [{'role': 'eth-release-signer', 'address': '0x' + '12' * 20}]}))
        rc, out = run('keys', '--inventory', path, '--role', 'btc-vault-signer')
        self.assertIn('--other-inventory', out['reason'])
        rc, out = run('keys', '--inventory', path, '--role', 'btc-vault-signer', '--other-inventory', other)
        self.assertEqual(rc, 0, out)
        shared = json.loads(path.read_text())['keys'][2]['address']
        other.write_text(json.dumps({'keys': [{'role': 'eth-release-signer', 'address': shared.upper().replace('0X', '0x')}]}))
        rc, bad = run('keys', '--inventory', path, '--role', 'btc-vault-signer', '--other-inventory', other)
        self.assertIn('also appears in the other inventory', bad['reason'])
        other.write_text(json.dumps({'keys': []}))
        self.assertEqual([k['pubkey'] for k in out['keys']], [c.pubkey(p).hex() for p in PRIVS])
        # an attestation made for the Ethereum release role is not accepted as a Bitcoin vault key, nor the reverse
        inv = json.loads(self.inventory().read_text())
        for k in inv['keys']:
            k['role'] = 'btc-vault-signer'
        path.write_text(json.dumps(inv))
        rc, out = run('keys', '--inventory', path, '--role', 'btc-vault-signer', '--other-inventory', other)
        self.assertEqual((rc, out['decision']), (1, 'refused'))
        self.assertIn('does not recover', out['reason'])

    def test_an_attestation_for_another_address_or_slot_is_refused(self):
        def swap(keys):
            keys[0]['attestation'], keys[1]['attestation'] = keys[1]['attestation'], keys[0]['attestation']
        rc, out = run('keys', '--inventory', self.inventory(swap))
        self.assertEqual((rc, out['decision']), (1, 'refused'))
        rc, out = run('keys', '--inventory', self.inventory(lambda keys: keys.pop()))
        self.assertEqual(rc, 1)
        rc, out = run('keys', '--inventory', self.inventory(lambda keys: keys[3].update(index=9)))
        self.assertEqual(rc, 1)

    def vault(self, **over):
        cfg = {'network': 'bitcoin-mainnet', 'threshold': 5, 'keys': [c.pubkey(p).hex() for p in PRIVS], 'anchor': None,
               'owner_address': OWNER, 'policy': pol.DEFAULT_POLICY, **over}
        path = self.dir / 'vault.json'
        path.write_text(json.dumps(cfg))
        return path

    def test_thread_address_before_the_anchor_and_refusals(self):
        rc, out = run('thread', '--config', self.vault())
        self.assertEqual(rc, 0, out)
        self.assertTrue(out['thread_address'].startswith('bc1q') and len(out['thread_address']) == 62)
        self.assertEqual(out['keys_in_script_order'], sorted(c.pubkey(p).hex() for p in PRIVS))
        rc, out = run('vault', '--config', self.vault())
        self.assertIn('anchor is undecided', out['reason'])
        rc, out = run('thread', '--config', self.vault(threshold=4))
        self.assertIn('5 of 7', out['reason'])
        rc, out = run('thread', '--config', self.vault(owner_address='TBD-owner'))
        self.assertIn('undecided', out['reason'])
        rc, out = run('thread', '--config', self.vault(owner_address='bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'))
        self.assertIn('P2WPKH', out['reason'])
        rc, out = run('thread', '--config', self.vault(keys=['TBD-owner'] * 7))
        self.assertEqual(rc, 1)
        rc, out = run('vault', '--config', self.vault(anchor={'txid': 'ab' * 32, 'vout': 1}))
        self.assertEqual(rc, 0, out)
        self.assertEqual(out['source_chain_id'], int('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f', 16))
        rc, addr = run('address', '--config', self.vault(anchor={'txid': 'ab' * 32, 'vout': 1}), '--recipient', '0x' + '11' * 20)
        self.assertTrue(addr['deposit_address'].startswith('bc1q') and addr['deposit_address'] != out['thread_address'])


if __name__ == '__main__':
    unittest.main()
