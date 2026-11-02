#!/usr/bin/env python3
"""The relayer gas key never reaches a command line on the public chains (agent 174, Low; agent 200 fix). No chain, no real key.

  python3 -m unittest -v test_relayer_key

`cast` is replaced by a stub that records its argv and answers like `cast wallet address` / `cast mktx` / `cast calldata`,
and `Vigia.rpc` by a stub, so `Vigia.send` runs its real code. The key below is a throwaway (anvil's account 1).
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vigia  # noqa: E402

KEY = '59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
STUB = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['A200_ARGV_LOG'], 'a') as f:
    f.write(json.dumps(sys.argv[1:]) + '\n')
cmd = sys.argv[1:3]
if cmd == ['wallet', 'address']:
    print('0x70997970c51812dc3a010c7d01b50e0d17dc79c8')
elif sys.argv[1] == 'mktx':
    print('0x02f8')
elif sys.argv[1] == 'calldata':
    print('0x12345678')
else:
    print('0x')
'''


class RelayerKey(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='a200-relayer-'))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.cast = self.d / 'cast'
        self.cast.write_text(STUB)
        self.cast.chmod(0o700)
        self.argv_log = self.d / 'argv.log'
        os.environ['A200_ARGV_LOG'] = str(self.argv_log)
        self.addCleanup(os.environ.pop, 'A200_ARGV_LOG', None)
        for name, text in (('raw.key', '0x' + KEY + '\n'), ('gas.keystore', '{"crypto": {}}'), ('gas.password', 'pw\n')):
            (self.d / name).write_text(text)
            (self.d / name).chmod(0o600)

    def vigia(self, **extra):
        cfg = {'shared_dir': str(self.d / 'shared'), 'token': '0x' + 'aa' * 20, 'source_vault': '0x' + 'bb' * 20,
               'source_route': '0x' + 'cc' * 32, 'threshold': 5, 'l2_rpc': 'http://127.0.0.1:9', 'eth_rpc': 'http://127.0.0.1:9',
               'cast': str(self.cast), **extra}
        p = self.d / 'cfg.json'
        p.write_text(json.dumps(cfg))
        v = vigia.Vigia(p)
        answers = {'eth_getTransactionCount': '0x0', 'eth_gasPrice': '0x1', 'eth_estimateGas': '0x5208',
                   'eth_sendRawTransaction': '0x' + 'ee' * 32}
        v.rpc = lambda url, method, params: answers[method]
        return v

    def argv_text(self):
        return self.argv_log.read_text() if self.argv_log.exists() else ''

    def keystore_cfg(self, side, password='gas.password'):
        return {f'{side}_relayer_keystore': str(self.d / 'gas.keystore'),
                f'{side}_relayer_password_file': password if password.startswith('credential:') else str(self.d / password)}

    def test_mainnet_keystore_send_puts_no_key_on_argv(self):
        v = self.vigia(l2_chain_id=700770, eth_chain_id=1, **self.keystore_cfg('l2'), **self.keystore_cfg('eth'))
        for side in ('l2', 'eth'):
            v.send(side, '0x' + '11' * 20, ['f()'])
        text = self.argv_text()
        self.assertIn('--keystore', text)
        self.assertIn('--password-file', text)
        self.assertNotIn('--private-key', text)
        self.assertNotIn(KEY, text.lower())

    def test_password_file_from_systemd_credentials(self):
        creds = self.d / 'creds'
        creds.mkdir()
        (creds / 'l2-gas.password').write_text('pw\n')
        (creds / 'l2-gas.password').chmod(0o400)
        os.environ['CREDENTIALS_DIRECTORY'] = str(creds)
        self.addCleanup(os.environ.pop, 'CREDENTIALS_DIRECTORY', None)
        v = self.vigia(l2_chain_id=700770, **self.keystore_cfg('l2', 'credential:l2-gas.password'))
        self.assertEqual(v.relayer_wallet('l2')[-1], str(creds / 'l2-gas.password'))

    def test_credential_without_load_credential_is_refused(self):
        os.environ.pop('CREDENTIALS_DIRECTORY', None)
        v = self.vigia(l2_chain_id=700770, **self.keystore_cfg('l2', 'credential:l2-gas.password'))
        with self.assertRaises(SystemExit) as e:
            v.relayer_wallet('l2')
        self.assertIn('CREDENTIALS_DIRECTORY', str(e.exception))

    def test_raw_key_refused_on_the_l2_mainnet(self):
        v = self.vigia(l2_chain_id=700770, l2_relayer_key=str(self.d / 'raw.key'))
        with self.assertRaises(SystemExit) as e:
            v.send('l2', '0x' + '11' * 20, ['f()'])
        self.assertIn('argv', str(e.exception))
        self.assertNotIn(KEY, self.argv_text().lower())

    def test_raw_key_refused_on_ethereum_mainnet(self):
        v = self.vigia(l2_chain_id=700771, eth_chain_id=1, eth_relayer_key=str(self.d / 'raw.key'))
        with self.assertRaises(SystemExit):
            v.relayer_wallet('eth')

    def test_files_readable_by_others_are_refused(self):
        for name in ('gas.keystore', 'gas.password'):
            (self.d / name).chmod(0o644)
            v = self.vigia(l2_chain_id=700770, **self.keystore_cfg('l2'))
            with self.assertRaises(SystemExit) as e:
                v.relayer_wallet('l2')
            self.assertIn('0644', str(e.exception))
            (self.d / name).chmod(0o600)
        (self.d / 'raw.key').chmod(0o640)
        v = self.vigia(l2_chain_id=700771, l2_relayer_key=str(self.d / 'raw.key'))
        with self.assertRaises(SystemExit):
            v.relayer_wallet('l2')

    def test_no_key_configured_is_refused(self):
        v = self.vigia(l2_chain_id=700770)
        with self.assertRaises(SystemExit):
            v.relayer_wallet('l2')

    def test_control_raw_key_still_works_for_throwaway_rehearsals(self):
        v = self.vigia(l2_chain_id=700771, eth_chain_id=11155111, l2_relayer_key=str(self.d / 'raw.key'))
        v.send('l2', '0x' + '11' * 20, ['f()'])
        self.assertIn('--private-key', self.argv_text())

    def test_mainnet_relayer_template_uses_keystores_and_credentials(self):
        tpl = json.loads((HERE.parent.parent / 'deployments/mainnet/busdc-ops/relayer.template.json').read_text())
        for side in ('l2', 'eth'):
            self.assertNotIn(f'{side}_relayer_key', tpl)
            self.assertTrue(tpl[f'{side}_relayer_keystore'])
            self.assertTrue(tpl[f'{side}_relayer_password_file'].startswith('credential:'))


if __name__ == '__main__':
    unittest.main()
