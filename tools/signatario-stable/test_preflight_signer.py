#!/usr/bin/env python3
"""Tests for preflight_signer.py. Offline: temporary files, stand-in binaries pinned through an `l2_pins` object, and a
stand-in signatario for the dry release. The last test runs the real signatario.py against the stand-in binaries and
shows the dry release refusing at the first thing that is wrong (so a refusal other than the expected one is reported).

  python3 -m unittest -v test_preflight_signer
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import l2_finality  # noqa: E402
import preflight_signer as pf  # noqa: E402

TEMPLATES = HERE.parent.parent / 'deployments/mainnet/busdc-ops'


def addr(i):
    return '0x' + format(0xA306_0000 + i, '040x')


class Host:
    """A filled signer host in a temporary directory, every file private, the three binaries stand-ins."""

    def __init__(self, tmp):
        self.root = Path(tmp)
        for d in ('work', 'signatures', 'signatures/.scan', 'publish', 'relayer', 'relayer/signatures', 'etc', 'bin'):
            (self.root / d).mkdir(parents=True)
        self.bins = {}
        for role in ('follower', 'produce', 'settled_rpc'):
            p = self.root / 'bin' / role
            p.write_bytes(f'stand-in {role}'.encode())
            self.bins[role] = p
        pins = dict(l2_finality.MAINNET_V2)
        pins['binaries'] = {r: hashlib.sha256(p.read_bytes()).hexdigest() for r, p in self.bins.items()}
        self.signer = json.loads((TEMPLATES / 'signer.template.json').read_text())
        self.signer.update(
            signer=1, signer_name='op1', l2_rpc='http://127.0.0.1:1', follower=str(self.root / 'follower'),
            follower_bin=str(self.bins['follower']), produce=str(self.bins['produce']),
            settled_rpc=str(self.bins['settled_rpc']), work_dir=str(self.root / 'work'),
            db=str(self.root / 'work/db.json'), token=addr(1), token_code_keccak='0x' + '11' * 32, token_from_block=1,
            source_vault=addr(2), source_route='0x' + '22' * 32, vault_from_block=1,
            keystore=self.private('etc/l2-mint.keystore'), password_file=self.private('etc/l2-mint.password'),
            eth_signer=addr(3), shared_dir=str(self.root / 'signatures'))
        self.signer['feed'].update(publish_dir=str(self.root / 'publish'), status_file=str(self.root / 'work/feed.json'),
                                   peers=[f'http://192.0.2.{i}:8787' for i in range(1, 7)],
                                   mint_signers=[addr(10 + i) for i in range(7)],
                                   release_signers=[addr(20 + i) for i in range(7)])
        self.pins = pins
        self.eth_half = json.loads((TEMPLATES / 'eth-half.template.json').read_text())
        self.eth_half.update(vault=addr(2), vault_code_keccak='0x' + '33' * 32, vault_from_block=1,
                             keystore=self.private('etc/eth-release.keystore'),
                             password_file=self.private('etc/eth-release.password'), db=str(self.root / 'work/eth.json'))
        self.relayer = json.loads((TEMPLATES / 'relayer.template.json').read_text())
        self.relayer.update(token=addr(1), source_vault=addr(2), source_route='0x' + '22' * 32, l2_rpc='http://127.0.0.1:1',
                            eth_rpc='http://127.0.0.1:8545', vault_from_block=1, token_from_block=1,
                            shared_dir=str(self.root / 'relayer/signatures'), db=str(self.root / 'relayer/db.json'),
                            l2_relayer_keystore=self.private('etc/l2-gas.keystore'),
                            eth_relayer_keystore=self.private('etc/eth-gas.keystore'), relay_role='backup',
                            relay_backup_index=3, relay_other_gas_addresses=[addr(40 + i) for i in range(12)])
        self.relayer['feed'].update(peers=[f'http://192.0.2.{i}:8787' for i in range(1, 8)],
                                    mint_signers=[addr(10 + i) for i in range(7)],
                                    release_signers=[addr(20 + i) for i in range(7)])
        self.signatario = self.root / 'bin/signatario-stand-in.py'
        self.answer(pf.DRY_REASON)

    def private(self, rel, text='x'):
        p = self.root / rel
        p.write_text(text)
        p.chmod(0o600)
        return str(p)

    def answer(self, reason, code=1, signed=False, write_out=False):
        """What the stand-in signatario does on the dry release."""
        body = f"""import json, sys
args = sys.argv[1:]
assert args[2] == 'release' and args[3] == '--burn-tx' and args[4] == {pf.DRY_BURN!r}, args
if {write_out!r}:
    open(args[args.index('--out') + 1], 'w').write('{{}}')
print(json.dumps({{'signed': {signed!r}, 'reason': {reason!r}}}))
raise SystemExit({code})
"""
        self.signatario.write_text(body)

    def write(self, pinned=True):
        s = copy.deepcopy(self.signer)
        if pinned:
            s['l2_pins'] = 'mainnet-v2'
        paths = {}
        for name, cfg in (('signer', s), ('eth-half', self.eth_half), ('relayer', self.relayer)):
            paths[name] = self.private(f'etc/{name}.json', json.dumps(cfg))
        return paths

    def run(self, *flags, relayer=True, eth_half=True):
        paths = self.write()
        argv = ['--config', paths['signer']] + list(flags)
        if eth_half:
            argv += ['--eth-half-config', paths['eth-half']]
        if relayer:
            argv += ['--relayer-config', paths['relayer']]
        saved = dict(l2_finality.MAINNET_V2)
        l2_finality.MAINNET_V2.update(self.pins)  # the stand-in binaries are "the pinned build" for this run
        try:
            return pf.run(argv, signatario=self.signatario)
        finally:
            l2_finality.MAINNET_V2.clear()
            l2_finality.MAINNET_V2.update(saved)


class PreflightSigner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.host = Host(self.tmp.name)

    def failed(self, report):
        return [r['check'] for r in report.failed]

    def assertFails(self, report, needle):
        self.assertTrue(any(needle in c for c in self.failed(report)), (needle, self.failed(report)))

    def test_a_filled_host_passes(self):
        report = self.host.run()
        self.assertEqual(self.failed(report), [])
        self.assertTrue(any(r['group'] == 'dry' and r['result'] == 'pass' for r in report.rows))
        self.assertFalse(any(r['result'] == 'warn' for r in report.rows))

    def test_the_committed_templates_fail_on_every_tbd_value(self):
        self.host.signer = json.loads((TEMPLATES / 'signer.template.json').read_text())
        self.host.eth_half = json.loads((TEMPLATES / 'eth-half.template.json').read_text())
        self.host.relayer = json.loads((TEMPLATES / 'relayer.template.json').read_text())
        report = self.host.run()
        for needle in ('signer config has no TBD-owner', 'eth-half config has no TBD-owner', 'relayer config has no TBD-owner',
                       'relay_role', 'dry release'):
            self.assertFails(report, needle)
        detail = next(r['detail'] for r in report.rows if r['check'] == 'signer config has no TBD-owner value')
        for key in ('signer', 'token', 'source_vault', 'eth_signer', 'feed.peers[0]'):
            self.assertIn(key, detail.split(', '))

    def test_decided_values_are_enforced(self):
        for key, bad in (('threshold', 4), ('vault_threshold', 6), ('l2_chain_id', 700771), ('source_chain_id', 11155111),
                         ('l2_source', 'rpc'), ('provenance', False), ('provenance', 1)):
            host = Host(tempfile.mkdtemp(dir=self.tmp.name))
            host.signer[key] = bad
            self.assertFails(host.run('--skip-dry-release'), f'signer {key} is')
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.eth_half['release_hold'] = True
        self.assertFails(host.run('--skip-dry-release'), 'eth-half release_hold is False')
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.signer['l1_rpc_urls'] = ['http://192.0.2.1:8080', 'http://192.0.2.1:8080']
        self.assertFails(host.run('--skip-dry-release'), 'two distinct L1 RPC')
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.signer['feed']['release_signers'][6] = host.signer['feed']['release_signers'][0]
        self.assertFails(host.run('--skip-dry-release'), 'feed.release_signers')

    def test_key_files_must_be_private(self):
        os.chmod(self.host.signer['keystore'], 0o640)
        os.chmod(self.host.eth_half['password_file'], 0o604)
        report = self.host.run()
        self.assertFails(report, 'L2 mint keystore is closed')
        self.assertFails(report, 'Ethereum release password file is closed')
        self.assertFails(report, 'dry release')  # not run while a file check fails
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.eth_half['keystore'] = host.signer['keystore']
        self.assertFails(host.run(), 'different files')
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        Path(host.signer['password_file']).unlink()
        self.assertFails(host.run(), 'L2 mint password file exists')

    def test_directories_must_exist(self):
        self.host.signer['shared_dir'] = str(self.host.root / 'missing')
        self.assertFails(self.host.run(), 'shared_dir is a writable directory')

    def test_ethereum_node_must_be_the_operators_own(self):
        for url in ('https://mainnet.example.org', 'http://8.8.8.8:8545'):
            host = Host(tempfile.mkdtemp(dir=self.tmp.name))
            host.signer['eth_rpc'] = host.eth_half['eth_rpc'] = url
            self.assertFails(host.run(), "eth_rpc is this operator's own node")
            report = host.run('--allow-remote-eth-rpc')
            self.assertEqual(self.failed(report), [])
            self.assertTrue(any(r['result'] == 'warn' and r['group'] == 'ethereum' for r in report.rows))
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.signer['eth_rpc'] = host.eth_half['eth_rpc'] = 'http://10.0.0.5:8545'
        self.assertEqual(self.failed(host.run()), [])
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.eth_half['eth_rpc'] = 'http://127.0.0.1:9999'
        self.assertFails(host.run(), 'same Ethereum node')

    def test_a_binary_that_is_not_the_pinned_build_fails(self):
        self.host.bins['settled_rpc'].write_bytes(b'another build')
        report = self.host.run()
        self.assertFails(report, 'pinned launch build')
        detail = next(r['detail'] for r in report.failed if 'pinned launch build' in r['check'])
        self.assertIn('settled_rpc', detail)
        self.assertFails(report, 'dry release')

    def test_the_real_pins_refuse_the_stand_in_binaries(self):
        paths = self.host.write()
        report = pf.run(['--config', paths['signer']], signatario=self.host.signatario)
        self.assertFails(report, 'pinned launch build')

    def test_relayer_rules(self):
        for key, bad, needle in (('relay_role', 'both', 'relay_role'), ('relay_backup_index', 7, 'relay_backup_index'),
                                 ('relay_backup_index', '3', 'relay_backup_index'),
                                 ('l2_max_gas_price_gwei', 51, 'l2_max_gas_price_gwei'),
                                 ('eth_max_gas_price_gwei', 301, 'eth_max_gas_price_gwei'),
                                 ('eth_max_gas_price_gwei', None, 'eth_max_gas_price_gwei'),
                                 ('relay_other_gas_addresses', [addr(40)] * 12, 'relay_other_gas_addresses'),
                                 ('l2_relayer_password_file', '/nonexistent/password', 'l2_relayer_password_file')):
            host = Host(tempfile.mkdtemp(dir=self.tmp.name))
            host.relayer[key] = bad
            self.assertFails(host.run('--skip-dry-release'), needle)
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.relayer['eth_relayer_keystore'] = host.relayer['l2_relayer_keystore']
        self.assertFails(host.run('--skip-dry-release'), 'two gas keystores')
        host = Host(tempfile.mkdtemp(dir=self.tmp.name))
        host.relayer.update(relay_role='primary', relay_backup_index=None)
        self.assertEqual(self.failed(host.run('--skip-dry-release')), [])

    def test_dry_release_must_refuse_for_the_one_reason(self):
        for kwargs, why in (({'reason': 'the settled_rpc binary is not the pinned build'}, 'another refusal'),
                            ({'reason': pf.DRY_REASON, 'code': 0}, 'exit 0'),
                            ({'reason': pf.DRY_REASON, 'signed': True}, 'signed'),
                            ({'reason': pf.DRY_REASON, 'write_out': True}, 'an output file was written')):
            self.host.answer(**kwargs)
            report = self.host.run()
            self.assertFails(report, 'dry release refuses only because the burn does not exist')
        self.host.answer('the L1 RPCs disagree')
        detail = next(r['detail'] for r in self.host.run().failed)
        self.assertIn('the L1 RPCs disagree', detail)
        self.host.signatario.write_text('raise SystemExit("crash before any answer")')
        detail = next(r['detail'] for r in self.host.run().failed)
        self.assertIn('crash before any answer', detail)

    def test_the_real_signatario_refuses_first_at_the_binary_pins(self):
        """signatario.py itself, on a filled config whose binaries are stand-ins: its dry release stops at the binary
        pins, and the preflight reports that reason instead of passing."""
        paths = self.host.write()
        report = pf.Report()
        pf.dry_release(report, paths['signer'], HERE / 'signatario.py')
        self.assertEqual(len(report.failed), 1)
        self.assertIn('binary is not the pinned build', report.failed[0]['detail'])

    def test_cli_exit_codes(self):
        import subprocess
        paths = self.host.write()
        done = subprocess.run([sys.executable, str(HERE / 'preflight_signer.py'), '--config', paths['signer'], '--json'],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 1)
        self.assertEqual(json.loads(done.stdout)['decision'], 'fail')
        done = subprocess.run([sys.executable, str(HERE / 'preflight_signer.py'), '--config', str(self.host.root / 'none.json')],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertNotIn('Traceback', done.stderr)


if __name__ == '__main__':
    unittest.main()
