#!/usr/bin/env python3
"""Offline tests of ops/bridgectl.py (agent 381): install, check, seal, upgrade, rollback and verify into a scratch root,
without systemd (BRIDGECTL_ROOT, BRIDGECTL_NO_SYSTEMD=1). The same paths run under real systemd in the container
rehearsal (ops/rehearse_containers.sh). `python3 -m unittest ops/test_bridgectl.py` from the repository root.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bundle  # noqa: E402

CTL = HERE / 'bridgectl.py'


def make(route='ethereum', role='reserves', tweak=None, man_tweak=None):
    files, man = bundle.assemble(route, role, worktree_ops=True)
    if tweak:
        tweak(files)
        man['files'] = {p: {'sha256': hashlib.sha256(d).hexdigest(), 'mode': f'{mo:04o}'} for p, (d, mo) in sorted(files.items())}
    if man_tweak:
        man_tweak(man)
    data = bundle.tar_bytes(files, man)
    return data, hashlib.sha256(data).hexdigest()


def raw_tar(entries):
    """entries: [(TarInfo, bytes or None)] -> gzip tar bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for info, data in entries:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


class Ctl(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='a381-ctl-'))
        self.root = self.tmp / 'root'
        self.root.mkdir()
        self.env = {**os.environ, 'BRIDGECTL_ROOT': str(self.root), 'BRIDGECTL_NO_SYSTEMD': '1'}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_ctl(self, *args, stdin=None):
        done = subprocess.run([sys.executable, str(CTL), *map(str, args)], capture_output=True, text=True, env=self.env, input=stdin)
        try:
            doc = json.loads(done.stdout) if done.stdout.strip().startswith('{') else {'raw': done.stdout}
        except ValueError:
            doc = {'raw': done.stdout}
        return done.returncode, doc

    def write(self, data, name='b.tar.gz'):
        p = self.tmp / name
        p.write_bytes(data)
        return p

    def install(self, role='reserves', **kw):
        data, sha = make(role=role, **kw)
        rc, doc = self.run_ctl('install', self.write(data), '--sha256', sha, '--allow-unreleased')
        self.assertEqual(rc, 0, doc)
        return doc

    def fill(self, inst, fn=None):
        etc = self.root / f'etc/bloch-bridge/{inst}'
        for f in etc.glob('*.json'):
            doc = json.loads(f.read_text())
            def walk(x):
                if isinstance(x, dict):
                    return {k: walk(v) for k, v in x.items()}
                if isinstance(x, list):
                    return [walk(v) for v in x]
                return 'filled' if isinstance(x, str) and x.startswith('TBD-') else x
            doc = walk(doc)
            if fn:
                fn(f.name, doc)
            f.write_text(json.dumps(doc))
            os.chmod(f, 0o640)

    def host_pins(self, cast=b'fake cast'):
        (self.root / 'opt/foundry/bin').mkdir(parents=True, exist_ok=True)
        (self.root / 'opt/foundry/bin/cast').write_bytes(cast)
        os.chmod(self.root / 'opt/foundry/bin/cast', 0o755)
        (self.root / 'etc/bloch-bridge/cast.sha256').write_text(hashlib.sha256(b'fake cast').hexdigest() + '\n')
        hook = self.root / 'etc/bloch-bridge/alert-hook'
        shutil.copyfile(HERE / 'alert-hook.example', hook)
        os.chmod(hook, 0o755)

    # ------------------------------------------------------------------ bundle refusals

    def test_wrong_sha_refused(self):
        data, sha = make()
        rc, doc = self.run_ctl('install', self.write(data), '--sha256', '0' * 64, '--allow-unreleased')
        self.assertEqual(rc, 1)
        self.assertIn('is not the expected', doc['refused'])
        rc, doc = self.run_ctl('install', self.write(data), '--sha256', 'abc', '--allow-unreleased')
        self.assertIn('64-hex', doc['refused'])

    def test_unreleased_refused_without_flag(self):
        data, sha = make()
        rc, doc = self.run_ctl('install', self.write(data), '--sha256', sha)
        self.assertEqual(rc, 1)
        self.assertIn('unreleased', doc['refused'])

    def test_member_tampered_after_manifest_refused(self):
        files, man = bundle.assemble('ethereum', 'reserves', worktree_ops=True)
        files['tools/reservas/reservas.py'] = (files['tools/reservas/reservas.py'][0] + b'\n# x\n', 0o644)
        data = bundle.tar_bytes(files, man)
        rc, doc = self.run_ctl('install', self.write(data), '--sha256', hashlib.sha256(data).hexdigest(), '--allow-unreleased')
        self.assertEqual(rc, 1)
        self.assertIn('differ from MANIFEST.json', doc['refused'])

    def test_unlisted_symlink_and_traversal_members_refused(self):
        files, man = bundle.assemble('ethereum', 'reserves', worktree_ops=True)
        good = bundle.tar_bytes(files, man)
        with tarfile.open(fileobj=io.BytesIO(good), mode='r:gz') as t:
            members = [(m, t.extractfile(m).read() if m.isreg() else None) for m in t.getmembers()]
        extra = tarfile.TarInfo('tools/reservas/evil.py')
        extra.size = 1
        link = tarfile.TarInfo('tools/reservas/link')
        link.type, link.linkname = tarfile.SYMTYPE, '/etc/shadow'
        up = tarfile.TarInfo('../escape')
        up.size = 1
        for bad, want in [((extra, b'x'), 'not as listed'), ((link, None), 'not a regular file'), ((up, b'x'), 'plain relative')]:
            data = raw_tar(members + [bad])
            rc, doc = self.run_ctl('install', self.write(data), '--sha256', hashlib.sha256(data).hexdigest(), '--allow-unreleased')
            self.assertEqual(rc, 1, want)
            self.assertIn(want, doc['refused'])

    # ------------------------------------------------------------------ install / check

    def test_install_layout_and_second_install_refused(self):
        doc = self.install()
        inst = 'ethereum-reserves'
        cur = self.root / f'opt/bloch-bridge/{inst}/current'
        self.assertTrue(cur.is_symlink())
        self.assertTrue((cur / 'tools/reservas/reservas.py').is_file())
        etc = self.root / f'etc/bloch-bridge/{inst}'
        self.assertEqual(oct(etc.stat().st_mode & 0o777), oct(0o750))
        self.assertEqual(oct((etc / 'reservas.json').stat().st_mode & 0o777), oct(0o640))
        self.assertEqual(oct((self.root / f'etc/credstore.encrypted/bloch-bridge-{inst}').stat().st_mode & 0o777), oct(0o700))
        self.assertTrue((self.root / f'etc/systemd/system/bloch-bridge-{inst}.service').is_file())
        self.assertTrue((self.root / f'etc/logrotate.d/bloch-bridge-{inst}').is_file())
        data, sha = make()
        rc, again = self.run_ctl('install', self.write(data), '--sha256', sha, '--allow-unreleased')
        self.assertEqual(rc, 1)
        self.assertIn('already installed', again['refused'])

    def test_check_gates_start(self):
        self.install(role='relayer')
        inst = 'ethereum-relayer'
        rc, doc = self.run_ctl('check', inst)
        self.assertEqual(rc, 1)
        joined = '\n'.join(doc['problems'])
        self.assertIn('still', joined)                  # TBD-owner values left
        self.assertIn('credential l2-gas.keystore', joined)
        self.assertIn('cast.sha256', joined)
        self.assertIn('alert-hook', joined)
        rc, doc = self.run_ctl('start', inst)
        self.assertEqual(rc, 1)
        self.assertIn('check failed', doc['refused'])
        self.fill(inst)
        for c in ('l2-gas.keystore', 'l2-gas.password', 'eth-gas.keystore', 'eth-gas.password'):
            rc, s = self.run_ctl('seal', inst, c, stdin='throwaway')
            self.assertEqual(rc, 0, s)
            self.assertNotIn('throwaway', json.dumps(s))
        rc, s = self.run_ctl('seal', inst, 'l2-gas.password', stdin='again')
        self.assertIn('exists', s['refused'])
        rc, s = self.run_ctl('seal', inst, 'not-a-credential', stdin='x')
        self.assertIn('is not a credential', s['refused'])
        self.host_pins()
        rc, doc = self.run_ctl('check', inst)
        self.assertEqual(rc, 0, doc)
        rc, doc = self.run_ctl('start', inst)
        self.assertEqual(rc, 0, doc)

    def test_check_refuses_a_secret_outside_the_staged_dir_and_writable_configs(self):
        self.install(role='relayer')
        inst = 'ethereum-relayer'
        self.host_pins()
        for c in ('l2-gas.keystore', 'l2-gas.password', 'eth-gas.keystore', 'eth-gas.password'):
            self.run_ctl('seal', inst, c, stdin='throwaway')
        self.fill(inst, lambda n, d: d.update(eth_relayer_password_file='credential:eth-gas.password'))
        rc, doc = self.run_ctl('check', inst)
        self.assertEqual(rc, 1)
        self.assertTrue(any('eth_relayer_password_file' in p for p in doc['problems']), doc)
        self.fill(inst)
        os.chmod(self.root / f'etc/bloch-bridge/{inst}/relayer.json', 0o666)
        rc, doc = self.run_ctl('check', inst)
        self.assertTrue(any('must not be able to change its own config' in p for p in doc['problems']), doc)
        os.chmod(self.root / f'etc/bloch-bridge/{inst}/relayer.json', 0o640)
        (self.root / 'opt/foundry/bin/cast').write_bytes(b'another cast')
        rc, doc = self.run_ctl('check', inst)
        self.assertTrue(any('not the pinned' in p for p in doc['problems']), doc)

    def test_optional_unit_credentials_only_when_selected(self):
        self.install(role='guardian')
        inst = 'ethereum-guardian'
        self.fill(inst)
        self.host_pins()
        for c in ('l2-guardian.keystore', 'l2-guardian.password', 'eth-guardian.keystore', 'eth-guardian.password'):
            self.run_ctl('seal', inst, c, stdin='throwaway')
        rc, doc = self.run_ctl('check', inst)
        self.assertEqual(rc, 0, doc)
        rc, doc = self.run_ctl('check', inst, '--with', 'sombra')
        self.assertEqual(rc, 1)
        self.assertTrue(any('sombra.keystore' in p for p in doc['problems']))
        rc, doc = self.run_ctl('check', inst, '--with', 'nosuch')
        self.assertIn('no such unit', doc['refused'])

    # ------------------------------------------------------------------ upgrade / rollback / verify

    def test_upgrade_rollback_and_epochs(self):
        self.install()
        inst = 'ethereum-reserves'
        first = json.loads((self.root / f'opt/bloch-bridge/{inst}/install.json').read_text())['current']
        data, sha = make()
        rc, doc = self.run_ctl('upgrade', inst, self.write(data), '--sha256', sha, '--allow-unreleased')
        self.assertIn('already current', doc['refused'])
        code = lambda f: f.__setitem__('tools/reservas/reservas.py', (f['tools/reservas/reservas.py'][0] + b'\n# v2\n', 0o644))  # noqa: E731
        data2, sha2 = make(tweak=code)
        rc, doc = self.run_ctl('upgrade', inst, self.write(data2, 'v2.tar.gz'), '--sha256', sha2, '--allow-unreleased')
        self.assertEqual(rc, 0, doc)
        second = doc['to']
        self.assertNotEqual(first, second)
        self.assertIn(b'# v2', (self.root / f'opt/bloch-bridge/{inst}/current/tools/reservas/reservas.py').read_bytes())
        rc, doc = self.run_ctl('rollback', inst)
        self.assertEqual(rc, 0, doc)
        self.assertEqual(doc['current'], first)
        self.assertNotIn(b'# v2', (self.root / f'opt/bloch-bridge/{inst}/current/tools/reservas/reservas.py').read_bytes())
        rc, doc = self.run_ctl('rollback', inst)
        self.assertEqual(doc['current'], second, 'a second rollback returns to the release rolled back from')

        def tpl(f):
            p = 'etc/templates/reservas.json'
            d = json.loads(f[p][0])
            d['new_key'] = 1
            f[p] = ((json.dumps(d, indent=2) + '\n').encode(), 0o644)
        data3, sha3 = make(tweak=tpl)
        rc, doc = self.run_ctl('upgrade', inst, self.write(data3, 'v3.tar.gz'), '--sha256', sha3, '--allow-unreleased')
        self.assertEqual(rc, 1)
        self.assertIn('templates changed', doc['refused'])
        self.assertTrue(any('new_key' in l for l in doc['diff']))
        rc, doc = self.run_ctl('upgrade', inst, self.write(data3, 'v3.tar.gz'), '--sha256', sha3, '--allow-unreleased', '--config-reviewed')
        self.assertEqual(rc, 0, doc)
        low = lambda m: m.__setitem__('state_epoch', 0)  # noqa: E731
        data4, sha4 = make(tweak=lambda f: f.__setitem__('tools/reservas/README.md', (b'x\n', 0o644)), man_tweak=low)
        rc, doc = self.run_ctl('upgrade', inst, self.write(data4, 'v4.tar.gz'), '--sha256', sha4, '--allow-unreleased', '--config-reviewed')
        self.assertIn('state epoch', doc['refused'])
        other, osha = make(role='relayer')
        rc, doc = self.run_ctl('upgrade', inst, self.write(other, 'o.tar.gz'), '--sha256', osha, '--allow-unreleased')
        self.assertIn('is for ethereum-relayer', doc['refused'])

    def test_rollback_without_previous_refused_and_verify_detects_tampering(self):
        self.install()
        inst = 'ethereum-reserves'
        rc, doc = self.run_ctl('rollback', inst)
        self.assertIn('no previous release', doc['refused'])
        rc, doc = self.run_ctl('verify', inst)
        self.assertEqual(rc, 0, doc)
        f = self.root / f'opt/bloch-bridge/{inst}/current/tools/reservas/reservas.py'
        f.write_bytes(f.read_bytes() + b'#')
        rc, doc = self.run_ctl('verify', inst)
        self.assertEqual(rc, 1)
        self.assertTrue(any('changed since install' in p for p in doc['problems']))
        unit = self.root / f'etc/systemd/system/bloch-bridge-{inst}.service'
        unit.write_text(unit.read_text() + '\nUser=root\n')
        rc, doc = self.run_ctl('verify', inst)
        self.assertTrue(any('differs from the current release' in p for p in doc['problems']))


if __name__ == '__main__':
    unittest.main()
