#!/usr/bin/env python3
"""Offline tests of ops/bundle.py (agent 381). `python3 -m unittest ops/test_bundle.py` from the repository root.

They read the route sources from git objects at the revisions in ops/routes.json and the ops files from the working tree.
"""
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bundle  # noqa: E402

MAN = bundle.load_manifest('worktree')  # inherited routes resolved, as the builder sees them
PAIRS = [(r, x) for r, route in MAN['routes'].items() for x in route['roles']]


def unit_sections(text):
    lines = [l for l in text.splitlines() if l and not l.startswith('#')]
    return lines


class Bundles(unittest.TestCase):
    built = {}

    @classmethod
    def setUpClass(cls):
        for route, role in PAIRS:
            cls.built[(route, role)] = bundle.assemble(route, role, worktree_ops=True)

    def test_every_route_role_assembles(self):
        self.assertTrue(PAIRS)
        for (route, role), (files, man) in self.built.items():
            self.assertEqual(man['inst'], f'{route}-{role}')
            self.assertTrue(any(p.startswith('units/') for p in files))

    def test_deterministic_bytes(self):
        for route, role in PAIRS[:2]:
            a = bundle.tar_bytes(*bundle.assemble(route, role, worktree_ops=True))
            b = bundle.tar_bytes(*bundle.assemble(route, role, worktree_ops=True))
            self.assertEqual(hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest(), f'{route}-{role}')

    def test_manifest_lists_every_file_with_its_hash(self):
        for (route, role), (files, man) in self.built.items():
            data = bundle.tar_bytes(files, man)
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
                regs = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isreg()}
                self.assertTrue(all(m.uid == 0 and m.mtime == 0 and not m.issym() for m in tar.getmembers()))
            listed = json.loads(regs.pop('MANIFEST.json'))['files']
            self.assertEqual(set(listed), set(regs))
            for p, b in regs.items():
                self.assertEqual(listed[p]['sha256'], hashlib.sha256(b).hexdigest(), p)

    def test_payload_has_no_tests_fakes_or_rehearsals(self):
        for (route, role), (files, man) in self.built.items():
            spec = MAN['routes'][route]['roles'][role]
            for p in files:
                if p.startswith('tools/'):
                    name = p.rsplit('/', 1)[-1]
                    self.assertFalse(re.match(r'test_|.*_fake\.py$', name), p)
            for u in spec['units']:
                script = next(a for a in u['exec'] if a.endswith('.py'))
                self.assertIn(script.replace('{release}/', ''), files, f'{route}-{role}: ExecStart script not in the bundle')

    def test_configs_change_only_the_declared_keys(self):
        """Every leaf the bundle does not `set` equals the route's committed template: no decided value is altered."""
        for (route, role), (files, man) in self.built.items():
            spec = MAN['routes'][route]['roles'][role]
            for name, c in spec.get('configs', {}).items():
                tpl = json.loads(bundle.read_at(bundle.rev_parse(MAN['routes'][route]['source_rev']), c['from']))
                got = json.loads(files[f'etc/templates/{name}'][0])
                sets = set(c.get('set', {}))
                for path, value in bundle.leaves(tpl):
                    if any(path == s or path.startswith(s + '.') for s in sets):
                        continue
                    cur = got
                    for part in path.split('.'):
                        cur = cur[int(part)] if isinstance(cur, list) else cur[part]
                    self.assertEqual(cur, value, f'{route}-{role} {name}:{path}')

    def test_owner_decisions_survive(self):
        f = lambda r, x, n: json.loads(self.built[(r, x)][0][f'etc/templates/{n}'][0])  # noqa: E731
        g = f('ethereum', 'guardian', 'guardiao.json')
        self.assertIs(g['vault_pause_on_mint'], True)
        self.assertIs(f('ethereum', 'signer', 'eth-half.json')['release_hold'], False)
        rel = f('ethereum', 'relayer', 'relayer.json')
        self.assertEqual((rel['l2_max_gas_price_gwei'], rel['eth_max_gas_price_gwei']), (50, 300))
        self.assertTrue(rel['relay_role'].startswith('TBD-owner'))
        s = f('ethereum', 'signer', 'signer.json')
        self.assertEqual((s['threshold'], s['vault_threshold'], s['l2_pins'], s['l2_source']), (5, 5, 'mainnet-v2', 'rebuild'))

    def test_every_secret_is_a_staged_credential(self):
        for (route, role), (files, man) in self.built.items():
            staged = {f'{u["run_dir"]}/{c}' for u in man['units'] for c in u['credentials']}
            for name in man['configs']:
                doc = json.loads(files[f'etc/templates/{name}'][0])
                for path, value in bundle.leaves(doc):
                    key = bundle.last_key(path)
                    if path.startswith('_') or not bundle.SECRET_KEY.search(key) or key.startswith('relay_other'):
                        continue
                    self.assertIn(value, staged, f'{route}-{role} {name}:{path}')

    def test_units_hardening_user_and_credentials(self):
        hard = MAN['hardening']['lines']
        for (route, role), (files, man) in self.built.items():
            user = man['layout']['user']
            for u in man['units']:
                text = files[f'units/{u["unit"]}'][0].decode()
                lines = unit_sections(text)
                for h in hard:
                    if u['kind'] == 'feed' and h.startswith('RestrictAddressFamilies'):
                        continue
                    self.assertIn(h, lines, f'{u["unit"]}: {h}')
                if u['kind'] == 'feed':
                    self.assertIn('DynamicUser=yes', lines)
                    self.assertTrue(any(l.startswith('InaccessiblePaths=') and man['layout']['run'] in l for l in lines))
                    continue
                self.assertIn(f'User={user}', lines)
                self.assertNotIn('User=root', lines)
                for c in u['credentials']:
                    self.assertIn(f'LoadCredentialEncrypted={c}:{man["layout"]["credstore"]}/{c}', lines)
                    self.assertIn(f'ExecStartPre=+/usr/bin/install -m 0400 -o {user} -g {user} ${{CREDENTIALS_DIRECTORY}}/{c} '
                                  f'{u["run_dir"]}/{c}', lines)
                plus = [l for l in lines if l.startswith('ExecStartPre=+') or l.startswith('ExecStart=+')]
                self.assertEqual(len(plus), len(u['credentials']), 'the only privileged steps are the credential copies')
                exec_line = next(l for l in lines if l.startswith('ExecStart='))
                self.assertNotRegex(exec_line, r'credstore|password|0x[0-9a-fA-F]{64}')
                self.assertIn('RuntimeDirectoryMode=0700', lines)
            health = files[f'units/bloch-bridge-{man["inst"]}-health.service'][0].decode()
            inacc = next(l for l in health.splitlines() if l.startswith('InaccessiblePaths='))
            for u in man['units']:
                if u['kind'] != 'feed':
                    self.assertIn('-' + u['run_dir'], inacc.split(), 'the health check and its hook never see staged secrets')
            self.assertIn('/etc/credstore.encrypted', inacc)

    def test_preflight_unit_shares_the_daemon_sandbox_and_conflicts(self):
        for (route, role), (files, man) in self.built.items():
            if not man.get('preflight_unit'):
                continue
            pre = files[f'units/{man["preflight_unit"]}'][0].decode().splitlines()
            primary = next(u for u in man['units'] if u['name'] == role)
            daemon = files[f'units/{primary["unit"]}'][0].decode().splitlines()
            self.assertIn(f'Conflicts={primary["unit"]}', pre)
            self.assertIn('Type=oneshot', pre)
            for l in daemon:
                if l.startswith(('LoadCredentialEncrypted=', 'ExecStartPre=', 'RuntimeDirectory=', 'User=')) or l in MAN['hardening']['lines']:
                    self.assertIn(l, pre, f'{man["preflight_unit"]}: {l}')

    def test_refusals(self):
        spec = MAN['routes']['ethereum']['roles']['relayer']
        lay = bundle.layout('ethereum', 'relayer')
        facts = set(MAN['facts']['values'])
        src = bundle.rev_parse(MAN['routes']['ethereum']['source_rev'])
        base = bundle.render_configs('ethereum', 'relayer', spec, src, lay, facts)['relayer.json']
        for path, value, want in [('l2_relayer_password_file', '/etc/bloch-bridge/ethereum-relayer/l2-gas.password', 'staged credential'),
                                  ('l2_relayer_password_file', 'credential:l2-gas.password', 'staged credential'),
                                  ('eth_rpc', 'http://some-provider.example/v1/KEY', 'neither TBD-owner'),
                                  ('token', '0x' + '11' * 32, '32-byte hex'),
                                  ('_about', '-----BEGIN ' + 'EC PRIVATE KEY' + '-----', 'PEM')]:
            doc = copy.deepcopy(base)
            doc[path] = value
            probs = bundle.check_config('relayer.json', doc, lay, 'relayer', spec, facts)
            self.assertTrue(any(want in p for p in probs), (path, value, probs))
        self.assertEqual(bundle.check_config('relayer.json', base, lay, 'relayer', spec, facts), [])
        bad = copy.deepcopy(MAN)
        bad['routes']['ethereum']['roles']['reserves']['units'][0]['extra'] = ['NoNewPrivileges=no']
        bundle.HARDENING_KEYS = {l.split('=')[0] for l in MAN['hardening']['lines']}
        u = bad['routes']['ethereum']['roles']['reserves']['units'][0]
        with self.assertRaises(bundle.BuildError):
            bundle.unit_text('daemon', bundle.layout('ethereum', 'reserves'), 'reserves', bad['routes']['ethereum']['roles']['reserves'],
                             u, src, MAN['hardening']['lines'])

    def test_routes_on_one_host_do_not_collide(self):
        """An operator may run several routes on one host: users, paths, units and feed ports must all differ."""
        ports, units, users = {}, {}, {}
        for (route, role), (files, man) in self.built.items():
            users.setdefault(man['layout']['user'], []).append(man['inst'])
            for u in man['units']:
                units.setdefault(u['unit'], []).append(man['inst'])
            for p in man['ports'].get('inbound', []):
                ports.setdefault(p['port'], []).append(man['inst'])
            for u in man['units']:
                if u['kind'] == 'feed':
                    port = files[f'units/{u["unit"]}'][0].decode().split('--port ')[1].split()[0]
                    self.assertEqual(int(port), man['ports']['inbound'][0]['port'], u['unit'])
        for d in (ports, units, users):
            self.assertTrue(all(len(v) == 1 for v in d.values()), {k: v for k, v in d.items() if len(v) > 1})

    def test_evm_networks_inherit_without_sombra_and_without_interval(self):
        for net in ('arbitrum-one', 'op-mainnet', 'linea'):
            files, man = self.built[(net, 'guardian')]
            self.assertEqual([u['name'] for u in man['units']], ['guardian'])
            self.assertNotIn('sombra.json', man['configs'])
            files, man = self.built[(net, 'signer')]
            text = files[f'units/bloch-bridge-{net}-signer.service'][0].decode()
            exec_line = next(l for l in text.splitlines() if l.startswith('ExecStart='))
            self.assertNotIn('--interval', exec_line, 'the EVM networks refuse a sign interval longer than their default')
            cfg = json.loads(files['etc/templates/signer.json'][0])
            self.assertEqual(cfg['timing_state'], f'/var/lib/bloch-bridge/{net}-signer/timing.json')
            self.assertEqual(cfg['source_chain_id'], {'arbitrum-one': 42161, 'op-mainnet': 10, 'linea': 59144}[net])

    def test_unknown_set_key_is_refused(self):
        doc = {'a': 1}
        with self.assertRaises(bundle.BuildError):
            bundle.set_path(doc, 'b', 2, False)
        bundle.set_path(doc, 'b', 2, True)
        self.assertEqual(doc['b'], 2)


if __name__ == '__main__':
    unittest.main()
