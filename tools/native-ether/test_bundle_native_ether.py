#!/usr/bin/env python3
"""The operator bundles of the ethereum-eth route (bETH) while the route is HELD (agent 412, round 20).

  python3 -m unittest test_bundle_native_ether        (from tools/native-ether)

It lives here and not under ops/ because ops/ belongs to the operator-packages line as a whole (the integrator's
identity check): this route adds nothing to that directory while it is held.

The committed ops/routes.json does not name the route: `bundle.py` then builds nothing for it, as for Base and BNB
Smart Chain. Its entry lives in deployments/ethereum-eth/beth-ops/route.ops.json. These tests add that entry to the
manifest IN MEMORY (nothing is written) and check that every role assembles from the committed sources at HEAD, that
the bytes are deterministic, that the rendered configs pass the builder's own lint (no literal but TBD-owner, layout
paths and listed facts; no key material), that the signer's payload carries the held gate, and that what differs
from the Ethereum USDC route's bundle is exactly what the entry says.
Route sources are read from git objects at HEAD: run on a committed tree.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'ops'
sys.path.insert(0, str(HERE))
import bundle  # noqa: E402

ROUTE = 'ethereum-eth'
ENTRY_FILE = ROOT / 'deployments/ethereum-eth/beth-ops/route.ops.json'
ROLES = ('signer', 'relayer', 'guardian', 'reserves')


def manifest_with_route():
    raw = json.loads((HERE / 'routes.json').read_text())
    doc = json.loads(ENTRY_FILE.read_text())
    raw['routes'][ROUTE] = {**copy.deepcopy(doc['entry']), 'source_rev': 'HEAD'}
    raw['facts']['values'].update(doc['facts'])
    for name, r in list(raw['routes'].items()):
        if 'inherit' in r:
            raw['routes'][name] = bundle.inherit(raw['routes'], name, r)
    return raw


class with_route:
    """bundle.load_manifest answers with the route added, for the duration."""

    def __enter__(self):
        self.real = bundle.load_manifest
        man = manifest_with_route()
        bundle.load_manifest = lambda ops_rev: copy.deepcopy(man)
        return man

    def __exit__(self, *exc):
        bundle.load_manifest = self.real


class Held(unittest.TestCase):
    def test_the_committed_manifest_does_not_name_the_route(self):
        man = bundle.load_manifest('worktree')
        self.assertNotIn(ROUTE, man['routes'])
        for role in ROLES:
            with self.assertRaises(bundle.BuildError) as ctx:
                bundle.assemble(ROUTE, role, worktree_ops=True)
            self.assertIn('unknown route', str(ctx.exception))
        self.assertNotIn('beth-mainnet', man['facts']['values'])

    def test_the_entry_says_held_and_names_no_revision(self):
        doc = json.loads(ENTRY_FILE.read_text())
        self.assertIn('HELD', doc['entry']['launch_status'])
        self.assertTrue(doc['entry']['source_rev'].startswith('TBD-integrator'))
        self.assertEqual(doc['entry']['inherit'], 'ethereum')


class Bundles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with with_route():
            cls.built = {role: bundle.assemble(ROUTE, role, worktree_ops=True) for role in ROLES}
        cls.usdc = {role: bundle.assemble('ethereum', role, worktree_ops=True) for role in ROLES}

    def test_every_role_assembles_with_its_units_and_configs(self):
        for role, (files, man) in self.built.items():
            self.assertEqual(man['inst'], f'{ROUTE}-{role}')
            self.assertIn('HELD', man['launch_status'])
            self.assertTrue(any(p.startswith('units/') for p in files), role)
            self.assertTrue(any(p.startswith('etc/templates/') for p in files), role)
            self.assertIn(f'units/bloch-bridge-{ROUTE}-{role}.service', files)

    def test_deterministic_bytes(self):
        with with_route():
            for role in ROLES:
                a = bundle.tar_bytes(*bundle.assemble(ROUTE, role, worktree_ops=True))
                b = bundle.tar_bytes(*bundle.assemble(ROUTE, role, worktree_ops=True))
                self.assertEqual(hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest(), role)

    def test_the_signer_payload_carries_the_held_gate(self):
        files, _ = self.built['signer']
        self.assertIn('tools/signatario-stable/native_ether.py', files)
        gate = files['tools/signatario-stable/native_ether.py'][0].decode()
        self.assertIn("LAUNCH = {'v1': False, 'state': 'held'}", gate)
        half = files['tools/signatario-stable/eth_half.py'][0].decode()
        self.assertIn('native_ether_gate', half)
        self.assertNotIn('tools/native-ether/rehearse_fork.py', files)
        self.assertFalse([p for p in files if '/test_' in p or '/rehearse_' in p])

    def test_configs_are_the_routes_own(self):
        cfg = lambda role, name: json.loads(self.built[role][0][f'etc/templates/{name}'][0])  # noqa: E731
        relayer = cfg('relayer', 'relayer.json')
        self.assertEqual(relayer['eth_max_gas_price_gwei'], 30)       # the route's ceiling (the USDC route: 2)
        self.assertEqual((relayer['eth_chain_id'], relayer['source_chain_id'], relayer['l2_chain_id']), (1, 1, 700770))
        self.assertEqual(cfg('guardian', 'guardiao.json')['name'], 'beth-mainnet')
        self.assertEqual(cfg('reserves', 'reservas.json')['bridges'][0]['name'], 'beth-mainnet')
        signer = cfg('signer', 'signer.json')
        self.assertEqual((signer['threshold'], signer['vault_threshold'], signer['provenance']), (5, 5, True))
        self.assertIn('ethereum-eth-feed', signer['feed']['publish_dir'])
        self.assertTrue(cfg('signer', 'eth-half.json')['provenance'])
        # the proof-path guardian needs a light-client verifier this route does not have
        self.assertNotIn('etc/templates/sombra.json', self.built['guardian'][0])
        self.assertIn('etc/templates/sombra.json', self.usdc['guardian'][0])

    def test_two_routes_of_one_operator_do_not_collide(self):
        """Users, paths, unit names and the feed port all differ from the Ethereum USDC route's."""
        for role in ROLES:
            mine, theirs = self.built[role][1], self.usdc[role][1]
            self.assertNotEqual(mine['inst'], theirs['inst'])
            self.assertFalse({u['unit'] for u in mine['units']} & {u['unit'] for u in theirs['units']})
            for key in ('release', 'etc', 'state'):
                if key in mine['layout']:
                    self.assertNotEqual(mine['layout'][key], theirs['layout'][key], key)
        self.assertIn('8794', json.dumps(self.built['signer'][1]))
        self.assertNotIn('8787', json.dumps(self.built['signer'][1]))
        taken = json.dumps(json.loads((HERE / 'routes.json').read_text()))
        self.assertNotIn('8794', taken)                                # no committed route uses the port

    def test_no_key_material_and_only_listed_literals(self):
        # assemble() already refuses a config or a unit that holds a 32-byte hex value outside the listed facts, a PEM
        # block or a literal that is neither TBD-owner, a layout path nor a fact; here the same on the whole bundle text
        for role, (files, _) in self.built.items():
            for path, (data, _) in files.items():
                if path.startswith(('units/', 'etc/templates/')):
                    text = data.decode()
                    self.assertIsNone(bundle.PEM.search(text), path)


if __name__ == '__main__':
    unittest.main()
