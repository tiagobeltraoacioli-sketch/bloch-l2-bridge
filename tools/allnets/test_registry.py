"""Tests of the bridges' registry (tools/allnets/registry.py). Each cross-route check is shown to fail on a tree
that breaks it (failing-first: every mutation below must produce exactly the named check's refusal)."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import registry  # noqa: E402


class Registry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg, cls.errors = registry.build()
        cls.routes = {r['id']: {k: v for k, v in r.items() if k != 'id'} for r in cls.reg['routes']}
        cls.findings = json.loads(registry.FINDINGS.read_text())['findings']

    def mutated(self, fn):
        out = copy.deepcopy(self.routes)
        fn(out)
        return registry.cross_checks(out, self.findings)

    def test_tree_passes_every_check(self):
        self.assertEqual(self.errors, [])

    def test_committed_registry_is_current(self):
        self.assertEqual(registry.OUT.read_text(), registry.render(self.reg))

    def test_readme_launch_table_is_the_registry_s(self):
        self.assertEqual(registry.README.read_text(), registry.readme_with(self.reg))
        for r in self.reg['routes']:
            for f in r['launch']['openFindings']:
                self.assertIn(f['id'], registry.readme_table(self.reg))

    def test_every_route_file_is_in_the_registry(self):
        files = sorted(p.parent.name for p in (registry.ROOT / 'deployments').glob('*/bridge.network.json'))
        self.assertEqual(sorted(set(self.routes) - {'ethereum'}), files)
        self.assertIn('ethereum', self.routes)

    def test_c2_shared_symbol_refused(self):
        errs = self.mutated(lambda o: o['tron']['l2'].__setitem__('symbol', 'bUSDC.arb'))
        self.assertTrue(any(e.startswith('C2 L2 symbol') for e in errs), errs)

    def test_c2_symbol_compare_ignores_case(self):
        errs = self.mutated(lambda o: o['tron']['l2'].__setitem__('symbol', 'BUSDC.ARB'))
        self.assertTrue(any(e.startswith('C2 L2 symbol') for e in errs), errs)

    def test_c2_shared_name_refused(self):
        errs = self.mutated(lambda o: o['solana']['l2'].__setitem__('name', o['stellar']['l2']['name']))
        self.assertTrue(any(e.startswith('C2 L2 name') for e in errs), errs)

    def test_c3_shared_source_chain_refused(self):
        errs = self.mutated(lambda o: o['linea'].__setitem__('sourceChainId', '42161'))
        self.assertTrue(any(e.startswith('C3') for e in errs), errs)

    def test_c4_shared_label_refused(self):
        errs = self.mutated(lambda o: o['tron'].__setitem__('sourceDomain', 'ethereum-mainnet'))
        self.assertTrue(any(e.startswith('C4') for e in errs), errs)

    def test_c4_missing_label_refused(self):
        errs = self.mutated(lambda o: o['tron'].__setitem__('sourceDomain', None))
        self.assertTrue(any(e.startswith('C4 tron: no source-domain') for e in errs), errs)

    def test_c5_other_token_refused(self):
        errs = self.mutated(lambda o: o['bitcoin']['l2'].__setitem__('creationCodeKeccak', '0x' + '11' * 32))
        self.assertTrue(any(e.startswith('C5 bitcoin') for e in errs), errs)

    def test_c5_other_l2_chain_refused(self):
        errs = self.mutated(lambda o: o['stellar']['l2'].__setitem__('chainId', 700771))
        self.assertTrue(any(e.startswith('C5 stellar') for e in errs), errs)

    def test_c6_foreign_fee_recipient_refused(self):
        errs = self.mutated(lambda o: o['op-mainnet']['fee'].__setitem__('recipient', '0x' + '22' * 20))
        self.assertTrue(any(e.startswith('C6 op-mainnet') for e in errs), errs)

    def test_c6_fee_recipient_case_matters(self):
        # the EIP-55 form is the owner's recorded text; a lower-case copy is a different text and is refused
        errs = self.mutated(lambda o: o['ethereum']['fee'].__setitem__('recipient', o['ethereum']['fee']['recipient'].lower()))
        self.assertTrue(any(e.startswith('C6 ethereum') for e in errs), errs)

    def test_c7_weaker_committee_refused(self):
        errs = self.mutated(lambda o: o['solana']['committee'].__setitem__('threshold', 4))
        self.assertTrue(any(e.startswith('C7 solana') for e in errs), errs)

    def test_c8_finding_of_unknown_route_refused(self):
        bad = self.findings + [{'id': 'X', 'routes': ['polygon'], 'severity': 'Medium', 'state': 'open', 'owner': 0}]
        self.assertTrue(any(e.startswith('C8') for e in registry.cross_checks(copy.deepcopy(self.routes), bad)))

    def test_launch_never_raised_and_lowered_by_findings(self):
        for net, r in self.routes.items():
            l = r['launch']
            self.assertEqual(l['v1'], l['state'] == 'launchable', net)
            if l['openFindings']:
                self.assertFalse(l['v1'], net)
            if l['sourceState'] != 'launchable':
                self.assertFalse(l['v1'], net)

    def test_base_and_bnb_never_launchable(self):
        self.assertEqual(self.routes['base']['launch']['state'], 'held')
        self.assertEqual(self.routes['bnb']['launch']['state'], 'out')

    def test_undeclared_route_is_not_launchable(self):
        for net, r in self.routes.items():
            if r['launch']['sourceState'] == 'undeclared':
                self.assertFalse(r['launch']['v1'], net)


    # Round 19 (agent 403): the launch table is ONE table of every open finding per route.

    def row(self, route):
        rows = [l for l in registry.readme_table(self.reg).splitlines() if l.startswith(f'| {route} |')]
        self.assertEqual(len(rows), 1, route)
        return rows[0]

    def test_every_finding_below_medium_is_in_its_route_s_row(self):
        listed = self.reg['listedFindings']
        self.assertTrue(listed)
        for f in listed:
            for route in f['routes']:
                self.assertIn(f"{f['id']} ({f['severity']})", self.row(route))

    def test_every_finding_of_medium_or_above_is_in_its_route_s_row(self):
        for f in self.findings:
            for route in f['routes']:
                self.assertIn(f"{f['id']} ({f['severity']}, {f['state']})", self.row(route))

    def test_a_row_names_no_finding_of_another_route(self):
        every = self.findings + self.reg['listedFindings']
        for r in self.reg['routes']:
            for f in every:
                if r['id'] not in f['routes']:
                    self.assertNotIn(f"{f['id']} (", self.row(r['id']))

    def test_findings_on_a_held_or_out_route_leave_its_state(self):
        # Base and BNB carry Medium-or-above findings (R325-EVM-1 High, R329-EVM-3P-2, R325-EVM-2): still held / out,
        # never `not-launchable-until-fixed` (which would read as "launchable once fixed").
        for net, state in (('base', 'held'), ('bnb', 'out')):
            launch = self.routes[net]['launch']
            self.assertTrue(launch['openFindings'], net)
            self.assertEqual((launch['state'], launch['v1']), (state, False))
        self.assertIn('High', [f['severity'] for f in self.routes['base']['launch']['openFindings']])

    def test_c8_listed_finding_of_unknown_route_refused(self):
        doc = json.loads(registry.FINDINGS.read_text())
        doc['listed'].append({'id': 'X-1', 'routes': ['nowhere'], 'severity': 'Low', 'what': 'x', 'source': 'x'})
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'open-findings.json'
            f.write_text(json.dumps(doc))
            with mock.patch.object(registry, 'FINDINGS', f):
                _, errors = registry.build()
        self.assertTrue(any(e.startswith('C8 finding X-1') for e in errors), errors)

    def test_a_finding_without_a_severity_word_is_refused(self):
        doc = json.loads(registry.FINDINGS.read_text())
        doc['listed'].append({'id': 'X-2', 'routes': ['tron'], 'severity': 'minor', 'what': 'x', 'source': 'x'})
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'open-findings.json'
            f.write_text(json.dumps(doc))
            with mock.patch.object(registry, 'FINDINGS', f):
                _, errors = registry.build()
        self.assertTrue(any(e.startswith('C8 finding X-2') for e in errors), errors)

if __name__ == '__main__':
    unittest.main()
