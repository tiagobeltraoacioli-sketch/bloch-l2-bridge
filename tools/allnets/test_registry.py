"""Tests of the bridges' registry (tools/allnets/registry.py). Each cross-route check is shown to fail on a tree
that breaks it (failing-first: every mutation below must produce exactly the named check's refusal)."""
import copy
import io
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

    # ── C9 (round 20): the launch limits decided on 2026-11-19 ──
    def test_c9_the_launch_limits_are_the_decided_ones(self):
        want = {'ethereum': (500_000, 50_000), 'arbitrum-one': (250_000, 25_000), 'op-mainnet': (250_000, 25_000),
                'linea': (250_000, 25_000), 'base': (100_000, 10_000), 'bnb': (100_000, 10_000)}
        for net, (cap, window) in want.items():
            lim = self.routes[net]['limits']
            self.assertEqual((lim['cap'], lim['window'], lim['windowSeconds']), (str(cap * 10**6), str(window * 10**6), 86400), net)
            self.assertEqual(int(lim['cap']), 10 * int(lim['window']), net)
        ll = self.reg['launchLimits']
        self.assertEqual([r['id'] for r in ll['routes']], ['ethereum', 'arbitrum-one', 'linea', 'op-mainnet'])
        self.assertEqual((ll['decided'], ll['windowsPerCap'], ll['aggregateCap']), ('2026-11-19', 10, str(1_250_000 * 10**6)))
        self.assertIn('AFTER launch', ll['audit'])
        self.assertIn('UNAUDITED', ll['audit'])
        self.assertIn('C9 launch limits', self.reg['checks'])

    def test_c9_another_cap_or_window_is_refused(self):
        def old(o):
            o['ethereum']['limits'].update(cap='100000000000', window='10000000000')
        cases = {
            'the values before the decision on Ethereum': old,
            'a larger cap on Ethereum': lambda o: o['ethereum']['limits'].__setitem__('cap', '5000000000000'),
            'the Ethereum limits on Linea': lambda o: o['linea']['limits'].update(cap='500000000000', window='50000000000'),
            'a larger window on OP Mainnet': lambda o: o['op-mainnet']['limits'].__setitem__('window', '250000000000'),
            'a 12 hour window on Arbitrum One': lambda o: o['arbitrum-one']['limits'].__setitem__('windowSeconds', 43200),
            'a raised cap on Base': lambda o: o['base']['limits'].update(cap='250000000000', window='25000000000'),
            'a cap as a number on Linea': lambda o: o['linea']['limits'].__setitem__('cap', 250000000000),
            'no cap on Linea': lambda o: o['linea']['limits'].pop('cap'),
        }
        for what, change in cases.items():
            errs = self.mutated(change)
            self.assertTrue(any(e.startswith('C9 ') for e in errs), (what, errs))
        self.assertEqual(self.mutated(lambda o: None), [])

    def test_c9_a_window_length_that_is_not_an_integer_and_a_chain_without_limits_are_refused(self):
        # review R420-9 (R1, R2): the two branches of C9 that no test reached
        for bad in (86400.0, '86400', True, None):
            errs = self.mutated(lambda o, bad=bad: o['linea']['limits'].__setitem__('windowSeconds', bad))
            self.assertTrue(any(e.startswith('C9 linea: cap, window, windowSeconds') for e in errs), (bad, errs))
        errs = self.mutated(lambda o: o['linea']['network'].__setitem__('chainId', 31337))   # an EVM chain with no limits record
        self.assertTrue(any(e.startswith('C9 linea: no launch limits are recorded for chain 31337') for e in errs), errs)

    def test_c9_other_kinds_of_route_are_not_held_to_the_evm_limits(self):
        # Bitcoin, TRON, Solana and Stellar keep their own limits (not part of the decision): C9 does not read them
        errs = self.mutated(lambda o: [o[n]['limits'].update(cap='1') for n in ('bitcoin', 'tron', 'solana', 'stellar')])
        self.assertFalse(any(e.startswith('C9 ') for e in errs), errs)

    def test_c9_an_untrusted_limits_record_fails_the_check(self):
        launch = registry.routes._launch()
        with tempfile.TemporaryDirectory() as tmp:
            reg = json.loads(launch.REGISTRY.read_text())
            reg['limits']['ethereum']['cap'] = 5_000_000 * 10**6
            (Path(tmp) / 'networks.json').write_text(json.dumps(reg))
            with mock.patch.object(launch, 'REGISTRY', Path(tmp) / 'networks.json'):
                errs = self.mutated(lambda o: None)
        self.assertTrue(any(e.startswith('C9 ethereum: the launch limits cannot be read') for e in errs), errs)

    def test_the_readme_states_the_limits_and_that_the_routes_are_unaudited(self):
        table = registry.readme_table(self.reg)
        for text in ('decided 2026-11-19', '| limits: ethereum | 500,000 | 50,000 |', '| limits: arbitrum-one | 250,000 | 25,000 |',
                     '| limits: op-mainnet | 250,000 | 25,000 |', '| limits: linea | 250,000 | 25,000 |', '| limits: all 4 under the one committee | 1,250,000 | |',
                     'external audit of the launchable routes is done AFTER launch', 'UNAUDITED'):
            self.assertIn(text, table, text)
        tail = table[table.index('Launch limits of the launchable routes'):]
        for held in ('base |', 'bnb |', 'bitcoin |', 'tron |', 'solana |', 'stellar |'):
            self.assertNotIn(held, tail)

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

    # R408-1 (reviewer 408, round 19): the findings file is read fail-closed.

    def build_with(self, change, raw=None):
        doc = json.loads(registry.FINDINGS.read_text())
        change(doc)
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'open-findings.json'
            if raw is None:
                f.write_text(json.dumps(doc))
            elif raw is not False:
                f.write_text(raw)
            with mock.patch.object(registry, 'FINDINGS', f):
                return registry.build()

    HIGH = {'id': 'X-HOLD', 'routes': ['linea'], 'severity': 'High', 'state': 'open', 'owner': 0, 'reviewer': 0,
            'what': 'x', 'source': 'x'}

    def test_control_a_finding_under_findings_holds_a_launchable_route(self):
        reg, errors = self.build_with(lambda d: d['findings'].append(dict(self.HIGH)))
        self.assertEqual(errors, [])
        linea = next(r for r in reg['routes'] if r['id'] == 'linea')['launch']
        self.assertEqual((linea['state'], linea['v1']), ('not-launchable-until-fixed', False))

    def test_a_missing_or_misspelled_findings_key_stops_the_generator(self):
        def misspelled(d):
            d['findings'].append(dict(self.HIGH))
            d['Findings'] = d.pop('findings')
        cases = {
            'misspelled': misspelled,
            'missing': lambda d: d.pop('findings'),
            'listed missing': lambda d: d.pop('listed'),
            'findings not a list': lambda d: d.__setitem__('findings', {}),
            'listed null': lambda d: d.__setitem__('listed', None),
            'unknown key beside them': lambda d: d.__setitem__('finding', []),
            'entry not an object': lambda d: d['findings'].append('X-HOLD'),
            'entry without routes': lambda d: d['findings'].append({k: v for k, v in self.HIGH.items() if k != 'routes'}),
            'routes not a list': lambda d: d['findings'].append({**self.HIGH, 'routes': 'linea'}),
            'entry without state': lambda d: d['findings'].append({k: v for k, v in self.HIGH.items() if k != 'state'}),
            'listed entry without severity': lambda d: d['listed'].append({'id': 'X', 'routes': ['tron'], 'what': 'x'}),
        }
        for name, change in cases.items():
            with self.subTest(name):
                with self.assertRaises(SystemExit) as stop:
                    self.build_with(change)
                self.assertIn('C8', str(stop.exception))

    def test_a_missing_or_unreadable_findings_file_stops_the_generator(self):
        for name, raw in (('missing', False), ('empty', ''), ('not json', '{'), ('a list', '[]')):
            with self.subTest(name):
                with self.assertRaises(SystemExit) as stop:
                    self.build_with(lambda d: None, raw=raw)
                self.assertIn('C8', str(stop.exception))

    def test_the_cli_fails_closed_on_a_misspelled_key(self):
        # reviewer 408's rig (tools/allnets/r408_findings_key.py on its review branch), as a test: `show`, `check` and
        # `write` exit non-zero, print no launchable linea and write nothing.
        doc = json.loads(registry.FINDINGS.read_text())
        doc['findings'].append(dict(self.HIGH))
        doc['Findings'] = doc.pop('findings')
        with tempfile.TemporaryDirectory() as d:
            f, out, readme = Path(d) / 'open-findings.json', Path(d) / 'bridges.json', Path(d) / 'README.md'
            f.write_text(json.dumps(doc))
            readme.write_text(registry.README.read_text())
            for mode in ('show', 'check', 'write'):
                with self.subTest(mode), mock.patch.object(registry, 'FINDINGS', f), \
                        mock.patch.object(registry, 'OUT', out), mock.patch.object(registry, 'README', readme), \
                        mock.patch('sys.stdout', new_callable=io.StringIO) as printed:
                    with self.assertRaises(SystemExit) as stop:
                        registry.main([mode])
                    self.assertIn('C8', str(stop.exception))
                    self.assertNotIn('v1=true', printed.getvalue())
            self.assertFalse(out.exists())
            self.assertEqual(readme.read_text(), registry.README.read_text())

    def test_coverage_notes_are_in_the_readme_table(self):
        notes = json.loads(registry.FINDINGS.read_text())['coverageNotes']
        self.assertTrue(notes)
        for note in notes:
            self.assertIn(note, registry.readme_table(self.reg))
        text = registry.readme_table(self.reg)
        for word in ('F381-2', 'operator-packages', 'ceremony', 'baa5391'):
            self.assertIn(word, text)

if __name__ == '__main__':
    unittest.main()
