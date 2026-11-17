"""Real offline state verifier and hash-pinned read-only collector regressions."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from custody_deployment_compare import NON_AUTHORIZING
from custody_deployment_manifest import canonical_sha256
from custody_deployment_state import SCHEMA, IMPLEMENTATION_SLOT, collect_custody_deployment_state, verify_custody_deployment_state
from test_custody_deployment_inclusion import inclusion_fixture, rebind
from verifier_fixture import private_copy

VECTORS = json.loads((ROOT / 'test-vectors/ethereum-deployment-state/synthetic.json').read_text())['cases']


def rebind_state(manifest, captures, ancestry, inclusion, state):
    for capture in captures:
        capture['evidence']['manifest_canonical_sha256'] = canonical_sha256(manifest)
    rebind(manifest, captures, ancestry, inclusion)
    state.update(schema=SCHEMA, manifestCanonicalSha256=canonical_sha256(manifest),
                 comparisonCanonicalSha256=inclusion['comparisonCanonicalSha256'],
                 ancestryEvidenceCanonicalSha256=canonical_sha256(ancestry),
                 inclusionEvidenceCanonicalSha256=canonical_sha256(inclusion))


def state_fixture(variant=0):
    row = VECTORS[variant]
    native = row['request']
    manifest, captures, ancestry, inclusion = inclusion_fixture(row['kind'])
    implementation = native['contracts'][2]['address']
    manifest['source']['token_implementation_address'] = implementation
    anchor = native['inclusion']['ancestry']['anchors'][0]
    for capture in captures:
        value = capture['evidence']
        for key in ('transaction', 'vault_runtime', 'token_runtime'):
            value[key]['block_hash'] = anchor['blockHash']
        value['source_evidence']['receipt']['blockHash'] = anchor['blockHash']
        for key in ('canonical_block', 'finalized_block'):
            value['source_evidence'][key].update(hash=anchor['blockHash'], stateRoot=anchor['stateRoot'])
        value['token_runtime'].update(implementation_address=implementation,
                                     implementation_slot='0x' + implementation[2:].rjust(64, '0'),
                                     implementation_getter='0x' + implementation[2:].rjust(64, '0'))
    ancestry['headers'] = copy.deepcopy(native['inclusion']['ancestry']['headers'])
    state = {'proofs': [copy.deepcopy(c['proof']) for c in native['contracts']]}
    rebind_state(manifest, captures, ancestry, inclusion, state)
    return manifest, captures, ancestry, inclusion, state


class Source:
    def __init__(self, inputs):
        self.inputs = copy.deepcopy(inputs)
        self.calls = []
        self.after_proof = None

    def eth(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        manifest, captures, _, _, state = self.inputs
        if method == 'eth_chainId':
            return '0x1'
        if method == 'eth_getBlockByNumber':
            if params == ['0x0', False]:
                return {'number': '0x0', 'hash': manifest['source']['genesis_hash']}
            if params == ['0x64', False]:
                return copy.deepcopy(captures[0]['evidence']['source_evidence']['canonical_block'])
        if method == 'eth_getProof':
            proofs = [p for p in state['proofs'] if p['address'] == params[0]]
            if len(proofs) == 1:
                if self.after_proof:
                    self.after_proof(params)
                return copy.deepcopy(proofs[0])
        raise AssertionError('unexpected RPC request')


class StateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([str(Path.home() / '.cargo/bin/cargo'), '+1.94.1', 'build', '--offline', '--locked',
                                 '--features', 'ethereum-inclusion', '--bin', 'ethereum_deployment_state_verifier'],
                                cwd=ROOT, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError('real state verifier build failed: ' + result.stderr)
        target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
        cls.built = (ROOT / target if not target.is_absolute() else target) / 'debug/ethereum_deployment_state_verifier'
        # A private copy with an explicit mode, never cargo's output under the process umask (verifier_fixture.py).
        cls.executable = private_copy(cls, cls.built)
        cls.pin = '0x' + hashlib.sha256(cls.executable.read_bytes()).hexdigest()

    def verify(self, inputs, pin=None):
        return verify_custody_deployment_state(*inputs, executable=str(self.executable), expected_verifier_sha256=pin or self.pin)

    def test_independent_vectors_verify_limited_coverage_without_authorization(self):
        for variant in range(4):
            inputs = state_fixture(variant)
            before = copy.deepcopy(inputs)
            report = self.verify(inputs)
            for key in ('accountProofsVerified', 'runtimeCodeStateProofsVerified', 'proxyImplementationStorageVerified',
                        'transactionInclusionVerified', 'receiptInclusionVerified', 'capturedHeaderRootsVerified'):
                self.assertIs(report[key], True)
            for key in (*NON_AUTHORIZING, 'anchorAuthenticationVerified', 'verifierIdentityAuthenticated',
                        'vaultControlsStorageVerified', 'tokenBalanceStorageVerified', 'capturedStateProofsVerified',
                        'runtimeExecutionReplayed', 'consensusRulesVerified', 'completeBlockContentsVerified'):
                self.assertIs(report[key], False)
            self.assertEqual(inputs, before)

    def test_rebound_manifest_and_code_cannot_change_authenticated_account(self):
        fields = [('vault_runtime', 'code', 'vault_runtime_sha256'),
                  ('token_runtime', 'proxy_code', 'token_proxy_runtime_sha256'),
                  ('token_runtime', 'implementation_code', 'token_implementation_runtime_sha256')]
        for index, (section, code_field, pin_field) in enumerate(fields):
            inputs = state_fixture()
            changed = '0x60036000fd'
            inputs[0]['source'][pin_field] = '0x' + hashlib.sha256(bytes.fromhex(changed[2:])).hexdigest()
            for capture in inputs[1]:
                capture['evidence'][section][code_field] = changed
            # Outer commitments are not accepted as substitutes for trie paths.
            rebind_state(*inputs)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.verify(inputs)

    def test_proof_substitutions_malformed_coverage_and_wrong_executable_refuse(self):
        for field in ('manifestCanonicalSha256', 'comparisonCanonicalSha256',
                      'ancestryEvidenceCanonicalSha256', 'inclusionEvidenceCanonicalSha256'):
            inputs = state_fixture()
            inputs[4][field] = '0x' + '99' * 32
            with self.subTest(field=field), patch('custody_deployment_state._stage_verifier') as stage:
                with self.assertRaises(ValueError):
                    self.verify(inputs)
                stage.assert_not_called()
        for action in range(7):
            inputs = state_fixture()
            proofs = inputs[4]['proofs']
            if action == 0:
                proofs.reverse()
            elif action == 1:
                proofs[1]['storageProof'][0]['value'] = '0x0'
            elif action == 2:
                proofs[0]['accountProof'].pop()
            elif action == 3:
                proofs[1]['storageProof'][0]['proof'].pop()
            elif action == 4:
                proofs[2]['balance'] = '0x1'
            elif action == 5:
                proofs[0]['extra'] = True
            else:
                proofs.append(proofs[0])
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.verify(inputs)
        with self.assertRaises(ValueError):
            self.verify(state_fixture(), pin='0x' + '99' * 32)

    def test_collector_pins_all_proofs_to_canonical_hash_and_rechecks_chain(self):
        inputs = state_fixture()
        source = Source(inputs)
        collected = collect_custody_deployment_state(*inputs[:4], source)
        self.assertEqual(collected, inputs[4])
        calls = [(method, params) for method, params in source.calls if method == 'eth_getProof']
        self.assertEqual(len(calls), 3)
        for index, (_, params) in enumerate(calls):
            self.assertEqual(params[0], inputs[4]['proofs'][index]['address'])
            self.assertEqual(params[1], [IMPLEMENTATION_SLOT] if index == 1 else [])
            self.assertEqual(params[2], {'blockHash': inputs[2]['anchors'][0]['blockHash'], 'requireCanonical': True})
        self.assertEqual(len(source.calls), 9)
        report = self.verify((*inputs[:4], collected))
        self.assertIs(report['proxyImplementationStorageVerified'], True)

    def test_collector_refuses_changed_chain_genesis_block_and_unsupported_selector(self):
        for action in range(5):
            inputs = state_fixture()
            source = Source(inputs)
            original = source.eth
            def changed(method, params):
                response = original(method, params)
                if method == 'eth_chainId' and action == 0:
                    return '0x2'
                if method == 'eth_getBlockByNumber' and params[0] == '0x0' and action == 1:
                    response['hash'] = '0x' + '99' * 32
                if method == 'eth_getBlockByNumber' and params[0] == '0x64' and action == 2 and len(source.calls) > 3:
                    response['hash'] = '0x' + '99' * 32
                if method == 'eth_getProof' and action == 3:
                    raise ValueError('selector unsupported; must not retry by height')
                if method == 'eth_chainId' and action == 4 and len(source.calls) > 3:
                    return '0x2'
                return response
            source.eth = changed
            with self.subTest(action=action), self.assertRaises(ValueError):
                collect_custody_deployment_state(*inputs[:4], source)
            if action == 3:
                self.assertEqual(sum(method == 'eth_getProof' for method, _ in source.calls), 1)

    def test_collector_freezes_inputs_and_refuses_invalid_context_before_rpc(self):
        inputs = state_fixture()
        source = Source(inputs)
        expected = copy.deepcopy(inputs[4])
        def mutate(params):
            inputs[0]['source']['token_implementation_address'] = '0x' + '99' * 20
            inputs[1][0]['evidence']['source_evidence']['canonical_block']['hash'] = '0x' + '99' * 32
            params[2]['blockHash'] = '0x' + '99' * 32
        source.after_proof = mutate
        self.assertEqual(collect_custody_deployment_state(*inputs[:4], source), expected)
        source.calls.clear()
        with self.assertRaises(ValueError):
            collect_custody_deployment_state(*inputs[:4], source)
        self.assertEqual(source.calls, [])

    def test_cli_uses_real_verifier_and_does_not_echo_refused_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, captures, ancestry, inclusion, state = state_fixture()
            for name, value in [('manifest', manifest), ('a', captures[0]['evidence']), ('b', captures[1]['evidence']),
                                ('ancestry', ancestry), ('inclusion', inclusion), ('state', state)]:
                (root / (name + '.json')).write_text(json.dumps(value))
            args = [sys.executable, str(ROOT / 'scripts/check-custody-deployment-state.py'), str(root/'manifest.json'),
                    '--capture', 'node-a='+str(root/'a.json'), '--capture', 'node-b='+str(root/'b.json'),
                    '--ancestry', str(root/'ancestry.json'), '--inclusion', str(root/'inclusion.json'),
                    '--state', str(root/'state.json'), '--verifier', str(self.executable), '--verifier-sha256', self.pin]
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIs(json.loads(result.stdout)['runtimeCodeStateProofsVerified'], True)
            (root/'state.json').write_text('{"schema":"do-not-echo-this-marker","schema":false}')
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertNotIn(directory, result.stderr)
            self.assertNotIn('do-not-echo', result.stderr)
            for key in NON_AUTHORIZING:
                self.assertIs(json.loads(result.stderr)[key], False)


if __name__ == '__main__':
    unittest.main()
