"""Local EVM proof data with fixed-schema test metadata, never mainnet evidence."""
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
from custody_deployment_ancestry import _context as ancestry_context
from custody_deployment_compare import NON_AUTHORIZING
from custody_deployment_evidence import _route
from custody_deployment_manifest import canonical_sha256
from custody_deployment_vault import SCHEMA, expected_slots, collect_custody_deployment_vault, verify_custody_deployment_vault
from test_custody_deployment_evidence import fixture
from verifier_fixture import private_copy
from usdt_observer.vault_state import expected_words

VECTOR = json.loads((ROOT / 'test-vectors/ethereum-deployment-vault/anvil-shanghai.json').read_text())


def vault_fixture():
    native = copy.deepcopy(VECTOR['request'])
    state_native = native['state']
    inc = state_native['inclusion']
    vault, proxy, implementation = state_native['contracts']
    manifest, captured = fixture()
    manifest['source'].update(vault_address=vault['address'], vault_runtime_sha256=vault['runtimeSha256'],
                              vault_build_sha256=native['buildArtifactSha256'], vault_creation_input_sha256=inc['creationInputSha256'],
                              token_proxy_runtime_sha256=proxy['runtimeSha256'], token_implementation_address=implementation['address'],
                              token_implementation_runtime_sha256=implementation['runtimeSha256'])
    block, receipt = copy.deepcopy(VECTOR['block']), copy.deepcopy(VECTOR['receipt'])
    captured['manifest_canonical_sha256'] = canonical_sha256(manifest)
    captured['transaction'].update(hash=inc['transactionHash'], block_hash=block['hash'], block_number=block['number'],
                                   transaction_index='0x0', input=VECTOR['input'], **{'from': inc['sender']})
    captured['source_evidence'].update(receipt=receipt, canonical_block=copy.deepcopy(block), finalized_block=copy.deepcopy(block))
    captured['token_runtime'].update(block_hash=block['hash'], block_number=block['number'],
                                    proxy_code=proxy['code'], implementation_code=implementation['code'],
                                    implementation_address=implementation['address'],
                                    implementation_slot='0x'+implementation['address'][2:].rjust(64,'0'),
                                    implementation_getter='0x'+implementation['address'][2:].rjust(64,'0'))
    captured['vault_runtime'].update(block_hash=block['hash'], block_number=block['number'], address=vault['address'], code=vault['code'])
    captured['vault_runtime']['configuration'].update({key: '0x'+value.hex() for key, value in expected_words(_route(manifest,1)).items()})
    captures = [{'source': name, 'evidence': copy.deepcopy(captured)} for name in ('local-test-a','local-test-b')]
    comparison, _, anchors = ancestry_context(manifest,captures)
    ancestry = {**inc['ancestry'], 'anchors': anchors, 'manifestCanonicalSha256': canonical_sha256(manifest),
                'comparisonCanonicalSha256': canonical_sha256(comparison)}
    inclusion = {'schema':'postern.custody-deployment-inclusion.v1', 'manifestCanonicalSha256':canonical_sha256(manifest),
                 'comparisonCanonicalSha256':canonical_sha256(comparison), 'ancestryEvidenceCanonicalSha256':canonical_sha256(ancestry),
                 **{key:inc[key] for key in ('transaction','transactionProof','receipt','receiptProof')}}
    state = {'schema':'postern.custody-deployment-state.v1', 'manifestCanonicalSha256':canonical_sha256(manifest),
             'comparisonCanonicalSha256':canonical_sha256(comparison), 'ancestryEvidenceCanonicalSha256':canonical_sha256(ancestry),
             'inclusionEvidenceCanonicalSha256':canonical_sha256(inclusion), 'proofs':[c['proof'] for c in state_native['contracts']]}
    vault = {key:value for key,value in state.items() if key.endswith('CanonicalSha256')}
    vault.update(schema=SCHEMA, stateEvidenceCanonicalSha256=canonical_sha256(state),
                 buildArtifactSha256=native['buildArtifactSha256'], storageProof=native['storageProof'])
    return manifest,captures,ancestry,inclusion,state,vault


class Source:
    def __init__(self, inputs):
        self.inputs = copy.deepcopy(inputs)
        self.calls = []
        self.on_proof = None

    def eth(self, method, params):
        self.calls.append((method,copy.deepcopy(params)))
        manifest,captures,_,_,state,vault = self.inputs
        if method == 'eth_chainId':
            return '0x1'
        if method == 'eth_getBlockByNumber':
            if params == ['0x0',False]:
                return copy.deepcopy(captures[0]['evidence']['source_evidence']['genesis'])
            if params == ['0x1',False]:
                return copy.deepcopy(captures[0]['evidence']['source_evidence']['canonical_block'])
        if method == 'eth_getProof':
            if self.on_proof:
                self.on_proof(params)
            return copy.deepcopy({**state['proofs'][0], 'storageProof':vault['storageProof']})
        raise AssertionError('unexpected collector RPC')


class VaultTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([str(Path.home()/'.cargo/bin/cargo'), '+1.94.1','build','--offline','--locked',
                                 '--features','ethereum-inclusion','--bin','ethereum_deployment_vault_verifier'],
                                cwd=ROOT,capture_output=True,text=True,timeout=120)
        if result.returncode:
            raise AssertionError('real vault verifier build failed: '+result.stderr)
        target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))
        cls.built = (ROOT/target if not target.is_absolute() else target)/'debug/ethereum_deployment_vault_verifier'
        # A private copy with an explicit mode, never cargo's output under the process umask (verifier_fixture.py).
        cls.executable = private_copy(cls, cls.built)
        cls.pin = '0x'+hashlib.sha256(cls.executable.read_bytes()).hexdigest()

    def verify(self, inputs, pin=None):
        return verify_custody_deployment_vault(*inputs, executable=str(self.executable),expected_verifier_sha256=pin or self.pin)

    def test_local_evm_fixture_opens_only_documented_storage_properties(self):
        inputs = vault_fixture()
        before = copy.deepcopy(inputs)
        report = self.verify(inputs)
        self.assertEqual(report['storageProofCount'],13)
        for key in ('vaultCompiledRuntimeVerified','vaultConstructorArgumentsVerified','vaultImmutableConfigurationVerified',
                    'vaultControlsStorageVerified','vaultInternalAccountingZeroVerified','vaultReentrancyGuardClearVerified',
                    'vaultSignerArrayVerified','configuredSignerMembershipsVerified','runtimeCodeStateProofsVerified',
                    'proxyImplementationStorageVerified','transactionInclusionVerified','receiptInclusionVerified'):
            self.assertIs(report[key],True)
        for key in (*NON_AUTHORIZING,'tokenBalanceStorageVerified','completeSignerMappingVerified','capturedStateProofsVerified',
                    'runtimeExecutionReplayed','anchorAuthenticationVerified','verifierIdentityAuthenticated','consensusRulesVerified'):
            self.assertIs(report[key],False)
        self.assertEqual(inputs,before)

    def test_every_binding_and_wrong_verifier_pin_refuses(self):
        for field in ('manifestCanonicalSha256','comparisonCanonicalSha256','ancestryEvidenceCanonicalSha256',
                      'inclusionEvidenceCanonicalSha256','stateEvidenceCanonicalSha256','buildArtifactSha256'):
            inputs = vault_fixture()
            inputs[5][field] = '0x'+'99'*32
            with self.subTest(field=field),patch('custody_deployment_vault._stage_verifier') as stage:
                with self.assertRaises(ValueError):
                    self.verify(inputs)
                stage.assert_not_called()
        with self.assertRaises(ValueError):
            self.verify(vault_fixture(),pin='0x'+'99'*32)

    def test_zero_storage_claims_still_need_complete_cryptographic_proofs(self):
        for index in (1,2):
            inputs = vault_fixture()
            nodes = inputs[5]['storageProof'][index]['proof']
            self.assertGreaterEqual(len(nodes),1)
            nodes.pop()
            with self.subTest(index=index),self.assertRaises(ValueError):
                self.verify(inputs)
        inputs = vault_fixture()
        inputs[5]['storageProof'][3]['proof'] = inputs[5]['storageProof'][4]['proof']
        with self.assertRaises(ValueError):
            self.verify(inputs)

    def test_collector_uses_thirteen_fixed_slots_at_one_canonical_hash(self):
        inputs = vault_fixture()
        source = Source(inputs)
        self.assertEqual(collect_custody_deployment_vault(*inputs[:5],source),inputs[5])
        self.assertEqual(len(source.calls),7)
        method,params = source.calls[3]
        self.assertEqual(method,'eth_getProof')
        self.assertEqual(params[0],inputs[0]['source']['vault_address'])
        self.assertEqual(params[1],[p['key'] for p in inputs[5]['storageProof']])
        self.assertEqual(params[2],{'blockHash':VECTOR['block']['hash'],'requireCanonical':True})
        self.assertEqual(expected_slots(VECTOR['request']['configuration']),[(p['key'],p['value']) for p in inputs[5]['storageProof']])

    def test_collector_rejects_reorg_account_change_and_unsupported_selectors(self):
        for action in range(5):
            inputs = vault_fixture()
            source = Source(inputs)
            original = source.eth
            def altered(method,params):
                result = original(method,params)
                if method == 'eth_chainId' and action == 0:
                    return '0x2'
                if method == 'eth_getProof' and action == 1:
                    result['storageHash'] = '0x'+'99'*32
                if method == 'eth_getProof' and action == 2:
                    raise ValueError('block hash selector unsupported')
                if method == 'eth_getBlockByNumber' and action == 3 and len(source.calls) > 4:
                    result['hash'] = '0x'+'99'*32
                if method == 'eth_getProof' and action == 4:
                    result['storageProof'].reverse()
                return result
            source.eth = altered
            with self.subTest(action=action),self.assertRaises(ValueError):
                collect_custody_deployment_vault(*inputs[:5],source)
            self.assertLessEqual(sum(m=='eth_getProof' for m,_ in source.calls),1)

    def test_collector_freezes_inputs_and_refuses_unreviewed_build_before_rpc(self):
        inputs = vault_fixture()
        source = Source(inputs)
        expected = copy.deepcopy(inputs[5])
        def mutate(params):
            inputs[0]['source']['vault_build_sha256'] = '0x'+'99'*32
            inputs[1][0]['evidence']['source_evidence']['canonical_block']['hash'] = '0x'+'99'*32
            params[2]['blockHash'] = '0x'+'99'*32
        source.on_proof = mutate
        self.assertEqual(collect_custody_deployment_vault(*inputs[:5],source),expected)
        source.calls.clear()
        with self.assertRaises(ValueError):
            collect_custody_deployment_vault(*inputs[:5],source)
        self.assertEqual(source.calls,[])

    def test_real_cli_success_and_duplicate_field_refusal_are_non_authorizing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            manifest,captures,ancestry,inclusion,state,vault = vault_fixture()
            for name,value in [('manifest',manifest),('a',captures[0]['evidence']),('b',captures[1]['evidence']),
                               ('ancestry',ancestry),('inclusion',inclusion),('state',state),('vault',vault)]:
                (root/(name+'.json')).write_text(json.dumps(value))
            args=[sys.executable,str(ROOT/'scripts/check-custody-deployment-vault.py'),str(root/'manifest.json'),
                  '--capture','local-test-a='+str(root/'a.json'),'--capture','local-test-b='+str(root/'b.json'),
                  '--ancestry',str(root/'ancestry.json'),'--inclusion',str(root/'inclusion.json'),
                  '--state',str(root/'state.json'),'--vault',str(root/'vault.json'),
                  '--verifier',str(self.executable),'--verifier-sha256',self.pin]
            result=subprocess.run(args,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIs(json.loads(result.stdout)['vaultControlsStorageVerified'],True)
            (root/'vault.json').write_text('{"schema":"do-not-echo-marker","schema":false}')
            result=subprocess.run(args,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stdout,'')
            self.assertNotIn(directory,result.stderr)
            self.assertNotIn('do-not-echo',result.stderr)
            for key in NON_AUTHORIZING:
                self.assertIs(json.loads(result.stderr)[key],False)


if __name__ == '__main__':
    unittest.main()
