"""LEGACY three-of-five line, not the 5-of-7 mainnet vault (docs/MAINNET-USDC-ACTIVATION-HANDOFF.md). Fixed-build vault configuration and initial storage proofs, never activation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

from custody_deployment_compare import NON_AUTHORIZING, _bounded_copy
from custody_deployment_manifest import canonical_sha256
from custody_deployment_state import _request as state_request
from usdt_observer.common import MAX_JSON, quantity, require, word
from usdt_observer.l2_settlement import _stage_verifier
from usdt_observer.verifier_process import run_verifier

ROOT = Path(__file__).resolve().parents[1]
BUILD_PATH = ROOT / 'test-vectors/vault-storage-build/solc-0.8.24.json'
DOMAIN = b'BLOCH-ETHEREUM-DEPLOYMENT-VAULT-v1\0'
SCHEMA = 'postern.custody-deployment-vault.v1'

# Reuse the repository's independently vector-tested stdlib Keccak primitive.
# It constructs read-only RPC keys; Rust independently derives every key again.
_spec = importlib.util.spec_from_file_location('vault_key_keccak', ROOT / 'contracts/verify_leaf.py')
_keccak = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_keccak)


def expected_slots(configuration):
    signers = [word(s, 20).rjust(32, b'\0') for s in configuration['signers']]
    require(len(signers) == 5 and signers == sorted(set(signers)) and all(any(s) for s in signers),
            'five sorted nonzero signers required')
    require(configuration['threshold'] == 3 and configuration['transferMode'] == 0,
            'three-of-five Ethereum custody required')
    def uint(value):
        return value.to_bytes(32, 'big')
    slots = [(uint(0), 5), (uint(2), 0), (uint(5), 0)]
    base = int.from_bytes(_keccak.keccak256(uint(0)), 'big')
    slots += [(uint((base + i) % (1 << 256)), int.from_bytes(s, 'big')) for i, s in enumerate(signers)]
    slots += [(_keccak.keccak256(s + uint(1)), 1) for s in signers]
    return [('0x' + key.hex(), hex(value)) for key, value in slots]


def _compiled_configuration(configuration, captured, build):
    values = {key: word(configuration[key], 32) for key in ('sourceDomain', 'nativeDomain', 'nativeAsset')}
    values['token'] = word(captured['token_runtime']['proxy_address'], 20).rjust(32, b'\0')
    for key in ('cap', 'threshold', 'transferMode'):
        values[key] = int(configuration[key]).to_bytes(32, 'big')
    runtime = bytearray.fromhex(build['runtimeTemplate'][2:])
    require(set(build['immutables']) == set(values), 'immutable build coverage mismatch')
    for key, references in build['immutables'].items():
        for location in references:
            start, length = location['start'], location['length']
            require(length == 32 and runtime[start:start + length] == bytes(32), 'invalid immutable template')
            runtime[start:start + length] = values[key]
    require(bytes(runtime) == word(captured['vault_runtime']['code'], len(runtime)), 'compiled vault runtime mismatch')
    head = b''.join(values[key] for key in ('sourceDomain', 'nativeDomain', 'nativeAsset', 'token', 'cap', 'transferMode'))
    args = head + (256).to_bytes(32, 'big') + values['threshold'] + (5).to_bytes(32, 'big')
    args += b''.join(word(s, 20).rjust(32, b'\0') for s in configuration['signers'])
    creation = bytes.fromhex(build['creationBytecode'][2:]) + args
    require(captured['transaction']['input'] == '0x' + creation.hex(), 'compiled constructor arguments mismatch')


def _context(manifest, captures, ancestry, inclusion, state):
    manifest, captures, ancestry, inclusion, state = map(_bounded_copy, (manifest, captures, ancestry, inclusion, state))
    _, comparison, state, native = state_request(manifest, captures, ancestry, inclusion, state)
    captured = captures[0]['evidence']
    build_bytes = BUILD_PATH.read_bytes()
    require(len(build_bytes) <= MAX_JSON, 'build artifact bound')
    build_hash = '0x' + hashlib.sha256(build_bytes).hexdigest()
    require(manifest['source']['vault_build_sha256'] == build_hash, 'manifest must pin this exact compiler artifact')
    build = json.loads(build_bytes)
    require(build['sourceSha256'] == '0x' + hashlib.sha256((ROOT / 'contracts/usdt/USDTSourceVault.sol').read_bytes()).hexdigest(),
            'vault source/build drift')
    configuration = {
        'sourceDomain': manifest['source']['source_domain'], 'nativeDomain': manifest['native']['domain'],
        'nativeAsset': manifest['native']['asset_id'], 'cap': str(manifest['cap']['base_units']),
        'threshold': manifest['custody']['threshold'], 'transferMode': manifest['source']['transfer_mode'],
        'signers': [c['ethereum_signer'] for c in manifest['custody']['custodians']],
    }
    slots = expected_slots(configuration)
    _compiled_configuration(configuration, captured, build)
    bindings = {key: value for key, value in state.items() if key.endswith('CanonicalSha256')}
    bindings.update(schema=SCHEMA, stateEvidenceCanonicalSha256=canonical_sha256(state), buildArtifactSha256=build_hash)
    return manifest, captured, comparison, native, configuration, slots, bindings


def _storage(proofs, slots):
    require(type(proofs) is list and len(proofs) == len(slots), 'complete fixed storage proof set required')
    for proof, (key, value) in zip(proofs, slots):
        require(type(proof) is dict and set(proof) == {'key', 'value', 'proof'}
                and proof['key'] == key and proof['value'] == value, 'storage slot/value mismatch')
        nodes = proof['proof']
        require(type(nodes) is list and len(nodes) <= 65, 'storage proof node bound')
        for node in nodes:
            require(type(node) is str and 4 <= len(node) <= 2050 and len(node) % 2 == 0
                    and re.fullmatch(r'0x[0-9a-f]+', node), 'canonical bounded storage proof node required')


def _request(manifest, captures, ancestry, inclusion, state, vault):
    vault = _bounded_copy(vault)
    _, _, comparison, native, configuration, slots, bindings = _context(manifest, captures, ancestry, inclusion, state)
    require(type(vault) is dict and set(vault) == {*bindings, 'storageProof'}
            and all(vault[key] == value for key, value in bindings.items()), 'vault proof evidence binding mismatch')
    _storage(vault['storageProof'], slots)
    value = {'schema': 'postern.custody-deployment-vault-request.v1', 'state': native,
             'buildArtifactSha256': bindings['buildArtifactSha256'], 'configuration': configuration,
             'storageProof': vault['storageProof']}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    require(len(DOMAIN) + len(raw) <= MAX_JSON, 'vault request exceeds bound')
    return DOMAIN + raw, comparison, value, vault


def collect_custody_deployment_vault(manifest, captures, ancestry, inclusion, state, source):
    manifest, captured, _, native, _, slots, bindings = _context(manifest, captures, ancestry, inclusion, state)
    expected_block = captured['source_evidence']['canonical_block']
    genesis_hash = word(manifest['source']['genesis_hash'], 32)
    def recheck():
        require(quantity(source.eth('eth_chainId', [])) == 1, 'wrong source chain')
        genesis = _bounded_copy(source.eth('eth_getBlockByNumber', ['0x0', False]))
        require(type(genesis) is dict and quantity(genesis.get('number')) == 0
                and word(genesis.get('hash'), 32) == genesis_hash, 'wrong source genesis')
        require(_bounded_copy(source.eth('eth_getBlockByNumber', [expected_block['number'], False])) == expected_block,
                'captured deployment block changed')
    recheck()
    response = _bounded_copy(source.eth('eth_getProof', [captured['vault_runtime']['address'], [key for key, _ in slots],
                                                       {'blockHash': expected_block['hash'], 'requireCanonical': True}]))
    prior = native['contracts'][0]['proof']
    require(type(response) is dict and set(response) == set(prior)
            and all(response[key] == value for key, value in prior.items() if key != 'storageProof'),
            'vault account proof changed')
    _storage(response['storageProof'], slots)
    recheck()
    return _bounded_copy({**bindings, 'storageProof': response['storageProof']})


def verify_custody_deployment_vault(manifest, captures, ancestry, inclusion, state, vault, *, executable, expected_verifier_sha256):
    request, comparison, native, vault = _request(manifest, captures, ancestry, inclusion, state, vault)
    pin = word(expected_verifier_sha256, 32)
    require(any(pin) and expected_verifier_sha256 == '0x' + pin.hex(), 'canonical verifier pin required')
    temporary = None
    try:
        temporary, staged, actual = _stage_verifier(executable)
        require(actual == pin, 'vault verifier checksum mismatch')
        result = run_verifier([str(staged)], input=request, timeout=10, max_input_bytes=MAX_JSON)
        commitment = hashlib.sha256(request).hexdigest()
        require(result.returncode == 0 and result.stdout == (commitment + '\n').encode('ascii'), 'vault verifier refused')
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('vault verifier unavailable') from exc
    finally:
        if temporary is not None:
            temporary.cleanup()
    return {
        'schema': 'postern.custody-deployment-vault-verification.v1',
        **{key: value for key, value in vault.items() if key.endswith('CanonicalSha256') or key == 'buildArtifactSha256'},
        'vaultEvidenceCanonicalSha256': canonical_sha256(vault), 'verifierRequestSha256': '0x' + commitment,
        'callerSuppliedVerifierSha256': expected_verifier_sha256,
        'blockNumber': comparison['blockNumber'], 'blockHash': comparison['blockHash'],
        'vaultAddress': native['state']['contracts'][0]['address'], 'storageProofCount': len(native['storageProof']),
        'captureComparisonRevalidated': True, 'rawHeaderAncestryVerified': True, 'capturedHeaderRootsVerified': True,
        'transactionInclusionVerified': True, 'receiptInclusionVerified': True, 'creationSignatureVerified': True,
        'creationInputVerified': True, 'createAddressDerived': True, 'accountProofsVerified': True,
        'runtimeCodeStateProofsVerified': True, 'proxyImplementationStorageVerified': True,
        'vaultCompiledRuntimeVerified': True, 'vaultConstructorArgumentsVerified': True,
        'vaultImmutableConfigurationVerified': True, 'vaultControlsStorageVerified': True,
        'vaultInternalAccountingZeroVerified': True, 'vaultReentrancyGuardClearVerified': True,
        'vaultSignerArrayVerified': True, 'configuredSignerMembershipsVerified': True,
        'completeSignerMappingVerified': False, 'tokenBalanceStorageVerified': False, 'capturedStateProofsVerified': False,
        'runtimeExecutionReplayed': False, 'anchorAuthenticationVerified': False, 'verifierIdentityAuthenticated': False,
        'consensusRulesVerified': False, 'completeBlockContentsVerified': False, **NON_AUTHORIZING,
    }
