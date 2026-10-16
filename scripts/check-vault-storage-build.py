#!/usr/bin/env python3
"""Reproduce the exact compiler output embedded by the vault storage verifier."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'contracts/usdt/USDTSourceVault.sol'
ARTIFACT = ROOT / 'test-vectors/vault-storage-build/solc-0.8.24.json'
COMPILER_PINS = {
    'cc2d44c706905ccc382f484625dff61d741e0c24232d226f139a6835fc644f3f',  # official macOS amd64
    'fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f',  # CI Linux static
}
SETTINGS = {'optimizer': {'enabled': True, 'runs': 200}, 'evmVersion': 'shanghai',
            'metadata': {'bytecodeHash': 'none'}, 'viaIR': False}


def compile_artifact(executable):
    compiler = Path(executable).resolve(strict=True)
    assert hashlib.sha256(compiler.read_bytes()).hexdigest() in COMPILER_PINS, 'unreviewed compiler bytes'
    version = subprocess.check_output([str(compiler), '--version'], text=True, timeout=10)
    assert '0.8.24+commit.e11b9ed9' in version, 'wrong compiler version'
    source = (ROOT / SOURCE).read_bytes()
    request = {'language': 'Solidity', 'sources': {SOURCE: {'content': source.decode()}}, 'settings': {
        **SETTINGS, 'outputSelection': {'*': {'': ['ast'], '*': ['storageLayout', 'evm.bytecode', 'evm.deployedBytecode']}},
    }}
    result = subprocess.run([str(compiler), '--standard-json'], input=json.dumps(request).encode(),
                            capture_output=True, timeout=45, check=True)
    output = json.loads(result.stdout)
    assert not any(e['severity'] == 'error' for e in output.get('errors', [])), 'compilation refused'
    contract = output['contracts'][SOURCE]['USDTSourceVault']
    ast = next(n for n in output['sources'][SOURCE]['ast']['nodes'] if n['nodeType'] == 'ContractDefinition')
    names = {str(n['id']): n['name'] for n in ast['nodes'] if n['nodeType'] == 'VariableDeclaration'}
    bytecode, runtime = contract['evm']['bytecode'], contract['evm']['deployedBytecode']
    assert bytecode['linkReferences'] == {} and runtime['linkReferences'] == {}
    immutables = {names[key]: value for key, value in runtime['immutableReferences'].items()}
    assert set(immutables) == {'sourceDomain', 'nativeDomain', 'nativeAsset', 'token', 'cap', 'threshold', 'transferMode'}
    positions = [(v['label'], v['slot'], v['offset'], v['type']) for v in contract['storageLayout']['storage']]
    assert positions == [
        ('signers', '0', 0, 't_array(t_address)dyn_storage'), ('isSigner', '1', 0, 't_mapping(t_address,t_bool)'),
        ('depositCount', '2', 0, 't_uint64'), ('totalLocked', '2', 8, 't_uint64'),
        ('controlNonce', '2', 16, 't_uint64'), ('depositsEnabled', '2', 24, 't_bool'),
        ('releasesEnabled', '2', 25, 't_bool'), ('releasedNonce', '3', 0, 't_mapping(t_uint64,t_bool)'),
        ('releasedBurn', '4', 0, 't_mapping(t_bytes32,t_bool)'), ('entered', '5', 0, 't_bool'),
    ], 'vault layout differs from the fixed verifier'
    used = set()
    for references in immutables.values():
        for location in references:
            assert location['length'] == 32
            slots = set(range(location['start'], location['start'] + 32))
            assert not used.intersection(slots)
            used.update(slots)
    return {'schema': 'postern.vault-storage-build.v1', 'sourcePath': SOURCE,
            'sourceSha256': '0x' + hashlib.sha256(source).hexdigest(), 'compilerVersion': '0.8.24+commit.e11b9ed9',
            'settings': SETTINGS, 'creationBytecode': '0x' + bytecode['object'],
            'runtimeTemplate': '0x' + runtime['object'], 'immutables': immutables,
            'storageLayout': contract['storageLayout']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--solc', required=True)
    parser.add_argument('--create', action='store_true', help='create the absent pinned artifact after source review')
    args = parser.parse_args()
    value = compile_artifact(args.solc)
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if args.create:
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        with ARTIFACT.open('xb') as stream:
            stream.write(data)
    else:
        assert ARTIFACT.read_bytes() == data, 'committed compiler artifact drift'
    print(json.dumps({'artifact': str(ARTIFACT.relative_to(ROOT)), 'sha256': '0x' + hashlib.sha256(data).hexdigest(),
                      'runtimeBytes': (len(value['runtimeTemplate']) - 2) // 2, 'buildReproduced': True}))


if __name__ == '__main__':
    main()
