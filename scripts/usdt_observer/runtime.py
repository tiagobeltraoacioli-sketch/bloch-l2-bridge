"""Block-bound Ethereum vault bytecode consistency, never deployment proof."""
import hashlib

from .common import integer, quantity, require, word
from .ethereum import validate
from .vault_state import collect_configuration, validate_configuration
from .reserves import collect_reserves, validate_reserves

MAX_CODE = 65536


def _validate_code(route, evidence, runtime):
    # Validate all receipt, finality and route bindings before using block fields.
    validate(route, evidence)
    require(type(runtime) is dict and set(runtime) == {'block_hash', 'block_number', 'address', 'code'},
            'explicit vault runtime evidence required')
    receipt = evidence['receipt']
    require(word(runtime['block_hash'], 32) == word(receipt['blockHash'], 32)
            and quantity(runtime['block_number']) == quantity(receipt['blockNumber']),
            'vault runtime is from another block')
    require(word(runtime['address'], 20) == word(route['vault_vm_hex'], 20),
            'vault runtime is for another address')
    require(integer(route['vault_deployment_height']) <= quantity(receipt['blockNumber']),
            'deposit precedes configured deployment')
    code = runtime['code']
    require(type(code) is str and 6 <= len(code) <= 2 + 2 * MAX_CODE,
            'empty or oversized vault runtime')
    code = word(code, (len(code) - 2) // 2)
    digest = hashlib.sha256(code).digest()
    require(digest == word(route['vault_runtime_sha256'], 32), 'vault runtime mismatch')
    return {'validation': 'source-rpc-bytecode-consistency-only',
            'vault_runtime_matched': True, 'runtime_sha256': '0x' + digest.hex(),
            'block_hash': '0x' + word(receipt['blockHash'], 32).hex(),
            'block_number': str(quantity(receipt['blockNumber'])),
            'deployment_verified': False, 'mint_authorized': False}


def validate_runtime(route, evidence, runtime):
    require(type(runtime) is dict and set(runtime) == {
        'block_hash', 'block_number', 'address', 'code', 'configuration', 'reserves'},
        'vault configuration evidence required')
    report = _validate_code(route, evidence, {
        k: v for k, v in runtime.items() if k not in ('configuration', 'reserves')})
    validate_configuration(route, runtime['configuration'])
    report['validation'] = 'source-rpc-vault-consistency-only'
    report['vault_configuration_matched'] = True
    report['reserves'] = validate_reserves(route, runtime['reserves'])
    return report


def collect_runtime(route, evidence, source):
    validate(route, evidence)
    receipt = evidence['receipt']
    block = '0x' + word(receipt['blockHash'], 32).hex()
    height = hex(quantity(receipt['blockNumber']))
    # EIP-1898 refuses a noncanonical block. Never retry with latest or a height.
    code = source.eth('eth_getCode', [route['vault_vm_hex'],
                                     {'blockHash': block, 'requireCanonical': True}])
    runtime = {'block_hash': block, 'block_number': height,
               'address': route['vault_vm_hex'], 'code': code}
    _validate_code(route, evidence, runtime)
    runtime['configuration'] = collect_configuration(route, block, source)
    runtime['reserves'] = collect_reserves(route, block, source)
    validate_runtime(route, evidence, runtime)
    canonical = source.eth('eth_getBlockByNumber', [height, False])
    require(type(canonical) is dict and canonical == evidence['canonical_block'],
            'canonical block changed during runtime collection')
    return runtime
