"""Strict ABI readback of configured Ethereum vault identities at one block.

Selectors are Keccak-256 prefixes, independently reproducible with `cast sig`.
An RPC readback does not prove consensus, backing, or deployment authenticity.
"""
from .common import abi_uint, require, word

SELECTORS = {
    'sourceDomain': '8ddb4a89', 'nativeDomain': '7e839aca', 'nativeAsset': '74d32ad4',
    'token': 'fc0c546a', 'decimals': '313ce567', 'cap': '355274ea',
    'threshold': '42cde4e8', 'transferMode': '6b3b64a1', 'routeId': '7360fd1e',
    'signerCount': '7ca548c6',
}
CONTROL_SELECTORS = {
    'controlNonce': '4faac8ca',
    'depositsEnabled': '5392fd1c',
    'releasesEnabled': '175b818c',
}
SIGNERS = '2079fb9a'
IS_SIGNER = '7df73e27'


def expected_words(route):
    signers = route['committee_signers']
    require(type(signers) is tuple and 2 <= len(signers) <= 16,
            'bounded configured committee required')
    addresses = [word(s, 20) for s in signers]
    require(addresses == sorted(set(addresses)) and all(any(s) for s in addresses),
            'invalid configured committee')
    require(type(route['committee_threshold']) is int
            and 2 <= route['committee_threshold'] <= len(signers), 'invalid threshold')
    return {
        'sourceDomain': word(route['source_domain'], 32),
        'nativeDomain': word(route['native_domain'], 32),
        'nativeAsset': word(route['native_asset'], 32),
        'token': word(route['token_vm_hex'], 20).rjust(32, b'\0'),
        'decimals': abi_uint(6), 'cap': abi_uint(route['cap']),
        'threshold': abi_uint(route['committee_threshold']),
        'transferMode': abi_uint(route['transfer_mode']),
        'routeId': word(route['route_id'], 32), 'signerCount': abi_uint(len(signers)),
    }


def validate_configuration(route, configuration):
    expected = expected_words(route)
    require(type(configuration) is dict
            and set(configuration) == set(expected) | {'signers', 'memberships', 'controls'},
            'exact vault configuration evidence required')
    for name, value in expected.items():
        require(word(configuration[name], 32) == value, 'vault configuration mismatch')
    signers, memberships = configuration['signers'], configuration['memberships']
    count = len(route['committee_signers'])
    require(type(signers) is list and type(memberships) is list
            and len(signers) == count and len(memberships) == count,
            'complete configured committee required')
    for configured, signer, member in zip(route['committee_signers'], signers, memberships):
        require(word(signer, 32) == word(configured, 20).rjust(32, b'\0'),
                'vault committee mismatch')
        require(word(member, 32) == abi_uint(1), 'vault signer membership mismatch')
    controls = configuration['controls']
    require(type(controls) is dict and set(controls) == set(CONTROL_SELECTORS),
            'exact vault controls required')
    nonce = int.from_bytes(word(controls['controlNonce'], 32), 'big')
    require(nonce <= (1 << 64) - 1, 'invalid vault control nonce')
    for name in ('depositsEnabled', 'releasesEnabled'):
        require(word(controls[name], 32) in (abi_uint(0), abi_uint(1)),
                'invalid vault control flag')


def collect_configuration(route, block_hash, source):
    expected = expected_words(route)
    block = '0x' + word(block_hash, 32).hex()

    def call(data):
        return source.eth('eth_call', [
            {'to': route['vault_vm_hex'], 'data': '0x' + data, 'gas': '0x186a0'},
            {'blockHash': block, 'requireCanonical': True}])

    result = {}
    for name, selector in SELECTORS.items():
        value = call(selector)
        require(word(value, 32) == expected[name], 'vault configuration mismatch')
        result[name] = value
    result['controls'] = {}
    for name, selector in CONTROL_SELECTORS.items():
        result['controls'][name] = call(selector)
    # Bound requests using the validated manifest, never an RPC-supplied count.
    result['signers'], result['memberships'] = [], []
    for index, signer in enumerate(route['committee_signers']):
        address = word(signer, 20).rjust(32, b'\0')
        actual = call(SIGNERS + abi_uint(index).hex())
        require(word(actual, 32) == address, 'vault committee mismatch')
        membership = call(IS_SIGNER + address.hex())
        require(word(membership, 32) == abi_uint(1), 'vault signer membership mismatch')
        result['signers'].append(actual)
        result['memberships'].append(membership)
    validate_configuration(route, result)
    return result
