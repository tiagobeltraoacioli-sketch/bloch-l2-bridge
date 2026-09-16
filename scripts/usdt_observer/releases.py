"""Match source payout observations to a supplied native release, never settle it."""
import hashlib

from .common import (TRANSFER_TOPIC, UINT64_MAX, abi_uint, integer, padded_address,
                     require, route_digest, validate_logs, word)
from .ethereum import validate_events

RELEASE_TOPIC = bytes.fromhex('efc74236f44fee676210517e8c459916af27488f41cc5bcb7973c09a425a4e1a')


def release_digest(route, nonce, recipient, amount, burn):
    return hashlib.sha256(b'BLOCH-USDT-RELEASE-v1'.ljust(32, b'\0') + route
                          + abi_uint(nonce) + recipient.rjust(32, b'\0')
                          + abi_uint(amount) + burn).digest()


def decode_releases(route, logs):
    validate_logs(logs)
    identity = route_digest(route)
    token, vault = word(route['token_vm_hex'], 20), word(route['vault_vm_hex'], 20)
    observations, nonces, burns = [], set(), set()
    start = 0
    for position, log in enumerate(logs):
        if log['address'] != vault or not log['topics'] or log['topics'][0] != RELEASE_TOPIC:
            continue
        topics, data = log['topics'], log['data']
        require(len(topics) == 3 and len(data) == 128 and topics[2] == identity,
                'invalid release event or route')
        nonce = integer(int.from_bytes(data[:32], 'big'))
        recipient = padded_address(data[32:64])
        amount = integer(int.from_bytes(data[64:96], 'big'))
        burn = data[96:]
        require(nonce < UINT64_MAX and nonce not in nonces and burn not in burns,
                'invalid or repeated release identity')
        require(any(recipient) and recipient not in (vault, token) and any(burn)
                and 0 < amount <= route['cap'], 'invalid release destination or amount')
        digest = release_digest(identity, nonce, recipient, amount, burn)
        require(topics[1] == digest, 'release digest mismatch')
        candidates = []
        for prior in logs[start:position]:
            if prior['address'] != token or not prior['topics'] or prior['topics'][0] != TRANSFER_TOPIC:
                continue
            require(len(prior['topics']) == 3 and len(prior['data']) == 32,
                    'noncanonical payout transfer')
            sender, destination = padded_address(prior['topics'][1]), padded_address(prior['topics'][2])
            if sender == vault and destination == recipient and int.from_bytes(prior['data'], 'big') == amount:
                candidates.append(prior['log_index'])
        require(len(candidates) == 1, 'release lacks one unambiguous preceding token payout')
        observations.append({'route_id': '0x' + identity.hex(), 'release_id': '0x' + digest.hex(),
                             'nonce': nonce, 'recipient': '0x' + recipient.hex(), 'amount': amount,
                             'native_burn': '0x' + burn.hex(), 'log_index': log['log_index'],
                             'transfer_log_index': candidates[0]})
        nonces.add(nonce)
        burns.add(burn)
        start = position + 1
    return observations


def match_release(route, evidence, expected):
    require(type(expected) is dict and set(expected) == {
        'native_domain', 'native_asset', 'route_id', 'nonce', 'recipient', 'amount', 'native_burn'},
        'exact native release fields required')
    for field in ['native_domain', 'native_asset', 'route_id']:
        require(word(expected[field], 32) == word(route[field], 32), 'native release context mismatch')
    # Public native u64 fields must be canonical decimal strings, never floats.
    def decimal(value):
        require(type(value) is str and 1 <= len(value) <= 20 and value.isascii()
                and value.isdecimal() and (value == '0' or value[0] != '0'), 'invalid release integer')
        return integer(int(value))
    nonce, amount = decimal(expected['nonce']), decimal(expected['amount'])
    recipient, burn = word(expected['recipient'], 20), word(expected['native_burn'], 32)
    observations = validate_events(route, evidence, decode_releases)
    matched = [o for o in observations if o['nonce'] == nonce and o['amount'] == amount
               and word(o['recipient'], 20) == recipient and word(o['native_burn'], 32) == burn]
    require(len(matched) == 1, 'no unique payout matching native release')
    result = dict(matched[0])
    for key in ['nonce', 'amount', 'block_number']:
        result[key] = str(result[key])
    return {'validation': 'source-rpc-release-consistency-only', 'release_observation_matched': True,
            'observation': result, 'native_release_authenticated': False,
            'finality_verified': False, 'redemption_settled': False, 'mint_authorized': False,
            'bridge_ready': False}
