"""Bounded decoding shared by the distinct Ethereum and TRON observers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

MAX_JSON = 1024 * 1024
MAX_LOGS = 4096
MAX_LOG_DATA = 65536
UINT64_MAX = (1 << 64) - 1
# Keccak-256 of the exact reviewed Solidity event signatures, not SHA3-256.
DEPOSIT_TOPIC = bytes.fromhex('86f22d28da637559602e716d294d9c661cb8177451cfdf19c194c0c79503c174')
TRANSFER_TOPIC = bytes.fromhex('ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef')


class Invalid(ValueError):
    """A stable local refusal; never include untrusted response text."""


def require(condition, message='invalid source evidence'):
    if not condition:
        raise Invalid(message)


def word(value, size, prefix=True):
    require(type(size) is int and 0 <= size <= MAX_LOG_DATA, 'invalid hex bound')
    start = '0x' if prefix else ''
    require(type(value) is str and re.fullmatch(start + r'[0-9a-fA-F]{%d}' % (size * 2), value),
            'invalid fixed-length hex')
    return bytes.fromhex(value[len(start):])


def integer(value):
    require(type(value) is int and 0 <= value <= UINT64_MAX, 'invalid uint64')
    return value


def quantity(value):
    require(type(value) is str and len(value) <= 18
            and re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', value),
            'invalid RPC quantity')
    return integer(int(value[2:], 16))


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def parse_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_JSON, 'JSON evidence exceeds limit')
    try:
        return json.loads(raw, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite JSON')))
    except (ValueError, UnicodeError, RecursionError):
        raise Invalid('invalid JSON evidence') from None


def load_json(path):
    with Path(path).open('rb') as stream:
        return parse_json(stream.read(MAX_JSON + 1))


def normalized_route(manifest, network, allow_synthetic=False, *, source_asset="USDT"):
    """Reuse the cap/deployment validator with an explicit source-token policy.

    The default retains the legacy two-route USDT manifest requirement.
    """
    path = Path(__file__).resolve().parents[1] / 'validate-usdt-routes.py'
    spec = importlib.util.spec_from_file_location('usdt_route_manifest', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        checked = module.validate(manifest, allow_synthetic=allow_synthetic, source_asset=source_asset)
    except (ValueError, TypeError, KeyError):
        raise Invalid('route manifest rejected') from None
    # The existing validator's result is configuration consistency, not deployment proof.
    route = next((r for r in manifest['routes'] if r['network'] == network), None)
    require(route is not None, 'route network not configured')
    output = next(r for r in checked['routes'] if r['network'] == network)
    return {**output, 'genesis_hash': route['genesis_hash'].lower(),
            'source_domain': route['source_domain'].lower(),
            'native_domain': manifest['native_domain'].lower(),
            'native_asset': manifest['native_asset'].lower(), 'cap': route['cap']}


def abi_uint(value):
    return integer(value).to_bytes(32, 'big')


def route_digest(route):
    cap = integer(route['cap'])
    require(cap > 0, 'zero route capacity')
    source = word(route['source_domain'], 32)
    native = word(route['native_domain'], 32)
    asset = word(route['native_asset'], 32)
    token = word(route['token_vm_hex'], 20)
    vault = word(route['vault_vm_hex'], 20)
    require(all(any(value) for value in (source, native, asset, token, vault))
            and source != native and token != vault, 'invalid route identities')
    digest = hashlib.sha256(b'BLOCH-USDT-ROUTE-v1'.ljust(32, b'\0') + source + native + asset
                            + token.rjust(32, b'\0') + vault.rjust(32, b'\0')
                            + abi_uint(6) + abi_uint(cap)).digest()
    require(digest == word(route['route_id'], 32), 'route ID mismatch')
    return digest


def deposit_digest(route_id, nonce, sender, amount, recipient):
    require(type(route_id) is bytes and len(route_id) == 32
            and type(sender) is bytes and len(sender) == 20
            and type(recipient) is bytes and len(recipient) == 32, 'invalid deposit fields')
    return hashlib.sha256(b'BLOCH-USDT-DEPOSIT-v1'.ljust(32, b'\0') + route_id
                          + abi_uint(nonce) + sender.rjust(32, b'\0')
                          + abi_uint(amount) + recipient).digest()


def padded_address(value):
    require(type(value) is bytes and len(value) == 32 and value[:12] == bytes(12),
            'noncanonical ABI address')
    return value[12:]


def decode_deposits(route, logs):
    """Bind each vault event to one preceding exact token transfer.

    The matching interval begins after the previous deposit from this vault.
    Ambiguous transfers, reused transfers, duplicate deposit IDs/nonces and
    malformed events fail the entire receipt. Unrelated emitters are ignored.
    Logs are observations, not storage proofs or token/vault code authentication.
    """
    route_id = route_digest(route)
    token = word(route['token_vm_hex'], 20)
    vault = word(route['vault_vm_hex'], 20)
    require(type(logs) is list and len(logs) <= MAX_LOGS, 'too many receipt logs')
    last_index = -1
    total_bytes = 0
    for log in logs:
        require(type(log) is dict and set(log) == {'address', 'topics', 'data', 'log_index'},
                'invalid normalized log')
        require(type(log['address']) is bytes and len(log['address']) == 20
                and type(log['topics']) is list and len(log['topics']) <= 4
                and all(type(t) is bytes and len(t) == 32 for t in log['topics'])
                and type(log['data']) is bytes and len(log['data']) <= MAX_LOG_DATA,
                'invalid normalized log bytes')
        index = integer(log['log_index'])
        require(index <= (1 << 32) - 1 and index > last_index, 'duplicate or unordered log index')
        require(last_index == -1 or index == last_index + 1, 'receipt log indices contain a gap')
        last_index = index
        total_bytes += len(log['data']) + 32 * len(log['topics']) + 20
    require(total_bytes <= MAX_JSON, 'receipt logs exceed total limit')
    observations, seen_ids, seen_nonces = [], set(), set()
    interval_start = 0
    for position, log in enumerate(logs):
        if log['address'] != vault or not log['topics'] or log['topics'][0] != DEPOSIT_TOPIC:
            continue
        topics, data = log['topics'], log['data']
        require(len(topics) == 3 and len(data) == 128, 'noncanonical deposit event')
        require(topics[2] == route_id, 'deposit names another route')
        nonce = integer(int.from_bytes(data[:32], 'big'))
        sender = padded_address(data[32:64])
        amount = integer(int.from_bytes(data[64:96], 'big'))
        recipient = data[96:128]
        require(any(sender) and sender != vault and any(recipient) and 0 < amount <= route['cap'],
                'invalid deposit amount or owner')
        require(nonce < UINT64_MAX and (not observations or nonce == observations[-1]['nonce'] + 1),
                'impossible deposit counter sequence')
        expected = deposit_digest(route_id, nonce, sender, amount, recipient)
        require(topics[1] == expected and expected not in seen_ids and nonce not in seen_nonces,
                'invalid or duplicate deposit identity')
        candidates = []
        for prior in logs[interval_start:position]:
            if prior['address'] != token or not prior['topics'] or prior['topics'][0] != TRANSFER_TOPIC:
                continue
            require(len(prior['topics']) == 3 and len(prior['data']) == 32, 'noncanonical token transfer')
            source, destination = padded_address(prior['topics'][1]), padded_address(prior['topics'][2])
            if source == sender and destination == vault and int.from_bytes(prior['data'], 'big') == amount:
                candidates.append(prior['log_index'])
        require(len(candidates) == 1, 'deposit lacks one unambiguous preceding source-token transfer')
        observations.append({'route_id': '0x' + route_id.hex(), 'deposit_id': '0x' + expected.hex(),
                             'source_domain': route['source_domain'], 'nonce': nonce,
                             'sender': '0x' + sender.hex(), 'amount': amount,
                             'pq_recipient_hash': '0x' + recipient.hex(), 'log_index': log['log_index'],
                             'transfer_log_index': candidates[0]})
        seen_ids.add(expected)
        seen_nonces.add(nonce)
        interval_start = position + 1
    return observations
