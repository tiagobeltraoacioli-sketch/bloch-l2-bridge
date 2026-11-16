#!/usr/bin/env python3
"""TRON wire layer for the bUSDT.trx bridge tools: addresses, the java-tron HTTP API, and transactions built and
checked locally.

Nothing here decides anything about the bridge. It exists because TRON differs from Ethereum in three places the
Ethereum tools cannot reach through JSON-RPC:

  addresses     21 bytes (0x41 + the 20-byte VM address) at the API boundary, Base58Check `T...` for people; inside
                the TVM, in ABI words, in event topics and in `ecrecover` results they are the same 20 bytes as on
                Ethereum. Every bridge id and digest uses the 20-byte form.
  finality      a block is final when it is "solidified" (confirmed by more than 70% of the 27 block producers).
                `/walletsolidity/*` answers from the latest solidified block only; `/wallet/*` answers from the head.
  transactions  protobuf, no account nonce: a transaction names a recent block (`ref_block`) and an expiration, and
                its id is sha256 of its `raw_data`. A node will build one for you (`/wallet/triggersmartcontract`),
                but a key must never sign bytes a node chose: `build_trigger` encodes `raw_data` here, so the only
                thing taken from the node is the reference block.

Only the standard library plus `cast` (keccak, ABI encoding, signing), as the other tools.
"""
import hashlib
import json
import subprocess
import time
import urllib.request
from pathlib import Path

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TRIGGER_URL = 'type.googleapis.com/protocol.TriggerSmartContract'
CREATE_URL = 'type.googleapis.com/protocol.CreateSmartContract'
TYPE_CREATE, TYPE_TRIGGER = 30, 31
MAX_EXPIRATION_MS = 24 * 3600 * 1000  # java-tron refuses an expiration further than this from the head


class TronError(RuntimeError):
    pass


# ── addresses ───────────────────────────────────────────────────────────────
def b58check_decode(text):
    """`T...` -> the 21 payload bytes. Refuses a bad alphabet, length, checksum or prefix."""
    if not isinstance(text, str) or not 30 <= len(text) <= 36 or any(c not in B58 for c in text):
        raise TronError(f'not a Base58 TRON address: {text!r}')
    n = 0
    for c in text:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(25, 'big') if n.bit_length() <= 200 else b''
    if len(raw) != 25 or hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] != raw[21:]:
        raise TronError(f'TRON address checksum failed: {text!r}')
    if raw[0] != 0x41:
        raise TronError(f'TRON address without the 0x41 prefix: {text!r}')
    return raw[:21]


def b58check_encode(payload21):
    raw = payload21 + hashlib.sha256(hashlib.sha256(payload21).digest()).digest()[:4]
    n, out = int.from_bytes(raw, 'big'), ''
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return out


def evm_address(value):
    """Any accepted form (`T...`, 41-prefixed 21-byte hex, 0x 20-byte hex) -> '0x' + 40 lowercase hex."""
    if isinstance(value, str) and value[:1] == 'T' and len(value) == 34:
        return '0x' + b58check_decode(value)[1:].hex()
    h = str(value).lower().removeprefix('0x')
    if len(h) == 42 and h[:2] == '41':
        h = h[2:]
    if len(h) != 40 or any(c not in '0123456789abcdef' for c in h):
        raise TronError(f'not a TRON or 20-byte address: {value!r}')
    return '0x' + h


def tron_hex(value):
    """-> 41-prefixed 21-byte hex, the form the HTTP API takes with `visible: false`."""
    return '41' + evm_address(value)[2:]


def base58(value):
    return b58check_encode(bytes.fromhex(tron_hex(value)))


# ── protobuf (the few shapes a contract call needs) ──────────────────────────
def _varint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7f, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(number, value):
    """bytes -> length-delimited; int -> varint. Zero ints and empty bytes are omitted, as proto3 does."""
    if isinstance(value, int):
        return _varint(number << 3) + _varint(value) if value else b''
    return _varint(number << 3 | 2) + _varint(len(value)) + value if value else b''


def pb_decode(data):
    """-> [(field number, int | bytes)] in wire order. Refuses wire types other than varint and length-delimited."""
    out, i = [], 0
    while i < len(data):
        key = shift = 0
        while True:
            b = data[i]; i += 1
            key |= (b & 0x7f) << shift; shift += 7
            if not b & 0x80:
                break
        number, wire = key >> 3, key & 7
        if wire == 0:
            v = shift = 0
            while True:
                b = data[i]; i += 1
                v |= (b & 0x7f) << shift; shift += 7
                if not b & 0x80:
                    break
            out.append((number, v))
        elif wire == 2:
            n = shift = 0
            while True:
                b = data[i]; i += 1
                n |= (b & 0x7f) << shift; shift += 7
                if not b & 0x80:
                    break
            if i + n > len(data):
                raise TronError('truncated protobuf')
            out.append((number, data[i:i + n])); i += n
        else:
            raise TronError(f'unexpected protobuf wire type {wire}')
    return out


def _raw(contract_type, type_url, message, ref_block, expiration_ms, timestamp_ms, fee_limit):
    number, block_id = ref_block
    any_ = _field(1, type_url.encode()) + _field(2, message)
    contract = _field(1, contract_type) + _field(2, any_)
    return (_field(1, (number & 0xffff).to_bytes(2, 'big')) + _field(4, bytes.fromhex(block_id)[8:16])
            + _field(8, expiration_ms) + _field(11, contract) + _field(14, timestamp_ms) + _field(18, fee_limit))


def build_trigger(owner, contract, data_hex, ref_block, expiration_ms, timestamp_ms, fee_limit):
    """raw_data of a TriggerSmartContract with no TRX and no TRC-10 value. `ref_block` = (number, block id hex)."""
    msg = (_field(1, bytes.fromhex(tron_hex(owner))) + _field(2, bytes.fromhex(tron_hex(contract)))
           + _field(4, bytes.fromhex(data_hex.removeprefix('0x'))))
    return _raw(TYPE_TRIGGER, TRIGGER_URL, msg, ref_block, expiration_ms, timestamp_ms, fee_limit)


def build_create(owner, name, abi_pb, code_hex, ref_block, expiration_ms, timestamp_ms, fee_limit,
                 origin_energy_limit, consume_user_resource_percent):
    """raw_data of a CreateSmartContract. `abi_pb` may be empty: the ABI stored on chain is only a convenience for
    wallets and explorers; the bridge tools carry their own."""
    new = (_field(1, bytes.fromhex(tron_hex(owner))) + _field(3, abi_pb)
           + _field(4, bytes.fromhex(code_hex.removeprefix('0x'))) + _field(6, consume_user_resource_percent)
           + _field(7, name.encode()) + _field(8, origin_energy_limit))
    msg = _field(1, bytes.fromhex(tron_hex(owner))) + _field(2, new)
    return _raw(TYPE_CREATE, CREATE_URL, msg, ref_block, expiration_ms, timestamp_ms, fee_limit)


def describe(raw_data):
    """Decodes a raw_data this module could have built. Anything else (a second contract, TRX or TRC-10 value, an
    unknown field) is refused, so the same function checks a transaction somebody else built before it is signed."""
    top = pb_decode(raw_data)
    if {n for n, _ in top} - {1, 4, 8, 11, 14, 18} or not {1, 4, 8, 11} <= {n for n, _ in top}:
        raise TronError('raw_data has fields a bridge transaction never carries, or lacks a required one')
    f = {}
    for n, v in top:
        if n in f:
            raise TronError('raw_data repeats a field (more than one contract?)')
        f[n] = v
    contract = dict(pb_decode(f[11]))
    any_ = dict(pb_decode(contract[2]))
    kind, url, msg = contract.get(1), any_[1].decode(), pb_decode(any_[2])
    out = {'ref_block_bytes': f[1].hex(), 'ref_block_hash': f[4].hex(), 'expiration': f.get(8, 0),
           'timestamp': f.get(14, 0), 'fee_limit': f.get(18, 0)}
    m = dict(msg)
    if len(m) != len(msg) or set(contract) - {1, 2} or set(any_) - {1, 2}:
        raise TronError('unexpected or repeated contract fields')
    if kind == TYPE_TRIGGER and url == TRIGGER_URL:
        if set(m) - {1, 2, 4}:
            raise TronError('the call carries TRX or TRC-10 value, or unknown fields')
        out.update(kind='trigger', owner='0x' + m[1][1:].hex(), contract='0x' + m[2][1:].hex(),
                   data='0x' + m.get(4, b'').hex())
    elif kind == TYPE_CREATE and url == CREATE_URL:
        new = dict(pb_decode(m[2]))
        if set(m) - {1, 2} or set(new) - {1, 3, 4, 6, 7, 8} or new[1] != m[1]:
            raise TronError('the creation carries value, a preset address or unknown fields')
        out.update(kind='create', owner='0x' + m[1][1:].hex(), code='0x' + new[4].hex(),
                   name=new.get(7, b'').decode(), consume_user_resource_percent=new.get(6, 0),
                   origin_energy_limit=new.get(8, 0))
    else:
        raise TronError(f'not a contract call or creation (type {kind}, {url})')
    return out


def txid(raw_data):
    return hashlib.sha256(raw_data).hexdigest()


# ── the node ────────────────────────────────────────────────────────────────
class Node:
    """One java-tron HTTP endpoint (FullNode API; `/walletsolidity` on the same base, as java-tron and TRE serve it,
    or on `solidity_url` when the operator runs a separate SolidityNode port)."""

    def __init__(self, url, solidity_url=None, cast=None, timeout=30):
        self.url, self.solidity_url = url.rstrip('/'), (solidity_url or url).rstrip('/')
        self.cast = cast or str(Path.home() / '.foundry/bin/cast')
        self.timeout = timeout

    def post(self, path, obj=None, solid=False):
        base = self.solidity_url if solid else self.url
        prefix = '/walletsolidity/' if solid else '/wallet/'
        req = urllib.request.Request(base + prefix + path, json.dumps(obj or {}).encode(),
                                     {'content-type': 'application/json', 'user-agent': 'bridge-tools'})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                text = r.read().decode()
        except OSError as e:
            raise TronError(f'TRON node {prefix}{path} unreachable: {e}') from e
        try:
            return json.loads(text) if text.strip() else {}
        except ValueError as e:
            raise TronError(f'TRON node {prefix}{path} answered no JSON: {text[:200]!r}') from e

    # blocks
    @staticmethod
    def _block(b):
        if not b or 'blockID' not in b:
            return None
        raw = b['block_header']['raw_data']
        number = raw.get('number', 0)
        if int(b['blockID'][:16], 16) != number:
            raise TronError('block id does not carry its own height')
        return {'number': number, 'id': b['blockID'], 'timestamp_ms': raw.get('timestamp', 0),
                'parent': raw.get('parentHash', '')}

    def head(self):
        return self._need(self._block(self.post('getnowblock')), 'head block')

    def solidified(self):
        return self._need(self._block(self.post('getnowblock', solid=True)), 'solidified block')

    def block(self, number, solid=False):
        return self._block(self.post('getblockbynum', {'num': int(number)}, solid=solid))

    @staticmethod
    def _need(value, what):
        if value is None:
            raise TronError(f'TRON node returned no {what}')
        return value

    # reads
    def call(self, contract, data_hex, solid=False, sender=None):
        """A constant call. Returns the return data as '0x...'; raises on a revert or a node-side failure."""
        out = self.post('triggerconstantcontract', {
            'owner_address': tron_hex(sender or '0x' + '00' * 20), 'contract_address': tron_hex(contract),
            'data': data_hex.removeprefix('0x'), 'visible': False}, solid=solid)
        res = out.get('result', {})
        if not res.get('result') or res.get('message') or 'constant_result' not in out:
            msg = res.get('message', '')
            try:
                msg = bytes.fromhex(msg).decode(errors='replace')
            except ValueError:
                pass
            raise TronError(f'constant call failed: {msg or res or out}')
        return '0x' + out['constant_result'][0]

    def estimate(self, owner, contract, data_hex):
        """Energy a call would use now (with the dynamic-energy penalty of the contracts it touches), or the revert."""
        out = self.post('triggerconstantcontract', {
            'owner_address': tron_hex(owner), 'contract_address': tron_hex(contract),
            'data': data_hex.removeprefix('0x'), 'visible': False})
        return {'ok': bool(out.get('result', {}).get('result')) and not out.get('result', {}).get('message'),
                'energy': out.get('energy_used', 0), 'penalty': out.get('energy_penalty', 0),
                'result': (out.get('constant_result') or [''])[0], 'message': out.get('result', {}).get('message', '')}

    def code(self, contract):
        """Runtime code and creation record of a contract, from the head state."""
        info = self.post('getcontractinfo', {'value': tron_hex(contract), 'visible': False})
        return {'runtime': '0x' + info.get('runtimecode', ''), 'record': info.get('smart_contract', {})}

    def tx_info(self, tx, solid=False):
        return self.post('gettransactioninfobyid', {'value': tx}, solid=solid) or None

    def block_infos(self, number, solid=False):
        out = self.post('gettransactioninfobyblocknum', {'num': int(number)}, solid=solid)
        return out if isinstance(out, list) else []

    # helpers through cast
    def run(self, *argv):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        if done.returncode:
            raise TronError(f'{argv[1] if len(argv) > 1 else argv[0]} failed: {done.stderr.strip()[-800:]}')
        return done.stdout.strip()

    def calldata(self, sig, *args):
        return self.run(self.cast, 'calldata', sig, *args)

    # writes
    def prepare(self, owner, contract, data_hex, fee_limit, valid_ms=60_000):
        """raw_data for a call, anchored at the SOLIDIFIED block (a transaction that names a block which is later
        dropped can never be included; one anchored at a solidified block is valid on every surviving fork)."""
        ref = self.solidified()
        now = max(self.head()['timestamp_ms'], ref['timestamp_ms'])
        if not 0 < valid_ms < MAX_EXPIRATION_MS:
            raise TronError('valid_ms out of range')
        return build_trigger(owner, contract, data_hex, (ref['number'], ref['id']), now + valid_ms,
                             int(time.time() * 1000), fee_limit)

    def sign(self, raw_data, wallet_args):
        """65-byte r||s||v over sha256(raw_data), by `cast wallet sign --no-hash` with the caller's wallet arguments
        (`--keystore F --password-file P`, or `--private-key K` for throwaway rehearsal keys only)."""
        sig = self.run(self.cast, 'wallet', 'sign', '--no-hash', *wallet_args, '0x' + txid(raw_data)).lower()
        if len(sig) != 132:
            raise TronError('signer returned a malformed signature')
        return bytes.fromhex(sig[2:])

    def broadcast(self, raw_data, signature):
        """Sends Transaction{raw_data, signature}. Returns the node's answer; `sent` is True when the node accepted it
        or already had it (DUP_TRANSACTION_ERROR): both mean 'look for it by id', never 'send another'."""
        tx = _field(1, raw_data) + _field(2, signature)
        out = self.post('broadcasthex', {'transaction': tx.hex()})
        code = out.get('code', 'SUCCESS' if out.get('result') else 'UNKNOWN')
        return {'txid': txid(raw_data), 'sent': bool(out.get('result')) or code == 'DUP_TRANSACTION_ERROR',
                'code': code, 'message': out.get('message', '')}

    def wait(self, tx, solid=True, timeout=120, poll=1.0):
        """The receipt once the transaction is in a (solidified, by default) block, else None after `timeout`."""
        end = time.time() + timeout
        while time.time() < end:
            info = self.tx_info(tx, solid=solid)
            if info and info.get('id') == tx:
                return info
            time.sleep(poll)
        return None


def receipt_ok(info):
    """True only for a contract call that executed and did not revert."""
    return bool(info) and info.get('receipt', {}).get('result') == 'SUCCESS' and info.get('result') != 'FAILED'


def energy(info):
    r = (info or {}).get('receipt', {})
    return {'energy_total': r.get('energy_usage_total', 0), 'energy_from_stake': r.get('energy_usage', 0),
            'energy_burned_sun': r.get('energy_fee', 0), 'energy_origin': r.get('origin_energy_usage', 0),
            'energy_penalty': r.get('energy_penalty_total', 0), 'bandwidth': r.get('net_usage', 0),
            'bandwidth_burned_sun': r.get('net_fee', 0), 'fee_sun': (info or {}).get('fee', 0),
            'result': r.get('result')}
