"""Bounded Bitcoin transaction decoding; not consensus or inclusion validation."""
from dataclasses import dataclass
from hashlib import sha256

MAX_RAW_BYTES = 4_000_000
MAX_ITEMS = 100_000
MAX_SCRIPT_BYTES = 10_000  # Observer policy, not a general consensus claim.
MAX_MONEY = 21_000_000 * 100_000_000
NETWORKS = frozenset(('bitcoin-mainnet', 'bitcoin-testnet4', 'bitcoin-signet', 'bitcoin-regtest'))


class Invalid(ValueError):
    pass


class Reader:
    def __init__(self, raw):
        self.raw = raw
        self.offset = 0

    def take(self, size):
        if size < 0 or size > len(self.raw) - self.offset:
            raise Invalid('Truncated transaction')
        start = self.offset
        self.offset += size
        return self.raw[start:self.offset]

    def integer(self, size):
        return int.from_bytes(self.take(size), 'little')

    def compact(self, limit):
        first = self.integer(1)
        if first < 253:
            value = first
        else:
            width, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 4294967296)}[first]
            value = self.integer(width)
            if value < minimum:
                raise Invalid('Noncanonical CompactSize')
        if value > limit:
            raise Invalid('Observer resource limit')
        return value


def digest(raw):
    return sha256(sha256(raw).digest()).digest()[::-1].hex()


@dataclass(frozen=True)
class Output:
    satoshis: int
    script_pubkey: bytes


@dataclass(frozen=True)
class Transaction:
    txid: str
    wtxid: str
    outputs: tuple
    coinbase: bool
    weight: int


def decode(raw):
    if type(raw) is not bytes or not 10 <= len(raw) <= MAX_RAW_BYTES:
        raise Invalid('Invalid transaction byte size/type')
    reader = Reader(raw)
    version = reader.take(4)
    segwit = raw[4] == 0
    if segwit and reader.take(2) != b'\x00\x01':
        raise Invalid('Unsupported witness marker/flag')
    base_start = reader.offset
    count = reader.compact(MAX_ITEMS)
    if not count:
        raise Invalid('No transaction inputs')
    seen = set()
    null_prevouts = 0
    for _ in range(count):
        prevout = reader.take(36)
        if prevout in seen:
            raise Invalid('Duplicate input')
        seen.add(prevout)
        null_prevouts += prevout == bytes(32) + b'\xff' * 4
        reader.take(reader.compact(MAX_SCRIPT_BYTES))
        reader.take(4)
    if null_prevouts and count != 1:
        raise Invalid('Null prevout in non-coinbase transaction')
    output_count = reader.compact(MAX_ITEMS)
    if not output_count:
        raise Invalid('No transaction outputs')
    outputs = []
    total = 0
    for _ in range(output_count):
        amount = reader.integer(8)
        total += amount
        if amount > MAX_MONEY or total > MAX_MONEY:
            raise Invalid('Output money range')
        outputs.append(Output(amount, reader.take(reader.compact(MAX_SCRIPT_BYTES))))
    base_end = reader.offset
    if segwit:
        has_witness = False
        for _ in range(count):
            items = reader.compact(MAX_ITEMS)
            has_witness |= items > 0
            for _ in range(items):
                reader.take(reader.compact(MAX_RAW_BYTES))
        if not has_witness:
            raise Invalid('Superfluous witness encoding')
    locktime = reader.take(4)
    if reader.offset != len(raw):
        raise Invalid('Trailing transaction bytes')
    stripped = version + raw[base_start:base_end] + locktime
    weight = 3 * len(stripped) + len(raw)
    if weight > MAX_RAW_BYTES:
        raise Invalid('Transaction weight limit')
    return Transaction(digest(stripped), digest(raw), tuple(outputs), bool(null_prevouts), weight)


def inspect_deposit(raw, *, network, expected_txid, vout, script_pubkey):
    """Match a selected output; caller authenticates network/script separately."""
    if type(network) is not str or network not in NETWORKS:
        raise Invalid('Unsupported Bitcoin network')
    if (type(expected_txid) is not str or len(expected_txid) != 64
            or any(c not in '0123456789abcdef' for c in expected_txid)):
        raise Invalid('Expected txid must be canonical lowercase display hex')
    if type(vout) is not int or not 0 <= vout <= 0xffffffff:
        raise Invalid('Invalid output index')
    if type(script_pubkey) is not bytes or not 1 <= len(script_pubkey) <= MAX_SCRIPT_BYTES:
        raise Invalid('Invalid expected locking script')
    tx = decode(raw)
    if tx.txid != expected_txid:
        raise Invalid('Transaction ID mismatch')
    if tx.coinbase:
        raise Invalid('Coinbase deposits are not supported')
    if vout >= len(tx.outputs):
        raise Invalid('Missing deposit output')
    output = tx.outputs[vout]
    if output.script_pubkey != script_pubkey or output.satoshis == 0:
        raise Invalid('Output does not match a positive deposit')
    return {
        'schema': 'bloch-btc-output-observation-v1',
        'network': network, 'txid': tx.txid, 'wtxid': tx.wtxid, 'vout': vout,
        'outpoint_key': '{}:{}:{}'.format(network, tx.txid, vout),
        'amount_sats': str(output.satoshis), 'script_pubkey_hex': script_pubkey.hex(),
        'inclusion_verified': False, 'finality_verified': False,
        'custody_verified': False, 'mint_authorized': False, 'bridge_ready': False,
    }
