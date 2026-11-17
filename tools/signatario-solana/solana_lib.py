#!/usr/bin/env python3
"""Solana side of the Bloch bridge tools: encodings, addresses, transactions, RPC and the vault's layouts.

Everything here is written against docs/SOLANA-VAULT.md and the program in solana/bloch-sol-vault. Standard
library only, except Ed25519 signing of the fee payer (`cryptography`), which is imported when a transaction is
signed. No key of the bridge committee is ever read here: committee and guardian signatures are made with `cast`
over a keystore, as in tools/signatario-stable.
"""
import base64
import hashlib
import ipaddress
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

# ── base58 ──────────────────────────────────────────────────────────────────
_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


class Refused(Exception):
    def __init__(self, reason, **detail):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def b58encode(data):
    n = int.from_bytes(data, 'big')
    out = ''
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + out


def b58decode(text, length=None):
    n = 0
    for ch in text:
        if ch not in _B58_INDEX:
            raise Refused('not base58', got=text)
        n = n * 58 + _B58_INDEX[ch]
    zeros = len(text) - len(text.lstrip('1'))
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    data = b'\0' * zeros + body
    if length is not None and len(data) != length:
        raise Refused(f'base58 value is not {length} bytes', got=text)
    return data


def pubkey(text):
    return b58decode(text, 32)


# ── keccak256 (Ethereum's, not NIST SHA3-256) ───────────────────────────────
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r, v = _ROT[x][y], a[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & _M64 if r else v
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    p = bytearray(data)
    p.append(0x01)
    p.extend(b'\0' * ((-len(p)) % rate))
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(p[off + 8 * i:off + 8 * i + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'


def sha256(data):
    return hashlib.sha256(data).digest()


# ── program-derived addresses ───────────────────────────────────────────────
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P


def on_curve(key):
    """True if the 32 bytes decompress to an Ed25519 point (as the runtime decides for derived addresses)."""
    y = (int.from_bytes(key, 'little') & ((1 << 255) - 1)) % _P
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    w = u * pow(v, _P - 2, _P) % _P
    return w == 0 or pow(w, (_P - 1) // 2, _P) == 1


# The eight points of small order (1, 2, 4, 8) have these five y coordinates; whatever the sign bit and whether or
# not y is written reduced, an address with one of them is a point NO private key can exist for: a public key is a
# multiple of the base point by a clamped scalar, which is never in the small subgroup (review 330, R330-SOL-1).
_SMALL_ORDER_Y = frozenset((0, 1, _P - 1, 0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826,
                            0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7))


def small_order(key):
    """True if the 32 bytes are one of the small-order points of the curve (in any spelling): nobody holds a key."""
    return on_curve(key) and (int.from_bytes(key, 'little') & ((1 << 255) - 1)) % _P in _SMALL_ORDER_Y


# ── Ed25519 verification (offline proofs of key control; pure Python, no key is ever handled here) ──────────────
_L = 2**252 + 27742317777372353535851937790883648493
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decompress(key):
    n = int.from_bytes(key, 'little')
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P or (x == 0 and sign):
        return None
    return ((_P - x) if x & 1 != sign else x, y)


def _edwards_add(a, b):
    """Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z; complete for a = -1 (RFC 8032, 5.1.4)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e, f = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    g, h = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    return ((f - e) * (h - g) % _P, (h + g) * (f + e) % _P, (h - g) * (h + g) % _P, (f - e) * (f + e) % _P)


def _edwards_mul(k, point):
    """k times an affine point (x, y); the result is affine again."""
    out, q = (0, 1, 1, 0), (point[0], point[1], 1, point[0] * point[1] % _P)
    while k:
        if k & 1:
            out = _edwards_add(out, q)
        q = _edwards_add(q, q)
        k >>= 1
    inv = pow(out[2], _P - 2, _P)
    return (out[0] * inv % _P, out[1] * inv % _P)


def _edwards_sum(a, b):
    """The sum of two affine points, affine."""
    x, y, z, _ = _edwards_add((a[0], a[1], 1, a[0] * a[1] % _P), (b[0], b[1], 1, b[0] * b[1] % _P))
    inv = pow(z, _P - 2, _P)
    return (x * inv % _P, y * inv % _P)


_BASE = _decompress((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, 'little'))


def ed25519_verify(public, message, signature):
    """RFC 8032 verification, strict: canonical encodings of the key, of R and of S; a small-order key is refused."""
    if len(public) != 32 or len(signature) != 64 or small_order(public):
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], 'little')
    if a is None or r is None or s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), 'little') % _L
    return _edwards_mul(s, _BASE) == _edwards_sum(r, _edwards_mul(k, a))


# ── secp256k1 recovery (committee and guardian signatures are checked in process, never by a CLI's exit code) ───
_SP = 2**256 - 2**32 - 977
_SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _secp_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if (y1 + y2) % _SP == 0:
            return None
        m = 3 * x1 * x1 * pow(2 * y1, _SP - 2, _SP) % _SP
    else:
        m = (y2 - y1) * pow(x2 - x1, _SP - 2, _SP) % _SP
    x = (m * m - x1 - x2) % _SP
    return x, (m * (x1 - x) - y1) % _SP


def _secp_mul(k, point):
    out = None
    while k:
        if k & 1:
            out = _secp_add(out, point)
        point = _secp_add(point, point)
        k >>= 1
    return out


def secp256k1_recover(digest, signature):
    """The 20-byte Ethereum-style address whose key signed the 32-byte `digest`, or None. `signature` is exactly
    65 bytes r | s | v with v in (27, 28, 0, 1), 0 < r < n and 0 < s < n. Anything else is None: the caller
    compares the address with the member it expects. Pure arithmetic: nothing is passed to another program."""
    if not isinstance(digest, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
        return None
    if len(digest) != 32 or len(signature) != 65:
        return None
    r, s, v = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:64], 'big'), signature[64]
    if v in (27, 28):
        v -= 27
    if v not in (0, 1) or not 0 < r < _SN or not 0 < s < _SN:
        return None
    y = pow((pow(r, 3, _SP) + 7) % _SP, (_SP + 1) // 4, _SP)
    if (y * y - pow(r, 3, _SP) - 7) % _SP:
        return None
    if y & 1 != v:
        y = _SP - y
    z, inv = int.from_bytes(digest, 'big') % _SN, pow(r, _SN - 2, _SN)
    q = _secp_add(_secp_mul(s * inv % _SN, (r, y)), _secp_mul((-z * inv) % _SN, _SG))
    if q is None:
        return None
    return keccak256(q[0].to_bytes(32, 'big') + q[1].to_bytes(32, 'big'))[12:]


def find_program_address(seeds, program_id):
    for bump in range(255, -1, -1):
        h = sha256(b''.join(seeds) + bytes([bump]) + program_id + b'ProgramDerivedAddress')
        if not on_curve(h):
            return h, bump
    raise Refused('no program-derived address for these seeds')


SYSTEM_PROGRAM = pubkey('11111111111111111111111111111111')
TOKEN_PROGRAM = pubkey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
TOKEN_2022_PROGRAM = pubkey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
ATA_PROGRAM = pubkey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
SECP256K1_PROGRAM = pubkey('KeccakSecp256k11111111111111111111111111111')
INSTRUCTIONS_SYSVAR = pubkey('Sysvar1nstructions1111111111111111111111111')
UPGRADEABLE_LOADER = pubkey('BPFLoaderUpgradeab1e11111111111111111111111')
COMPUTE_BUDGET_PROGRAM = pubkey('ComputeBudget111111111111111111111111111111')


def associated_token_address(owner, mint):
    return find_program_address([owner, TOKEN_PROGRAM, mint], ATA_PROGRAM)[0]


def program_data_address(program_id):
    return find_program_address([program_id], UPGRADEABLE_LOADER)[0]


# ── EVM-shaped hashing (docs/SOLANA-VAULT.md, "Digests") ────────────────────
def tag(text):
    return text.encode().ljust(32, b'\0')


def w64(v):
    if not 0 <= v < 2**64:
        raise Refused('value out of uint64 range', got=v)
    return v.to_bytes(32, 'big')


def waddr(a):
    if len(a) != 20:
        raise Refused('not a 20-byte address')
    return a.rjust(32, b'\0')


def id20(domain, *parts):
    return keccak256(domain.encode() + b''.join(parts))[12:]


def account_id(key):
    """The 20-byte commitment of a Solana wallet: what an L2 burn names as its recipient."""
    return id20('BLOCH-SVM-ACCOUNT-ID-v1', key)


def chain_id_of(genesis_hash):
    """The source chain id of a cluster: a function of its genesis hash (32 bytes)."""
    return keccak256(b'BLOCH-SVM-CHAIN-ID-v1' + genesis_hash)


EIP191_PREFIX = b'\x19Ethereum Signed Message:\n32'


def eip191(authorization):
    return keccak256(EIP191_PREFIX + authorization)


def hx(data):
    return '0x' + bytes(data).hex()


def unhex(text, length=None, what='value'):
    h = str(text).lower()
    h = h[2:] if h.startswith('0x') else h
    try:
        data = bytes.fromhex(h)
    except ValueError:
        raise Refused(f'{what} is not hex', got=text)
    if length is not None and len(data) != length:
        raise Refused(f'{what} must be {length} bytes', got=text)
    return data


# ── which cluster this is (review 330, R330-SOL-2) ──────────────────────────
# Genesis hashes of the public clusters, each read from its own public endpoint (getGenesisHash) on 2026-11-17.
MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'
PUBLIC_GENESIS = {MAINNET_GENESIS: 'mainnet-beta', 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG': 'devnet',
                  '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY': 'testnet'}


def is_loopback(url):
    """True only for an http(s) URL whose host is `localhost` or a literal loopback IP address."""
    try:
        parts = urllib.parse.urlsplit(str(url))
        host = (parts.hostname or '').lower()
        if parts.scheme not in ('http', 'https') or not host:
            return False
        return host == 'localhost' or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def rehearsal(doc, urls=(), genesis=None):
    """Whether the vault file describes a rehearsal, decided by the CLUSTER and never by the flag alone.

    `solana.rehearsal: true` relaxes rules that exist for real funds (two agreeing endpoints for a mint, the burn
    router and an L2 endpoint for a release, the mainnet policy of the configuration). It is therefore refused,
    not obeyed, when the genesis hash (the file's, and the node's when given) is a public cluster's, and when any
    endpoint is not on loopback: a rehearsal is a local private cluster and nothing else. With the flag false or
    absent every production rule applies, whatever the cluster."""
    if not bool((doc.get('solana') or {}).get('rehearsal')):
        return False
    hashes = {str(doc['solana'].get('genesisHash'))} | ({b58encode(genesis)} if genesis is not None else set())
    for text in hashes:
        if text in PUBLIC_GENESIS:
            raise Refused('`solana.rehearsal: true` is refused on a public cluster: the genesis hash is '
                          f'{PUBLIC_GENESIS[text]}\'s. The production rules cannot be switched off there', genesisHash=text)
    remote = [u for u in urls if not is_loopback(u)]
    if remote:
        raise Refused('`solana.rehearsal: true` is refused with an endpoint that is not on loopback: a rehearsal is '
                      'a local private cluster. The production rules cannot be switched off for a remote cluster',
                      endpoints=len(remote))
    return True


# ── how long a paid release record must stay readable (review 330, R330-SOL-3) ──
# The guardian watch compares a paid record (amount, recipient, burn) with its L2 burn only while the record
# exists; once closed, one bit is left. `record_retention` must therefore outlast the longest time a guardian may
# go without a completed round. The floor is derived from the watch interval: a paid record stays readable for at
# least RETENTION_WATCH_ROUNDS rounds of the slowest watch allowed (so a guardian that is down for a long weekend
# still reads every paid record in full when it returns), and never less than a guardian pause (what was paid just
# before a pause stays inspectable for the whole pause). 4,320 rounds of 60 s = 259,200 s = 3 days.
GUARDIAN_WATCH_INTERVAL = 60
RETENTION_WATCH_ROUNDS = 4320


def retention_floor(pause_duration=0, watch_interval=GUARDIAN_WATCH_INTERVAL):
    return max(RETENTION_WATCH_ROUNDS * int(watch_interval), int(pause_duration))


# ── configuration ───────────────────────────────────────────────────────────
MAX_SIGNERS, MAX_GUARDIANS = 16, 7
CONFIG_FIXED = 288
VAULT_LEN = 4 + 32 + CONFIG_FIXED + 20 * MAX_SIGNERS + 20 * MAX_GUARDIANS + 20 + 20 + 32 * 4 + 32 + 8 * 4 + 2 + 8 * 6 + 8 * MAX_GUARDIANS + 24
DEPOSIT_LEN = 211
RELEASE_LEN = 208
LAYOUT_VERSION = 2
PAGE_NONCES = 8192            # burn nonces per paid page
PAGE_HEADER = 43
PAGE_LEN = PAGE_HEADER + PAGE_NONCES // 8
DEPOSIT_WINDOW = 4            # record addresses a deposit names by default (the program takes up to 8)
CONFIG_U64 = ('cap', 'window_limit', 'window_seconds', 'min_deposit', 'l2_min_burn', 'large_release_threshold',
              'release_delay', 'pause_duration', 'pause_cooldown', 'max_valid_seconds', 'record_retention')


class Config:
    """The vault's immutable configuration, from a deployments/solana/*.config.json file or from chain bytes."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    @staticmethod
    def from_json(doc, allow_undecided=False):
        v = doc['vault']
        genesis = b58decode(doc['solana']['genesisHash'], 32)

        def addresses(items, what):
            out = []
            for item in items:
                a = item.get('address') if isinstance(item, dict) else item
                if a in (None, 'TBD-owner'):
                    if allow_undecided:
                        continue
                    raise Refused(f'{what} address is undecided')
                out.append(unhex(a, 20, what))
            return out

        fee_owner = v['fees']['owner']
        cfg = Config(
            mint=pubkey(v['mint']), fee_owner=pubkey(fee_owner),
            source_chain_id=chain_id_of(genesis), source_domain=tag(v['sourceDomainLabel']),
            native_domain=tag(v['nativeDomainLabel']), native_asset=tag(v['assetLabel']),
            cap=int(v['cap']), window_limit=int(v['policy']['windowLimit']),
            window_seconds=int(v['policy']['windowSeconds']), min_deposit=int(v['policy']['minDeposit']),
            l2_min_burn=int(v['policy']['l2MinBurn']),
            large_release_threshold=int(v['policy']['largeReleaseThreshold']),
            release_delay=int(v['policy']['releaseDelay']), pause_duration=int(v['guard']['pauseDuration']),
            pause_cooldown=int(v['guard']['pauseCooldown']), max_valid_seconds=int(v['policy']['maxValidSeconds']),
            record_retention=int(v['policy']['recordRetention']),
            deposit_fee_bps=int(v['fees']['depositBps']), release_fee_bps=int(v['fees']['releaseBps']),
            threshold=int(v['signers']['threshold']), switch_threshold=int(v['policy']['unpauseThreshold']),
            signers=addresses(v['signers']['set'], 'signer'), guardians=addresses(v['guard']['guardians'], 'guardian'))
        if v.get('tokenProgram', b58encode(TOKEN_PROGRAM)) != b58encode(TOKEN_PROGRAM):
            raise Refused('only the classic SPL Token program is supported', got=v.get('tokenProgram'))
        return cfg

    def encode(self):
        d = self.mint + self.fee_owner + self.source_chain_id + self.source_domain + self.native_domain + self.native_asset
        for name in CONFIG_U64:
            d += getattr(self, name).to_bytes(8, 'little')
        d += self.deposit_fee_bps.to_bytes(2, 'little') + self.release_fee_bps.to_bytes(2, 'little')
        d += bytes([self.threshold, self.switch_threshold, len(self.signers), len(self.guardians)])
        return d + b''.join(self.signers) + b''.join(self.guardians)

    @staticmethod
    def decode_fixed(d):
        f = dict(mint=d[0:32], fee_owner=d[32:64], source_chain_id=d[64:96], source_domain=d[96:128],
                 native_domain=d[128:160], native_asset=d[160:192])
        at = 192
        for name in CONFIG_U64:
            f[name] = int.from_bytes(d[at:at + 8], 'little')
            at += 8
        f['deposit_fee_bps'] = int.from_bytes(d[at:at + 2], 'little')
        f['release_fee_bps'] = int.from_bytes(d[at + 2:at + 4], 'little')
        f['threshold'], f['switch_threshold'], ns, ng = d[at + 4:at + 8]
        return f, ns, ng

    def problems(self, mainnet=False):
        """The program's own rules (state.rs validate), so a bad file is refused before any transaction."""
        p = []
        n, g = len(self.signers), len(self.guardians)
        fee = self.min_deposit * self.deposit_fee_bps // 10_000
        checks = [
            (self.deposit_fee_bps <= 30 and self.release_fee_bps <= 30, 'a fee is above 30 bps'),
            (n <= MAX_SIGNERS and g <= MAX_GUARDIANS, 'too many signers or guardians'),
            (2 <= self.threshold <= n, 'threshold must be between 2 and the number of signers'),
            (self.threshold <= self.switch_threshold <= n, 'unpause threshold must be between threshold and the set'),
            (self.cap > 0 and 0 < self.window_limit <= self.cap and self.window_seconds > 0, 'cap / window'),
            (self.l2_min_burn > 0 and self.l2_min_burn <= self.min_deposit <= self.window_limit, 'min deposit'),
            (self.min_deposit - fee >= self.l2_min_burn, 'min deposit nets below the L2 min burn'),
            (self.release_delay <= 14 * 86400, 'release delay above 14 days'),
            (self.release_delay != 0 or self.large_release_threshold == 0, 'large threshold without a delay'),
            (60 <= self.max_valid_seconds <= 86400, 'max valid seconds must be within 60 and 86400'),
            (0 <= self.record_retention <= 30 * 86400, 'record retention above 30 days'),
            (self.source_domain != self.native_domain, 'source and native domain are equal'),
            (sorted(set(self.signers)) == self.signers and all(any(s) for s in self.signers), 'signers must be strictly ascending'),
            (sorted(set(self.guardians)) == self.guardians and not set(self.guardians) & set(self.signers),
             'guardians must be strictly ascending and never signers'),
            ((g == 0 and self.pause_duration == 0 and self.pause_cooldown == 0)
             or (g != 0 and 0 < self.pause_duration <= 14 * 86400 and self.pause_duration <= self.pause_cooldown <= 14 * 86400),
             'pause duration / cooldown'),
            (g == 0 or self.pause_duration > self.max_valid_seconds,
             'a guardian pause must outlast every certificate (pauseDuration > maxValidSeconds); the program refuses it too'),
            (self.threshold <= 5, 'a release certificate of more than 5 signatures does not fit one transaction'),
        ]
        if mainnet:
            checks += [
                (n == 7 and self.threshold == 5 and self.switch_threshold == 6, 'mainnet policy: 7 signers, 5 release, 6 unpause'),
                (g == 3, 'mainnet policy: exactly 3 guardians'),
                (self.deposit_fee_bps == 5 and self.release_fee_bps == 5, 'mainnet policy: 5 + 5 bps'),
                (on_curve(self.fee_owner) and not small_order(self.fee_owner),
                 'the fee owner is not a wallet address (off the curve, or a point without a key)'),
                (self.record_retention >= retention_floor(self.pause_duration),
                 f'mainnet policy: recordRetention {self.record_retention} is below the floor '
                 f'{retention_floor(self.pause_duration)} s ({RETENTION_WATCH_ROUNDS} guardian watch rounds of '
                 f'{GUARDIAN_WATCH_INTERVAL} s, and never less than pauseDuration): a paid record could be closed '
                 'before a guardian read it'),
            ]
        return [text for ok, text in checks if not ok]


class Addresses:
    """Every address and identity that follows from (program id, configuration)."""

    def __init__(self, program_id, config):
        self.program_id = program_id
        self.config = config
        self.config_hash = sha256(b'BLOCH-SVM-VAULT-CONFIG-v1' + config.encode())
        self.vault, self.vault_bump = find_program_address([b'vault', self.config_hash], program_id)
        self.tokens, _ = find_program_address([b'tokens', self.vault], program_id)
        self.fee_account = associated_token_address(config.fee_owner, config.mint)
        self.vault20 = id20('BLOCH-SVM-VAULT-ID-v1', program_id, self.vault)
        self.mint20 = id20('BLOCH-SVM-MINT-ID-v1', config.mint)
        self.route = sha256(tag('BLOCH-USDT-ROUTE-v1') + config.source_domain + config.native_domain + config.native_asset
                            + waddr(self.mint20) + waddr(self.vault20) + w64(6) + w64(config.cap))
        self.genesis = keccak256(tag('BLOCH-USDT-MINT-CHAIN-v1') + config.source_chain_id + waddr(self.vault20) + self.route)
        self.program_data = program_data_address(program_id)

    def deposit_record(self, nonce):
        return find_program_address([b'deposit', self.vault, nonce.to_bytes(8, 'little')], self.program_id)[0]

    def release_record(self, nonce):
        return find_program_address([b'release', self.vault, nonce.to_bytes(8, 'little')], self.program_id)[0]

    def paid_page(self, nonce):
        """The page whose bit says "the release of this burn nonce was paid and its record closed"."""
        return find_program_address([b'paid', self.vault, (nonce // PAGE_NONCES).to_bytes(8, 'little')], self.program_id)[0]

    def summary(self):
        return {'programId': b58encode(self.program_id), 'vault': b58encode(self.vault),
                'vaultTokenAccount': b58encode(self.tokens), 'feeTokenAccount': b58encode(self.fee_account),
                'programData': b58encode(self.program_data), 'configHash': hx(self.config_hash),
                'sourceChainId': str(int.from_bytes(self.config.source_chain_id, 'big')),
                'sourceVault': hx(self.vault20), 'sourceRoute': hx(self.route), 'mintId': hx(self.mint20),
                'mintChainGenesis': hx(self.genesis)}


# ── account decoding ────────────────────────────────────────────────────────
class _Reader:
    def __init__(self, data):
        self.d, self.at = data, 0

    def take(self, n):
        out = self.d[self.at:self.at + n]
        if len(out) != n:
            raise Refused('account data too short')
        self.at += n
        return out

    def u64(self):
        return int.from_bytes(self.take(8), 'little')


def decode_vault(data):
    if len(data) != VAULT_LEN or data[0] != 1 or data[1] != LAYOUT_VERSION:
        raise Refused('not a vault account of this layout', length=len(data))
    r = _Reader(data)
    r.take(2)
    v = {'bump': r.take(1)[0], 'token_bump': r.take(1)[0], 'config_hash': r.take(32)}
    fixed, ns, ng = Config.decode_fixed(r.take(CONFIG_FIXED))
    signers = [r.take(20) for _ in range(MAX_SIGNERS)]
    guardians = [r.take(20) for _ in range(MAX_GUARDIANS)]
    v['config'] = Config(signers=signers[:ns], guardians=guardians[:ng], **fixed)
    if any(any(s) for s in signers[ns:]) or any(any(g) for g in guardians[ng:]):
        raise Refused('vault account has addresses beyond its counts')
    for name, size in (('vault20', 20), ('mint20', 20), ('route', 32), ('genesis', 32), ('token_account', 32),
                       ('fee_token_account', 32), ('head', 32)):
        v[name] = r.take(size)
    for name in ('deposit_count', 'total_locked', 'fees_accrued', 'control_nonce'):
        v[name] = r.u64()
    v['deposits_enabled'] = r.take(1)[0] == 1
    v['releases_enabled'] = r.take(1)[0] == 1
    for name in ('release_bucket', 'bucket_updated_at', 'paused_until', 'pause_count', 'guardian_blocked_until',
                 'pause_chain'):
        v[name] = r.u64()
    v['guardian_last_chain'] = [r.u64() for _ in range(MAX_GUARDIANS)]
    v['approval_seq'] = r.u64()
    v['void_through_seq'] = r.u64()
    v['last_pause_at'] = r.u64()
    return v


def available_to_release(v, now):
    c = v['config']
    refilled = v['release_bucket'] + max(0, now - v['bucket_updated_at']) * c.window_limit // c.window_seconds
    return min(refilled, c.window_limit)


def decode_deposit(data):
    if len(data) != DEPOSIT_LEN or data[0] != 2 or data[1] != LAYOUT_VERSION:
        raise Refused('not a deposit record of this layout', length=len(data))
    r = _Reader(data)
    r.take(2)
    return {'bump': r.take(1)[0], 'vault': r.take(32), 'nonce': r.u64(), 'id': r.take(32), 'depositor': r.take(32),
            'sender20': r.take(20), 'l2_recipient': r.take(20), 'amount': r.u64(), 'fee': r.u64(),
            'head_after': r.take(32), 'slot': r.u64(), 'timestamp': r.u64()}


def decode_release(data):
    if len(data) != RELEASE_LEN or data[0] != 3 or data[1] != LAYOUT_VERSION:
        raise Refused('not a release record of this layout', length=len(data))
    r = _Reader(data)
    r.take(2)
    return {'bump': r.take(1)[0], 'state': r.take(1)[0], 'vault': r.take(32), 'nonce': r.u64(),
            'release_id': r.take(32), 'recipient': r.take(20), 'amount': r.u64(), 'native_burn': r.take(32),
            'ready_at': r.u64(), 'seq': r.u64(), 'approved_at': r.u64(), 'paid_at': r.u64(), 'paid_amount': r.u64(),
            'payer': r.take(32)}


def decode_page(data):
    """{'vault', 'page', 'bits'} of a paid page."""
    if len(data) != PAGE_LEN or data[0] != 4 or data[1] != LAYOUT_VERSION:
        raise Refused('not a paid page of this layout', length=len(data))
    return {'bump': data[2], 'vault': data[3:35], 'page': int.from_bytes(data[35:43], 'little'), 'bits': data[PAGE_HEADER:]}


def page_bit(page, nonce):
    i = nonce % PAGE_NONCES
    return bool(page['bits'][i // 8] & (1 << (i % 8)))


def page_nonces(page):
    """Every burn nonce a paid page marks as paid and closed."""
    base = page['page'] * PAGE_NONCES
    return [base + 8 * i + b for i, byte in enumerate(page['bits']) if byte for b in range(8) if byte & (1 << b)]


def decode_token_account(data):
    if len(data) != 165:
        raise Refused('not a classic token account', length=len(data))
    return {'mint': data[0:32], 'owner': data[32:64], 'amount': int.from_bytes(data[64:72], 'little'),
            'delegate': data[76:108] if data[72:76] != b'\0' * 4 else None, 'state': data[108],
            'close_authority': data[133:165] if data[129:133] != b'\0' * 4 else None}


def decode_mint(data):
    if len(data) != 82:
        raise Refused('not a classic mint', length=len(data))
    return {'mint_authority': data[4:36] if data[0:4] != b'\0' * 4 else None,
            'supply': int.from_bytes(data[36:44], 'little'), 'decimals': data[44], 'initialized': data[45] == 1,
            'freeze_authority': data[50:82] if data[46:50] != b'\0' * 4 else None}


# ── digests ─────────────────────────────────────────────────────────────────
def deposit_id(route, nonce, sender20, net, l2_recipient):
    h = sha256(tag('BLOCH-USDT-DEPOSIT-v2') + route + w64(nonce) + waddr(sender20) + w64(net) + waddr(l2_recipient))
    return nonce.to_bytes(8, 'big') + h[8:]


def chain_step(head, dep_id, net, l2_recipient):
    return keccak256(head + dep_id + w64(net) + waddr(l2_recipient))


RELEASE_FIELDS = ('route', 'nonce', 'recipient', 'amount', 'nativeBurn', 'mintCount', 'mintedTotal', 'mintHead')
CONTEXT_FIELDS = ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash', 'nativeFinalizedNumber', 'nativeFinalizedHash')


def release_id(rel):
    return sha256(tag('BLOCH-USDT-RELEASE-v2') + rel['route'] + w64(rel['nonce']) + waddr(rel['recipient'])
                  + w64(rel['amount']) + rel['nativeBurn'] + w64(rel['mintCount']) + w64(rel['mintedTotal'])
                  + rel['mintHead'])


def release_authorization(chain_id, vault20, rel, ctx):
    return keccak256(tag('BLOCH-USDT-RELEASE-AUTH-v2') + chain_id + waddr(vault20) + release_id(rel)
                     + w64(ctx['validUntil']) + w64(ctx['sourceAnchorNumber']) + ctx['sourceAnchorHash']
                     + w64(ctx['nativeFinalizedNumber']) + ctx['nativeFinalizedHash'])


def controls_authorization(chain_id, vault20, route, deposits, releases, nonce, valid_until):
    return keccak256(tag('BLOCH-USDT-CONTROLS-v1') + chain_id + waddr(vault20) + route + w64(int(deposits))
                     + w64(int(releases)) + w64(nonce) + w64(valid_until))


def unpause_authorization(chain_id, vault20, route, count, valid_until):
    return keccak256(tag('BLOCH-USDT-UNPAUSE-v1') + chain_id + waddr(vault20) + route + w64(count) + w64(valid_until))


def guardian_pause_authorization(chain_id, vault20, route, count, valid_until):
    return keccak256(tag('BLOCH-SVM-GUARDIAN-PAUSE-v1') + chain_id + waddr(vault20) + route + w64(count) + w64(valid_until))


# ── instructions ────────────────────────────────────────────────────────────
class Meta:
    def __init__(self, key, signer=False, writable=False):
        self.key, self.signer, self.writable = key, signer, writable


class Instruction:
    def __init__(self, program_id, metas, data):
        self.program_id, self.metas, self.data = program_id, metas, bytes(data)


def secp_instruction(authorization, signatures, index):
    """The canonical secp256k1 instruction. `signatures`: (address20, 65-byte r||s||v) pairs, any order; they are
    placed in ascending address order. `index`: the position this instruction will have in the transaction."""
    items = sorted(signatures, key=lambda p: p[0])
    n = len(items)
    if not 1 <= n <= 255 or len({a for a, _ in items}) != n:
        raise Refused('a certificate needs distinct signers')
    data = bytearray(1 + 96 * n + 60)
    data[0] = n
    entries, message = 1 + 11 * n, 1 + 96 * n
    for i, (address, sig) in enumerate(items):
        if len(address) != 20 or len(sig) != 65 or sig[64] not in (0, 1, 27, 28):
            raise Refused('malformed signature')
        o, e = 1 + 11 * i, entries + 85 * i
        data[o:o + 11] = (e.to_bytes(2, 'little') + bytes([index]) + (e + 65).to_bytes(2, 'little') + bytes([index])
                          + message.to_bytes(2, 'little') + (60).to_bytes(2, 'little') + bytes([index]))
        data[e:e + 64] = sig[:64]
        data[e + 64] = sig[64] - 27 if sig[64] >= 27 else sig[64]
        data[e + 65:e + 85] = address
    data[message:message + 28] = EIP191_PREFIX
    data[message + 28:] = authorization
    return Instruction(SECP256K1_PROGRAM, [], data)


def compute_limit_instruction(units):
    return Instruction(COMPUTE_BUDGET_PROGRAM, [], b'\x02' + units.to_bytes(4, 'little'))


def create_ata_instruction(payer, owner, mint):
    return Instruction(ATA_PROGRAM, [Meta(payer, True, True), Meta(associated_token_address(owner, mint), False, True),
                                     Meta(owner), Meta(mint), Meta(SYSTEM_PROGRAM), Meta(TOKEN_PROGRAM)], b'\x01')


class VaultIx:
    """Instruction builders of the vault program (account order and data: docs/SOLANA-VAULT.md)."""

    def __init__(self, addresses):
        self.a = addresses

    def initialize(self, payer):
        a = self.a
        return Instruction(a.program_id, [Meta(payer, True, True), Meta(a.vault, False, True), Meta(a.tokens, False, True),
                                          Meta(a.config.mint), Meta(a.program_data), Meta(TOKEN_PROGRAM),
                                          Meta(SYSTEM_PROGRAM)], b'\x00' + a.config.encode())

    def deposit(self, depositor, source, nonce, amount, l2_recipient, window=1):
        """`nonce` is the vault's deposit count as the depositor read it; `window` record addresses are named
        (counts nonce .. nonce + window - 1, at most 8), so deposits that land in between do not make this one
        fail: the program uses the record of the count it finds."""
        a = self.a
        if not 1 <= window <= 8:
            raise Refused('a deposit names 1 to 8 record addresses')
        return Instruction(a.program_id, [
            Meta(depositor, True, True), Meta(source, False, True), Meta(a.vault, False, True),
            Meta(a.tokens, False, True), Meta(a.config.mint), Meta(a.deposit_record(nonce), False, True),
            Meta(TOKEN_PROGRAM), Meta(SYSTEM_PROGRAM)]
            + [Meta(a.deposit_record(nonce + i), False, True) for i in range(1, window)],
            b'\x01' + amount.to_bytes(8, 'little') + l2_recipient)

    def approve_release(self, payer, rel, ctx):
        a = self.a
        data = (b'\x02' + rel['nonce'].to_bytes(8, 'little') + rel['recipient'] + rel['amount'].to_bytes(8, 'little')
                + rel['nativeBurn'] + rel['mintCount'].to_bytes(8, 'little') + rel['mintedTotal'].to_bytes(8, 'little')
                + rel['mintHead'] + ctx['validUntil'].to_bytes(8, 'little')
                + ctx['sourceAnchorNumber'].to_bytes(8, 'little') + ctx['sourceAnchorHash']
                + ctx['nativeFinalizedNumber'].to_bytes(8, 'little') + ctx['nativeFinalizedHash'])
        return Instruction(a.program_id, [
            Meta(payer, True, True), Meta(a.vault, False, True), Meta(a.release_record(rel['nonce']), False, True),
            Meta(a.deposit_record(max(rel['mintCount'], 1) - 1)), Meta(a.paid_page(rel['nonce']), False, True),
            Meta(INSTRUCTIONS_SYSVAR), Meta(SYSTEM_PROGRAM)], data)

    def close_release(self, nonce, rent_payer):
        """Closes a paid release record after the retention; its rent returns to `rent_payer` (the record names it)."""
        a = self.a
        return Instruction(a.program_id, [
            Meta(a.vault, False, True), Meta(a.release_record(nonce), False, True),
            Meta(a.paid_page(nonce), False, True), Meta(rent_payer, False, True)], b'\x08' + nonce.to_bytes(8, 'little'))

    def execute_release(self, nonce, owner):
        a = self.a
        return Instruction(a.program_id, [
            Meta(a.vault, False, True), Meta(a.tokens, False, True), Meta(a.config.mint),
            Meta(a.release_record(nonce), False, True), Meta(associated_token_address(owner, a.config.mint), False, True),
            Meta(TOKEN_PROGRAM)], b'\x03' + nonce.to_bytes(8, 'little') + owner)

    def _certified(self, data):
        return Instruction(self.a.program_id, [Meta(self.a.vault, False, True), Meta(INSTRUCTIONS_SYSVAR)], data)

    def guardian_pause(self, valid_until):
        return self._certified(b'\x04' + valid_until.to_bytes(8, 'little'))

    def unpause(self, count, valid_until):
        return self._certified(b'\x05' + count.to_bytes(8, 'little') + valid_until.to_bytes(8, 'little'))

    def set_controls(self, deposits, releases, nonce, valid_until):
        return self._certified(bytes([6, int(deposits), int(releases)]) + nonce.to_bytes(8, 'little')
                               + valid_until.to_bytes(8, 'little'))

    def sweep_fees(self):
        a = self.a
        return Instruction(a.program_id, [Meta(a.vault, False, True), Meta(a.tokens, False, True), Meta(a.config.mint),
                                          Meta(a.fee_account, False, True), Meta(TOKEN_PROGRAM)], b'\x07')


# ── transactions ────────────────────────────────────────────────────────────
def _compact(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def compile_message(fee_payer, instructions, blockhash):
    """Legacy message. Returns (bytes, ordered signer keys)."""
    flags = {fee_payer: [True, True]}
    order = [fee_payer]
    for ix in instructions:
        for m in ix.metas:
            if m.key not in flags:
                flags[m.key] = [False, False]
                order.append(m.key)
            flags[m.key][0] |= m.signer
            flags[m.key][1] |= m.writable
    for ix in instructions:
        if ix.program_id not in flags:
            flags[ix.program_id] = [False, False]
            order.append(ix.program_id)
    groups = [[k for k in order if flags[k] == [s, w]] for s, w in ((True, True), (True, False), (False, True), (False, False))]
    keys = [k for g in groups for k in g]
    if len(keys) > 255:
        raise Refused('too many accounts')
    index = {k: i for i, k in enumerate(keys)}
    msg = bytearray([len(groups[0]) + len(groups[1]), len(groups[1]), len(groups[3])])
    msg += _compact(len(keys)) + b''.join(keys) + blockhash + _compact(len(instructions))
    for ix in instructions:
        msg += bytes([index[ix.program_id]]) + _compact(len(ix.metas)) + bytes(index[m.key] for m in ix.metas)
        msg += _compact(len(ix.data)) + ix.data
    return bytes(msg), keys[:len(groups[0]) + len(groups[1])]


class Keypair:
    """An Ed25519 fee-payer key in the `solana-keygen` JSON format. It pays fees and rent; it has no power over
    the vault. The file must not be readable by group or others."""

    def __init__(self, path):
        st = os.stat(path)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise Refused('the fee-payer key file is readable by group or others', path=str(path))
        raw = bytes(json.loads(open(path).read()))
        if len(raw) != 64:
            raise Refused('not a solana-keygen key file', path=str(path))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        self._key = Ed25519PrivateKey.from_private_bytes(raw[:32])
        self.public = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if self.public != raw[32:]:
            raise Refused('the key file is inconsistent', path=str(path))

    def sign(self, message):
        return self._key.sign(message)


def sign_transaction(fee_payer, instructions, blockhash, extra_signers=()):
    message, signer_keys = compile_message(fee_payer.public, instructions, blockhash)
    by_key = {k.public: k for k in (fee_payer, *extra_signers)}
    sigs = []
    for key in signer_keys:
        if key not in by_key:
            raise Refused('missing a signer for the transaction', key=b58encode(key))
        sigs.append(by_key[key].sign(message))
    raw = _compact(len(sigs)) + b''.join(sigs) + message
    if len(raw) > 1232:
        raise Refused('the transaction does not fit one packet', bytes=len(raw))
    return raw, b58encode(sigs[0])


# ── RPC ─────────────────────────────────────────────────────────────────────
class RpcError(Exception):
    def __init__(self, method, error):
        super().__init__(f'{method}: {error}')
        self.method, self.error = method, error


class Rpc:
    def __init__(self, url, timeout=30):
        self.url, self.timeout = url, timeout

    def call(self, method, params=()):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        req = urllib.request.Request(self.url, data=body, headers={'Content-Type': 'application/json',
                                                                   'User-Agent': 'generic-client'})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                out = json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise RpcError(method, str(e))
        if out.get('error'):
            raise RpcError(method, out['error'])
        return out.get('result')

    def genesis_hash(self):
        return b58decode(self.call('getGenesisHash'), 32)

    def slot(self, commitment):
        return int(self.call('getSlot', [{'commitment': commitment}]))

    def account(self, key, commitment, min_context_slot=None):
        """(context slot, owner bytes, data bytes, lamports), or (context slot, None, None, 0) if absent."""
        cfg = {'encoding': 'base64', 'commitment': commitment}
        if min_context_slot is not None:
            cfg['minContextSlot'] = min_context_slot
        out = self.call('getAccountInfo', [b58encode(key), cfg])
        slot, value = int(out['context']['slot']), out['value']
        if value is None:
            return slot, None, None, 0
        return slot, pubkey(value['owner']), base64.b64decode(value['data'][0]), int(value['lamports'])

    def account_info(self, key, commitment):
        """The account as the node shows it: None when absent, else owner, data, lamports and the executable flag."""
        out = self.call('getAccountInfo', [b58encode(key), {'encoding': 'base64', 'commitment': commitment}])
        value = out['value']
        if value is None:
            return None
        return {'owner': pubkey(value['owner']), 'data': base64.b64decode(value['data'][0]),
                'lamports': int(value['lamports']), 'executable': bool(value.get('executable')),
                'slot': int(out['context']['slot'])}

    def last_block(self, commitment, at_or_below=None):
        """(slot, blockhash) of the newest block at this commitment (skipped slots have no block)."""
        top = at_or_below if at_or_below is not None else self.slot(commitment)
        for _ in range(8):
            slots = self.call('getBlocks', [max(0, top - 64), top, {'commitment': commitment}])
            if slots:
                return int(slots[-1]), self.block_hash(int(slots[-1]), commitment)
            top -= 65
            if top < 0:
                break
        raise RpcError('getBlocks', 'no block found near the head')

    def block_hash(self, slot, commitment):
        """The blockhash of `slot`, or None when the slot was skipped or is not available on this node."""
        try:
            out = self.call('getBlock', [slot, {'encoding': 'json', 'transactionDetails': 'none', 'rewards': False,
                                                'commitment': commitment, 'maxSupportedTransactionVersion': 0}])
        except RpcError as e:
            code = e.error.get('code') if isinstance(e.error, dict) else None
            if code in (-32004, -32007, -32009, -32001):
                return None
            raise
        return b58decode(out['blockhash'], 32) if out else None

    def block_time(self, slot):
        return self.call('getBlockTime', [slot])

    def latest_blockhash(self, commitment='finalized'):
        out = self.call('getLatestBlockhash', [{'commitment': commitment}])
        return b58decode(out['value']['blockhash'], 32), int(out['value']['lastValidBlockHeight'])

    def send(self, raw, skip_preflight=False):
        return self.call('sendTransaction', [base64.b64encode(raw).decode(),
                                             {'encoding': 'base64', 'skipPreflight': skip_preflight,
                                              'preflightCommitment': 'confirmed', 'maxRetries': 5}])

    def status(self, signature):
        out = self.call('getSignatureStatuses', [[signature], {'searchTransactionHistory': True}])
        return out['value'][0]

    def block_height(self, commitment='confirmed'):
        return int(self.call('getBlockHeight', [{'commitment': commitment}]))

    def transaction(self, signature, commitment='confirmed'):
        return self.call('getTransaction', [signature, {'encoding': 'json', 'commitment': commitment,
                                                        'maxSupportedTransactionVersion': 0}])

    def signatures_for(self, key, commitment='finalized', limit=10):
        return self.call('getSignaturesForAddress', [b58encode(key), {'commitment': commitment, 'limit': limit}])


def send_and_confirm(rpc, fee_payer, instructions, extra_signers=(), commitment='confirmed', wait=90):
    """Signs with a recent blockhash, sends, and waits until the transaction reaches `commitment` or its blockhash
    expires. Returns {'signature', 'slot', 'err', 'logs', 'units'}; a program error is returned, not raised.

    A transaction is identified by its signature and can land at most once (the blockhash expires after about 150
    blocks), so resending the same bytes is safe. Whether its EFFECT happened is always read from the vault's
    accounts afterwards, never inferred from this answer."""
    blockhash, last_valid = rpc.latest_blockhash('confirmed')
    raw, signature = sign_transaction(fee_payer, instructions, blockhash, extra_signers)
    try:
        rpc.send(raw)
    except RpcError as e:
        data = e.error.get('data') if isinstance(e.error, dict) else None
        if isinstance(data, dict) and data.get('err') is not None:
            return {'signature': signature, 'slot': None, 'err': data['err'], 'logs': data.get('logs') or [],
                    'units': data.get('unitsConsumed')}
        raise
    deadline = time.time() + wait
    levels = {'processed': 0, 'confirmed': 1, 'finalized': 2}
    while time.time() < deadline:
        st = rpc.status(signature)
        if st is not None and levels.get(st.get('confirmationStatus'), 0) >= levels[commitment]:
            tx = rpc.transaction(signature, 'finalized' if commitment == 'finalized' else 'confirmed') or {}
            meta = tx.get('meta') or {}
            return {'signature': signature, 'slot': st.get('slot'), 'err': st.get('err'),
                    'logs': meta.get('logMessages') or [], 'units': meta.get('computeUnitsConsumed')}
        if st is None and rpc.block_height('confirmed') > last_valid:
            raise Refused('the transaction expired without landing', signature=signature)
        try:
            rpc.send(raw, skip_preflight=True)
        except RpcError:
            pass
        time.sleep(0.5)
    raise Refused('no confirmation in time; read the vault state before sending anything again', signature=signature)


def custom_error(err):
    """The vault's custom error code inside a transaction error, or None."""
    try:
        return int(err['InstructionError'][1]['Custom'])
    except (KeyError, TypeError, IndexError, ValueError):
        return None


VAULT_ERRORS = {100: 'InvalidConfiguration', 101: 'InvalidAccount', 102: 'InvalidTransfer', 103: 'InvalidRelease',
                104: 'InvalidCertificate', 105: 'InvalidControls', 106: 'InsufficientBacking', 107: 'InvalidContext',
                108: 'RateLimited', 109: 'NotGuardian', 110: 'InvalidPause', 111: 'Paused', 112: 'ProvenanceMismatch',
                113: 'NotApproved', 114: 'NotReady', 115: 'AlreadyReleased', 116: 'Voided', 117: 'NotTopLevel',
                118: 'ProgramUpgradeable', 119: 'WrongRecipient', 120: 'Expired', 121: 'StaleCertificate'}
