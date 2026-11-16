"""Pure primitives of the Bitcoin bridge (bBTC): hashes, secp256k1, bech32, scripts, transactions, BIP143, the vault marker.

No I/O, no keys on disk, no network. Everything here is deterministic and is what `btc_policy.build_vault_tx`
and the tests are built on. UNAUDITED.

The pure-Python secp256k1 below is used for VERIFICATION, public-key recovery and for throwaway rehearsal keys.
Production signers never load a key here: they sign the 32-byte BIP143 digest with `cast wallet sign --no-hash`
from their encrypted keystore (tools/signatario-btc/btc_signer.py), exactly as the Ethereum half signs a release.
"""
import hashlib
import hmac

# ── hashes ───────────────────────────────────────────────────────────────────


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


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
                r = _ROT[x][y]
                v = a[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & _M64 if r else v
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    p = bytearray(data)
    p.append(0x01)
    while len(p) % rate:
        p.append(0)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(p[off + 8 * i:off + 8 * i + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


# ── secp256k1 ────────────────────────────────────────────────────────────────
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


class BadKey(ValueError):
    pass


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (m * m - a[0] - b[0]) % P
    return x, (m * (a[0] - x) - a[1]) % P


def _mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def compress(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')


def decompress(b):
    if len(b) != 33 or b[0] not in (2, 3):
        raise BadKey('a compressed secp256k1 public key is 33 bytes starting 02 or 03')
    x = int.from_bytes(b[1:], 'big')
    if x >= P:
        raise BadKey('x out of range')
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        raise BadKey('not on the curve')
    return x, y if (y & 1) == (b[0] & 1) else P - y


def pubkey(priv):
    if not 0 < priv < N:
        raise BadKey('private key out of range')
    return compress(_mul(priv, G))


def eth_address(pub33):
    x, y = decompress(pub33)
    return '0x' + keccak256(x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))[12:].hex()


def sign(digest, priv):
    """RFC 6979 deterministic ECDSA, low s. Returns (r, s, recid). Throwaway keys only (see module docstring)."""
    z = int.from_bytes(digest, 'big')
    x = priv.to_bytes(32, 'big')
    k, v = b'\0' * 32, b'\1' * 32
    k = hmac.new(k, v + b'\0' + x + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\1' + x + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        nonce = int.from_bytes(v, 'big')
        if 0 < nonce < N:
            pt = _mul(nonce, G)
            r = pt[0] % N
            s = pow(nonce, -1, N) * (z + r * priv) % N
            if r and s:
                rec = pt[1] & 1
                if s > N // 2:
                    s, rec = N - s, rec ^ 1
                return r, s, rec
        k = hmac.new(k, v + b'\0', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def verify(digest, r, s, pub33):
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(digest, 'big')
    w = pow(s, -1, N)
    pt = _add(_mul(z * w % N, G), _mul(r * w % N, decompress(pub33)))
    return pt is not None and pt[0] % N == r


def recover(digest, r, s, recid):
    """The public key behind an Ethereum-style (r, s, v) signature over `digest` (v = 27/28 or 0/1)."""
    recid = recid - 27 if recid >= 27 else recid
    if recid not in (0, 1) or not (0 < r < N and 0 < s < N):
        raise BadKey('bad signature')
    rp = decompress(bytes([2 + recid]) + r.to_bytes(32, 'big'))
    z = int.from_bytes(digest, 'big')
    ri = pow(r, -1, N)
    pt = _add(_mul(s * ri % N, rp), _mul((-z * ri) % N, G))
    if pt is None:
        raise BadKey('bad signature')
    return compress(pt)


def der_sig(r, s, sighash=1):
    """Strict DER (BIP66), low s (BIP146), plus the sighash byte. A high s is normalised: n - s verifies equally."""
    if s > N // 2:
        s = N - s

    def i(v):
        b = v.to_bytes(32, 'big').lstrip(b'\0')
        return b'\x02' + bytes([len(b) + (b[0] >> 7)]) + (b'\0' if b[0] >> 7 else b'') + b

    body = i(r) + i(s)
    return b'\x30' + bytes([len(body)]) + body + bytes([sighash])


def parse_rsv(sig65):
    """65-byte r || s || v as `cast wallet sign --no-hash` prints it."""
    if len(sig65) != 65:
        raise BadKey('a signature is 65 bytes r || s || v')
    return int.from_bytes(sig65[:32], 'big'), int.from_bytes(sig65[32:64], 'big'), sig65[64]


# ── bech32 / bech32m (BIP173, BIP350) ────────────────────────────────────────
_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
HRP = {'bitcoin-mainnet': 'bc', 'bitcoin-testnet4': 'tb', 'bitcoin-signet': 'tb', 'bitcoin-regtest': 'bcrt'}
GENESIS = {'bitcoin-mainnet': '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
           'bitcoin-regtest': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'}


class BadAddress(ValueError):
    pass


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convert(data, frm, to, pad):
    acc = bits = 0
    out = []
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if pad and bits:
        out.append((acc << (to - bits)) & ((1 << to) - 1))
    elif not pad and (bits >= frm or (acc << (to - bits)) & ((1 << to) - 1)):
        raise BadAddress('bad padding')
    return out


def segwit_encode(hrp, version, program):
    const = 1 if version == 0 else 0x2bc830a3
    data = [version] + _convert(program, 8, 5, True)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    return hrp + '1' + ''.join(_CHARSET[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def segwit_decode(hrp, addr):
    """(version, program) of a segwit address of this network; refuses anything else."""
    if type(addr) is not str or not 14 <= len(addr) <= 90 or (addr.lower() != addr and addr.upper() != addr):
        raise BadAddress('not a segwit address')
    addr = addr.lower()
    pos = addr.rfind('1')
    if addr[:pos] != hrp or any(c not in _CHARSET for c in addr[pos + 1:]):
        raise BadAddress('wrong network prefix or character')
    data = [_CHARSET.index(c) for c in addr[pos + 1:]]
    if len(data) < 7:
        raise BadAddress('too short')
    version = data[0]
    const = _polymod(_hrp_expand(hrp) + data)
    if version > 16 or const != (1 if version == 0 else 0x2bc830a3):
        raise BadAddress('bad checksum for this witness version')
    program = bytes(_convert(data[1:-6], 5, 8, False))
    if not 2 <= len(program) <= 40 or (version == 0 and len(program) not in (20, 32)):
        raise BadAddress('bad witness program length')
    return version, program


def spk_from_address(network, addr):
    version, program = segwit_decode(HRP[network], addr)
    return bytes([0x50 + version if version else 0, len(program)]) + program


def address_from_spk(network, spk):
    if len(spk) >= 4 and spk[1] == len(spk) - 2 and (spk[0] == 0 or 0x51 <= spk[0] <= 0x60):
        return segwit_encode(HRP[network], spk[0] - 0x50 if spk[0] else 0, spk[2:])
    raise BadAddress('not a witness program')


# ── scripts ──────────────────────────────────────────────────────────────────
OP_DROP, OP_CHECKMULTISIG, OP_RETURN = 0x75, 0xae, 0x6a
THREAD_TAG = b'bloch.bbtc.vault.v1'
MARKER_TAG = b'BBTC\x02'  # version 2: the operations byte (burns set aside, late payments)
MAX_KEYS = 15


def sorted_keys(keys):
    """Lexicographic (BIP67) order, distinct, valid points."""
    keys = sorted(bytes(k) for k in keys)
    for k in keys:
        decompress(k)
    if len(set(keys)) != len(keys) or not 1 <= len(keys) <= MAX_KEYS:
        raise BadKey('the committee keys must be 1..15 distinct compressed public keys')
    return keys


def multisig_script(threshold, keys):
    keys = sorted_keys(keys)
    if not 1 <= threshold <= len(keys):
        raise BadKey('threshold out of range')
    return bytes([0x50 + threshold]) + b''.join(b'\x21' + k for k in keys) + bytes([0x50 + len(keys), OP_CHECKMULTISIG])


def vault_id(network, anchor_txid, anchor_vout):
    """12 bytes binding every deposit address to one vault thread on one network."""
    return sha256(THREAD_TAG + bytes.fromhex(GENESIS[network]) + bytes.fromhex(anchor_txid)
                  + anchor_vout.to_bytes(4, 'little'))[:12]


def deposit_script(threshold, keys, vid, recipient20):
    """<vault id || L2 recipient> OP_DROP <k-of-n multisig>: the recipient is committed by the address itself."""
    if len(vid) != 12 or len(recipient20) != 20 or not any(recipient20):
        raise BadAddress('a deposit script names a 12-byte vault id and a non-zero 20-byte L2 address')
    return b'\x20' + vid + recipient20 + bytes([OP_DROP]) + multisig_script(threshold, keys)


def p2wsh(script):
    return b'\x00\x20' + sha256(script)


def p2wpkh(h160):
    return b'\x00\x14' + h160


def is_standard_payout(spk):
    """What a release may pay: P2WPKH only (the token's burn names 20 bytes)."""
    return len(spk) == 22 and spk[:2] == b'\x00\x14'


# ── transactions ─────────────────────────────────────────────────────────────


def compact(n):
    if n < 253:
        return bytes([n])
    if n < 65536:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def ser_script(b):
    return compact(len(b)) + b


SEQUENCE = 0xfffffffd  # opt-in replace-by-fee (BIP125), no relative lock


class Tx:
    """A version-2 transaction of the vault. inputs: [(txid_hex, vout)], outputs: [(sats, spk)]."""

    def __init__(self, inputs, outputs, witnesses=None):
        self.inputs = [(t, int(v)) for t, v in inputs]
        self.outputs = [(int(s), bytes(k)) for s, k in outputs]
        self.witnesses = witnesses

    def _ins(self):
        return b''.join(bytes.fromhex(t)[::-1] + v.to_bytes(4, 'little') + b'\x00' + SEQUENCE.to_bytes(4, 'little')
                        for t, v in self.inputs)

    def _outs(self):
        return b''.join(s.to_bytes(8, 'little') + ser_script(k) for s, k in self.outputs)

    def stripped(self):
        return (b'\x02\x00\x00\x00' + compact(len(self.inputs)) + self._ins() + compact(len(self.outputs))
                + self._outs() + b'\x00\x00\x00\x00')

    def serialize(self):
        if not self.witnesses:
            return self.stripped()
        wit = b''.join(compact(len(w)) + b''.join(ser_script(i) for i in w) for w in self.witnesses)
        return (b'\x02\x00\x00\x00\x00\x01' + compact(len(self.inputs)) + self._ins() + compact(len(self.outputs))
                + self._outs() + wit + b'\x00\x00\x00\x00')

    parsed_txid = None
    script_sigs = None

    def txid(self):
        return self.parsed_txid or sha256d(self.stripped())[::-1].hex()

    def sighash(self, index, script_code, value):
        """BIP143, SIGHASH_ALL."""
        prevouts = sha256d(b''.join(bytes.fromhex(t)[::-1] + v.to_bytes(4, 'little') for t, v in self.inputs))
        sequences = sha256d(SEQUENCE.to_bytes(4, 'little') * len(self.inputs))
        outputs = sha256d(self._outs())
        t, v = self.inputs[index]
        return sha256d(b'\x02\x00\x00\x00' + prevouts + sequences + bytes.fromhex(t)[::-1] + v.to_bytes(4, 'little')
                       + ser_script(script_code) + value.to_bytes(8, 'little') + SEQUENCE.to_bytes(4, 'little')
                       + outputs + b'\x00\x00\x00\x00' + b'\x01\x00\x00\x00')


def witness_size(threshold, script_len):
    """Serialized witness bytes of one k-of-n input with 72-byte signatures (low s; r may carry a pad byte)."""
    return 1 + 1 + threshold * 73 + len(compact(script_len)) + script_len


def vsize(n_thread_like, n_deposit, out_spk_lens, threshold, thread_script_len, deposit_script_len):
    """Virtual size the builder charges for: exact for the base, upper bound for the witness."""
    n_in = n_thread_like + n_deposit
    base = 4 + len(compact(n_in)) + 41 * n_in + len(compact(len(out_spk_lens))) \
        + sum(8 + len(compact(l)) + l for l in out_spk_lens) + 4
    wit = 2 + n_thread_like * witness_size(threshold, thread_script_len) \
        + n_deposit * witness_size(threshold, deposit_script_len)
    return (4 * base + wit + 3) // 4


# ── the marker: the vault's state, carried by every vault transaction ────────
MARKER_PAYLOAD = 80  # bytes; the OP_RETURN payload limit of the oldest relay policy still deployed
MARKER_FIXED = 40    # tag, four 8-byte fields, the fee rate, the operations byte
MAX_BITMAP = MARKER_PAYLOAD - MARKER_FIXED  # bytes of bitmap when the transaction sets nothing aside and pays no late burn
MAX_LATE = 4         # late payments (burns set aside earlier) one vault transaction may carry


class Marker:
    """State after a vault transaction, and what the transaction did to the burns that were set aside.

    next_deposit  nonce the next swept deposit takes (deposit nonces are 0, 1, 2, ...)
    burn_base     every burn nonce <= burn_base is SETTLED: paid, or set aside (burn nonces start at 1)
    liabilities   sats owed for L2 value: credited deposits minus paid burns, in sats (100 per token unit). A burn that
                  is set aside and not yet paid is still inside this number: its coins stay in the vault
    owner_due     fee sats owed to the owner's address and not yet paid out
    feerate       sat/vB this transaction charged its items (lets anyone recompute every credit and payout)
    paid          burn nonces > burn_base already settled (a set; encoded as a bitmap)

    Two fields describe THIS transaction only (they are not state; the set of burns set aside and still unpaid is
    rebuilt by replaying the thread, btc_policy.replay_tx):
    aside_through 0, or a burn nonce T: every nonce in (parent's burn_base, T] that the parent had not settled is set
                  aside by this transaction: counted as settled so the window moves on, NOT paid, payable later
    late          burn nonces set aside by an earlier transaction that this transaction pays (ascending, at most 4)
    """

    def __init__(self, next_deposit=0, burn_base=0, liabilities=0, owner_due=0, feerate=0, paid=(), aside_through=0, late=()):
        self.next_deposit, self.burn_base = next_deposit, burn_base
        self.liabilities, self.owner_due, self.feerate = liabilities, owner_due, feerate
        self.paid = frozenset(paid)
        self.aside_through, self.late = aside_through, tuple(late)

    def normalised(self):
        base, paid = self.burn_base, set(self.paid)
        while base + 1 in paid:
            base += 1
            paid.discard(base)
        return Marker(self.next_deposit, base, self.liabilities, self.owner_due, self.feerate, paid, self.aside_through, self.late)

    def is_paid(self, nonce):
        """Settled in the marker: paid, or set aside. Whether a settled burn was PAID needs the replayed set of
        burns set aside (`settled_unpaid` of the thread state): see btc_policy.burn_paid."""
        return nonce <= self.burn_base or nonce in self.paid

    def encode(self):
        m = self.normalised()
        for v, bits in ((m.next_deposit, 64), (m.burn_base, 64), (m.liabilities, 64), (m.owner_due, 64), (m.feerate, 16),
                        (m.aside_through, 64)):
            if not 0 <= v < 1 << bits:
                raise ValueError('marker field out of range')
        late = list(m.late)
        if len(late) > MAX_LATE or late != sorted(set(late)) or any(not 0 < n < 1 << 64 for n in late):
            raise ValueError('at most 4 late payments per vault transaction, ascending')
        ops = bytes([(0x80 if m.aside_through else 0) | len(late)])
        if m.aside_through:
            ops += m.aside_through.to_bytes(8, 'big')
        ops += b''.join(n.to_bytes(8, 'big') for n in late)
        room = MARKER_PAYLOAD - (MARKER_FIXED - 1) - len(ops)
        bitmap = bytearray(room)
        for n in m.paid:
            i = n - m.burn_base - 1
            if not 0 <= i < 8 * room:
                raise ValueError('a paid burn lies outside the marker window; pay the older burns first, or set aside '
                                 'the ones that cannot be paid now')
            bitmap[i // 8] |= 1 << (i % 8)
        payload = (MARKER_TAG + m.next_deposit.to_bytes(8, 'big') + m.burn_base.to_bytes(8, 'big')
                   + m.liabilities.to_bytes(8, 'big') + m.owner_due.to_bytes(8, 'big') + m.feerate.to_bytes(2, 'big')
                   + ops + bytes(bitmap).rstrip(b'\0'))
        return bytes([OP_RETURN]) + (bytes([len(payload)]) if len(payload) < 76 else b'\x4c' + bytes([len(payload)])) + payload

    @staticmethod
    def decode(spk):
        if len(spk) < 2 or spk[0] != OP_RETURN:
            raise ValueError('not a marker')
        body = spk[2:] if spk[1] < 76 else spk[3:]
        declared = spk[1] if spk[1] < 76 else (spk[2] if spk[1] == 0x4c and len(spk) > 2 else -1)
        if declared != len(body) or not MARKER_FIXED <= len(body) <= MARKER_PAYLOAD or body[:5] != MARKER_TAG:
            raise ValueError('not a marker')
        f = lambda o, n: int.from_bytes(body[o:o + n], 'big')
        base, ops, at = f(13, 8), body[39], MARKER_FIXED
        if ops & 0x70 or (ops & 0x0f) > MAX_LATE:
            raise ValueError('non-canonical marker')
        through = 0
        if ops & 0x80:
            through, at = f(at, 8), at + 8
        late = []
        for _ in range(ops & 0x0f):
            late.append(f(at, 8))
            at += 8
        if at > len(body):
            raise ValueError('non-canonical marker')
        paid = {base + 1 + i for i in range(8 * (len(body) - at)) if body[at + i // 8] >> (i % 8) & 1}
        m = Marker(f(5, 8), base, f(21, 8), f(29, 8), f(37, 2), paid, through, late)
        try:
            same = m.encode() == spk
        except ValueError:
            same = False
        if not same:
            raise ValueError('non-canonical marker')
        return m

    def as_dict(self):
        return {'next_deposit': self.next_deposit, 'burn_base': self.burn_base, 'liabilities': self.liabilities,
                'owner_due': self.owner_due, 'feerate': self.feerate, 'paid': sorted(self.paid),
                'aside_through': self.aside_through, 'late': list(self.late)}


# ── L2 identities (what BridgedStablecoinV3 binds) ───────────────────────────


def abi_word(v):
    if isinstance(v, bytes):
        return v.rjust(32, b'\0') if len(v) == 20 else v.ljust(32, b'\0')
    return int(v).to_bytes(32, 'big')


def source_chain_id(network):
    """The token's `sourceChainId`: the network's genesis block hash as an integer (no EVM chain id collides)."""
    return int(GENESIS[network], 16)


def source_route(network, threshold, keys, anchor_txid, anchor_vout, policy_hash, owner_spk):
    """The token's `sourceRoute`: commits the L2 token to the network, committee, thread anchor, policy and fee address."""
    return sha256(b'bloch.bbtc.route.v1' + bytes.fromhex(GENESIS[network]) + sha256(multisig_script(threshold, keys))
                  + bytes.fromhex(anchor_txid) + anchor_vout.to_bytes(4, 'little') + policy_hash + sha256(owner_spk))


def source_vault(threshold, keys):
    """The token's `sourceVault` (an address-sized commitment; nothing is deployed there): low 20 bytes of the
    thread script hash. The token refuses it as a burn recipient, which costs nothing here."""
    return sha256(multisig_script(threshold, keys))[12:]


def outpoint_sender(txid, vout):
    """The 20 bytes standing where the Ethereum vault puts the depositor: a commitment to the Bitcoin outpoint."""
    return sha256(b'bloch.bbtc.outpoint.v1' + bytes.fromhex(txid) + vout.to_bytes(4, 'little'))[:20]


def deposit_id(route, nonce, sender20, amount_units, recipient20):
    """ProvenanceSourceVault.depositId, byte for byte (tools/signatario-stable/signatario.py `deposit_id`, provenance)."""
    h = sha256(b'BLOCH-USDT-DEPOSIT-v2'.ljust(32, b'\0') + route + abi_word(nonce) + abi_word(sender20)
               + abi_word(amount_units) + abi_word(recipient20))
    return nonce.to_bytes(8, 'big') + h[8:]


def mint_chain_genesis(chain_id, vault20, route):
    return keccak256(b'BLOCH-USDT-MINT-CHAIN-v1'.ljust(32, b'\0') + abi_word(chain_id) + abi_word(vault20) + route)


def mint_chain_step(head, dep_id, amount_units, recipient20):
    return keccak256(head + dep_id + abi_word(amount_units) + abi_word(recipient20))


def parse_tx(raw):
    """Any serialized Bitcoin transaction -> (Tx, version, locktime, sequences). General: legacy, nested-segwit,
    coinbase and taproot spends all parse (the scriptSigs are kept in `tx.script_sigs`). Strict about the encoding:
    truncated, oversized or trailing bytes raise ValueError and nothing else. What makes a transaction a VAULT
    transaction (version 2, locktime 0, the fixed sequence, empty scriptSigs) is checked by the caller that needs it
    (btc_vault.VaultView._replay), never here: this parser also reads strangers' transactions."""
    if not isinstance(raw, (bytes, bytearray)) or not 10 <= len(raw) <= 4_000_000:
        raise ValueError('not a transaction')
    raw = bytes(raw)
    pos = 0

    def take(n):
        nonlocal pos
        if n < 0 or pos + n > len(raw):
            raise ValueError('truncated transaction')
        pos += n
        return raw[pos - n:pos]

    def varint():
        first = take(1)[0]
        if first < 253:
            return first
        value = int.from_bytes(take({253: 2, 254: 4, 255: 8}[first]), 'little')
        if value > len(raw):
            raise ValueError('a count larger than the transaction')
        return value

    version = int.from_bytes(take(4), 'little')
    segwit = raw[4:6] == b'\x00\x01'
    if segwit:
        take(2)
    body_start = pos
    inputs, sequences, script_sigs = [], [], []
    for _ in range(varint()):
        txid = take(32)[::-1].hex()
        vout = int.from_bytes(take(4), 'little')
        script_sigs.append(take(varint()))
        inputs.append((txid, vout))
        sequences.append(int.from_bytes(take(4), 'little'))
    outputs = []
    for _ in range(varint()):
        sats = int.from_bytes(take(8), 'little')
        outputs.append((sats, take(varint())))
    body_end = pos
    witnesses = None
    if segwit:
        witnesses = [[take(varint()) for _ in range(varint())] for _ in inputs]
    locktime = int.from_bytes(take(4), 'little')
    if pos != len(raw) or not inputs or not outputs:
        raise ValueError('malformed transaction')
    tx = Tx(inputs, outputs, witnesses)
    tx.script_sigs = script_sigs
    # the identity of the transaction as serialized (any version, sequence or locktime), not as the vault would write it
    tx.parsed_txid = sha256d(raw[:4] + raw[body_start:body_end] + raw[-4:])[::-1].hex()
    return tx, version, locktime, sequences


# ── signed requests from L2 accounts (EIP-191 personal messages) ─────────────


def personal_digest(text):
    data = text.encode()
    return keccak256(b'\x19Ethereum Signed Message:\n' + str(len(data)).encode() + data)


def signer_of(text, signature_hex):
    """The Ethereum address that signed `text` as a personal message (`cast wallet sign TEXT`, any wallet's personal_sign)."""
    sig = bytes.fromhex(str(signature_hex).removeprefix('0x'))
    return eth_address(recover(personal_digest(text), *parse_rsv(sig)))


def refund_text(vault_id, txid, vout, bitcoin_address):
    """What the L2 recipient of an unswept deposit signs to have it sent back."""
    return (f'bloch.bbtc.refund.v1: refund the deposit {txid}:{vout} of vault {vault_id.hex()} '
            f'to the Bitcoin address {bitcoin_address}')


def p2wpkh_hash(network, bitcoin_address):
    """The 20-byte key hash of a P2WPKH address of this network; anything else raises BadAddress."""
    spk = spk_from_address(network, bitcoin_address)
    if not is_standard_payout(spk) or not any(spk[2:]):
        raise BadAddress('not a P2WPKH address')
    return spk[2:]
