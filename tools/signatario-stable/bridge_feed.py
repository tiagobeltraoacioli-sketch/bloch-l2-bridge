#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bridge partial signatures over sigfeed: what a signer publishes, what it accepts, where it keeps it.

Feed layout (static files, one per signer per item, so the size is bounded by construction):
  bridge/<token>/mint/<depositId>/<signer>.json      one mint partial
  bridge/<token>/release/<burnId>/<signer>.json      {"certs": [...]}: at most MAX_CERTS live certificates

A reader asks only for deposits and burns it discovered on its own nodes, and only for the pinned
signers. A body is accepted only if every signed field is what this bridge expects, the digest
recomputes locally, and the signature recovers to the signer named by the path. Fields that are not
covered by the signature are dropped before storing, so nothing unauthenticated travels on. Because
only verified items enter `shared_dir`, re-exporting it lets any operator relay the others' signatures:
a server can withhold or delay, but it cannot forge, and it cannot evict what a reader already holds.
"""
import hashlib
import json
from pathlib import Path
import threading
import time

import sigfeed

MAX_CERTS = 4
MAX_ROUNDS_PER_BURN = 32
MAX_OPEN_ITEMS = 512
SECP_P = 2**256 - 2**32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
_KECCAK_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
              0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
              0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
              0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
              0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_KECCAK_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = 2**64 - 1


def keccak256(data):
    """Keccak-256 (Ethereum's, not NIST SHA3-256)."""
    rate = 136
    padded = bytearray(data) + b'\x01' + b'\0' * ((rate - (len(data) + 1) % rate) % rate)
    padded[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(padded[off + i * 8:off + i * 8 + 8], 'little')
        for rc in _KECCAK_RC:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x + 4) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    v, r = a[x][y] ^ d[x], _KECCAK_ROT[x][y]
                    b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & _M64 if r else v
            for x in range(5):
                for y in range(5):
                    a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y] & _M64)
            a[0][0] ^= rc
    out = b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(rate // 8))
    return out[:32]


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % SECP_P == 0:
            return None
        s = 3 * p[0] * p[0] * pow(2 * p[1], -1, SECP_P) % SECP_P
    else:
        s = (q[1] - p[1]) * pow(q[0] - p[0], -1, SECP_P) % SECP_P
    x = (s * s - p[0] - q[0]) % SECP_P
    return x, (s * (p[0] - x) - p[1]) % SECP_P


def _mul(k, p):
    out = None
    while k:
        if k & 1:
            out = _add(out, p)
        p = _add(p, p)
        k >>= 1
    return out


def address_of(point):
    return '0x' + keccak256(point[0].to_bytes(32, 'big') + point[1].to_bytes(32, 'big'))[12:].hex()


def recover(digest, signature):
    """ecrecover over 32 + 65 bytes, low-s and v in {27, 28} only. Returns the address or None."""
    if len(digest) != 32 or len(signature) != 65:
        return None
    r, s, v = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:64], 'big'), signature[64]
    if v not in (27, 28) or not 0 < r < SECP_N or not 0 < s <= SECP_N // 2:
        return None
    y2 = (pow(r, 3, SECP_P) + 7) % SECP_P
    y = pow(y2, (SECP_P + 1) // 4, SECP_P)
    if y * y % SECP_P != y2:
        return None
    if y % 2 != v - 27:
        y = SECP_P - y
    e = int.from_bytes(digest, 'big')
    r_inv = pow(r, -1, SECP_N)
    q = _add(_mul(s * r_inv % SECP_N, (r, y)), _mul(-e * r_inv % SECP_N, SECP_G))
    return address_of(q) if q else None


class Bad(ValueError):
    pass


def _hex(value, nbytes, what):
    if not isinstance(value, str) or not value.startswith('0x') or len(value) != 2 + 2 * nbytes:
        raise Bad(f'{what}: not {nbytes} bytes of 0x hex')
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError:
        raise Bad(f'{what}: not hex') from None
    if value != value.lower():
        raise Bad(f'{what}: not lower case')
    return raw


def _uint(value, bits, what):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**bits:
        raise Bad(f'{what}: not a uint{bits}')
    return value.to_bytes(32, 'big')


def _word(raw):
    return raw.rjust(32, b'\0')


def _tag(text):
    return text.encode().ljust(32, b'\0')


def mint_digest(version, chain_id, token, source_chain, vault, route, deposit, nonce, amount, recipient):
    """BridgedStablecoin.mintDigest: EIP-712, as signatario.py computes it (all arguments are 32-byte words)."""
    domain_type = b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
    mint_type = (b'Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,'
                 b'uint64 depositNonce,uint64 amount,address recipient)')
    domain = keccak256(keccak256(domain_type) + keccak256(b'Bloch Bridged Stablecoin') + keccak256(version.encode())
                       + chain_id + token)
    struct = keccak256(keccak256(mint_type) + source_chain + vault + route + deposit + nonce + amount + recipient)
    return keccak256(b'\x19\x01' + domain + struct)


def release_digest(chain_id, vault, route, nonce, recipient, amount, burn, valid, anchor_n, anchor_h, native_n, native_h):
    """ContextBoundSourceVault.releaseDigest, as eth_half.py computes it (all arguments are 32-byte words)."""
    release_id = hashlib.sha256(_tag('BLOCH-USDT-RELEASE-v1') + route + nonce + recipient + amount + burn).digest()
    auth = keccak256(_tag('BLOCH-USDT-RELEASE-AUTH-v2') + chain_id + vault + release_id + valid + anchor_n + anchor_h
                     + native_n + native_h)
    return keccak256(b'\x19Ethereum Signed Message:\n32' + auth)


class Verifier:
    """Accepts a signature only for this bridge, this item and this signer."""

    def __init__(self, cfg, version, now=time.time):
        self.l2_chain = int(cfg['l2_chain_id'])
        self.token = cfg['token'].lower()
        self.source_chain = int(cfg['source_chain_id'])
        self.vault = cfg['source_vault'].lower()
        self.route = cfg['source_route'].lower()
        self.version = version  # callable: the token's EIP-712 version
        self.now = now          # callable: the Ethereum clock ("chain" or the wall clock)
        self.max_valid = int(cfg.get('max_valid_seconds', 3600))

    def _signature(self, doc, digest, signer):
        raw = _hex(doc.get('signature'), 65, 'signature')
        if recover(digest, raw) != signer:
            raise Bad('the signature does not recover to the signer')

    def mint(self, doc, deposit, signer):
        """The signed fields of a mint partial for `deposit` by `signer`, or Bad."""
        if not isinstance(doc, dict) or doc.get('kind') != 'stable-mint':
            raise Bad('not a mint partial')
        if doc.get('signer') != signer or doc.get('deposit_id') != deposit:
            raise Bad('names another signer or deposit')
        if (doc.get('l2_chain_id'), doc.get('token'), doc.get('source_chain_id'), doc.get('source_vault'),
                doc.get('source_route')) != (self.l2_chain, self.token, self.source_chain, self.vault, self.route):
            raise Bad('for another bridge')
        recipient = _hex(doc.get('recipient'), 20, 'recipient')
        got = _hex(doc.get('digest'), 32, 'digest')
        want = mint_digest(self.version(), _uint(self.l2_chain, 256, 'chain'), _word(bytes.fromhex(self.token[2:])),
                           _uint(self.source_chain, 256, 'source chain'), _word(bytes.fromhex(self.vault[2:])),
                           bytes.fromhex(self.route[2:]), _hex(deposit, 32, 'deposit'),
                           _uint(doc.get('deposit_nonce'), 64, 'nonce'), _uint(doc.get('amount'), 64, 'amount'),
                           _word(recipient))
        if got != want:
            raise Bad('the digest does not match the fields')
        self._signature(doc, want, signer)
        return {k: doc[k] for k in ('kind', 'signer', 'l2_chain_id', 'token', 'source_chain_id', 'source_vault',
                                    'source_route', 'deposit_id', 'deposit_nonce', 'amount', 'recipient', 'digest',
                                    'signature')} | {'signed': True}

    def release(self, doc, burn, signer):
        """The signed fields of a live release certificate for `burn` by `signer`, or Bad."""
        if not isinstance(doc, dict) or doc.get('kind') != 'stable-release':
            raise Bad('not a release certificate')
        if doc.get('signer') != signer or doc.get('source_chain_id') != self.source_chain \
                or doc.get('source_vault') != self.vault:
            raise Bad('names another signer or vault')
        rel, ctx = doc.get('release'), doc.get('context')
        if not isinstance(rel, dict) or not isinstance(ctx, dict):
            raise Bad('no release or context')
        if rel.get('nativeBurn') != burn or rel.get('route') != self.route:
            raise Bad('for another burn or route')
        valid = ctx.get('validUntil')
        if isinstance(valid, bool) or not isinstance(valid, int):
            raise Bad('validUntil is not an integer')
        now = int(self.now())
        if not now < valid <= now + self.max_valid:
            raise Bad('expired, or validUntil beyond the policy')
        got = _hex(doc.get('digest'), 32, 'digest')
        want = release_digest(_uint(self.source_chain, 256, 'chain'), _word(bytes.fromhex(self.vault[2:])),
                              bytes.fromhex(self.route[2:]), _uint(rel.get('nonce'), 64, 'nonce'),
                              _word(_hex(rel.get('recipient'), 20, 'recipient')), _uint(rel.get('amount'), 64, 'amount'),
                              _hex(burn, 32, 'burn'), _uint(valid, 256, 'validUntil'),
                              _uint(ctx.get('sourceAnchorNumber'), 256, 'anchor'),
                              _hex(ctx.get('sourceAnchorHash'), 32, 'anchor hash'),
                              _uint(ctx.get('nativeFinalizedNumber'), 64, 'native number'),
                              _hex(ctx.get('nativeFinalizedHash'), 32, 'native hash'))
        if got != want:
            raise Bad('the digest does not match the fields')
        self._signature(doc, want, signer)
        return {k: doc[k] for k in ('kind', 'signer', 'source_chain_id', 'source_vault', 'digest', 'signature')} \
            | {'signed': True,
               'release': {k: rel[k] for k in ('route', 'nonce', 'recipient', 'amount', 'nativeBurn')},
               'context': {k: ctx[k] for k in ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash',
                                               'nativeFinalizedNumber', 'nativeFinalizedHash')}}


def round_name(cert):
    c = cert['context']
    return f"r-{c['validUntil']}-{c['sourceAnchorNumber']}-{cert['digest'][2:]}"


def parse_json(body):
    try:
        return json.loads(body.decode('utf-8'))
    except (ValueError, RecursionError):
        raise Bad('not JSON') from None


class BridgeFeed:
    """A signer's or relayer's view: pulls into `shared_dir` (private, verified) and exports to `publish_dir`."""

    def __init__(self, cfg, version, now, log):
        f = cfg['feed']
        self.shared = Path(cfg['shared_dir'])
        self.publish = Path(f['publish_dir']) if f.get('publish_dir') else None
        self.prefix = f"bridge/{cfg['token'].lower()[2:]}"
        self.mint_signers = [a.lower() for a in f['mint_signers']]
        self.release_signers = [a.lower() for a in f['release_signers']]
        self.peers = sigfeed.Peers(f.get('peers', []))
        self.verify = Verifier(cfg, version, now)
        self.now, self.log = now, log
        self.max_store = int(f.get('max_store_bytes', 256 * 2**20))
        self.min_free = int(f.get('min_free_bytes', 2**30))
        self.peer_budget = float(f.get('peer_budget', 20))
        self.fetch_deadline = float(f.get('fetch_deadline', 5))
        self.ca_file = f.get('ca_file')
        self.status_file = Path(f['status_file']) if f.get('status_file') else None
        self.lock = threading.Lock()
        self.used = 0
        self.full_logged = False

    # ── ingest ───────────────────────────────────────────────────────────────
    def room(self, size):
        """Verified data still has a ceiling; a full store refuses ingest, and signing carries on."""
        if self.used + size > self.max_store or sigfeed.disk_free(self.shared) < self.min_free:
            if not self.full_logged:
                self.log(kind='feed-store-full', used=self.used, max=self.max_store)
                self.full_logged = True
            return False
        self.used += size
        return True

    def store(self, path, doc):
        data = (json.dumps(doc, sort_keys=True, indent=1) + '\n').encode()
        with self.lock:
            if path.exists():
                return True
            if not self.room(len(data)):
                return False
            sigfeed.atomic_write(path, data)
        return True

    def accept(self, path, body, url):
        """Called by sigfeed.pull with an untrusted body from `url`."""
        parts = path.split('/')
        kind, item, signer = parts[2], '0x' + parts[3], '0x' + parts[4][:-5]
        try:
            doc = parse_json(body)
            if kind == 'mint':
                clean = self.verify.mint(doc, item, signer)
                return self.store(self.shared / 'mint' / item[2:] / f'{signer[2:]}.json', clean)
            if not isinstance(doc, dict) or not isinstance(doc.get('certs'), list) or len(doc['certs']) > MAX_CERTS:
                raise Bad('not a certificate list')
            d = self.shared / 'release' / item[2:]
            taken, problems = 0, []
            for cert in doc['certs']:
                try:  # one stale or forged entry does not cost the signer's live certificates
                    clean = self.verify.release(cert, item, signer)
                    rnd = d / round_name(clean)
                    if not rnd.exists() and sum(1 for _ in d.glob('r-*')) >= MAX_ROUNDS_PER_BURN:
                        raise Bad('too many rounds for this burn')
                    taken += self.store(rnd / f'{signer[2:]}.json', clean)
                except Bad as e:
                    problems.append(str(e))
            if problems:
                self.log(kind='feed-rejected', peer=url, path=path, reason=problems[0], count=len(problems))
            return taken > 0
        except Bad as e:
            self.log(kind='feed-rejected', peer=url, path=path, reason=str(e))
            return False

    def sync(self, deposits, burns):
        """Pull what these open items still lack, then export. Items come from the caller's own chain view."""
        deposits, burns = deposits[:MAX_OPEN_ITEMS], burns[:MAX_OPEN_ITEMS]
        # The quota covers open items, so finished history can never stall a later deposit.
        self.used = sigfeed.tree_bytes(*[self.shared / 'mint' / d[2:] for d in deposits],
                                       *[self.shared / 'release' / b[2:] for b in burns])
        self.full_logged = False
        self.prune(burns)
        paths = []
        for dep in deposits:
            have = self.mint_have(dep)
            paths += [f'{self.prefix}/mint/{dep[2:]}/{s[2:]}.json' for s in self.mint_signers if s not in have]
        if paths:
            sigfeed.pull(self.peers, paths, self.accept, fetch_deadline=self.fetch_deadline,
                         peer_budget=self.peer_budget, ca_file=self.ca_file)
        paths = [f'{self.prefix}/release/{b[2:]}/{s[2:]}.json' for b in burns for s in self.release_signers]
        if paths:  # a signer's certificates change round by round: every peer is asked, and the union kept
            sigfeed.pull(self.peers, paths, self.accept, fetch_deadline=self.fetch_deadline,
                         peer_budget=self.peer_budget, ca_file=self.ca_file, first_wins=False)
        self.export(deposits, burns)
        self.write_status()

    def mint_have(self, dep):
        have = set()
        for f in (self.shared / 'mint' / dep[2:]).glob('*.json'):
            doc = load(f)
            if doc:
                have.add(doc.get('signer'))
        return have

    # ── export ───────────────────────────────────────────────────────────────
    def export(self, deposits, burns):
        if self.publish is None:
            return
        for dep in deposits:
            for f in (self.shared / 'mint' / dep[2:]).glob('*.json'):
                doc = load(f)
                if doc and doc.get('signer') in self.mint_signers:
                    self.put(f"mint/{dep[2:]}/{doc['signer'][2:]}.json", doc)
        for burn in burns:
            per_signer = {}
            for rnd in sorted((self.shared / 'release' / burn[2:]).glob('r-*'), reverse=True):
                for f in rnd.glob('*.json'):
                    doc = load(f)
                    if doc and doc.get('signer') in self.release_signers:
                        certs = per_signer.setdefault(doc['signer'], [])
                        if len(certs) < MAX_CERTS and all(c['digest'] != doc['digest'] for c in certs):
                            certs.append(doc)
            for signer, certs in per_signer.items():
                self.put(f'release/{burn[2:]}/{signer[2:]}.json', {'certs': certs})

    def put(self, rel, doc):
        doc = {k: v for k, v in doc.items() if k not in ('eth', 'l2')} if 'certs' not in doc else \
            {'certs': [{k: v for k, v in c.items() if k not in ('eth', 'l2')} for c in doc['certs']]}
        data = (json.dumps(doc, sort_keys=True, indent=1) + '\n').encode()
        path = self.publish / self.prefix / rel
        if not path.exists() or path.read_bytes() != data:
            sigfeed.atomic_write(path, data)

    def retire(self, kind, item):
        """The item is finished on chain: nobody needs its signatures any more."""
        if self.publish is None:
            return
        d = self.publish / self.prefix / kind / item[2:]
        for f in d.glob('*.json'):
            f.unlink(missing_ok=True)
        if d.exists():
            try:
                d.rmdir()
            except OSError:
                pass

    def prune(self, burns):
        now = int(self.now())
        for burn in burns:
            for rnd in (self.shared / 'release' / burn[2:]).glob('r-*'):
                try:
                    expired = int(rnd.name.split('-')[1]) <= now
                except (IndexError, ValueError):
                    expired = True
                if expired:
                    for f in rnd.iterdir():
                        f.unlink(missing_ok=True)
                    rnd.rmdir()

    def write_status(self):
        if self.status_file is None:
            return
        doc = {'t': int(time.time()), 'peers': self.peers.status(), 'store_bytes': self.used}
        sigfeed.atomic_write(self.status_file, (json.dumps(doc, indent=1) + '\n').encode())


def load(path):
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def agreeing(files, need):
    """The files of one message signed by at least `need` distinct signers, one per signer.
    A forged, corrupt or dissenting partial is left out, so it cannot veto the honest group."""
    groups = {}
    for f in sorted(files):
        doc = load(f)
        if doc and isinstance(doc.get('digest'), str) and isinstance(doc.get('signer'), str):
            groups.setdefault(doc['digest'], {}).setdefault(doc['signer'], f)
    for group in groups.values():
        if len(group) >= need:
            return list(group.values())
    return []


def round_rank(rnd):
    """(distinct signers, name): the comparison signers converge on."""
    signers = {d.get('signer') for d in map(load, rnd.glob('*.json')) if d}
    return len(signers), rnd.name
