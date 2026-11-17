#!/usr/bin/env python3
"""Shared by the unit tests of the Solana bridge tools: throwaway signers and a fake L2.

Nothing here is used by the tools. The Ed25519 and secp256k1 SIGNING below exists only so that tests can make
signatures; the tools verify and never sign with anyone's key.
"""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_proof  # noqa: E402
import sol_recipient  # noqa: E402
import test_solana_tools as T  # noqa: E402


def compress(point):
    return (point[1] | ((point[0] & 1) << 255)).to_bytes(32, 'little')


def ed25519_keypair(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little') & ((1 << 254) - 8) | (1 << 254)
    return a, h[32:], compress(S._edwards_mul(a, S._BASE))


def ed25519_sign(seed, message):
    a, prefix, public = ed25519_keypair(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), 'little') % S._L
    big_r = compress(S._edwards_mul(r, S._BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), 'little') % S._L
    return big_r + ((r + k * a) % S._L).to_bytes(32, 'little')


def secp_sign(key, digest):
    k = int.from_bytes(S.sha256(key.to_bytes(32, 'big') + digest), 'big') % S._SN
    point = S._secp_mul(k, S._SG)
    r = point[0] % S._SN
    s = pow(k, S._SN - 2, S._SN) * (int.from_bytes(digest, 'big') + r * key) % S._SN
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + (point[1] & 1)])


def secp_address(key):
    q = S._secp_mul(key, S._SG)
    return S.keccak256(q[0].to_bytes(32, 'big') + q[1].to_bytes(32, 'big'))[12:]


def seed_of(label):
    return S.sha256(('bloch test wallet ' + label).encode())


def wallet_of(label):
    """(seed, 32-byte address, base58) of a throwaway wallet."""
    seed = seed_of(label)
    public = ed25519_keypair(seed)[2]
    return seed, public, S.b58encode(public)


def keyless_address(label):
    """32 bytes on the curve and not of small order that no test holds a key for (a hash)."""
    key = S.sha256(('nobody holds a key for ' + label).encode())
    while not S.on_curve(key) or S.small_order(key):
        key = S.sha256(key)
    return key


def make_proof(seed, message, tag=0, domain=None):
    public = ed25519_keypair(seed)[2]
    covered = sol_proof.covered_bytes(tag, message.encode('ascii'), public, domain)
    return bytes([tag]) + ed25519_sign(seed, covered) + (domain or b'')


def word(v):
    return int(v).to_bytes(32, 'big')


def dynamic(data):
    return word(len(data)) + data.ljust((len(data) + 31) // 32 * 32, b'\0')


class L2:
    """A fake L2 with one token and one burn router: the JSON-RPC answers the tools ask for."""

    BURNER = '0x' + 'ab' * 20
    CODE = b'\x60\x80 the pinned router code'

    def __init__(self, case, cluster, chain_id=700771):
        self.c, self.chain_id = cluster, chain_id
        self.router, self.token = '0x' + '11' * 20, '0x' + '22' * 20
        self.code, self.mint, self.route = self.CODE, cluster.config.mint, cluster.a.route
        self.router_token = self.token
        self.logs, self.burn_nonce, self.router_nonce, self.block = [], 0, {}, 100
        self.fake = T.Fake(self.answer)
        case.addCleanup(self.fake.close)

    def cfg(self, **more):
        return dict({'l2_rpc': self.fake.url, 'burn_router': self.router, 'l2_chain_id': self.chain_id, 'token': self.token,
                     'burn_router_code_keccak': S.hx(S.keccak256(self.CODE))}, **more)

    # ── what happens on the L2 ──────────────────────────────────────────────
    def _burned(self, sender, amount, recipient20):
        self.burn_nonce += 1
        self.block += 1
        burn_id = S.hx(S.keccak256(b'burn' + word(self.burn_nonce)))
        self.logs.append({'address': self.token, 'blockNumber': hex(self.block), 'transactionHash': S.hx(S.sha256(burn_id.encode())),
                          'topics': [sol_recipient.topic(sol_recipient.BURNED_EVENT), burn_id, S.hx(word(self.burn_nonce)),
                                     '0x' + '00' * 12 + sender[2:]],
                          'data': S.hx(word(amount) + bytes(12) + recipient20 + word(2) + word(201 * 10**6) + self.c.state['head'])})
        return {'burn_id': burn_id, 'nonce': self.burn_nonce, 'amount': amount, 'recipient': S.hx(recipient20), 'from': sender,
                'mint_count': 2, 'minted_total': 201 * 10**6, 'mint_head': S.hx(self.c.state['head']), 'block': self.block}

    def next_nonce(self, burner):
        n = self.router_nonce.get(burner, 0)
        self.router_nonce[burner] = n + 1
        return n

    def message(self, text, burner, amount, nonce):
        return sol_proof.exit_message(text, burner, amount, nonce, self.router, S.hx(self.route), self.chain_id)

    def exit(self, label=None, amount=10**7, burner=None, tag=0, text=None, proof=None, signer=None, domain=None):
        """A burn through the router to the wallet `label` (or the address `text`), with its proof."""
        burner = burner or self.BURNER
        seed, public, shown = wallet_of(label) if label else (None, S.pubkey(text), text)
        text = text or shown
        wallet = S.pubkey(text)
        nonce = self.next_nonce(burner)
        if proof is None:
            proof = make_proof(seed_of(signer) if signer else seed, self.message(text, burner, amount, nonce), tag, domain)
        burn = self._burned(self.router, amount, S.account_id(wallet))
        data = (word(amount) + bytes(12) + S.account_id(wallet) + word(192) + word(nonce)
                + word(192 + len(dynamic(text.encode()))) + S.sha256(b'exit hash') + dynamic(text.encode()) + dynamic(proof))
        self.logs.append({'address': self.router, 'blockNumber': hex(self.block), 'transactionHash': '0x' + '00' * 32,
                          'topics': [sol_recipient.topic(sol_recipient.EXIT_EVENT), burn['burn_id'], '0x' + '00' * 12 + burner[2:]],
                          'data': S.hx(data)})
        return dict(burn, burner=burner, wallet=wallet, text=text, router_nonce=nonce)

    def direct(self, recipient20, amount=10**7, burner=None):
        burner = burner or self.BURNER
        return dict(self._burned(burner, amount, recipient20), burner=burner)

    def redirect(self, burn, label=None, sender=None, tag=0, text=None, proof=None, signer=None, nonce=None, burner_in_message=None):
        """`redirectHeldBurn(burn, wallet, nonce, proof)` sent by `sender` (default: the burn's burner)."""
        sender = sender or burn['burner']
        seed, public, shown = wallet_of(label) if label else (None, S.pubkey(text), text)
        text = text or shown
        nonce = self.next_nonce(sender) if nonce is None else nonce
        if proof is None:
            message = sol_proof.redirect_message(text, burner_in_message or sender, burn['burn_id'], nonce, self.router,
                                                 S.hx(self.route), self.chain_id)
            proof = make_proof(seed_of(signer) if signer else seed, message, tag)
        self.block += 1
        data = word(nonce) + bytes(12) + S.account_id(S.pubkey(text)) + word(128) + word(128 + len(dynamic(text.encode()))) \
            + dynamic(text.encode()) + dynamic(proof)
        self.logs.append({'address': self.router, 'blockNumber': hex(self.block), 'transactionHash': '0x' + '00' * 32,
                          'topics': [sol_recipient.topic(sol_recipient.REDIRECT_EVENT), burn['burn_id'], '0x' + '00' * 12 + sender[2:]],
                          'data': S.hx(data)})
        return {'nonce': nonce, 'wallet': S.pubkey(text), 'text': text, 'block': self.block}

    # ── JSON-RPC ────────────────────────────────────────────────────────────
    def answer(self, method, params):
        if method == 'eth_chainId':
            return hex(self.chain_id)
        if method == 'eth_getCode':
            return S.hx(self.code) if params[0].lower() == self.router else '0x'
        if method == 'eth_call':
            if params[0]['to'].lower() == self.router:
                for signature, value in (('solanaMint()', self.mint), ('route()', self.route),
                                         ('token()', bytes(12) + bytes.fromhex(self.router_token[2:]))):
                    if params[0]['data'] == S.hx(S.keccak256(signature.encode())[:4]):
                        return S.hx(value)
            raise KeyError('eth_call')
        if method == 'eth_getLogs':
            f = params[0]
            top = 10**9 if f.get('toBlock') in ('latest', 'finalized', 'safe', None) else int(f['toBlock'], 16)
            return [l for l in self.logs if l['address'] == f['address'].lower() and int(l['blockNumber'], 16) <= top
                    and all(want is None or l['topics'][i].lower() == want.lower() for i, want in enumerate(f.get('topics') or []))]
        raise KeyError(method)

    def intent(self, burn, directory, name='intent.json', **release):
        """The intent the unchanged Bloch half hands to the Solana half for this burn."""
        import json
        c = self.c
        rel = {'route': S.hx(c.a.route), 'nonce': burn['nonce'], 'recipient': burn['recipient'], 'amount': burn['amount'],
               'nativeBurn': burn['burn_id'], 'mintCount': 2, 'mintedTotal': 201 * 10**6, 'mintHead': S.hx(c.state['head'])}
        rel.update(release)
        doc = {'kind': 'stable-release-intent', 'version': 1, 'source_chain_id': int.from_bytes(c.config.source_chain_id, 'big'),
               'vault': S.hx(c.a.vault20), 'release': rel, 'native': {'nativeFinalizedNumber': 5, 'nativeFinalizedHash': S.hx(S.sha256(b'l2'))},
               'l2': {'from': burn['from'], 'chain_id': self.chain_id, 'token': self.token, 'finalized_number': self.block},
               'proposed_context': None, 'l2_mints': []}
        path = Path(directory) / name
        path.write_text(json.dumps(doc))
        return str(path)


SIGNER_KEYS = [7001 + i for i in range(7)]  # throwaway secp256k1 keys of a test committee


def fake_cast(directory, key):
    """An executable standing in for `cast wallet address` / `cast wallet sign --no-hash` with one throwaway key."""
    path = Path(directory) / 'cast'
    path.write_text(f'''#!{sys.executable}
import sys
sys.path.insert(0, {str(HERE)!r})
import testkit as K, solana_lib as S
a = sys.argv[1:]
if a[:2] == ['wallet', 'address']:
    print(S.hx(K.secp_address({key})))
elif a[:2] == ['wallet', 'sign']:
    print(S.hx(K.secp_sign({key}, S.unhex(a[-1], 32))))
else:
    raise SystemExit(2)
''')
    path.chmod(0o755)
    return str(path)
