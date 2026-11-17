"""Minimal read-only view of the L2 token for the Bitcoin tools (JSON-RPC, no key). UNAUDITED."""
import json
import urllib.request

import btc_core as c

BURNED_V3 = 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)'


class L2Error(Exception):
    pass


def topic(signature):
    return '0x' + c.keccak256(signature.encode()).hex()


class Token:
    def __init__(self, url, token, chain_id=None, code_keccak=None):
        self.url, self.token = url, token.lower()
        self.chain_id, self.code_keccak = chain_id, code_keccak

    def rpc(self, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(self.url, body, {'content-type': 'application/json'}),
                                        timeout=60) as r:
                out = json.loads(r.read())
        except (OSError, ValueError) as e:
            raise L2Error(f'L2 RPC {method} failed: {type(e).__name__}') from None
        if 'error' in out:
            raise L2Error(f"L2 RPC {method}: {out['error']}")
        return out['result']

    def check(self, block='latest'):
        """Chain id and the pinned runtime code hash, as signatario.py `check_contract`."""
        if self.chain_id is not None and int(self.rpc('eth_chainId', []), 16) != int(self.chain_id):
            raise L2Error('the L2 RPC serves another chain')
        if self.code_keccak is not None:
            code = self.rpc('eth_getCode', [self.token, block])
            if code in ('0x', '') or '0x' + c.keccak256(bytes.fromhex(code[2:])).hex() != self.code_keccak.lower():
                raise L2Error('the token runtime code differs from the pinned hash')

    def call(self, signature, *words, block='latest'):
        data = '0x' + c.keccak256(signature.encode())[:4].hex() + b''.join(c.abi_word(w) for w in words).hex()
        out = self.rpc('eth_call', [{'to': self.token, 'data': data}, block])
        if not isinstance(out, str) or len(out) < 66 or (len(out) - 2) % 64:
            raise L2Error(f'{signature}: malformed answer')
        return bytes.fromhex(out[2:])

    def uint(self, signature, *words, block='latest'):
        return int.from_bytes(self.call(signature, *words, block=block)[:32], 'big')

    def word(self, signature, *words, block='latest'):
        return self.call(signature, *words, block=block)[:32]

    def block(self, tag):
        b = self.rpc('eth_getBlockByNumber', [tag, False])
        if b is None:
            raise L2Error(f'the L2 has no {tag} block')
        return {'number': int(b['number'], 16), 'hash': b['hash'].lower(), 'time': int(b['timestamp'], 16)}

    def burns(self, from_block, to_block, chunk=10_000):
        """Every Burned log up to `to_block`: [{'nonce', 'units', 'recipient': 20 bytes, 'tx', 'burn_id', 'block', ...}]."""
        out, t0 = [], topic(BURNED_V3)
        for lo in range(from_block, to_block + 1, chunk):
            for l in self.rpc('eth_getLogs', [{'address': self.token, 'topics': [t0], 'fromBlock': hex(lo),
                                              'toBlock': hex(min(lo + chunk - 1, to_block))}]):
                data = bytes.fromhex(l['data'][2:])
                if len(l['topics']) != 4 or len(data) != 160 or any(data[32:44]):
                    raise L2Error('malformed Burned log')
                out.append({'burn_id': l['topics'][1].lower(), 'nonce': int(l['topics'][2], 16),
                            'from': '0x' + l['topics'][3][-40:].lower(), 'units': int.from_bytes(data[:32], 'big'),
                            'recipient': data[44:64], 'mint_count': int.from_bytes(data[64:96], 'big'),
                            'minted_total': int.from_bytes(data[96:128], 'big'), 'mint_head': data[128:160],
                            'tx': l['transactionHash'].lower(), 'block': int(l['blockNumber'], 16)})
        return sorted(out, key=lambda b: b['nonce'])


class Router:
    """Read-only view of BitcoinBurnRouter through the same JSON-RPC as the token (pass the Token that was verified).

    What it answers decides where and when a burn is paid, so signers read it at the finalized block of the L2 they
    verified themselves, after comparing the router's runtime code with the pinned hash (btc_signer.py)."""

    def __init__(self, token, router):
        self.token, self.router = token, str(router).lower()

    def _call(self, signature, *words, block='latest'):
        data = '0x' + c.keccak256(signature.encode())[:4].hex() + b''.join(c.abi_word(w) for w in words).hex()
        out = self.token.rpc('eth_call', [{'to': self.router, 'data': data}, block])
        if not isinstance(out, str) or len(out) < 66 or (len(out) - 2) % 64:
            raise L2Error(f'router {signature}: malformed answer')
        return bytes.fromhex(out[2:])

    def code_keccak(self, block='latest'):
        code = self.token.rpc('eth_getCode', [self.router, block])
        return None if code in ('0x', '') else '0x' + c.keccak256(bytes.fromhex(code[2:])).hex()

    def numbers(self, block='latest'):
        """The immutables a payout is computed from, plus the token and prefix the router serves."""
        out = {k: int.from_bytes(self._call(k + '()', block=block)[:32], 'big')
               for k in ('unitSats', 'releaseFeeBps', 'chargeVbytes', 'dustSats', 'feeRateCeiling')}
        out['token'] = '0x' + self._call('token()', block=block)[12:32].hex()
        raw = self._call('hrp()', block=block)
        out['hrp'] = raw[64:64 + int.from_bytes(raw[32:64], 'big')].decode('ascii', 'replace')
        return out

    def max_fee_rate(self, burn_id, block='latest'):
        """Highest fee rate the burner of a router burn accepts (sat/vB); 0 when the router did not make this burn."""
        return int.from_bytes(self._call('maxFeeRateOf(bytes32)', bytes.fromhex(str(burn_id).removeprefix('0x')), block=block)[:32], 'big')

    def claim(self, burner, nonce, block='latest'):
        """(key hash, fee ceiling) the burner of a direct burn claimed on the router, or None when it made no claim."""
        raw = self._call('claimOf(address,uint64)', bytes.fromhex(str(burner).removeprefix('0x')), int(nonce), block=block)
        if len(raw) != 64 or any(raw[20:32]):
            raise L2Error('router claimOf: malformed answer')
        rate = int.from_bytes(raw[32:64], 'big')
        if rate == 0 or not any(raw[:20]):
            return None
        return raw[:20], rate


def burn_terms(router, router_address, burn_from, burn_id, nonce, named, block='latest'):
    """Where a burn is paid and the highest fee rate its burner accepts: {'through_router', 'destination': 20 bytes or
    None, 'max_fee_rate': int or None, 'state': 'payable' | 'unclaimed'}.

    A burn made through the router is paid to the key hash the router checked and burned with (`named`). A burn made
    directly on the token is NEVER paid to the 20 bytes it names (they may be an Ethereum address): it is paid to the
    address the burning account claimed on the router, and until it claims it is not paid at all. There is no timeout.
    """
    if str(burn_from).lower() == str(router_address).lower():
        rate = router.max_fee_rate(burn_id, block)
        if rate < 1:
            raise L2Error('a burn made by the router has no fee ceiling recorded: not the pinned router')
        return {'through_router': True, 'destination': named, 'max_fee_rate': rate, 'state': 'payable'}
    got = router.claim(burn_from, nonce, block)
    if got is None:
        return {'through_router': False, 'destination': None, 'max_fee_rate': None, 'state': 'unclaimed'}
    return {'through_router': False, 'destination': got[0], 'max_fee_rate': got[1], 'state': 'payable'}


UNCLAIMED = ('made directly on the token and not claimed: never paid to the 20 bytes it names; paid when the account '
             'that burned calls BitcoinBurnRouter.claimDirectBurn (no timeout). Its coins stay in the vault')


def ledger_prefix_problem(token, vault, credits, block='latest'):
    """None if every mint the token holds agrees with the vault's deposit ledger; otherwise the reason to hold.

    (a) the token's mint chain after `mintCount` credits equals the ledger's chain: every credited token has a swept
        deposit behind it, in order;
    (b) every open slot (credited < slot < nextSlot) is held by the ledger's deposit id for that nonce, or is free.
    A reorganisation that removed an attested sweep, or a forged mint, shows up here, and every signer then refuses
    to attest any deposit and to pay any burn until the guardians have cancelled the stray mint (it fails safe).
    """
    import btc_policy as pol
    count = token.uint('mintCount()', block=block)
    nxt = token.uint('nextSlot()', block=block)
    if count > len(credits):
        return f'the token credited {count} mints but the Bitcoin ledger has only {len(credits)} deposits'
    chain = pol.mint_chain(vault, credits[:count])
    if token.word('mintHead()', block=block) != chain[count][2] or token.uint('mintedTotal()', block=block) != chain[count][1]:
        return f'the token mint chain after {count} credits is not the Bitcoin ledger chain'
    for slot in range(count, nxt):
        key = token.word('slotKey(uint64)', slot, block=block)
        if any(key) and (slot >= len(credits) or key != credits[slot]['deposit_id']):
            return f'slot {slot} is held by a mint that is not the Bitcoin ledger deposit of that nonce'
    return None
