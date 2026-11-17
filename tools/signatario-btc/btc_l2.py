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

    def block_time(self, number):
        """The timestamp of an L2 block by number (kept for the life of this object)."""
        cache = self.__dict__.setdefault('_times', {})
        if number not in cache:
            b = self.rpc('eth_getBlockByNumber', [hex(number), False])
            if b is None:
                raise L2Error(f'the L2 has no block {number}')
            cache[number] = int(b['timestamp'], 16)
        return cache[number]

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

    def has_code(self, account, block='latest'):
        """True when `account` has any code at that block (a contract, or an account that delegates to one)."""
        return self.token.rpc('eth_getCode', [str(account).lower(), block]) not in ('0x', '')

    def numbers(self, block='latest'):
        """The immutables a payout is computed from, plus the token and prefix the router serves."""
        out = {k: int.from_bytes(self._call(k + '()', block=block)[:32], 'big')
               for k in ('unitSats', 'releaseFeeBps', 'chargeVbytes', 'dustSats', 'feeRateCeiling', 'feeRateFloor')}
        out['token'] = '0x' + self._call('token()', block=block)[12:32].hex()
        raw = self._call('hrp()', block=block)
        out['hrp'] = raw[64:64 + int.from_bytes(raw[32:64], 'big')].decode('ascii', 'replace')
        return out

    @staticmethod
    def _terms(raw, what):
        """(burner, fee ceiling, L2 block of the burner's latest call) from a `Terms` struct, or None when empty."""
        if len(raw) != 96 or any(raw[:12]):
            raise L2Error(f'router {what}: malformed answer')
        rate, block = int.from_bytes(raw[32:64], 'big'), int.from_bytes(raw[64:96], 'big')
        if rate == 0:
            return None
        if not 0 < rate < 1 << 16 or not 0 < block < 1 << 40:
            raise L2Error(f'router {what}: values out of range')
        return '0x' + raw[12:32].hex(), rate, block

    def exit_terms(self, burn_id, block='latest'):
        """Terms of a burn made through the router, or None when the router did not make this burn."""
        return self._terms(self._call('exitTermsOf(bytes32)', bytes.fromhex(str(burn_id).removeprefix('0x')), block=block), 'exitTermsOf')

    def first_claim(self, burner, nonce, block='latest'):
        """The key hash of the FIRST claim `burner` made for this burn nonce, or None."""
        raw = self._call('claimOf(address,uint64)', bytes.fromhex(str(burner).removeprefix('0x')), int(nonce), block=block)
        if len(raw) != 64 or any(raw[20:32]):
            raise L2Error('router claimOf: malformed answer')
        return raw[:20] if int.from_bytes(raw[32:64], 'big') and any(raw[:20]) else None

    def claim_terms(self, burner, nonce, key_hash, block='latest'):
        """Terms of the claim (burner, nonce, key hash), or None when there is none."""
        return self._terms(self._call('claimTermsOf(address,uint64,bytes20)', bytes.fromhex(str(burner).removeprefix('0x')), int(nonce),
                                      bytes(key_hash), block=block), 'claimTermsOf')


def burn_terms(router, router_address, burn_from, burn_id, nonce, named, block='latest'):
    """Where a burn is paid, the highest fee rate its burner accepts and the L2 block of the burner's latest call:
    {'through_router', 'destination': 20 bytes or None, 'max_fee_rate', 'updated_block', 'state': 'payable' |
    'unclaimed', 'contract_burner'}.

    A burn made through the router is paid to the key hash the router checked and burned with (`named`).
    A burn made directly on the token is not paid until its burner claims it on the router; there is no timeout.
      * burner WITHOUT code: paid to the address of its FIRST claim, never to the 20 bytes the burn named (they may be
        an Ethereum address);
      * burner WITH code (a contract, which others may be able to drive: review R342-BTC-3): only a claim for the
        very 20 bytes the burn named counts, so nobody who can make the contract call can re-point the payout. Such a
        burn must name its Bitcoin key hash when it is made; a contract that named something else is never paid.
    """
    if str(burn_from).lower() == str(router_address).lower():
        got = router.exit_terms(burn_id, block)
        if got is None:
            raise L2Error('a burn made by the router has no terms recorded: not the pinned router')
        return {'through_router': True, 'destination': named, 'max_fee_rate': got[1], 'updated_block': got[2], 'state': 'payable',
                'contract_burner': False}
    contract = router.has_code(burn_from, block)
    key = named if contract else router.first_claim(burn_from, nonce, block)
    got = router.claim_terms(burn_from, nonce, key, block) if key is not None else None
    if got is None:
        return {'through_router': False, 'destination': None, 'max_fee_rate': None, 'updated_block': 0, 'state': 'unclaimed',
                'contract_burner': contract}
    return {'through_router': False, 'destination': key, 'max_fee_rate': got[1], 'updated_block': got[2], 'state': 'payable',
            'contract_burner': contract}


UNCLAIMED = ('made directly on the token and not claimed: never paid to the 20 bytes it names; paid when the account '
             'that burned calls BitcoinBurnRouter.claimDirectBurn (no timeout). Its coins stay in the vault')
UNCLAIMED_CONTRACT = ('made directly on the token by a contract and not claimed for the 20 bytes the burn named: a '
                      'contract burner is paid only to those bytes, after it calls BitcoinBurnRouter.claimDirectBurn '
                      'with the address they encode (no timeout). Its coins stay in the vault')


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
