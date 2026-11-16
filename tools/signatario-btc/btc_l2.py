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
