#!/usr/bin/env python3
"""Ethereum half of the stablecoin bridge signer (production; eth_half_fake.py is its test double).

  eth_half.py --config ETH.json deposit --deposit-id 0xID
  eth_half.py --config ETH.json release --intent INTENT.json

Interface: README.md, "Ethereum-half interface". It answers one JSON object on stdout:
{"ok": true, ...} with exit 0, or {"ok": false, "reason": ...} with exit 1. It reads only this signer's
own Ethereum node and signs only what it checked there:

deposit  the configured chain id; the vault code at `finalized` equals the pin; exactly one `Deposited`
         log of the vault with that id between `vault_from_block` and `finalized`; its block is canonical
         (hash by number) and its transaction succeeded with that same log in the receipt; the vault's own
         `depositId(...)` at `finalized` recomputes the id. Signs nothing (the Bloch half signs the mint).
release  chain id and code pin at `latest`; `route == routeId()`; releases enabled; no guardian pause; nonce and burn not
         released; the vault still in committee mode (no light-client verifier active; a pending
         proposal is reported as `pending_verifier`); amount <= totalLocked and within what the deployment-fixed release bucket allows now;
         recipient not zero nor the vault; `nativeFinalizedHash` non-zero. Anchor: its own `finalized`
         block (refused if the node's finality lags the head by more than `anchor_max_age`), or the
         proposed one when it is a canonical block of this node, <= finalized and at most `anchor_max_age`
         behind the head. `validUntil` in (now, now + max_valid_seconds]. The digest is computed here and
         must equal the vault's `releaseDigest`. A local database refuses to sign two different releases
         for one nonce or one burn (equivocation guard), whatever the vault would accept later.

Config (one JSON per signer, written once at deploy): `eth_rpc`, `eth_chain_id`, `vault`,
`vault_code_keccak`, `vault_from_block`, `keystore`, `password_file`, `db`; optional `cast`,
`anchor_max_age` (blocks, default 160: the vault's blockhash window is 256), `valid_seconds` (default 1800),
`max_valid_seconds` (default 3600), `log_chunk` (default 10000 blocks per eth_getLogs).
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

DEPOSITED = 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)'
RELEASE_TUPLE = '(bytes32,uint64,address,uint64,bytes32)'
CONTEXT_TUPLE = '(uint256,uint256,bytes32,uint64,bytes32)'
RELEASE_FIELDS = ('route', 'nonce', 'recipient', 'amount', 'nativeBurn')
CONTEXT_FIELDS = ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash', 'nativeFinalizedNumber',
                  'nativeFinalizedHash')
BLOCKHASH_WINDOW = 256


def answer(ok, **fields):
    print(json.dumps({'ok': ok, 'signed': ok and 'signature' in fields, **fields}, indent=2))
    raise SystemExit(0 if ok else 1)


def refuse(reason, **detail):
    answer(False, reason=reason, **detail)


def tag(text):
    """bytes32("...") as Solidity writes it."""
    return '0x' + text.encode().ljust(32, b'\0').hex()


def as_int(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def hex32(value, what):
    h = str(value).lower().removeprefix('0x')
    if len(h) != 64 or any(ch not in '0123456789abcdef' for ch in h):
        refuse(f'{what} must be 32 bytes of hex', got=value)
    return '0x' + h


def address(value, what):
    h = str(value).lower().removeprefix('0x')
    if len(h) != 40 or any(ch not in '0123456789abcdef' for ch in h):
        refuse(f'{what} must be a 20-byte address', got=value)
    return '0x' + h


def uint(value, bits, what):
    try:
        n = as_int(value)
    except (TypeError, ValueError):
        refuse(f'{what} is not an integer', got=value)
    if not 0 <= n < 2**bits:
        refuse(f'{what} out of uint{bits} range', got=value)
    return n


class Eth:
    def __init__(self, cfg_path):
        c = self.cfg = json.loads(Path(cfg_path).read_text())
        self.url = c['eth_rpc']
        self.cast = c.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.vault = address(c['vault'], 'vault')
        self.anchor_max_age = int(c.get('anchor_max_age', 160))
        self.valid_seconds = int(c.get('valid_seconds', 1800))
        self.max_valid_seconds = int(c.get('max_valid_seconds', 3600))
        if not 0 < self.anchor_max_age < BLOCKHASH_WINDOW or not 0 < self.valid_seconds <= self.max_valid_seconds:
            refuse('config: anchor_max_age must be in (0, 256) and valid_seconds in (0, max_valid_seconds]')
        chain = int(self.rpc('eth_chainId', []), 16)
        if chain != int(c['eth_chain_id']):
            refuse('this Ethereum node serves another chain', node=chain, config=int(c['eth_chain_id']))
        self.chain_id = chain

    # ── tools ────────────────────────────────────────────────────────────────
    def run(self, argv, what):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        if done.returncode:
            refuse(f'{what} failed', stderr=done.stderr.strip()[-1500:])
        return done.stdout.strip()

    def keccak(self, hexdata):
        return self.run([self.cast, 'keccak', hexdata], 'cast keccak').lower()

    def abi_encode(self, sig, *values):
        return self.run([self.cast, 'abi-encode', sig, *[str(v) for v in values]], 'cast abi-encode').lower()

    def sha256_abi(self, sig, *values):
        return '0x' + hashlib.sha256(bytes.fromhex(self.abi_encode(sig, *values)[2:])).hexdigest()

    def rpc(self, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(self.url, body, {'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
        except OSError as e:
            refuse(f'Ethereum RPC {method} unreachable', error=str(e))
        if 'error' in out:
            refuse(f'Ethereum RPC {method} error', error=out['error'])
        return out['result']

    def block(self, tag_or_number):
        ref = hex(tag_or_number) if isinstance(tag_or_number, int) else tag_or_number
        b = self.rpc('eth_getBlockByNumber', [ref, False])
        if b is None:
            refuse('Ethereum block not found', block=str(tag_or_number))
        return b

    def call(self, sig, *args, block='latest'):
        data = self.run([self.cast, 'calldata', sig, *[str(a) for a in args]], 'cast calldata')
        ref = hex(block) if isinstance(block, int) else block
        return self.rpc('eth_call', [{'to': self.vault, 'data': data}, ref])

    def word(self, hexdata, i=0):
        return int(hexdata[2 + 64 * i:2 + 64 * (i + 1)], 16)

    def check_code(self, block):
        ref = hex(block) if isinstance(block, int) else block
        code = self.rpc('eth_getCode', [self.vault, ref])
        if code in ('0x', ''):
            refuse('the vault has no code at this block (deployment not finalized yet)', block=str(block))
        got = self.keccak(code)
        if got != self.cfg['vault_code_keccak'].lower():
            refuse('the vault code differs from the pinned build', block=str(block), got=got,
                   pinned=self.cfg['vault_code_keccak'])

    def release_digest(self, rel, context):
        """ContextBoundSourceVault.releaseDigest, computed here."""
        release_id = self.sha256_abi('f(bytes32,bytes32,uint256,address,uint256,bytes32)',
                                     tag('BLOCH-USDT-RELEASE-v1'), *[rel[k] for k in RELEASE_FIELDS])
        auth = self.keccak(self.abi_encode(
            'f(bytes32,uint256,address,bytes32,uint256,uint256,bytes32,uint256,bytes32)',
            tag('BLOCH-USDT-RELEASE-AUTH-v2'), self.chain_id, self.vault, release_id,
            *[context[k] for k in CONTEXT_FIELDS]))
        return release_id, self.keccak('0x' + b'\x19Ethereum Signed Message:\n32'.hex() + auth[2:])


# ── deposit ─────────────────────────────────────────────────────────────────
def cmd_deposit(eth, args):
    dep_id = hex32(args[args.index('--deposit-id') + 1], 'deposit id')
    fin = eth.block('finalized')
    finalized = int(fin['number'], 16)
    eth.check_code(finalized)
    topic0 = eth.run([eth.cast, 'keccak', DEPOSITED], 'cast keccak').lower()
    start, chunk, logs = int(eth.cfg.get('vault_from_block', 0)), int(eth.cfg.get('log_chunk', 10000)), []
    for lo in range(start, finalized + 1, chunk):
        logs += eth.rpc('eth_getLogs', [{'address': eth.vault, 'topics': [topic0, dep_id], 'fromBlock': hex(lo),
                                         'toBlock': hex(min(lo + chunk - 1, finalized))}])
    if not logs:
        later = eth.rpc('eth_getLogs', [{'address': eth.vault, 'topics': [topic0, dep_id],
                                         'fromBlock': hex(finalized + 1), 'toBlock': 'latest'}])
        refuse('deposit not finalized on Ethereum' if later else 'no Deposited log with this id in the vault',
               finalized_number=finalized)
    if len(logs) != 1 or logs[0].get('removed'):
        refuse(f'expected one Deposited log for this id, found {len(logs)}')
    log = logs[0]
    number = int(log['blockNumber'], 16)
    if eth.block(number)['hash'].lower() != log['blockHash'].lower():
        refuse('deposit log is not on the canonical chain')
    receipt = eth.rpc('eth_getTransactionReceipt', [log['transactionHash']])
    if not receipt or receipt.get('status') != '0x1' or receipt['blockHash'].lower() != log['blockHash'].lower() \
            or not any(l['logIndex'] == log['logIndex'] and l['address'].lower() == eth.vault
                       and [t.lower() for t in l['topics']] == [t.lower() for t in log['topics']]
                       and l['data'].lower() == log['data'].lower() for l in receipt['logs']):
        refuse('deposit transaction failed or its receipt does not hold this log')
    if len(log['topics']) != 3 or len(log['data']) != 2 + 64 * 4:
        refuse('malformed Deposited log')
    d = log['data']
    nonce, sender_w, amount, pq = eth.word(d, 0), eth.word(d, 1), eth.word(d, 2), '0x' + d[2 + 192:2 + 256].lower()
    sender = '0x' + f'{sender_w:064x}'[24:]
    recomputed = eth.call('depositId(uint64,address,uint64,bytes32)', nonce, sender, amount, pq, block=finalized)
    if recomputed.lower() != dep_id:
        refuse('the vault does not recompute this depositId from the log fields', got=recomputed)
    route = eth.call('routeId()', block=finalized).lower()
    if route != log['topics'][2].lower():
        refuse('Deposited route differs from the vault routeId')
    answer(True, source_chain_id=eth.chain_id, vault=eth.vault, route=route, deposit_id=dep_id, nonce=nonce,
           sender=sender, amount=amount, pq_recipient_hash=pq, tx_hash=log['transactionHash'].lower(),
           log_index=int(log['logIndex'], 16), block_number=number, block_hash=log['blockHash'].lower(),
           finalized=True, finalized_number=finalized)


# ── release ─────────────────────────────────────────────────────────────────
def cmd_release(eth, args):
    intent = json.loads(Path(args[args.index('--intent') + 1]).read_text())
    if intent.get('kind') != 'stable-release-intent' or int(intent.get('version', 0)) != 1:
        refuse('not a stable-release-intent v1')
    if address(intent.get('vault', ''), 'intent vault') != eth.vault \
            or uint(intent.get('source_chain_id', 0), 256, 'source_chain_id') != eth.chain_id:
        refuse('intent for another chain or vault')
    r, n = intent['release'], intent['native']
    rel = {'route': hex32(r['route'], 'route'), 'nonce': uint(r['nonce'], 64, 'nonce'),
           'recipient': address(r['recipient'], 'recipient'), 'amount': uint(r['amount'], 64, 'amount'),
           'nativeBurn': hex32(r['nativeBurn'], 'nativeBurn')}
    native = {'nativeFinalizedNumber': uint(n['nativeFinalizedNumber'], 64, 'nativeFinalizedNumber'),
              'nativeFinalizedHash': hex32(n['nativeFinalizedHash'], 'nativeFinalizedHash')}
    if rel['amount'] == 0 or rel['recipient'] in ('0x' + '0' * 40, eth.vault) or int(rel['nativeBurn'], 16) == 0 \
            or int(native['nativeFinalizedHash'], 16) == 0:
        refuse('release the vault would refuse (zero amount, burn or native hash; recipient zero or the vault)')

    eth.check_code('latest')
    if eth.call('routeId()').lower() != rel['route']:
        refuse('release route is not this vault route')
    if eth.word(eth.call('verifier()')):
        refuse('the vault switched to its light-client verifier; the committee is retired (releaseWithProof)')
    if not eth.word(eth.call('releasesEnabled()')):
        refuse('vault releases are disabled')
    if eth.word(eth.call('paused()')):
        refuse('the vault is paused by a guardian; retry after the pause',
               paused_until=eth.word(eth.call('pausedUntil()')))
    pending = '0x' + eth.call('proposedVerifier()')[-40:]
    switch = {} if int(pending, 16) == 0 else {
        'pending_verifier': pending, 'verifier_activates_at': eth.word(eth.call('verifierActivatesAt()'))}
    if eth.word(eth.call('releasedBurn(bytes32)', rel['nativeBurn'])) or \
            eth.word(eth.call('releasedNonce(uint64)', rel['nonce'])):
        refuse('this burn or nonce is already released on Ethereum')
    locked = eth.word(eth.call('totalLocked()'))
    if rel['amount'] > locked:
        refuse('amount exceeds the vault totalLocked', total_locked=locked)

    head_block = eth.block('latest')
    head, now = int(head_block['number'], 16), int(time.time())
    chain_now = int(head_block['timestamp'], 16)
    if eth.cfg.get('eth_clock') == 'chain':  # the vault checks validUntil against block.timestamp
        now = chain_now
    limit, seconds = eth.word(eth.call('windowLimit()')), eth.word(eth.call('windowSeconds()'))
    available = eth.word(eth.call('availableToRelease()'))
    if rel['amount'] > available:
        refuse('release window is full; retry after it refills', window_limit=limit, available=available,
               retry_after_s=-((available - rel['amount']) * seconds // limit))

    finalized = int(eth.block('finalized')['number'], 16)
    prop = intent.get('proposed_context')
    if prop:
        number = uint(prop['sourceAnchorNumber'], 256, 'sourceAnchorNumber')
        anchor_hash = hex32(prop['sourceAnchorHash'], 'sourceAnchorHash')
        if number > finalized or head - number > eth.anchor_max_age \
                or eth.block(number)['hash'].lower() != anchor_hash:
            refuse('proposed anchor is not a recent finalized block of this node', finalized_number=finalized,
                   head_number=head)
        valid_until = uint(prop['validUntil'], 256, 'validUntil')
        if not now < valid_until <= now + eth.max_valid_seconds:
            refuse('proposed validUntil outside policy', now=now, max_valid_seconds=eth.max_valid_seconds)
    else:
        if head - finalized > eth.anchor_max_age:
            refuse('this node finality lags the head too much for a usable anchor', finalized_number=finalized,
                   head_number=head)
        number, anchor_hash = finalized, eth.block(finalized)['hash'].lower()
        valid_until = now + eth.valid_seconds
    context = {'validUntil': valid_until, 'sourceAnchorNumber': number, 'sourceAnchorHash': anchor_hash, **native}

    release_id, digest = eth.release_digest(rel, context)
    rel_arg = '(' + ','.join(str(rel[k]) for k in RELEASE_FIELDS) + ')'
    ctx_arg = '(' + ','.join(str(context[k]) for k in CONTEXT_FIELDS) + ')'
    onchain = eth.call(f'releaseDigest({RELEASE_TUPLE},{CONTEXT_TUPLE})', rel_arg, ctx_arg).lower()
    if onchain != digest:
        refuse('local releaseDigest differs from the vault', local=digest, vault=onchain)

    db_path = Path(eth.cfg['db'])
    with open(db_path.with_suffix('.lock'), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db = json.loads(db_path.read_text()) if db_path.exists() else {'releases': {}}
        for key in (f"nonce:{rel['nonce']}", f"burn:{rel['nativeBurn']}"):
            if db['releases'].get(key, release_id) != release_id:
                refuse('already signed a different release for this nonce or burn', key=key,
                       signed_release_id=db['releases'][key], this_release_id=release_id)
        ks, pw = eth.cfg['keystore'], eth.cfg['password_file']
        signer = eth.run([eth.cast, 'wallet', 'address', '--keystore', ks, '--password-file', pw],
                         'cast wallet address').lower()
        if not eth.word(eth.call('isSigner(address)', signer)):
            refuse('this key is not a signer of the vault', signer=signer)
        for key in (f"nonce:{rel['nonce']}", f"burn:{rel['nativeBurn']}"):
            db['releases'][key] = release_id
        tmp = db_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(db, indent=2) + '\n')
        os.replace(tmp, db_path)
        sig = eth.run([eth.cast, 'wallet', 'sign', '--no-hash', '--keystore', ks, '--password-file', pw, digest],
                      'cast wallet sign').lower()
    if len(sig) != 132 or int(sig[66:130], 16) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0:
        refuse('signer produced a malformed or high-s signature')
    answer(True, signer=signer, release=rel, context=context, digest=digest, signature=sig,
           eth_finalized_number=finalized, eth_head_number=head, **switch)


def main():
    args = sys.argv[1:]
    if '--config' not in args or not ({'deposit', 'release'} & set(args)):
        print(__doc__)
        raise SystemExit(2)
    eth = Eth(args[args.index('--config') + 1])
    (cmd_deposit if 'deposit' in args else cmd_release)(eth, args)


main()
