#!/usr/bin/env python3
"""TEST DOUBLE of the Ethereum half of the stablecoin signer. Tests only; never use with real funds.

It implements the interface in README.md against an Ethereum JSON-RPC (anvil in the tests), with
the minimum checks the real half must also make, but without a code pin, persistent replay
database or fee/rate policy.

  eth_half_fake.py --rpc URL --vault ADDR --keystore KS --password-file PW [--cast CAST] [--tamper-amount]
                   deposit --deposit-id 0xID
  eth_half_fake.py --rpc URL --vault ADDR --keystore KS --password-file PW [--cast CAST]
                   release --intent INTENT.json

Answers one JSON object on stdout: {"ok": true, ...} (exit 0) or {"ok": false, "reason": ...} (exit 1).
`--tamper-amount` makes `deposit` lie about the amount (to test that the Bloch half recomputes the id).
"""
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ANCHOR_MAX_AGE = 200  # blocks; the vault accepts only anchors within the 256-block blockhash window
MAX_VALID_SECONDS = 3600
DEPOSITED = 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)'
RELEASE_T = '(bytes32,uint64,address,uint64,bytes32)'
CONTEXT_T = '(uint256,uint256,bytes32,uint64,bytes32)'

args = sys.argv[1:]


def opt(name, default=None):
    return args[args.index(name) + 1] if name in args else default


def answer(ok, **fields):
    print(json.dumps({'ok': ok, 'signed': ok and 'signature' in fields, **fields}))
    raise SystemExit(0 if ok else 1)


RPC, VAULT, CAST = opt('--rpc'), opt('--vault').lower(), opt('--cast', 'cast')


def sh(*argv):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if done.returncode:
        answer(False, reason=f'{argv[1]} failed', stderr=done.stderr[-800:])
    return done.stdout.strip()


def rpc(method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(RPC, body, {'content-type': 'application/json'}),
                                timeout=30) as r:
        out = json.loads(r.read())
    if 'error' in out:
        answer(False, reason=f'Ethereum RPC {method} error', error=out['error'])
    return out['result']


def call(sig, *a):
    data = sh(CAST, 'calldata', sig, *a)
    return rpc('eth_call', [{'to': VAULT, 'data': data}, 'latest'])


def block(tag):
    return rpc('eth_getBlockByNumber', [tag, False])


chain_id = int(rpc('eth_chainId', []), 16)
finalized = int(block('finalized')['number'], 16)

if 'deposit' in args:
    dep_id = opt('--deposit-id').lower()
    topic0 = sh(CAST, 'keccak', DEPOSITED).lower()
    logs = rpc('eth_getLogs', [{'address': VAULT, 'topics': [topic0, dep_id], 'fromBlock': '0x0',
                                'toBlock': 'latest'}])
    if len(logs) != 1:
        answer(False, reason=f'expected one Deposited log for this id, found {len(logs)}')
    log = logs[0]
    number = int(log['blockNumber'], 16)
    if number > finalized:
        answer(False, reason='deposit not finalized on Ethereum', block_number=number, finalized_number=finalized)
    if block(hex(number))['hash'].lower() != log['blockHash'].lower():
        answer(False, reason='deposit log is not on the canonical chain')
    d = log['data'][2:]
    words = [d[64 * i:64 * (i + 1)] for i in range(4)]
    amount = int(words[2], 16) + (1 if '--tamper-amount' in args else 0)
    answer(True, source_chain_id=chain_id, vault=VAULT, route=log['topics'][2].lower(), deposit_id=dep_id,
           nonce=int(words[0], 16), sender='0x' + words[1][24:], amount=amount, pq_recipient_hash='0x' + words[3],
           tx_hash=log['transactionHash'], log_index=int(log['logIndex'], 16), block_number=number,
           block_hash=log['blockHash'].lower(), finalized=True, finalized_number=finalized)

elif 'release' in args:
    intent = json.loads(Path(opt('--intent')).read_text())
    rel, native, prop = intent['release'], intent['native'], intent.get('proposed_context')
    if intent.get('vault', '').lower() != VAULT or int(intent.get('source_chain_id', 0)) != chain_id:
        answer(False, reason='intent for another chain or vault')
    if int(call('routeId()'), 16) != int(rel['route'], 16):
        answer(False, reason='release route is not this vault route')
    if not int(call('releasesEnabled()'), 16):
        answer(False, reason='vault releases are disabled')
    if int(call('releasedBurn(bytes32)', rel['nativeBurn']), 16) or int(call('releasedNonce(uint64)',
                                                                              str(rel['nonce'])), 16):
        answer(False, reason='this burn or nonce is already released on Ethereum')
    head = int(block('latest')['number'], 16)
    now = int(time.time())
    if prop:
        number = int(prop['sourceAnchorNumber'])
        b = block(hex(number))
        if b is None or b['hash'].lower() != prop['sourceAnchorHash'].lower() or number > finalized \
                or head - number > ANCHOR_MAX_AGE:
            answer(False, reason='proposed anchor is not a recent finalized block of this node')
        if not now < int(prop['validUntil']) <= now + MAX_VALID_SECONDS:
            answer(False, reason='proposed validUntil outside policy')
        anchor = {'validUntil': int(prop['validUntil']), 'sourceAnchorNumber': number,
                  'sourceAnchorHash': prop['sourceAnchorHash'].lower()}
    else:
        anchor = {'validUntil': now + 1800, 'sourceAnchorNumber': finalized,
                  'sourceAnchorHash': block(hex(finalized))['hash'].lower()}
    context = {**anchor, **native}
    rel_arg = '(' + ','.join(str(rel[k]) for k in ('route', 'nonce', 'recipient', 'amount', 'nativeBurn')) + ')'
    ctx_arg = '(' + ','.join(str(context[k]) for k in ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash',
                                                       'nativeFinalizedNumber', 'nativeFinalizedHash')) + ')'
    digest = '0x' + call(f'releaseDigest({RELEASE_T},{CONTEXT_T})', rel_arg, ctx_arg)[2:66].lower()
    ks, pw = opt('--keystore'), opt('--password-file')
    sig = sh(CAST, 'wallet', 'sign', '--no-hash', '--keystore', ks, '--password-file', pw, digest).lower()
    signer = sh(CAST, 'wallet', 'address', '--keystore', ks, '--password-file', pw).lower()
    answer(True, signer=signer, release=rel, context=context, digest=digest, signature=sig,
           eth_finalized_number=finalized, eth_head_number=head)
else:
    answer(False, reason='unknown command')
