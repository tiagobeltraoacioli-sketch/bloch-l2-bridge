#!/usr/bin/env python3
"""Private anvil rehearsal of a light-client release under the D6 design (agents/110-lc-guest-v3.md), adapted by agent 138
to the bridge V3 launch tip (9f91a56 + RecoverableReleaseVerifier): T = 0 (every mint queues 12 h, then executeMint), the
forged deposit id carries its slot in the top 8 bytes (F1), RecoverableReleaseVerifier with the 30-day handoff on.
Set V3_T0=0 for the a97c3cb flow of agents 110 and 130 (instant mints, all three transactions in one block), which is
the state their stored proofs bind.

  rehearse_v3.py WORK nets      start the two loopback anvils (E: chain 31337, L2: chain 700771), stay in background
  rehearse_v3.py WORK burn      deploy the V3 vault on E and BridgedStablecoinV3 on L2, make an honest and a forged burn
                                in one L2 block; writes WORK/fix/v3-l2.json, WORK/fix/v3-receipts.json, WORK/jobs/*.json
  rehearse_v3.py WORK verify    with the real release proofs in WORK/out/{rh,rf}/release.json: verify on E through
                                SP1ReleaseVerifier and through RecoverableReleaseVerifier; writes WORK/v3-rehearsal.json
  rehearse_v3.py WORK stop      stop both anvils

WORK holds bin/{anvil,forge,cast} and bridge/ (the d6-cdi contracts plus RecoverableReleaseVerifier). Loopback only,
throwaway keys generated here and kept in WORK/anvil-keys.json (mode 0600). Nothing here touches a public network.
"""
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

WORK = Path(sys.argv[1])
BRIDGE = WORK / 'bridge'
CAST, FORGE, ANVIL = (str(WORK / 'bin' / n) for n in ('cast', 'forge', 'anvil'))
PORT_E, PORT_L2 = int(os.environ.get('V3_PORT_E', '31000')), int(os.environ.get('V3_PORT_L2', '31001'))
E, L2 = f'http://127.0.0.1:{PORT_E}', f'http://127.0.0.1:{PORT_L2}'
E_CHAIN, L2_CHAIN = 31337, 700771
U = 10**6
T0 = os.environ.get('V3_T0', '1') == '1'
CAP, BUCKET, LARGE, MIN = 100_000 * U, 10_000 * U, (0 if T0 else 1_000 * U), 10 * U
GENESIS, EPOCH = 1786656679, 960
DELAY, WINDOW, COOLDOWN = 14 * 86400, 3 * 86400, 14 * 86400
HANDOFF = int(os.environ.get('V3_HANDOFF', str(30 * 86400)))
USDC = 'solidity-tests/D6Compose.t.sol:ComposeUsdc'
VAULT = 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault'
TOKEN = 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3'
PLAIN = 'contracts/usdt/SP1ReleaseVerifier.sol:SP1ReleaseVerifier'
RECOVERABLE = 'contracts/usdt/RecoverableReleaseVerifier.sol:RecoverableReleaseVerifier'
SP1 = 'contracts/sp1/v6.1.0/SP1VerifierGroth16.sol:SP1Verifier'
REL_T = '(bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32)'


def sh(*a):
    p = subprocess.run(list(map(str, a)), capture_output=True, text=True, cwd=BRIDGE)
    if p.returncode:
        raise RuntimeError(f'{a[:3]}: {p.stdout[-800:]} {p.stderr[-1500:]}')
    return p.stdout.strip()


def rpc(url, method, *params):
    q = urllib.request.Request(url, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode(),
                               headers={'content-type': 'application/json'})
    r = json.loads(urllib.request.urlopen(q, timeout=60).read())
    if 'error' in r:
        raise RuntimeError(r['error'])
    return r['result']


def keys():
    f = WORK / 'anvil-keys.json'
    if f.exists():
        return json.loads(f.read_text())
    names = ['deployer', 'alice', 'bob', 'mallory', 'relayer', 'stranger', 'authority'] + [f'm{i}' for i in range(7)] + [f'e{i}' for i in range(7)]
    k = {n: '0x' + secrets.token_hex(32) for n in names}
    f.touch(mode=0o600)
    f.write_text(json.dumps(k))
    return k


_addr = {}


def addr(k):
    if k not in _addr:
        _addr[k] = sh(CAST, 'wallet', 'address', '--private-key', k)
    return _addr[k]


def sorted_keys(k, prefix):
    return sorted((k[f'{prefix}{i}'] for i in range(7)), key=lambda x: int(addr(x), 16))


def fund(url, *ks):
    for x in ks:
        rpc(url, 'anvil_setBalance', addr(x), hex(10**21))


def create(url, key, contract, *args):
    a = [FORGE, 'create', '--broadcast', '--rpc-url', url, '--private-key', key, contract]
    if args:
        a += ['--constructor-args', *args]
    out = sh(*a)
    return next(l.split()[-1] for l in out.splitlines() if l.startswith('Deployed to'))


def send(url, key, to, sig, *args):
    r = json.loads(sh(CAST, 'send', '--json', '--rpc-url', url, '--private-key', key, to, sig, *args))
    if r['status'] != '0x1':
        raise RuntimeError(f'{sig} reverted: {r}')
    return r


def send_async(url, key, to, sig, *args):
    return sh(CAST, 'send', '--async', '--gas-limit', '1000000', '--rpc-url', url, '--private-key', key, to, sig, *args).splitlines()[-1].strip()


def refused(url, key, to, sig, *args):
    p = subprocess.run([CAST, 'send', '--json', '--rpc-url', url, '--private-key', key, to, sig, *map(str, args)],
                       capture_output=True, text=True, cwd=BRIDGE)
    if p.returncode == 0 and json.loads(p.stdout)['status'] == '0x1':
        raise RuntimeError(f'{sig} was expected to fail')
    msg = (p.stderr or p.stdout).strip()
    return msg[msg.find('execution reverted'):][:160] if 'execution reverted' in msg else msg[-160:]


def call(url, to, sig, *args):
    return sh(CAST, 'call', '--rpc-url', url, to, sig, *args)


def decode_err(data):
    return sh(CAST, 'decode-error', '--sig', data) if data else ''


def now(url):
    return int(rpc(url, 'eth_getBlockByNumber', 'latest', False)['timestamp'], 16)


def warp(url, t):
    rpc(url, 'evm_setNextBlockTimestamp', hex(t))
    rpc(url, 'evm_mine')


def gas(r):
    return int(r['gasUsed'], 16)


def blob(digest, ks, n):
    return '0x' + ''.join(sh(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, digest)[2:] for x in ks[:n])


def cert(digest, ks, n):
    return '[' + ','.join(sh(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, digest) for x in ks[:n]) + ']'


def state():
    return json.loads((WORK / 'v3-state.json').read_text())


def nets():
    logs = WORK / 'logs'
    logs.mkdir(exist_ok=True)
    pids = {}
    for name, port, chain in (('e', PORT_E, E_CHAIN), ('l2', PORT_L2, L2_CHAIN)):
        p = subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--port', str(port), '--chain-id', str(chain), '--accounts', '0',
                              '--timestamp', str(int(time.time())), '--block-base-fee-per-gas', '0', '--gas-price', '0',
                              '--order', 'fifo', '--state', str(WORK / f'anvil-{name}.state')],
                             stdout=open(logs / f'anvil-{name}.log', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
        pids[name] = p.pid
    for url in (E, L2):
        for _ in range(60):
            try:
                rpc(url, 'eth_chainId')
                break
            except Exception:
                time.sleep(0.5)
    (WORK / 'anvil.pids').write_text(json.dumps(pids))
    print(json.dumps(pids))


def stop():
    pids = json.loads((WORK / 'anvil.pids').read_text())
    for pid in pids.values():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    print('stopped', pids)


def item_of(token_url, token, receipt, route):
    topic = sh(CAST, 'keccak', 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)')
    for l in receipt['logs']:
        if l['address'].lower() == token.lower() and l['topics'][0] == topic:
            d = bytes.fromhex(l['data'][2:])
            w = [d[i:i + 32] for i in range(0, len(d), 32)]
            return {'route': route, 'nonce': int(l['topics'][2], 16), 'recipient': '0x' + w[1][12:].hex(), 'amount': int.from_bytes(w[0], 'big'),
                    'native_burn': l['topics'][1], 'mint_count': int.from_bytes(w[2], 'big'), 'minted_total': int.from_bytes(w[3], 'big'),
                    'mint_head': '0x' + w[4].hex()}
    raise RuntimeError('no V3 Burned log')


def tup(i):
    return f"({i['route']},{i['nonce']},{i['recipient']},{i['amount']},{i['native_burn']},{i['mint_count']},{i['minted_total']},{i['mint_head']})"


def burn():
    k = keys()
    ek, mk = sorted_keys(k, 'e'), sorted_keys(k, 'm')
    users = [k[n] for n in ('deployer', 'alice', 'bob', 'mallory', 'relayer', 'stranger', 'authority')]
    fund(E, *users)
    fund(L2, *users)
    s = {'e_chain': E_CHAIN, 'l2_chain': L2_CHAIN, 'gas': {}}
    s['usdc'] = usdc = create(E, k['deployer'], USDC)
    eth_signers = '[' + ','.join(addr(x) for x in ek) + ']'
    s['vault'] = vault = create(E, k['deployer'], VAULT, '0x' + sh(CAST, 'keccak', 'ethereum')[2:], sh(CAST, 'keccak', 'bloch-l2'),
                                sh(CAST, 'keccak', 'USDC'), usdc, str(CAP), '0', eth_signers, '5',
                                f'({BUCKET},86400,6,{DELAY},{MIN},{MIN})', '([],0,0)', '(1,0,0x0000000000000000000000000000000000000000,(0x0000000000000000000000000000000000000000,0,0))')
    s['route'] = route = call(E, vault, 'routeId()(bytes32)')
    until = str(now(E) + 3600)
    d = call(E, vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', until)
    send(E, k['deployer'], vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', until, cert(d, ek, 5))
    mint_signers = '[' + ','.join(addr(x) for x in mk) + ']'
    s['token'] = token = create(L2, k['deployer'], TOKEN, 'Bloch Bridged USDC', 'bUSDC', str(E_CHAIN), vault, route, mint_signers, '5',
                                f'({CAP},{BUCKET},{BUCKET // 86400},{LARGE},43200,{MIN})', '([],0,0)', f'(6,{14 * 86400})')
    assert call(L2, token, 'mintHead()(bytes32)') == call(E, vault, 'mintChainGenesis()(bytes32)'), 'genesis differs'
    # Deposits on E: Alice 500 (to be minted), Bob 2,000 (not yet minted: the slack a forger takes).
    deps = []
    for who, amount in (('alice', 500 * U), ('bob', 2000 * U)):
        send(E, k['deployer'], usdc, 'mint(address,uint256)', addr(k[who]), str(amount))
        send(E, k[who], usdc, 'transferFrom(address,address,uint256)', addr(k[who]), addr(k[who]), '0')
        nonce = int(call(E, vault, 'depositCount()(uint64)').split()[0])
        r = send(E, k[who], vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + addr(k[who])[2:])
        dep_id = r['logs'][-1]['topics'][1]
        deps.append({'who': who, 'nonce': nonce, 'id': dep_id, 'amount': amount, 'tx': r['transactionHash']})
    s['deposits'] = deps
    a = deps[0]
    dg = call(L2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', a['id'], str(a['nonce']), str(a['amount']), addr(k['alice']))
    if T0:
        # T = 0: every mint queues 12 h; nobody cancels (no guardians on this net). Alice's honest mint is queued, the
        # forger's mint into Bob's slot 1 one hour later, so Alice's credit (12 h on) does not drain it. Then one L2
        # block: Alice burns 400 at mintCount 1 (honest), anyone executes the forgery, Mallory burns 400 at mintCount 2.
        fake = '0x' + (1).to_bytes(8, 'big').hex() + secrets.token_hex(24)
        r = send(L2, k['relayer'], token, 'mint(bytes32,uint64,uint64,address,bytes)', a['id'], str(a['nonce']), str(a['amount']), addr(k['alice']), blob(dg, mk, 5))
        s['gas']['l2_mint_honest_queue'] = gas(r)
        warp(L2, now(L2) + 3600)
        fg = call(L2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', fake, '1', str(600 * U), addr(k['mallory']))
        r = send(L2, k['relayer'], token, 'mint(bytes32,uint64,uint64,address,bytes)', fake, '1', str(600 * U), addr(k['mallory']), blob(fg, mk, 5))
        s['gas']['l2_mint_forged_queue'] = gas(r)
        warp(L2, now(L2) + 43200 - 3600 + 1)
        s['gas']['l2_execute_honest'] = gas(send(L2, k['stranger'], token, 'executeMint(bytes32)', a['id']))
        assert int(call(L2, token, 'mintCount()(uint64)').split()[0]) == 1
        warp(L2, now(L2) + 3600)
        rpc(L2, 'evm_setAutomine', False)
        txs = [send_async(L2, k['alice'], token, 'burn(uint64,address)', str(400 * U), addr(k['alice'])),
               send_async(L2, k['stranger'], token, 'executeMint(bytes32)', fake),
               send_async(L2, k['mallory'], token, 'burn(uint64,address)', str(400 * U), addr(k['mallory']))]
    else:
        # The relayer mints Alice's deposit (instant: at most LARGE). Honest.
        r = send(L2, k['relayer'], token, 'mint(bytes32,uint64,uint64,address,bytes)', a['id'], str(a['nonce']), str(a['amount']), addr(k['alice']), blob(dg, mk, 5))
        s['gas']['l2_mint_honest'] = gas(r)
        assert int(call(L2, token, 'mintCount()(uint64)').split()[0]) == 1
        # One L2 block: Alice burns 400 (honest); the mint quorum forges Bob's slot to Mallory; Mallory burns 400.
        fake = '0x' + secrets.token_hex(32)
        fg = call(L2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', fake, '1', str(600 * U), addr(k['mallory']))
        fblob = blob(fg, mk, 5)
        rpc(L2, 'evm_setAutomine', False)
        txs = [send_async(L2, k['alice'], token, 'burn(uint64,address)', str(400 * U), addr(k['alice'])),
               send_async(L2, k['relayer'], token, 'mint(bytes32,uint64,uint64,address,bytes)', fake, '1', str(600 * U), addr(k['mallory']), fblob),
               send_async(L2, k['mallory'], token, 'burn(uint64,address)', str(400 * U), addr(k['mallory']))]
    rpc(L2, 'evm_mine')
    rpc(L2, 'evm_setAutomine', True)
    rec = [rpc(L2, 'eth_getTransactionReceipt', t) for t in txs]
    assert all(r and r['status'] == '0x1' for r in rec), rec
    n = int(rec[0]['blockNumber'], 16)
    assert all(int(r['blockNumber'], 16) == n for r in rec), 'one block'
    blk = rpc(L2, 'eth_getBlockByNumber', hex(n), False)
    receipts = rpc(L2, 'eth_getBlockReceipts', hex(n))
    s['l2_block'] = {'number': n, 'hash': blk['hash'], 'receipts_root': blk['receiptsRoot'], 'txs': txs}
    s['honest'] = item_of(L2, token, rec[0], route)
    s['forged'] = item_of(L2, token, rec[-1], route)
    s['forged_mint'] = {'fake_deposit_id': fake, 'slot': 1, 'amount': 600 * U}
    s['forged_receipt_index'] = len(rec) - 1
    s['gas'].update(l2_burn_honest=gas(rec[0]), l2_burn_forged=gas(rec[-1]))
    s['gas']['l2_mint_forged' if not T0 else 'l2_execute_forged'] = gas(rec[1])
    # What the vault thinks of each, before any proof.
    for tag in ('honest', 'forged'):
        i = s[tag]
        s[tag]['vault_release_id'] = call(E, vault, f'releaseId({REL_T})(bytes32)', tup(i))
        s[tag]['provenance_matches'] = call(E, vault, 'provenanceMatches(uint64,uint64,bytes32)(bool)', str(i['mint_count']), str(i['minted_total']), i['mint_head'])
    s['vault_head_at_2'] = call(E, vault, 'chainHeadAt(uint64)(bytes32)', '2')
    (WORK / 'fix').mkdir(exist_ok=True)
    (WORK / 'fix' / 'v3-l2.json').write_text(json.dumps({'l2_number': n, 'l2_block_hash': blk['hash'], 'receipts_root': blk['receiptsRoot']}))
    (WORK / 'fix' / 'v3-receipts.json').write_text(json.dumps(receipts))
    (WORK / 'v3-state.json').write_text(json.dumps(s, indent=1))
    rpc(E, 'anvil_dumpState')
    print(json.dumps(s, indent=1))


def jobs():
    """After dump_v3_release_chain: the step and the two release jobs."""
    s = state()
    a = json.loads((WORK / 'fix' / 'v3-anchor.json').read_text())
    receipts = json.loads((WORK / 'fix' / 'v3-receipts.json').read_text())
    (WORK / 'jobs').mkdir(exist_ok=True)
    (WORK / 'jobs' / 'st.json').write_text(json.dumps({'anchor': {k: a[k] for k in ('epoch', 'root', 'state_root')}, 'proof': str(WORK / 'fix' / 'v3-step-e8700.bin')}))
    base = dict(headers=[(WORK / 'fix' / 'v3-checkpoint-header.hex').read_text().strip()], block=(WORK / 'fix' / 'v3-block.hex').read_text().strip(),
                l2_chain_id=L2_CHAIN, l2_number=s['l2_block']['number'], receipts=receipts, burn_index=0, l2_token=s['token'], route=s['route'],
                source_chain_id=E_CHAIN, vault=s['vault'])
    for tag, idx in (('rh', 0), ('rf', s.get('forged_receipt_index', 2))):
        j = dict(base, receipt_index=idx, step=str(WORK / 'out' / 'st' / 'step-compressed.bin'))
        (WORK / 'jobs' / f'{tag}.json').write_text(json.dumps(j))
    print('jobs written')


def verify():
    k = keys()
    s = state()
    ek = sorted_keys(k, 'e')
    vault, token = s['vault'], s['token']
    tr = json.loads((WORK / 'fix' / 'v3-trust.json').read_text())
    rh, rf = (json.loads((WORK / 'out' / t / 'release.json').read_text()) for t in ('rh', 'rf'))
    res = {'ran': 'real SP1 6.8.0 Groth16 release proofs of the rebuilt release program, real SP1VerifierGroth16 v6.1.0, '
                  'real ProvenanceSourceVault and BridgedStablecoinV3 on private anvils; L1 settlement and finality made up',
           'trust': tr, 'gas': {}, 'refusals': {}, 'checks': {}}
    for tag, r in (('honest', rh), ('forged', rf)):
        assert '0x' + r['public_values'][320:384] == s[tag]['vault_release_id'], f'{tag}: proof binds another release id'
        assert '0x' + r['public_values'][:64] == tr['trust_anchor'], f'{tag}: trust anchor'
    res['checks']['proof_release_ids_equal_vault_ids'] = True
    ph = sh(CAST, 'abi-encode', 'f(bytes,bytes)', '0x' + rh['public_values'], rh['proof_bytes'])
    pf = sh(CAST, 'abi-encode', 'f(bytes,bytes)', '0x' + rf['public_values'], rf['proof_bytes'])
    bad = rh['proof_bytes'][:-2] + ('00' if rh['proof_bytes'][-2:] != '00' else '01')
    pbad = sh(CAST, 'abi-encode', 'f(bytes,bytes)', '0x' + rh['public_values'], bad)
    hi, fi = tup(s['honest']), tup(s['forged'])
    # The forger's best lie: the forged burn's fields with the vault's real head at mintCount (so provenance matches).
    lie = dict(s['forged'], mint_head=s['vault_head_at_2'])
    li = tup(lie)
    lie_id = call(E, vault, f'releaseId({REL_T})(bytes32)', li)
    snap = rpc(E, 'evm_snapshot')
    sp1 = create(E, k['deployer'], SP1)
    res['sp1_verifier'], res['sp1_version'] = sp1, call(E, sp1, 'VERSION()(string)')
    plain = create(E, k['deployer'], PLAIN, sp1, tr['release_vkey'], tr['trust_anchor'], str(L2_CHAIN), token)
    cfg = (f"({sp1},{tr['release_vkey']},{tr['step_vkey']},{tr['step_vkey_words']},0x{tr['anchor_digest']},{L2_CHAIN},{token},"
           f"{GENESIS},{EPOCH},{addr(k['authority'])},{DELAY},{WINDOW},{COOLDOWN},{HANDOFF})")
    rec = create(E, k['deployer'], RECOVERABLE, cfg)
    assert call(E, rec, 'trustAnchor()(bytes32)') == tr['trust_anchor'], 'on-chain trust anchor derivation'
    res['checks']['recoverable_trust_anchor_derived_on_chain'] = True
    res['recoverable_handoff_delay'] = int(call(E, rec, 'handoffDelay()(uint64)').split()[0])
    res['codehash'] = {n: sh(CAST, 'codehash', '--rpc-url', E, a) for n, a in (('sp1_verifier', sp1), ('sp1_release_verifier', plain), ('recoverable_release_verifier', rec), ('vault', vault))}
    base_state = rpc(E, 'evm_snapshot')
    for name, v in (('sp1_release_verifier', plain), ('recoverable_release_verifier', rec)):
        out = {'verifier': v}
        # Direct calls on the verifier (views): the honest proof and the forged proof are both valid proofs.
        out['verify_honest'] = call(E, v, 'verifyRelease(address,bytes32,bytes)(bytes4)', vault, s['honest']['vault_release_id'], ph)
        out['verify_forged'] = call(E, v, 'verifyRelease(address,bytes32,bytes)(bytes4)', vault, s['forged']['vault_release_id'], pf)
        out['gas_verifyRelease_estimate'] = int(sh(CAST, 'estimate', '--rpc-url', E, v, 'verifyRelease(address,bytes32,bytes)', vault, s['honest']['vault_release_id'], ph))
        # Switch the vault through its own path: 6 of 7, 14 days.
        until = str(now(E) + 3600)
        nonce = call(E, vault, 'switchNonce()(uint64)').split()[0]
        d = call(E, vault, 'switchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', v, sh(CAST, 'codehash', '--rpc-url', E, v), nonce, until)
        out['gas_proposeVerifier'] = gas(send(E, k['deployer'], vault, 'proposeVerifier(address,uint64,uint256,bytes[])', v, nonce, until, cert(d, ek, 6)))
        warp(E, now(E) + DELAY + 1)
        out['gas_activateVerifier'] = gas(send(E, k['stranger'], vault, 'activateVerifier()'))
        rf_ = out.setdefault('refusals', {})
        rf_['forged_burn_real_proof'] = refused(E, k['stranger'], vault, f'releaseWithProof({REL_T},bytes)', fi, pf)
        rf_['forged_burn_lied_head_real_proof'] = refused(E, k['stranger'], vault, f'releaseWithProof({REL_T},bytes)', li, pf)
        rf_['forged_proof_for_honest_item'] = refused(E, k['stranger'], vault, f'releaseWithProof({REL_T},bytes)', hi, pf)
        rf_['tampered_honest_proof'] = refused(E, k['stranger'], vault, f'releaseWithProof({REL_T},bytes)', hi, pbad)
        out['gas_releaseWithProof_estimate'] = int(sh(CAST, 'estimate', '--rpc-url', E, '--from', addr(k['stranger']), vault, f'releaseWithProof({REL_T},bytes)', hi, ph))
        before = int(call(E, s['usdc'], 'balanceOf(address)(uint256)', s['honest']['recipient']).split()[0])
        r = send(E, k['stranger'], vault, f'releaseWithProof({REL_T},bytes)', hi, ph)
        out['gas_releaseWithProof'] = gas(r)
        out['release_tx'] = r['transactionHash']
        out['paid'] = int(call(E, s['usdc'], 'balanceOf(address)(uint256)', s['honest']['recipient']).split()[0]) - before
        assert out['paid'] == s['honest']['amount'], out
        rf_['replay'] = refused(E, k['stranger'], vault, f'releaseWithProof({REL_T},bytes)', hi, ph)
        rf_['forged_after_honest_paid'] = refused(E, k['stranger'], vault, f'releaseWithProof({REL_T},bytes)', fi, pf)
        out['vault_locked_after'] = int(call(E, vault, 'totalLocked()(uint64)').split()[0])
        res[name] = out
        rpc(E, 'evm_revert', base_state)
        base_state = rpc(E, 'evm_snapshot')
    res['lie_release_id'] = lie_id
    # What each refusal decodes to, for the report.
    for tag, sig in (('ProvenanceMismatch', 'ProvenanceMismatch()'), ('InvalidProof', 'InvalidProof()'), ('InvalidRelease', 'InvalidRelease()')):
        res['checks'][f'selector_{tag}'] = sh(CAST, 'sig', sig)
    rpc(E, 'evm_revert', snap)
    (WORK / 'v3-rehearsal.json').write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1))


{'nets': nets, 'burn': burn, 'jobs': jobs, 'verify': verify, 'stop': stop}[sys.argv[2]]()
