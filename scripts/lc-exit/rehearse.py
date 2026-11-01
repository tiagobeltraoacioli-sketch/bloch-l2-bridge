#!/usr/bin/env python3
"""Private anvil rehearsal of the light-client exit path, with real SP1 Groth16 proofs.

  rehearse.py WORK vault-route      deploy token + vault, print the vault address and route, stop
  rehearse.py WORK vault            release and recovery through the vault only (no step proof needed)
  rehearse.py WORK full             the whole rehearsal; writes WORK/rehearsal.json

WORK holds bin/{anvil,forge,cast} and out/<tag>/ from the proof jobs. Loopback only, chain id 31337,
throwaway keys generated here and kept in WORK/anvil-keys.json. Nothing here touches a public network.
"""
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

WORK = Path(sys.argv[1])
BRIDGE = WORK / 'bridge'
CAST, FORGE, ANVIL = (str(WORK / 'bin' / n) for n in ('cast', 'forge', 'anvil'))
PORT = 24700
RPC = f'http://127.0.0.1:{PORT}'
GENESIS, EPOCH = 1786656679, 960
DELAY, WINDOW, COOLDOWN = 14 * 86400, 3 * 86400, 14 * 86400
L2_CHAIN, L2_TOKEN = 700771, '0x1267d2203aa5956d7b89181472a681e810868920'
USDT = 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault'
RECOVERABLE = 'contracts/usdt/RecoverableReleaseVerifier.sol:RecoverableReleaseVerifier'
PLAIN = 'contracts/usdt/SP1ReleaseVerifier.sol:SP1ReleaseVerifier'
SP1 = 'contracts/sp1/v6.1.0/SP1VerifierGroth16.sol:SP1Verifier'
TOKEN = 'solidity-tests/RecoverableReleaseVerifier.t.sol:RToken'


def sh(*a, check=True):
    p = subprocess.run(list(map(str, a)), capture_output=True, text=True, cwd=BRIDGE)
    if check and p.returncode:
        raise RuntimeError(f'{a[:3]}: {p.stdout[-800:]} {p.stderr[-1500:]}')
    return p.stdout.strip() if not check else p.stdout.strip()


def rpc(method, *params):
    q = urllib.request.Request(RPC, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode(),
                               headers={'content-type': 'application/json'})
    r = json.loads(urllib.request.urlopen(q, timeout=30).read())
    if 'error' in r:
        raise RuntimeError(r['error'])
    return r['result']


def keys():
    f = WORK / 'anvil-keys.json'
    if f.exists():
        return json.loads(f.read_text())
    k = {n: '0x' + secrets.token_hex(32) for n in ('deployer', 's1', 's2', 's3', 'authority', 'stranger')}
    f.touch(mode=0o600)
    f.write_text(json.dumps(k))
    return k


def addr(k):
    return sh(CAST, 'wallet', 'address', '--private-key', k)


class Net:
    def __init__(self, start_time):
        self.p = subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--port', str(PORT), '--chain-id', '31337', '--accounts', '0',
                                   '--timestamp', str(start_time), '--block-base-fee-per-gas', '0', '--gas-price', '0', '--order', 'fifo'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                rpc('eth_chainId')
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError('anvil did not start')

    def stop(self):
        self.p.terminate()
        self.p.wait()


def fund(*keys_):
    for k in keys_:
        rpc('anvil_setBalance', addr(k), hex(10**21))


def create(key, contract, *args):
    a = [FORGE, 'create', '--broadcast', '--rpc-url', RPC, '--private-key', key, contract]
    if args:
        a += ['--constructor-args', *args]
    out = sh(*a)
    return next(l.split()[-1] for l in out.splitlines() if l.startswith('Deployed to'))


def send(key, to, sig, *args):
    r = json.loads(sh(CAST, 'send', '--json', '--rpc-url', RPC, '--private-key', key, to, sig, *args))
    if r['status'] != '0x1':
        raise RuntimeError(f'{sig} reverted: {r}')
    return r


def refused(key, to, sig, *args):
    p = subprocess.run([CAST, 'send', '--json', '--rpc-url', RPC, '--private-key', key, to, sig, *map(str, args)],
                       capture_output=True, text=True, cwd=BRIDGE)
    if p.returncode == 0 and json.loads(p.stdout)['status'] == '0x1':
        raise RuntimeError(f'{sig} was expected to fail')
    return (p.stderr or p.stdout).strip()[-200:]


def call(to, sig, *args):
    return sh(CAST, 'call', '--rpc-url', RPC, to, sig, *args)


def warp(t):
    rpc('evm_setNextBlockTimestamp', hex(t))
    rpc('evm_mine')


def now():
    return int(rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)


def sign_digest(key, digest):
    return sh(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, digest)


def deploy_vault(k):
    """Same keys and order give the same addresses, which the release proofs bind."""
    fund(k['deployer'], k['s1'], k['s2'], k['s3'], k['authority'], k['stranger'])
    token = create(k['deployer'], TOKEN)
    signers = sorted(((addr(k[n]), k[n]) for n in ('s1', 's2', 's3')), key=lambda x: int(x[0], 16))
    k['_signers'] = signers
    vault = create(k['deployer'], USDT, '0x' + '01' * 32, '0x' + '02' * 32, '0x' + '03' * 32, token, str(10**12), '0',
                   '[' + ','.join(a for a, _ in signers) + ']', '2',
                   f'({10**10},86400,3,{7 * 86400},1,1)', '([],0,0)')
    return token, vault


def certify(k, digest, n=3):
    return '[' + ','.join(sign_digest(key, digest) for _, key in k['_signers'][:n]) + ']'


def recoverable(k, sp1, step_vkey, release_vkey, words, digest):
    cfg = f"({sp1},{release_vkey},{step_vkey},{words},{digest},{L2_CHAIN},{L2_TOKEN},{GENESIS},{EPOCH},{addr(k['authority'])},{DELAY},{WINDOW},{COOLDOWN})"
    return create(k['deployer'], RECOVERABLE, cfg)


def load(tag, name):
    return json.loads((WORK / 'out' / tag / f'{name}.json').read_text())


def gas(r):
    return int(r['gasUsed'], 16)


def full():
    k = keys()
    res = {'ran': 'real SP1 6.8.0 Groth16 proofs on a private anvil, real SP1VerifierGroth16 v6.1.0', 'gas': {}, 'refusals': {}}
    # Deployment time: before the real mainnet checkpoint, so the delay ends just after it.
    life = sys.argv[2] == 'full'
    real = load('real-step', 'step') if life else None
    real_epoch = int.from_bytes(bytes.fromhex(real['public_values'])[80:88], 'little') if life else 7108
    real_time = GENESIS + real_epoch * EPOCH
    start = real_time - DELAY + WINDOW - 7 * 86400 - 3600
    net = Net(start)
    try:
        token, vault = deploy_vault(k)
        sp1 = create(k['deployer'], SP1)
        res.update(token=token, vault=vault, sp1_verifier=sp1, sp1_version=call(sp1, 'VERSION()(string)'))
        r1, r2 = load('r1', 'release'), load('r2', 'release')
        t0, t1 = json.loads((WORK / 'fix' / 'trust-a0.json').read_text()), json.loads((WORK / 'fix' / 'trust-c1.json').read_text())
        tr = json.loads((WORK / 'fix' / 'trust-real.json').read_text())
        lc = recoverable(k, sp1, t0['step_vkey'], t0['release_vkey'], t0['step_vkey_words'], '0x' + t0['anchor_digest'])
        assert call(lc, 'trustAnchor()(bytes32)') == t0['trust_anchor'], 'trust anchor'
        res['verifier_a0'] = lc
        # A plain verifier on the new anchor is the successor: the re-anchor after a permanent stop.
        succ = create(k['deployer'], PLAIN, sp1, t1['release_vkey'], t1['trust_anchor'], str(L2_CHAIN), L2_TOKEN)
        res['successor_c1'] = succ
        # Fund, enable, switch through the vault's own 7-day path.
        item = r1['detail']['release_item']
        send(k['deployer'], token, 'mint(address,uint256)', addr(k['stranger']), str(10**9))
        until = str(now() + 3600)
        d = call(vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', until)
        send(k['deployer'], vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', until, certify(k, d, 2))
        send(k['stranger'], token, 'transferFrom(address,address,uint256)', addr(k['stranger']), addr(k['stranger']), '0')
        amount = item['amount']
        send(k['stranger'], vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + addr(k['stranger'])[2:])
        d = call(vault, 'switchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', lc,
                 sh(CAST, 'codehash', '--rpc-url', RPC, lc), '0', until)
        res['gas']['proposeVerifier'] = gas(send(k['deployer'], vault, 'proposeVerifier(address,uint64,uint256,bytes[])', lc, '0', until, certify(k, d, 3)))
        warp(now() + 7 * 86400)
        res['gas']['activateVerifier'] = gas(send(k['stranger'], vault, 'activateVerifier()'))
        route = call(vault, 'routeId()(bytes32)')
        item_t = f"({route},{item['nonce']},{item['recipient']},{item['amount']},{item['native_burn']})"
        release_id = call(vault, 'releaseId((bytes32,uint64,address,uint64,bytes32))(bytes32)', item_t)
        res['release_id'] = release_id
        assert ('0x' + r1['public_values'][320:384]) == release_id, 'proof binds another release id'
        p1 = sh(CAST, 'abi-encode', 'f(bytes,bytes)', '0x' + r1['public_values'], r1['proof_bytes'])
        p2 = sh(CAST, 'abi-encode', 'f(bytes,bytes)', '0x' + r2['public_values'], r2['proof_bytes'])
        # The real release proof passes the real verifier through the vault's verifier, before recovery.
        sel = call(lc, 'verifyRelease(address,bytes32,bytes)(bytes4)', vault, release_id, p1)
        res['verify_release_a0'] = sel
        res['gas']['verifyRelease_estimate_a0'] = int(sh(CAST, 'estimate', '--rpc-url', RPC, lc, 'verifyRelease(address,bytes32,bytes)(bytes4)', vault, release_id, p1))
        res['gas']['releaseWithProof_direct_estimate'] = int(sh(CAST, 'estimate', '--rpc-url', RPC, '--from', addr(k['stranger']), vault, 'releaseWithProof((bytes32,uint64,address,uint64,bytes32),bytes)', item_t, p1))
        res['refusals']['tampered_proof'] = refused(k['stranger'], vault, 'releaseWithProof((bytes32,uint64,address,uint64,bytes32),bytes)', item_t,
                                                    sh(CAST, 'abi-encode', 'f(bytes,bytes)', '0x' + r1['public_values'], r1['proof_bytes'][:-2] + ('00' if r1['proof_bytes'][-2:] != '00' else '01')))
        res['refusals']['new_anchor_proof_before_recovery'] = refused(k['stranger'], vault, 'releaseWithProof((bytes32,uint64,address,uint64,bytes32),bytes)', item_t, p2)
        # The light client "stops": the authority proposes the re-anchored successor.
        proposal_t = now()
        res['gas']['proposeSuccessor'] = gas(send(k['authority'], lc, 'proposeSuccessor(address)', succ))
        res['refusals']['activate_early'] = refused(k['stranger'], lc, 'activateSuccessor()')
        warp(proposal_t + DELAY + 2)
        res['gas']['activateSuccessor'] = gas(send(k['stranger'], lc, 'activateSuccessor()'))
        assert call(lc, 'successor()(address)').lower() == succ.lower()
        # After recovery: the old anchor's proof is refused, the new one pays through the same vault.
        res['refusals']['old_anchor_proof_after_recovery'] = refused(k['stranger'], vault, 'releaseWithProof((bytes32,uint64,address,uint64,bytes32),bytes)', item_t, p1)
        before = int(call(token, 'balanceOf(address)(uint256)', item['recipient']).split()[0])
        r = send(k['stranger'], vault, 'releaseWithProof((bytes32,uint64,address,uint64,bytes32),bytes)', item_t, p2)
        res['gas']['releaseWithProof_via_successor'] = gas(r)
        res['release_tx'] = r['transactionHash']
        after = int(call(token, 'balanceOf(address)(uint256)', item['recipient']).split()[0])
        res['paid'] = after - before
        assert res['paid'] == item['amount']
        res['refusals']['replay'] = refused(k['stranger'], vault, 'releaseWithProof((bytes32,uint64,address,uint64,bytes32),bytes)', item_t, p2)
    finally:
        net.stop()
    if not life:
        print(json.dumps(res, indent=1))
        return
    # Second net: a real mainnet step proof stops a proposal. Fresh time so the proposal's window holds it.
    net = Net(start)
    try:
        fund(k['deployer'], k['authority'], k['stranger'])
        sp1 = create(k['deployer'], SP1)
        lc = recoverable(k, sp1, tr['step_vkey'], tr['release_vkey'], tr['step_vkey_words'], '0x' + tr['anchor_digest'])
        keep = create(k['deployer'], PLAIN, sp1, tr['release_vkey'], tr['trust_anchor'], str(L2_CHAIN), L2_TOKEN)
        # Propose so that activation falls WINDOW after the real checkpoint's start.
        warp(real_time + WINDOW - DELAY - 3600)
        send(k['authority'], lc, 'proposeSuccessor(address)', keep)
        at = int(call(lc, 'activatesAt()(uint64)').split()[0])
        res['life'] = {'real_checkpoint_epoch': real_epoch, 'checkpoint_time': real_time, 'activates_at': at,
                       'earliest_life_checkpoint': at - WINDOW}
        pv = '0x' + real['public_values']
        res['refusals']['life_before_checkpoint_exists'] = refused(k['stranger'], lc, 'proveLife(bytes,bytes)', pv, real['proof_bytes'])
        warp(real_time + 1800)
        bad = real['proof_bytes'][:-2] + ('00' if real['proof_bytes'][-2:] != '00' else '01')
        res['refusals']['life_tampered'] = refused(k['stranger'], lc, 'proveLife(bytes,bytes)', pv, bad)
        r = send(k['stranger'], lc, 'proveLife(bytes,bytes)', pv, real['proof_bytes'])
        res['gas']['proveLife_real_mainnet_step'] = gas(r)
        res['life']['tx'] = r['transactionHash']
        assert int(call(lc, 'proposedSuccessor()(address)'), 16) == 0
        warp(at + 1)
        res['refusals']['activate_after_life'] = refused(k['stranger'], lc, 'activateSuccessor()')
    finally:
        net.stop()
    (WORK / 'rehearsal.json').write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1))


def vault_route():
    k = keys()
    net = Net(int(time.time()))
    try:
        token, vault = deploy_vault(k)
        print(json.dumps({'token': token, 'vault': vault, 'route': call(vault, 'routeId()(bytes32)'), 'chain_id': 31337}))
    finally:
        net.stop()


{'full': full, 'vault': full, 'vault-route': vault_route}[sys.argv[2]]()
