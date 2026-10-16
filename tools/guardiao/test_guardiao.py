#!/usr/bin/env python3
"""End-to-end test of guardiao.py on two anvil chains (self-contained: random ports, temp dir, cleanup).

  python3 test_guardiao.py FOUNDRY_PROJECT_DIR

"L2" = anvil 700771 with WrappedGnBV2 / BridgedStablecoinV2 (2-of-3 signers, one guardian, pause 2 h,
cooldown 2 h, large mints > 10 units delayed 1 h). "GnB" = gnb_node_fake.py over a fixture of transactions.
"Ethereum" = anvil 11155111 with a six-decimal MockStable and ContextBoundSourceVault (contracts/usdt).
Scenarios: healthy flows (no pause, release accounted, soft liveness alert only), forged mint (k signer
keys, no lock) -> pause, repeated rounds and cooldown -> no second pause tx, re-pause after the cooldown,
large queued mint without provenance -> pause before readyAt and executeMint reverts, reserves shortfall
(vault theft) -> pause, forged stable mint -> pause, vault release without a burn -> pause.
Needs Foundry (anvil, forge, cast) in ~/.foundry/bin.
"""
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
GUARDIAN_KEY = '0x' + '6a' * 32
VAULT_GUARDIAN_KEY = '0x' + '6b' * 32  # this guardian's Ethereum key (vault guardianPause)
SOMBRA_GUARDIAN = '0x' + '5b' * 20  # the vault's other guardian (sombra.py); not used here
USER_KEY = '0x' + '0b' * 32
L2_CHAIN, ETH_CHAIN, GNB_CHAIN = 700771, 11155111, '0x474E0002'
PREFIX = 'gnb1t'
VAULT_SCRIPT = '02' + '7a' * 32  # a 33-byte policy script
PAUSE, COOLDOWN, DELAY = 7200, 7200, 3600
MAX = str(2**256 - 1)
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:4]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-1500:]}' if detail and not cond else ''))


def address_of(script_hex):
    h = bytes.fromhex(script_hex)
    return PREFIX + (h + hashlib.sha3_256(hashlib.sha3_256(h).digest()).digest()[:4]).hex()


def marker(burn_id):
    return hashlib.sha3_256(b'GNB-RELEASE-v1' + bytes.fromhex(burn_id[2:])).digest()[:20].hex()


def start_anvil(chain_id):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain_id), '--port', str(port), '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


def create(project, url, target, *ctor):
    args = ['--constructor-args', *ctor] if ctor else []
    dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
              target, *args)
    return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()


def send(url, key, to, *call, ok=True):
    done = sh(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', ok=ok)
    return json.loads(done.stdout) if done.returncode == 0 else done


def view(url, to, sig, *args):
    return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]


def warp(url, seconds):
    sh(CAST, 'rpc', 'evm_increaseTime', str(seconds), '--rpc-url', url)
    sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', url)


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='guardiao-test-'))
    procs = []
    try:
        l2_proc, l2 = start_anvil(L2_CHAIN)
        procs.append(l2_proc)
        eth_proc, eth = start_anvil(ETH_CHAIN)
        procs.append(eth_proc)
        user = out(CAST, 'wallet', 'address', '--private-key', USER_KEY).lower()
        guardian = out(CAST, 'wallet', 'address', '--private-key', GUARDIAN_KEY).lower()
        for url in (l2, eth):
            sh(CAST, 'rpc', 'anvil_setBalance', user, hex(10**21), '--rpc-url', url)
        sh(CAST, 'rpc', 'anvil_setBalance', guardian, hex(10**21), '--rpc-url', l2)
        vault_guardian = out(CAST, 'wallet', 'address', '--private-key', VAULT_GUARDIAN_KEY).lower()
        sh(CAST, 'rpc', 'anvil_setBalance', vault_guardian, hex(10**21), '--rpc-url', eth)
        sh(CAST, 'wallet', 'import', 'vault-guardian', '--private-key', VAULT_GUARDIAN_KEY, '--keystore-dir', work,
           '--unsafe-password', 'guardian-password')
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        signer_list = '[' + ','.join(a for a, _ in signers) + ']'
        (work / 'pw').write_text('guardian-password\n')
        sh(CAST, 'wallet', 'import', 'guardian', '--private-key', GUARDIAN_KEY, '--keystore-dir', work,
           '--unsafe-password', 'guardian-password')
        guard = f'([{guardian}],{PAUSE},{COOLDOWN})'

        def guardian_nonce():
            return int(out(CAST, 'nonce', guardian, '--rpc-url', l2))

        def sign_concat(digest):
            return '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, digest)[2:]
                                  for _, k in signers[:2])

        def run_guardian(cfg, *extra):
            done = sh(sys.executable, HERE / 'guardiao.py', '--config', cfg, 'check', *extra, ok=False)
            lines = [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')]
            return done.returncode, lines, done.stderr[-800:]

        def kinds(lines, kind, **match):
            return [l for l in lines if l.get('kind') == kind and all(l.get(k) == v for k, v in match.items())]

        # ════════════════════════════ wGnB ════════════════════════════
        def deploy_wgnb():
            unit = 10**8
            limits = f'({1000 * unit},{100 * unit},{100 * unit // 86400},{10 * unit},{DELAY},100000)'
            return create(project, l2, 'contracts/wgnb/WrappedGnBV2.sol:WrappedGnBV2', GNB_CHAIN, signer_list, '2',
                          limits, guard)

        def mint_wgnb(token, txid, amount, recipient):
            d = view(l2, token, 'mintDigest(bytes32,uint32,uint64,address)(bytes32)', '0x' + txid, '0', str(amount),
                     recipient)
            r = send(l2, DEPLOYER, token, 'mint(bytes32,uint32,uint64,address,bytes)', '0x' + txid, '0', str(amount),
                     recipient, sign_concat(d))
            assert r['status'] == '0x1', r

        def wgnb_setup(name, txs, **extra):
            fx = work / f'{name}-fixture.json'
            fx.write_text(json.dumps({'prefix': PREFIX, 'txs': txs}))
            token = deploy_wgnb()
            fake = [sys.executable, str(HERE / 'gnb_node_fake.py'), '--fixture', str(fx)]
            cfg = {'kind': 'wgnb', 'name': name, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': token,
                   'gnb_chain_id': GNB_CHAIN, 'keystore': str(work / 'guardian'),
                   'password_file': str(work / 'pw'), 'cast': CAST, 'state': str(work / f'{name}-state.json'),
                   'gnb_utxos': fake + ['utxos', '--address', '{address}'],
                   'gnb_tx': fake + ['tx', '--txid', '{txid}'], 'gnb_vault_address': address_of(VAULT_SCRIPT),
                   'gnb_vault_script': VAULT_SCRIPT, 'gnb_address_prefix': PREFIX, 'gnb_min_conf': 30,
                   'reserves_grace_s': 0, 'provenance_grace_s': 0, 'pause_margin_s': 600, 'release_sla_s': 600,
                   **extra}
            path = work / f'{name}.json'
            path.write_text(json.dumps(cfg))
            return token, fx, path

        def fixture_add(fx, txid, tx):
            data = json.loads(fx.read_text())
            data['txs'][txid] = tx
            fx.write_text(json.dumps(data))

        user20 = user[2:]
        lock1, lock2 = '11' * 32, '22' * 32
        locks = {lock1: {'outputs': [[5 * 10**8, VAULT_SCRIPT], [546, user20], [7, '99' * 20]], 'confirmations': 50},
                 lock2: {'outputs': [[15 * 10**8, VAULT_SCRIPT], [546, user20]], 'confirmations': 50}}

        # ── healthy flow ──
        token, fx, cfg = wgnb_setup('healthy', dict(locks))
        mint_wgnb(token, lock1, 5 * 10**8, user)
        mint_wgnb(token, lock2, 15 * 10**8, user)  # large: queued for DELAY
        rc, lines, err = run_guardian(cfg)
        check('wgnb healthy: no violation after valid mints (one queued)', rc == 0 and not kinds(lines, 'alert'),
              (rc, lines, err))
        check('wgnb healthy: no pause sent', guardian_nonce() == 0 and view(l2, token, 'paused()(bool)') == 'false')
        rnd = kinds(lines, 'round')[0] if kinds(lines, 'round') else {}
        check('wgnb healthy: supply + pending == backing', rnd.get('total_supply') == 5 * 10**8
              and rnd.get('pending_supply') == 15 * 10**8 and rnd.get('backing') == 20 * 10**8, rnd)
        warp(l2, DELAY + 1)
        key2 = out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(bytes32,uint32)', '0x' + lock2, '0'))
        r = send(l2, DEPLOYER, token, 'executeMint(bytes32)', key2, ok=False)
        check('wgnb healthy: the queued mint executes (not paused)', isinstance(r, dict) and r['status'] == '0x1')
        spk = '42' * 20
        burn = send(l2, USER_KEY, token, 'burn(uint64,bytes)', str(2 * 10**8), '0x' + spk)
        burn_id = burn['logs'][-1]['topics'][1].lower()
        rc, lines, err = run_guardian(cfg)
        check('wgnb healthy: a burn not yet released is counted in flight', rc == 0
              and kinds(lines, 'round')[0].get('in_flight') == 2 * 10**8, (rc, lines, err))
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        warp(l2, 601)
        rc, lines, err = run_guardian(cfg)
        soft = kinds(lines, 'alert', severity='soft')
        check('wgnb liveness: finalized burn past the SLA -> soft alert only', rc == 3 and len(soft) == 1
              and soft[0]['id'] == f'liveness:{burn_id}' and not kinds(lines, 'pause')
              and guardian_nonce() == 0, (rc, lines, err))
        rc, lines, err = run_guardian(cfg)
        check('wgnb liveness: the alert is not repeated', rc == 3 and not kinds(lines, 'alert'), (rc, lines))
        release = 'a1' * 32
        fixture_add(fx, release, {'inputs': [[lock1, 0]], 'outputs': [[2 * 10**8 - 546 - 1000, spk],
                                                                      [546, marker(burn_id)],
                                                                      [3 * 10**8, VAULT_SCRIPT]]})
        rc, lines, err = run_guardian(cfg)
        check('wgnb healthy: the release is matched to its burn, alert resolved', rc == 0
              and kinds(lines, 'resolved') and kinds(lines, 'round')[0].get('released') == 1
              and kinds(lines, 'round')[0].get('backing') == 18 * 10**8, (rc, lines, err))
        check('wgnb healthy: never paused', guardian_nonce() == 0)

        # ── forged mint: k signer keys used without a lock ──
        token, fx, cfg = wgnb_setup('forged', {lock1: locks[lock1]})
        mint_wgnb(token, lock1, 5 * 10**8, user)
        mint_wgnb(token, 'cd' * 32, 3 * 10**8, user)  # no such lock
        rc, lines, err = run_guardian(cfg)
        ids = {l['id'] for l in kinds(lines, 'alert', severity='hard')}
        check('wgnb forged mint: hard alerts (provenance + reserves)', rc == 2 and 'reserves' in ids
              and any(i.startswith('mint:') for i in ids), (rc, lines, err))
        check('wgnb forged mint: pause sent and mints stopped', kinds(lines, 'pause', ok=True)
              and view(l2, token, 'paused()(bool)') == 'true' and guardian_nonce() == 1, (lines, err))
        is_paused = out(CAST, 'sig', 'IsPaused()')
        d = view(l2, token, 'mintDigest(bytes32,uint32,uint64,address)(bytes32)', '0x' + lock2, '0', '1', user)
        r = send(l2, DEPLOYER, token, 'mint(bytes32,uint32,uint64,address,bytes)', '0x' + lock2, '0', '1', user,
                 sign_concat(d), ok=False)
        check('wgnb forged mint: a validly signed mint reverts IsPaused', not isinstance(r, dict)
              and is_paused in r.stderr + r.stdout, getattr(r, 'stderr', r))
        rc, lines, err = run_guardian(cfg)
        check('wgnb forged mint: next round sends nothing (already paused)', rc == 2 and guardian_nonce() == 1
              and kinds(lines, 'pause-skip', reason='already paused') and not kinds(lines, 'alert'), (rc, lines))
        rc, lines, err = run_guardian(cfg)
        check('wgnb forged mint: the skip is logged once', not kinds(lines, 'pause-skip'), lines)
        warp(l2, PAUSE + 1)
        rc, lines, err = run_guardian(cfg)
        check('wgnb cooldown: pause expired, cooldown respected (no tx)', view(l2, token, 'paused()(bool)') == 'false'
              and guardian_nonce() == 1 and kinds(lines, 'pause-skip', reason='pause cooldown'), (rc, lines))
        warp(l2, COOLDOWN + 1)
        rc, lines, err = run_guardian(cfg)
        check('wgnb cooldown: the violation persists -> pauses again after the cooldown',
              guardian_nonce() == 2 and view(l2, token, 'pauseCount()(uint64)') == '2', (rc, lines))

        # ── large mint queued without provenance: pause before readyAt ──
        # lock2 is in the vault but not minted: the forged mint fits the reserves, so only provenance sees it.
        token, fx, cfg = wgnb_setup('queued', dict(locks), provenance_grace_s=86400)
        n0 = guardian_nonce()
        mint_wgnb(token, lock1, 5 * 10**8, user)
        mint_wgnb(token, 'ef' * 32, 15 * 10**8, user)  # forged and large: queued for DELAY
        key = out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(bytes32,uint32)', '0x' + 'ef' * 32, '0'))
        ready = int(out(CAST, 'call', token, 'pendingMints(bytes32)(address,uint64,uint64)', key,
                        '--rpc-url', l2).splitlines()[2].split()[0])
        rc, lines, err = run_guardian(cfg)
        alert = [l for l in kinds(lines, 'alert', severity='hard') if l['id'] == f'mint:{key}']
        check('wgnb queued: alert with a deadline before readyAt, no pause yet', rc == 2 and alert
              and alert[0]['deadline'] <= ready - 600 and guardian_nonce() == n0
              and not any(l['id'] == 'reserves' for l in kinds(lines, 'alert')), (rc, lines, err))
        warp(l2, DELAY - 600 + 5)
        rc, lines, err = run_guardian(cfg)
        now = int(json.loads(out(CAST, 'block', 'latest', '--json', '--rpc-url', l2))['timestamp'], 0)
        check('wgnb queued: paused before the mint is executable', kinds(lines, 'pause', ok=True) and now < ready
              and view(l2, token, 'paused()(bool)') == 'true', (rc, lines, err))
        warp(l2, 700)
        r = send(l2, DEPLOYER, token, 'executeMint(bytes32)', key, ok=False)
        check('wgnb queued: executeMint after readyAt reverts IsPaused', not isinstance(r, dict)
              and is_paused in r.stderr + r.stdout, getattr(r, 'stderr', r))

        # ── reserves shortfall: the vault is drained on the source chain ──
        token, fx, cfg = wgnb_setup('reserves', {lock1: locks[lock1]})
        mint_wgnb(token, lock1, 5 * 10**8, user)
        n0 = guardian_nonce()
        rc, lines, err = run_guardian(cfg)
        check('wgnb reserves: healthy before the theft', rc == 0 and guardian_nonce() == n0, (rc, lines, err))
        fixture_add(fx, 'be' * 32, {'inputs': [[lock1, 0]], 'outputs': [[4 * 10**8, '66' * 20],
                                                                         [10**8 - 1000, VAULT_SCRIPT]]})
        rc, lines, err = run_guardian(cfg)
        ids = {l['id'] for l in kinds(lines, 'alert', severity='hard')}
        res = [l for l in kinds(lines, 'alert', severity='hard') if l['id'] == 'reserves']
        check('wgnb reserves: shortfall + vault spend without a burn -> hard', 'reserves' in ids
              and f'release-unknown:{"be" * 32}' in ids and res and res[0]['shortfall'] == 4 * 10**8 + 1000,
              (rc, lines, err))
        check('wgnb reserves: pause sent', kinds(lines, 'pause', ok=True) and view(l2, token, 'paused()(bool)') == 'true')

        # ════════════════════════════ stablecoin ════════════════════════════
        mock = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda t: out(CAST, 'keccak', t)
        vault = create(project, eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), mock, str(10**12), '0', signer_list,
                       '2', f'({10**11},86400,2,604800)',
                       f'([{",".join(sorted([vault_guardian, SOMBRA_GUARDIAN]))}],{PAUSE},{COOLDOWN})')
        vu = str(int(time.time()) + 3600)
        d = view(eth, vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
        send(eth, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
             '[' + ','.join(sigs) + ']')
        route = view(eth, vault, 'routeId()(bytes32)').lower()
        send(eth, DEPLOYER, mock, 'mintTo(address,uint256)', user, str(100 * 10**6))
        send(eth, USER_KEY, mock, 'approve(address,uint256)', vault, MAX)
        dep_topic = k('Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
        r = send(eth, USER_KEY, vault, 'deposit(uint64,bytes32)', str(10 * 10**6), '0x' + '00' * 12 + user20)
        dep_log = next(l for l in r['logs'] if l['topics'][0].lower() == dep_topic)
        dep_id = dep_log['topics'][1].lower()
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)

        def deploy_stable():
            unit = 10**6
            limits = f'({1000 * unit},{100 * unit},{100 * unit // 86400},{50 * unit},{DELAY},{unit})'
            return create(project, l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch USDC',
                          'bUSDC', str(ETH_CHAIN), vault, route, signer_list, '2', limits, guard)

        def mint_stable(token, deposit_id, nonce, amount):
            d = view(l2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', deposit_id, str(nonce),
                     str(amount), user)
            r = send(l2, DEPLOYER, token, 'mint(bytes32,uint64,uint64,address,bytes)', deposit_id, str(nonce),
                     str(amount), user, sign_concat(d))
            assert r['status'] == '0x1', r

        def stable_cfg(name, token, vault_pause=True):
            cfg = {'kind': 'stable', 'name': name, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': token,
                   'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': vault, 'keystore': str(work / 'guardian'),
                   'password_file': str(work / 'pw'), 'cast': CAST, 'state': str(work / f'{name}-state.json'),
                   'reserves_grace_s': 0, 'provenance_grace_s': 0, 'release_sla_s': 600,
                   'vault_pause': vault_pause, 'l2_raw_tx': True, 'eth_keystore': str(work / 'vault-guardian'), 'eth_password_file': str(work / 'pw')}
            path = work / f'{name}.json'
            path.write_text(json.dumps(cfg))
            return path

        def vault_release(nonce, recipient, amount, native_burn, l2_block, l2_hash):
            anchor = int(out(CAST, 'block-number', '--rpc-url', eth)) - 1
            anchor_hash = json.loads(out(CAST, 'block', str(anchor), '--json', '--rpc-url', eth))['hash']
            item = f'({route},{nonce},{recipient},{amount},{native_burn})'
            ctx = f'({int(time.time()) + 86400 * 10},{anchor},{anchor_hash},{l2_block},{l2_hash})'
            sig = 'releaseDigest((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32))'
            d = view(eth, vault, sig + '(bytes32)', item, ctx)
            cert = '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d)
                                  for _, key in signers[:2]) + ']'
            r = send(eth, DEPLOYER, vault, 'release((bytes32,uint64,address,uint64,bytes32),'
                     '(uint256,uint256,bytes32,uint64,bytes32),bytes[])', item, ctx, cert)
            assert r['status'] == '0x1', r
            sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)

        # ── healthy: deposit -> mint -> burn -> release ──
        n0 = guardian_nonce()
        stable = deploy_stable()
        cfg = stable_cfg('stable-healthy', stable)
        mint_stable(stable, dep_id, 0, 10 * 10**6)
        rc, lines, err = run_guardian(cfg)
        check('stable healthy: deposit-backed mint, no violation', rc == 0 and not kinds(lines, 'alert')
              and kinds(lines, 'round')[0].get('backing') == 10 * 10**6, (rc, lines, err))
        bob = '0x' + 'b0' * 20
        burn = send(l2, USER_KEY, stable, 'burn(uint64,address)', str(2 * 10**6), bob)
        burn_id = burn['logs'][-1]['topics'][1].lower()
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        rc, lines, err = run_guardian(cfg)
        check('stable healthy: finalized burn within the SLA, in flight, no alert', rc == 0
              and kinds(lines, 'round')[0].get('in_flight') == 2 * 10**6, (rc, lines, err))
        vault_release(1, bob, 2 * 10**6, burn_id, int(burn['blockNumber'], 16), burn['blockHash'])
        rc, lines, err = run_guardian(cfg)
        rnd = kinds(lines, 'round')[0] if kinds(lines, 'round') else {}
        check('stable healthy: release matched, backing == supply', rc == 0 and rnd.get('released') == 1
              and rnd.get('backing') == 8 * 10**6 and rnd.get('total_supply') == 8 * 10**6, (rc, lines, err))
        vault_nonce = lambda: int(out(CAST, 'nonce', vault_guardian, '--rpc-url', eth))
        check('stable healthy: never paused', guardian_nonce() == n0 and vault_nonce() == 0
              and view(eth, vault, 'paused()(bool)') == 'false')
        healthy_nonce = guardian_nonce()

        # ── forged stable mint (no deposit) ──
        forged = deploy_stable()
        # a second token on the same test vault: the healthy token's release is "unknown" to it, so this
        # config leaves the vault alone (in production a vault has exactly one token)
        cfg2 = stable_cfg('stable-forged', forged, vault_pause=False)
        mint_stable(forged, '0x' + '5e' * 32, 7, 10**6)
        rc, lines, err = run_guardian(cfg2)
        ids = {l['id'] for l in kinds(lines, 'alert', severity='hard')}
        check('stable forged mint: provenance violation -> pause', rc == 2 and f'mint:0x{"5e" * 32}' in ids
              and kinds(lines, 'pause', ok=True) and view(l2, forged, 'paused()(bool)') == 'true'
              and guardian_nonce() == healthy_nonce + 1, (rc, lines, err))

        # ── vault release without an L2 burn (k vault keys misused) ──
        vault_release(99, '0x' + '66' * 20, 10**6, '0x' + '77' * 32, 1, '0x' + '88' * 32)
        rc, lines, err = run_guardian(cfg)
        ids = {l['id'] for l in kinds(lines, 'alert', severity='hard')}
        check('stable release without burn: hard (release + reserves) -> pause', rc == 2 and 'reserves' in ids
              and any(i.startswith('release-unknown:') for i in ids) and kinds(lines, 'pause', ok=True)
              and view(l2, stable, 'paused()(bool)') == 'true', (rc, lines, err))
        vp = kinds(lines, 'vault-pause', ok=True)
        check('stable release without burn: vault guardianPause with the Ethereum key', vp and vault_nonce() == 1
              and view(eth, vault, 'paused()(bool)') == 'true' and 'reserves' in vp[0]['violations'], lines)
        dep = send(eth, USER_KEY, vault, 'deposit(uint64,bytes32)', str(10**6), '0x' + '00' * 12 + user20, ok=False)
        check('stable vault paused: deposit reverts Paused', not isinstance(dep, dict)
              and out(CAST, 'sig', 'Paused()') in (dep.stderr + dep.stdout), getattr(dep, 'stderr', dep))
        rc, lines, err = run_guardian(cfg)
        check('stable vault paused: next round skips, no second vault tx', kinds(lines, 'vault-pause-skip')
              and not kinds(lines, 'vault-pause') and vault_nonce() == 1, lines)
        sh(CAST, 'rpc', 'evm_increaseTime', str(PAUSE), '--rpc-url', eth)
        sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', eth)
        dep = send(eth, USER_KEY, vault, 'deposit(uint64,bytes32)', str(10**6), '0x' + '00' * 12 + user20)
        check('stable vault pause expired: deposit works again', dep.get('status') == '0x1', dep)
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
