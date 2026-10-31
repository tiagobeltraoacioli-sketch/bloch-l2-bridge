#!/usr/bin/env python3
"""End-to-end test of sombra.py (shadow-mode guardian) on an anvil "Ethereum" (self-contained: random port,
temp dir, cleanup).

  python3 test_sombra.py FOUNDRY_PROJECT_DIR

Ethereum = anvil 11155111 with a six-decimal MockStable, ContextBoundSourceVault (contracts/usdt) (2-of-3
releases, 3-of-3 switch/unpause, one guardian, pause 2 h, cooldown 1 h) and a shadow SP1ReleaseVerifier
over MockSP1. The light-client prover is simulated by writing its state.json/status.json; a fake Bloch L1
RPC serves `getchaininfo` for the epoch grace.
Scenarios: a proven committee release -> no pause; an unproven one -> pending, then a rejected proof does
not close it, then after the grace -> guardianPause (committee releases revert Paused), no second tx while
paused, a 3-of-3 unpause settles the finding (no further pause, still open), a valid proof -> resolved and no
pause after expiry; stale prover -> soft only; epoch grace holds the pause until L1 finalizes N epochs;
release first seen at or after `lc_max_epoch` (programs built before an L1 fork) -> soft only;
not a guardian -> unverifiable; after the light-client switch -> retired, no action.
Needs Foundry (anvil, forge, cast) in ~/.foundry/bin.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
GUARDIAN_KEY = '0x' + '6a' * 32
USER_KEY = '0x' + '0b' * 32
ETH_CHAIN, L2_CHAIN = 11155111, 700771
PAUSE, COOLDOWN, GRACE = 7200, 7200, 1800
VKEY = '0x' + '11' * 32
ANCHOR = '0x' + '22' * 32
L2_TOKEN = '0x000000000000000000000000000000000000b05c'
results = []
L1 = {'epoch': 100}


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


def start_anvil():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(ETH_CHAIN), '--port', str(port), '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


class FakeL1(BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers['content-length'])))
        body = json.dumps({'jsonrpc': '2.0', 'id': req['id'],
                           'result': {'finalized': {'epoch': L1['epoch']}}}).encode()
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


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
    work = Path(tempfile.mkdtemp(prefix='sombra-test-'))
    procs = []
    l1 = HTTPServer(('127.0.0.1', 0), FakeL1)
    threading.Thread(target=l1.serve_forever, daemon=True).start()
    l1_url = f'http://127.0.0.1:{l1.server_address[1]}'
    try:
        eth_proc, eth = start_anvil()
        procs.append(eth_proc)
        user = out(CAST, 'wallet', 'address', '--private-key', USER_KEY).lower()
        guardian = out(CAST, 'wallet', 'address', '--private-key', GUARDIAN_KEY).lower()
        for a in (user, guardian):
            sh(CAST, 'rpc', 'anvil_setBalance', a, hex(10**21), '--rpc-url', eth)
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        signer_list = '[' + ','.join(a for a, _ in signers) + ']'
        (work / 'pw').write_text('guardian-password\n')
        sh(CAST, 'wallet', 'import', 'guardian', '--private-key', GUARDIAN_KEY, '--keystore-dir', work,
           '--unsafe-password', 'guardian-password')
        sh(CAST, 'wallet', 'import', 'outsider', '--private-key', USER_KEY, '--keystore-dir', work,
           '--unsafe-password', 'guardian-password')

        def sigs(digest, n):
            return '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, digest)
                                  for _, k in signers[:n]) + ']'

        k = lambda t: out(CAST, 'keccak', t)
        usdc = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        sp1 = create(project, eth, 'solidity-tests/ContextBoundSourceVaultSwitch.t.sol:MockSP1')
        shadow = create(project, eth, 'contracts/usdt/SP1ReleaseVerifier.sol:SP1ReleaseVerifier',
                        sp1, VKEY, ANCHOR, str(L2_CHAIN), L2_TOKEN)
        send(eth, DEPLOYER, usdc, 'mintTo(address,uint256)', user, str(10**12))

        def deploy_vault(native):
            v = create(project, eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-sepolia'), k(native), k('USDC'), usdc, str(10**12), '0', signer_list, '2',
                       f'({10**11},86400,3,604800,1,1)', f'([{guardian}],{PAUSE},{COOLDOWN})')
            vu = str(2**40)
            d = view(eth, v, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
            send(eth, DEPLOYER, v, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu, sigs(d, 2))
            send(eth, USER_KEY, usdc, 'approve(address,uint256)', v, str(10**12))
            send(eth, USER_KEY, v, 'deposit(uint64,bytes32)', str(1000 * 10**6), '0x' + '00' * 12 + user[2:])
            return v

        vault = deploy_vault('bloch-l2-700771')
        def item(nonce, amount, v=None):
            route = view(eth, v or vault, 'routeId()(bytes32)')
            return f'({route},{nonce},{user},{amount},{k(f"burn-{nonce}")})'

        def rid(nonce, amount, v=None):
            return view(eth, v or vault, 'releaseId((bytes32,uint64,address,uint64,bytes32))(bytes32)',
                        item(nonce, amount, v)).lower()

        def committee_release(nonce, amount, v=None, ok=True):
            v = v or vault
            n = int(out(CAST, 'block-number', '--rpc-url', eth)) - 1
            h = json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', eth))['hash']
            ctx = f'({2**40},{n},{h},7,{k("l2-block-7")})'
            d = view(eth, v, 'releaseDigest((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,uint64,'
                     'bytes32))(bytes32)', item(nonce, amount, v), ctx)
            for attempt in range(3):
                r = send(eth, DEPLOYER, v, 'release((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,'
                         'uint64,bytes32),bytes[])', item(nonce, amount, v), ctx, sigs(d, 2), ok=ok)
                # cast exits 0 on a mined revert. About 1 run in 20 on a loaded host: the test must not read that as "no release".
                if not ok or not isinstance(r, dict) or r.get('status') == '0x1':
                    return r
                print(f'harness: release {nonce} reverted on chain, attempt {attempt + 1}', flush=True)
            raise SystemExit(f'release {nonce} reverted three times')

        def proof(nonce, amount, v=None, valid=True):
            pv = view(eth, shadow, 'expectedPublicValues(address,bytes32)(bytes)', v or vault, rid(nonce, amount, v))
            inner = k(out(CAST, 'abi-encode', 'f(bytes32,bytes)', VKEY, pv))
            pb = out(CAST, 'abi-encode', 'f(bytes32)', inner if valid else k('forged'))
            return {'status': 'proven', 'mode': 'groth16', 'release_id': rid(nonce, amount, v), 'public_values': pv,
                    'proof_bytes': pb, 'l2_number': 7, 'seconds': 1800}

        prover = work / 'prover'
        prover.mkdir()

        def prover_state(burns, fresh=True):
            (prover / 'state.json').write_text(json.dumps({'burns': burns}))
            (prover / 'status.json').write_text('{}')
            if not fresh:
                old = time.time() - 7200
                os.utime(prover / 'status.json', (old, old))

        def config(name, v, **extra):
            cfg = {'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': v, 'vault_from_block': 0,
                   'prover_dir': str(prover), 'shadow_verifier': shadow, 'grace_s': GRACE,
                   'keystore': str(work / 'guardian'), 'password_file': str(work / 'pw'), 'cast': CAST,
                   'state': str(work / f'{name}.state.json'), **extra}
            f = work / f'{name}.json'
            f.write_text(json.dumps(cfg))
            return f

        def run(cfg):
            done = sh(sys.executable, HERE / 'sombra.py', '--config', cfg, 'check', ok=False)
            lines = [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')]
            return done.returncode, lines, done.stderr[-800:]

        def kinds(lines, kind):
            return [l for l in lines if l.get('kind') == kind]

        nonce_of = lambda: int(out(CAST, 'nonce', guardian, '--rpc-url', eth))
        cfg = config('main', vault)

        # 1. a committee release the prover proves: no alarm
        committee_release(1, 10 * 10**6)
        prover_state({k('burn-1'): dict(proof(1, 10 * 10**6), burn_id=k('burn-1'))})
        code, lines, err = run(cfg)
        check('proven release: exit 0, verified by the shadow verifier', code == 0 and kinds(lines, 'proven')
              and kinds(lines, 'proven')[0]['how'] == 'shadow verifier', (code, lines, err))
        check('proven release: no pause', not kinds(lines, 'pause') and nonce_of() == 0)

        # 2. an unbacked release (no burn, no proof): pending inside the grace
        committee_release(2, 7 * 10**6)
        burns = {k('burn-1'): dict(proof(1, 10 * 10**6), burn_id=k('burn-1'))}
        prover_state(burns)
        code, lines, _ = run(cfg)
        check('unproven release within the grace: pending, exit 0', code == 0 and kinds(lines, 'pending'), lines)
        burns[k('burn-2')] = dict(proof(2, 7 * 10**6, valid=False), burn_id=k('burn-2'))
        prover_state(burns)
        code, lines, _ = run(cfg)
        check('forged proof is rejected by the shadow verifier, still no pause yet',
              any('proof rejected' in (l.get('reason') or '') for l in lines) and not kinds(lines, 'pause')
              and nonce_of() == 0, lines)

        # 3. past the grace: pause
        warp(eth, GRACE)
        code, lines, _ = run(cfg)
        p = kinds(lines, 'pause')
        check('past the grace: hard finding, guardianPause sent', code == 2 and p and p[0]['ok'], lines)
        check('vault paused, pauseCount 1', view(eth, vault, 'paused()(bool)') == 'true'
              and view(eth, vault, 'pauseCount()(uint64)') == '1')
        r = committee_release(3, 1 * 10**6, ok=False)
        check('committee release reverts while paused', not isinstance(r, dict)
              and out(CAST, 'sig', 'Paused()') in (r.stderr + r.stdout), getattr(r, 'stderr', r))
        n0 = nonce_of()
        code, lines, _ = run(cfg)
        check('next round: pause-skip, no second tx', code == 2 and kinds(lines, 'pause-skip')
              and not kinds(lines, 'pause') and nonce_of() == n0, lines)

        # 4. a 3-of-3 committee unpause settles this finding: it stays open, and starts no further pause
        until = str(2**40)
        d = view(eth, vault, 'unpauseDigest(uint64,uint256)(bytes32)', '1', until)
        bad = send(eth, DEPLOYER, vault, 'unpause(uint64,uint256,bytes[])', '1', until, sigs(d, 2), ok=False)
        check('2-of-3 cannot unpause', not isinstance(bad, dict))
        send(eth, DEPLOYER, vault, 'unpause(uint64,uint256,bytes[])', '1', until, sigs(d, 3))
        code, lines, _ = run(cfg)
        check('after a committee unpause: settled, still open, no tx', code == 2 and kinds(lines, 'settled-by-unpause')
              and nonce_of() == n0, lines)
        warp(eth, COOLDOWN)
        code, lines, _ = run(cfg)
        check('after the cooldown, still unproven: the old finding does not undo the unpause', code == 2
              and not kinds(lines, 'pause') and nonce_of() == n0 and view(eth, vault, 'pauseCount()(uint64)') == '1', lines)

        # 5. the (simulated) prover finally proves it: resolved, no pause after expiry
        burns[k('burn-2')] = dict(proof(2, 7 * 10**6), burn_id=k('burn-2'))
        prover_state(burns)
        code, lines, _ = run(cfg)
        check('valid proof arrives: proven + resolved, exit 0', code == 0 and kinds(lines, 'proven')
              and kinds(lines, 'resolved'), lines)
        warp(eth, PAUSE)
        n1 = nonce_of()
        code, lines, _ = run(cfg)
        check('pause expired, nothing open: no new pause', code == 0 and nonce_of() == n1
              and view(eth, vault, 'paused()(bool)') == 'false', lines)

        # 6. stale prover: soft only
        prover_state(burns, fresh=False)
        code, lines, _ = run(cfg)
        check('stale prover status: soft alert (exit 3), no pause', code == 3 and nonce_of() == n1
              and any(l.get('id') == 'prover-stale' for l in lines), lines)
        prover_state(burns)

        # 7. epoch grace: time alone is not enough
        vault2 = deploy_vault('another-native-domain')
        cfg2 = config('epochs', vault2, l1_rpc=l1_url, grace_l1_epochs=3)
        committee_release(9, 5 * 10**6, v=vault2)
        code, lines, _ = run(cfg2)
        warp(eth, GRACE)
        L1['epoch'] += 2
        code, lines, _ = run(cfg2)
        check('epoch grace: past grace_s but 2 < 3 L1 epochs -> no pause', code == 0 and nonce_of() == n1, lines)
        L1['epoch'] += 1
        code, lines, _ = run(cfg2)
        check('epoch grace: 3 L1 epochs -> pause', code == 2 and kinds(lines, 'pause')
              and view(eth, vault2, 'paused()(bool)') == 'true', lines)

        # 7b. a release first seen at an L1 epoch the deployed light-client programs cannot prove: soft only
        vault3 = deploy_vault('third-native-domain')
        cfg3 = config('lc-range', vault3, l1_rpc=l1_url, lc_max_epoch=L1['epoch'])
        committee_release(11, 5 * 10**6, v=vault3)
        code, lines, _ = run(cfg3)
        warp(eth, GRACE)
        n3 = nonce_of()
        code, lines, _ = run(cfg3)
        soft = [l for l in lines if str(l.get('id', '')).startswith('lc-out-of-range:')]
        check('lc_max_epoch: unproven release past the light-client build range -> soft lc-out-of-range, no pause',
              code == 3 and soft and soft[0]['severity'] == 'soft' and nonce_of() == n3
              and view(eth, vault3, 'paused()(bool)') == 'false', lines)

        # 8. a key that is not a guardian: unverifiable, no tx
        out_cfg = config('outsider', vault, keystore=str(work / 'outsider'))
        committee_release(4, 1 * 10**6)
        warp(eth, GRACE)
        un = int(out(CAST, 'nonce', user, '--rpc-url', eth))
        code, lines, _ = run(out_cfg)
        check('not a guardian: unverifiable (exit 1), no tx', code == 1 and int(out(CAST, 'nonce', user, '--rpc-url', eth)) == un,
              lines)

        # 9. after the one-way switch the guardian is retired
        vu = str(2**40)
        sw = view(eth, vault, 'switchNonce()(uint64)')
        code_hash = k(out(CAST, 'code', shadow, '--rpc-url', eth))
        d = view(eth, vault, 'switchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', shadow, code_hash, sw, vu)
        send(eth, DEPLOYER, vault, 'proposeVerifier(address,uint64,uint256,bytes[])', shadow, sw, vu, sigs(d, 3))
        warp(eth, 7 * 86400)
        send(eth, DEPLOYER, vault, 'activateVerifier()')
        n2 = nonce_of()
        code, lines, _ = run(cfg)
        check('after the switch: retired, exit 0, no tx', code == 0 and kinds(lines, 'switched') and nonce_of() == n2,
              lines)
    finally:
        for p in procs:
            p.terminate()
        l1.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    passed = sum(ok for _, ok in results)
    print(f'{passed}/{len(results)} passed')
    sys.exit(0 if passed == len(results) else 1)


if __name__ == '__main__':
    main()
