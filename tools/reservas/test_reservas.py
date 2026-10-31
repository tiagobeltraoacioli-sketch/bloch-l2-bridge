#!/usr/bin/env python3
"""Test of reservas.py (self-contained: one anvil as both "Ethereum" and "L2", a fake GnB-SMH RPC, temp dir).

  python3 test_reservas.py FOUNDRY_PROJECT_DIR

Stable: ContextBoundSourceVault (contracts/usdt) over MockStable (deposits, a committee release) against a
MockSupplyV2 token. wGSMH: a fake `getutxos` against a MockSupplyV1 / V2 token. Scenarios: equal -> ok;
deposit not yet minted -> surplus (soft) and a tolerance absorbs it; release without a burn -> deficit
(hard); pendingSupply counts as a liability; GnB-SMH equal / deficit; truncated GnB-SMH answer, foreign script and
a token without totalSupply -> unverifiable, never a deficit; exit codes with several bridges.
Needs Foundry (anvil, forge, cast) in ~/.foundry/bin.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
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
USER_KEY = '0x' + '0b' * 32
SCRIPT = '02' + '33' * 32
GNB = {'utxos': [], 'truncated': False}
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
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-1200:]}' if detail and not cond else ''))


class FakeGnB(BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers['content-length'])))
        u = GNB['utxos']
        res = {'address': req['params'][0], 'utxos': u, 'returned': len(u), 'utxo_count': len(u),
               'truncated': GNB['truncated'], 'satoshis': str(sum(int(x['value']) for x in u))}
        body = json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': res}).encode()
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='reservas-test-'))
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    anvil = subprocess.Popen([ANVIL, '--chain-id', '11155111', '--port', str(port), '--silent'])
    url = f'http://127.0.0.1:{port}'
    gnb = HTTPServer(('127.0.0.1', 0), FakeGnB)
    threading.Thread(target=gnb.serve_forever, daemon=True).start()
    gnb_url = f'http://127.0.0.1:{gnb.server_address[1]}'
    try:
        for _ in range(50):
            if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
                break
            time.sleep(0.2)
        user = out(CAST, 'wallet', 'address', '--private-key', USER_KEY).lower()
        sh(CAST, 'rpc', 'anvil_setBalance', user, hex(10**21), '--rpc-url', url)

        def create(target, *ctor):
            args = ['--constructor-args', *ctor] if ctor else []
            dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
                      target, *args)
            return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

        def send(key, to, *call):
            return json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json'))

        def view(to, sig, *args):
            return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

        def finalize():
            sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)

        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        k = lambda t: out(CAST, 'keccak', t)
        usdc = create('solidity-tests/BridgedStablecoin.t.sol:MockStable')
        vault = create('contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), usdc, str(10**12), '0',
                       '[' + ','.join(a for a, _ in signers) + ']', '2', f'({10**11},86400,2,604800,1,1)', '([],0,0)')
        sigs = lambda d: '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d)
                                        for _, key in signers[:2]) + ']'
        vu = str(2**40)
        send(DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
             sigs(view(vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)))
        send(DEPLOYER, usdc, 'mintTo(address,uint256)', user, str(10**9))
        send(USER_KEY, usdc, 'approve(address,uint256)', vault, str(10**9))
        send(USER_KEY, vault, 'deposit(uint64,bytes32)', str(10 * 10**6), '0x' + '00' * 12 + user[2:])
        token = create('solidity-tests/fixtures/MockSupply.sol:MockSupplyV2')
        wtoken = create('solidity-tests/fixtures/MockSupply.sol:MockSupplyV1')
        wtoken2 = create('solidity-tests/fixtures/MockSupply.sol:MockSupplyV2')
        send(DEPLOYER, token, 'set(uint256,uint256)', str(10 * 10**6), '0')
        finalize()

        stable = {'kind': 'stable', 'name': 'busdc', 'l2_rpc': url, 'token': token, 'eth_rpc': url, 'vault': vault}
        wgnb = {'kind': 'wgnb', 'name': 'wgsmh', 'l2_rpc': url, 'token': wtoken, 'gnb_rpc': gnb_url,
                'gnb_vault_address': 'gnb1mtest', 'gnb_vault_script': SCRIPT}

        def run(*bridges):
            f = work / 'cfg.json'
            f.write_text(json.dumps({'bridges': list(bridges), 'cast': CAST}))
            done = sh(sys.executable, HERE / 'reservas.py', '--config', f, 'check', ok=False)
            lines = [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')]
            return done.returncode, lines

        rows = lambda lines: [l for l in lines if l['kind'] == 'reserves']
        alerts = lambda lines, sev: [l for l in lines if l['kind'] == 'alert' and l['severity'] == sev]

        code, lines = run(stable)
        r = rows(lines)
        check('stable equal: ok, exit 0', code == 0 and r and r[0]['status'] == 'ok' and r[0]['backing'] == 10**7
              and r[0]['total_locked'] == 10**7 and not alerts(lines, 'hard'), lines)

        send(USER_KEY, vault, 'deposit(uint64,bytes32)', str(2 * 10**6), '0x' + '00' * 12 + user[2:])
        finalize()
        code, lines = run(stable)
        check('stable deposit not yet minted: surplus, soft, exit 3', code == 3 and rows(lines)[0]['difference'] == 2 * 10**6
              and alerts(lines, 'soft'), lines)
        g0 = json.loads(out(CAST, 'block', '0', '--json', '--rpc-url', url))['hash']
        code, lines = run(dict(stable, l2_genesis_hash=g0))
        check('l2_genesis_hash pin matches: still reported', code == 3 and rows(lines), lines)
        code, lines = run(dict(stable, l2_genesis_hash='0x' + '63' * 32))
        check('l2_genesis_hash pin differs: unverifiable (exit 1), no deficit', code == 1 and not rows(lines)
              and not alerts(lines, 'hard') and alerts(lines, 'soft')[0]['id'] == 'unverifiable', lines)
        code, lines = run(dict(stable, tolerance=2 * 10**6))
        check('stable surplus within tolerance: ok', code == 0 and rows(lines)[0]['status'] == 'ok', lines)
        send(DEPLOYER, token, 'set(uint256,uint256)', str(10 * 10**6), str(2 * 10**6))
        finalize()
        code, lines = run(stable)
        check('stable pendingSupply counts: queued mint makes it equal', code == 0
              and rows(lines)[0]['pending_supply'] == 2 * 10**6 and rows(lines)[0]['liabilities'] == 12 * 10**6, lines)

        # committee release with no burn behind it: the vault loses 3 while the L2 supply stays
        route = view(vault, 'routeId()(bytes32)')
        n = int(out(CAST, 'block-number', '--rpc-url', url)) - 1
        h = json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', url))['hash']
        item = f'({route},77,{"0x" + "66" * 20},{3 * 10**6},{k("no-burn")})'
        ctx = f'({2**40},{n},{h},1,{k("l2")})'
        d = view(vault, 'releaseDigest((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,uint64,'
                 'bytes32))(bytes32)', item, ctx)
        send(DEPLOYER, vault, 'release((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,uint64,'
             'bytes32),bytes[])', item, ctx, sigs(d))
        code, lines = run(stable)
        check('stable release not yet finalized on the source: still ok', code == 0, lines)
        finalize()
        code, lines = run(stable)
        hard = alerts(lines, 'hard')
        check('stable release without a burn: deficit 3 USDC, hard, exit 2', code == 2 and hard
              and hard[0]['shortfall'] == 3 * 10**6 and rows(lines)[0]['total_locked'] == 9 * 10**6, lines)

        # wGSMH
        send(DEPLOYER, wtoken, 'set(uint256)', '68295768')
        send(DEPLOYER, wtoken2, 'set(uint256,uint256)', '60000000', '8295768')
        finalize()
        GNB['utxos'] = [{'txid': 'aa' * 32, 'index': 2, 'value': '68295768', 'script_pubkey': SCRIPT}]
        code, lines = run(wgnb)
        r = rows(lines)
        check('wgnb v1 token, equal: ok (no pendingSupply -> 0)', code == 0 and r and r[0]['backing'] == 68295768
              and r[0]['pending_supply'] == 0 and r[0]['utxos'] == 1, lines)
        code, lines = run(dict(wgnb, token=wtoken2))
        check('wgnb v2 token: supply + pending == vault', code == 0 and rows(lines)[0]['liabilities'] == 68295768, lines)
        GNB['utxos'] = [{'txid': 'aa' * 32, 'index': 2, 'value': '60000000', 'script_pubkey': SCRIPT}]
        code, lines = run(wgnb)
        check('wgnb vault spent without a burn: deficit, exit 2', code == 2
              and alerts(lines, 'hard')[0]['shortfall'] == 8295768, lines)
        GNB['truncated'] = True
        code, lines = run(wgnb)
        check('wgnb truncated getutxos: unverifiable (exit 1), no deficit', code == 1 and not alerts(lines, 'hard')
              and alerts(lines, 'soft')[0]['id'] == 'unverifiable', lines)
        GNB['truncated'] = False
        GNB['utxos'] = [{'txid': 'aa' * 32, 'index': 2, 'value': '68295768', 'script_pubkey': '02' + '44' * 32}]
        code, lines = run(wgnb)
        check('wgnb UTXO paying another script: unverifiable', code == 1 and not alerts(lines, 'hard'), lines)
        code, lines = run(dict(wgnb, token=usdc))
        check('token without totalSupply: unverifiable, not a deficit', code == 1 and not alerts(lines, 'hard'), lines)

        GNB['utxos'] = [{'txid': 'aa' * 32, 'index': 2, 'value': '68295768', 'script_pubkey': SCRIPT}]
        code, lines = run(wgnb, stable)
        check('two bridges: one line each, the deficit sets exit 2', code == 2 and len(rows(lines)) == 2, lines)
        code, lines = run(wgnb, dict(stable, token=usdc))
        check('ok + unreadable bridge: exit 1, the readable one still reported', code == 1
              and rows(lines)[0]['status'] == 'ok', lines)
    finally:
        anvil.terminate()
        gnb.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    passed = sum(ok for _, ok in results)
    print(f'{passed}/{len(results)} passed')
    sys.exit(0 if passed == len(results) else 1)


if __name__ == '__main__':
    main()
