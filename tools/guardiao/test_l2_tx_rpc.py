#!/usr/bin/env python3
"""A guardian that reads a read-only replica and sends elsewhere, on private anvils.

  python3 test_l2_tx_rpc.py <foundry project>

The "replica" is a loopback stub in front of anvil: it refuses eth_sendRawTransaction with the settled RPC's real
message, and can freeze `latest` to show only settled blocks. Throwaway keys.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
FOUNDRY = Path.home() / '.foundry/bin'
ANVIL, CAST, FORGE = (str(FOUNDRY / n) for n in ('anvil', 'cast', 'forge'))
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
        '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ea870594951c0dd29efaa5a',
        '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
GUARDIAN_KEY = '0x' + '0c' * 32
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:3]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:600]}' if detail and not cond else ''), flush=True)


def start_anvil(chain_id):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain_id), '--port', str(port), '--host', '127.0.0.1', '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


class Replica:
    """Read-only: refuses sends as the settled RPC does. `frozen` pins `latest` to the last settled block."""
    REFUSAL = "can't insert transaction into the noop pool that does nothing"

    def __init__(self, upstream):
        self.frozen, self.refused, self.down = None, 0, False
        me = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers['content-length'])))
                if req.get('method') == 'eth_sendRawTransaction':
                    me.refused += 1
                    return self.reply({'jsonrpc': '2.0', 'id': req.get('id'),
                                       'error': {'code': -32003, 'message': me.REFUSAL}})
                params = list(req.get('params') or [])
                if me.frozen is not None:
                    params = [hex(me.frozen) if p == 'latest' else p for p in params]
                    if req.get('method') == 'eth_blockNumber':
                        return self.reply({'jsonrpc': '2.0', 'id': req.get('id'), 'result': hex(me.frozen)})
                body = json.dumps({**req, 'params': params}).encode()
                with urllib.request.urlopen(urllib.request.Request(upstream, body, {'content-type': 'application/json'})) as r:
                    self.reply(json.loads(r.read()))

            def reply(self, obj):
                data = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='l2-tx-rpc-test-'))
    procs, stub = [], None
    try:
        eth_proc, eth = start_anvil(ETH_CHAIN)
        l2_proc, l2 = start_anvil(L2_CHAIN)
        procs += [eth_proc, l2_proc]
        stub = Replica(l2)

        def create(url, target, *ctor):
            args = ['--constructor-args', *ctor] if ctor else []
            dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target, *args)
            return next(x.split()[-1] for x in dep.splitlines() if 'Deployed to' in x).lower()

        def view(url, to, sig, *args):
            return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in KEYS)
        addrs = '[' + ','.join(a for a, _ in signers) + ']'
        guardian = out(CAST, 'wallet', 'address', '--private-key', GUARDIAN_KEY).lower()
        sh(CAST, 'rpc', 'anvil_setBalance', guardian, hex(10**21), '--rpc-url', l2)
        sh(CAST, 'wallet', 'import', 'guardian', '--private-key', GUARDIAN_KEY, '--keystore-dir', work, '--unsafe-password', 'pw')
        (work / 'pw').write_text('pw\n')
        k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
        token = create(eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        vault = create(eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault', k('ethereum-sepolia'),
                       k('bloch-l2-700771'), k('USDC'), token, str(1_000_000 * U), '0', addrs, '2',
                       *POLICY_ARGS, '([],0,0)')
        route = view(eth, vault, 'routeId()(bytes32)').lower()
        limits = f'({1_000_000 * U},{100_000 * U},{100_000 * U // 86400},{50 * U},43200,{U})'
        stable = create(l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch Bridged USDC', 'bUSDC',
                        str(ETH_CHAIN), vault, route, addrs, '2', limits, f'([{guardian}],7200,7200)')
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)  # the vault is below the Ethereum `finalized` head
        fake = '0x' + 'fa' * 32
        who = '0x' + 'ab' * 20
        d = view(l2, stable, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', fake, '0', str(5 * U), who)
        blob = '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d)[2:] for _, key in signers[:2])
        sh(CAST, 'send', stable, 'mint(bytes32,uint64,uint64,address,bytes)', fake, '0', str(5 * U), who, blob,
           '--rpc-url', l2, '--private-key', DEPLOYER)

        def config(name, **extra):
            c = {'kind': 'stable', 'name': name, 'l2_rpc': stub.url, 'l2_chain_id': L2_CHAIN, 'token': stable,
                 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': vault, 'keystore': str(work / 'guardian'),
                 'password_file': str(work / 'pw'), 'cast': CAST, 'state': str(work / f'{name}.state'),
                 'reserves_grace_s': 0, 'provenance_grace_s': 0, 'release_sla_s': 600, 'l2_raw_tx': True,
                 'pause_retry_s': 0, 'l2_receipt_timeout_s': 20, **extra}
            path = work / f'{name}.json'
            path.write_text(json.dumps(c))
            return path

        def run(cfg):
            done = sh(sys.executable, HERE / 'guardiao.py', '--config', cfg, 'check', ok=False)
            return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')], done.stderr

        def kinds(lines, kind):
            return [x for x in lines if x.get('kind') == kind]

        def healthy(name):
            path = work / f'{name}.state.health.json'
            return json.loads(path.read_text()).get('healthy') if path.exists() else None

        def paused():
            return int(view(l2, stable, 'pauseCount()(uint64)')) > 0

        # ── the failure: reads and sends both on the read-only replica ──
        before = stub.refused
        rc, lines, err = run(config('same-rpc'))
        check('repro: the violation is detected', any(x.get('due') for x in lines), lines)
        check('repro: the read-only RPC refused the send and nothing paused', stub.refused > before and not paused(), lines)
        critical = [x for x in lines if x.get('kind') == 'alert' and x.get('id') == 'pause-failed']
        check('a failed pause raises a critical alert, not only a log line',
              critical and critical[0].get('severity') == 'critical', lines)
        check('a failed pause is retried within the round', stub.refused - before >= 3, stub.refused - before)
        check('a failed pause exits non-zero with its own code', rc == 4, (rc, lines, err))
        health = work / 'same-rpc.state.health.json'
        doc = json.loads(health.read_text()) if health.exists() else {}
        check('a failed pause marks the guardian unhealthy', doc.get('healthy') is False and 'pause-failed' in doc.get('problems', {}), doc)

        # alert_command gets the failure
        marker = work / 'alert.txt'
        cmd = [sys.executable, '-c', 'import sys;open(sys.argv[1],"a").write(sys.argv[2]+"\\n")', str(marker), '{id}']
        run(config('alerting', alert_command=cmd))
        check('alert_command runs on the failure', marker.exists() and 'pause-failed' in marker.read_text())

        # ── mainnet mode ──
        rc, lines, err = run(config('mainnet', l2_chain_id=700770))
        check('mainnet mode refuses a config without l2_tx_rpc', rc != 0 and 'l2_tx_rpc' in err and not lines, (rc, lines, err))

        # ── the fix: replica for reads, another endpoint for sends, with the replica frozen at the settled block ──
        stub.frozen = int(out(CAST, 'block-number', '--rpc-url', l2))
        before = stub.refused
        cfg = config('split', l2_tx_rpc=l2)
        rc, lines, err = run(cfg)
        sent = kinds(lines, 'pause')
        check('split: the pause lands through l2_tx_rpc', paused() and sent and sent[0].get('ok') is True, (rc, lines, err))
        check('split: nothing was sent to the replica', stub.refused == before, stub.refused - before)
        check('split: a violation still open exits 2, healthy', rc == 2, (rc, err))
        check('split: health file says healthy',
              healthy('split') is True)
        check('split: the replica does not show the pause yet', int(view(stub.url, stable, 'pauseCount()(uint64)')) == 0)
        rc, lines, err = run(cfg)
        check('split: not sent again while the settled view lags', not kinds(lines, 'pause')
              and kinds(lines, 'pause-skip') and int(view(l2, stable, 'pauseCount()(uint64)')) == 1, lines)
        # never visible on the reads side: the gateway's receipt is not the truth
        state = work / 'split.state'
        doc = json.loads(state.read_text())
        doc['pauses'][-1]['t'] -= 100_000
        state.write_text(json.dumps(doc))
        rc, lines, err = run(cfg)
        check('split: a pause never visible on the replica raises a critical alert',
              any(x.get('id') == 'pause-not-visible' and x.get('severity') == 'critical' for x in lines), lines)
        stub.frozen = None
        rc, lines, err = run(cfg)
        check('settled: the replica shows the pause, the guardian skips and is healthy again',
              kinds(lines, 'pause-skip') and not kinds(lines, 'pause')
              and healthy('split') is True, lines)
    finally:
        for p in procs:
            p.kill()
            p.wait()
        if stub:
            stub.server.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


POLICY_ARGS = [f'({100_000 * U},86400,2,604800,1,1)']

if __name__ == '__main__':
    main()
