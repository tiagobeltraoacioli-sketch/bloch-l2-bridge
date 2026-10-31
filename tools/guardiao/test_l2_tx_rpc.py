#!/usr/bin/env python3
"""A guardian that reads a read-only replica and sends elsewhere, on private anvils.

  python3 test_l2_tx_rpc.py <foundry project>

The "replica" is a loopback stub in front of anvil: it refuses eth_sendRawTransaction with the settled RPC's real
message, and can freeze `latest` to show only settled blocks. Throwaway keys.
"""
import json
import os
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
        self.closed, self.age = False, None  # stub finality; with REAL_SETTLED_RPC the real binary answers instead
        self.real = None
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
                tagged = req.get('method') == 'eth_getBlockByNumber' and params[:1] in (['finalized'], ['safe'])
                if me.real and (tagged or req.get('method') == 'bloch_finality'):
                    body = json.dumps(req).encode()
                    with urllib.request.urlopen(urllib.request.Request(me.real, body, {'content-type': 'application/json'})) as r:
                        return self.reply(json.loads(r.read()))
                if me.closed and tagged:
                    return self.reply({'jsonrpc': '2.0', 'id': req.get('id'),
                                       'error': {'code': -32001, 'message': 'finality unavailable: the follower status is missing'}})
                if req.get('method') == 'bloch_finality' and (me.closed or me.age is not None):
                    status = {'state': 'missing', 'age_s': None} if me.closed else {'state': 'ok', 'age_s': me.age}
                    return self.reply({'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'status': status}})
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
        doc = json.loads((work / 'split.state.health.json').read_text())
        check('health: a verified round records verified_t', abs(doc.get('verified_t', 0) - time.time()) < 60, doc)
        check('health: group-readable for the monitor, under any umask',
              (work / 'split.state.health.json').stat().st_mode & 0o777 == 0o640)
        rc, lines, err = run(config('blind', l2_genesis_hash='0x' + 'ab' * 32))
        doc = json.loads((work / 'blind.state.health.json').read_text())
        check('health: an unverifiable guardian looks healthy but has no verified_t, which the monitor raises',
              doc.get('healthy') is True and doc.get('verified_t') is None
              and any(x.get('id') == 'unverifiable' for x in lines), (doc, lines))

        # ── the settled RPC's finality levels close, or its follower stops (stub, or the real binary with REAL_SETTLED_RPC) ──
        status_file = os.environ.get('REAL_STATUS_FILE')
        stub.real = os.environ.get('REAL_SETTLED_RPC')
        saved = Path(status_file).read_bytes() if status_file else None

        def finality(state):
            stub.closed, stub.age = state == 'closed', {'stale': 100_000, 'fresh': 10}.get(state)
            if status_file:
                if state == 'closed':
                    Path(status_file).unlink()
                else:
                    doc = json.loads(saved)
                    if state == 'fresh':
                        doc['written_at_unix'] = int(time.time())
                    Path(status_file).write_text(json.dumps(doc))
                time.sleep(4)

        closed_cfg = config('closed', l2_stall_alert_s=2700)
        finality('closed')
        rc, lines, err = run(closed_cfg)
        ids = [x.get('id') for x in kinds(lines, 'alert')]
        check('closed: -32001 raises its own critical alert, exit 4', 'l2-finality-closed' in ids and rc == 4, (rc, ids, err))
        check('closed: not unverifiable, the round completes with finalized unknown',
              'unverifiable' not in ids and kinds(lines, 'round') and kinds(lines, 'round')[0].get('l2_finalized') is None, lines)
        check('closed: the checks at latest still find the violation', any(str(i).startswith(('reserves', 'provenance', 'mint')) for i in ids), ids)
        doc = json.loads((work / 'closed.state.health.json').read_text())
        check('closed: health is unhealthy for the monitor, verified_t still set',
              doc['healthy'] is False and 'l2-finality-closed' in doc['problems'] and doc.get('verified_t'), doc)
        finality('stale')
        rc, lines, err = run(closed_cfg)
        ids = [x.get('id') for x in kinds(lines, 'alert')]
        check('stale: a reopened level clears the closed problem', not json.loads((work / 'closed.state.health.json').read_text())['problems'].get('l2-finality-closed'), lines)
        check('stale: a follower stopped past the limit is critical, from age_s', 'l2-status-stale' in ids and rc == 4, (rc, ids, err))
        finality('fresh')
        rc, lines, err = run(closed_cfg)
        doc = json.loads((work / 'closed.state.health.json').read_text())
        check('fresh: a young status clears it', 'l2-status-stale' not in doc['problems'], doc)
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
