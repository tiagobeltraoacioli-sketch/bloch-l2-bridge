#!/usr/bin/env python3
"""Guardian, vigia, signer and monitor code against a real bloch-l2-settled-rpc, on a private copy of its data.

  python3 check_real_settled_rpc.py BINARY CANONICAL_DIR STATUS_JSON L2_MONITOR_PY PORT

Loopback only. It reads and never sends. The levels close by editing the status file, as in report 41, not by a follower
failing on its own. Each state prints one JSON line, and the exit code is non-zero if any expectation fails.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'guardiao'), str(ROOT / 'signatario-stable')]
import guardiao  # noqa: E402
import signatario  # noqa: E402
import vigia  # noqa: E402

NET = ['--rules', 'mainnet', '--domain', '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
       '--genesis-time', '1786656679']
failed = []


def raw(url, method, *params):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode(),
                                 {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def expect(state, name, cond, got):
    if not cond:
        failed.append((state, name, got))
    print(json.dumps({'state': state, 'check': name, 'ok': bool(cond), 'got': got}, default=str), flush=True)


def guardian(url, work):
    g = guardiao.Guardian.__new__(guardiao.Guardian)
    g.l2, g.cfg, g.name, g.stall_alert, g.frozen = url, {}, 'real', 2700, False
    g.state = {'problems': {}}
    return g


def relay(url, work):
    v = vigia.Vigia.__new__(vigia.Vigia)
    v.cfg = {'l2_rpc': url, 'token_from_block': 0}
    v.token, v.log_chunk, v.status_stale, v.last_burns = '0x' + '11' * 20, 10000, 2700, [{'burn_id': '0xkept'}]
    v.cast = str(Path.home() / '.foundry/bin/cast')
    return v


def monitor(script, url):
    done = subprocess.run([sys.executable, script, '--profile', 'mainnet', '--phase', 'live', '--l2-rpc', f'A={url}', '--json'],
                          capture_output=True, text=True, timeout=60)
    return {c['check']: c['level'] for c in json.loads(done.stdout)['checks']}


def main():
    binary, canonical, status_src, mon, port = sys.argv[1:6]
    url = f'http://127.0.0.1:{port}'
    work = Path(tempfile.mkdtemp(prefix='real-rpc-', dir=os.environ.get('WORK')))
    shutil.copytree(canonical, work / 'canonical')
    status = work / 'status.json'
    shutil.copy(status_src, status)
    saved = status.read_bytes()
    network = json.loads(saved)['network']
    log = open(work / 'rpc.log', 'w')
    proc = subprocess.Popen([binary, '--data-dir', str(work / 'canonical'), '--view-dir', str(work / 'view'), '--finality-status',
                             str(status), '--network', network, '--port', str(port), '--poll-ms', '1000', *NET], stdout=log, stderr=log)
    try:
        seen = []
        for _ in range(240):
            try:
                out = raw(url, 'eth_getBlockByNumber', 'finalized', False)
            except OSError:
                time.sleep(0.25)
                continue
            seen.append('-32001' if out.get('error', {}).get('code') == -32001 else 'null' if out.get('result') is None else 'block')
            if seen[-1] == 'block':
                break
            time.sleep(0.25)
        expect('startup', 'answers seen before a block', seen[-1:] == ['block'], sorted(set(seen)))
        for state, edit in [('frozen', None), ('deleted', 'unlink'), ('restored', 'restore'), ('corrupt', 'corrupt'),
                            ('fresh', 'fresh')]:
            if edit == 'unlink':
                status.unlink()
            elif edit == 'corrupt':
                status.write_text('{corrupt')
            elif edit == 'restore':
                status.write_bytes(saved)
            elif edit == 'fresh':
                doc = json.loads(saved)
                doc['written_at_unix'] = int(time.time())
                status.write_text(json.dumps(doc))
            if edit:
                time.sleep(4)
            closed = state in ('deleted', 'corrupt')
            old = state in ('frozen', 'restored')
            final = raw(url, 'eth_getBlockByNumber', 'finalized', False)
            stat = raw(url, 'bloch_finality')['result'].get('status')
            expect(state, 'real RPC: finalized', ('error' in final and final['error']['code'] == -32001) if closed else 'result' in final,
                   final.get('error') or int(final['result']['number'], 16))
            expect(state, 'real RPC: latest still served', isinstance(raw(url, 'eth_getBlockByNumber', 'latest', False).get('result'), dict), None)
            expect(state, 'real RPC: status', stat['state'] in ('missing', 'invalid') if closed else stat['state'] == 'ok', stat)
            g = guardian(url, work)
            g.log = lambda **kv: None
            fin = g.finalized_l2()
            g.track_head(int(time.time()), int(time.time()))
            expect(state, 'guardian: finalized None and a problem when closed, a number otherwise',
                   (fin is None and 'l2-finality-closed' in g.state['problems']) if closed
                   else (isinstance(fin, int) and 'l2-finality-closed' not in g.state['problems']), (fin, list(g.state['problems'])))
            expect(state, 'guardian: stale status from age_s', ('l2-status-stale' in g.state['problems']) == old and g.frozen == old,
                   (g.status_age(), list(g.state['problems']), g.frozen))
            v = relay(url, work)
            burns = v.burns()
            expect(state, 'vigia: closed keeps the last burns, open reads the chain', burns == [{'burn_id': '0xkept'}] if closed else burns == [], burns)
            got = signatario.finalized_or_closed(url)
            expect(state, 'signer: wait loop reads closed as not yet', (got is None) if closed else isinstance(got, dict), bool(got))
            levels = monitor(mon, url)
            want_age = {'frozen': 'CRIT', 'restored': 'CRIT', 'fresh': 'OK'}.get(state)
            expect(state, 'monitor: backend up, closed or age graded',
                   levels.get('l2_rpc[A]') == 'OK' and levels.get('l2_backends') == 'OK'
                   and (levels.get('l2_finality_closed[A]') == 'CRIT' if closed else levels.get('l2_status_age[A]') == want_age),
                   {k: v for k, v in levels.items() if k.startswith(('l2_rpc', 'l2_backends', 'l2_finality_closed', 'l2_status_age'))})
    finally:
        proc.terminate()
        proc.wait(20)
        shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({'failed': failed, 'binary_sha256_prefix': subprocess.run(['sha256sum', binary], capture_output=True, text=True).stdout[:16]}))
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
