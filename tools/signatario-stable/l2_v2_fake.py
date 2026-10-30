#!/usr/bin/env python3
"""Test double of the v2 L2 binaries the signer runs, over an anvil "L2" (tests only, never deployed).

  l2_v2_fake.py reconstruct --target T --l1-follower F [--timestamp-rule R] [--rules ... --domain ... --genesis-time ...]
  l2_v2_fake.py --data-dir T --view-dir V --finality-status S --network N --port P [--rules ...]

`reconstruct` (bloch-l2-produce-dev): reads F/upstream.json {"url": anvil, "genesis": optional override,
"tamper_block": optional L2 number whose rebuilt hash is changed, "expect_args": [...], "log": optional
file}, writes T/upstream.json and prints the v2 report {"genesis", "native_blocks", "settled", "blocks"}.

Settled RPC (bloch-l2-settled-rpc): serves the anvil chain on 127.0.0.1:P like the real binary, with
`finalized` and `safe` taken only from the follower status S, checked like the real one (schema v2, network
N, production_finality false, chain id, L2 genesis final and equal to the local block 0, settlements
contiguous from 1 and equal to the local headers). Unverifiable status: `finalized` is null.
Every invocation is appended to the `log` file (argv), so tests can check the network arguments.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import urllib.request

TAG_METHODS = {'eth_getBlockByNumber': 0, 'eth_call': 1, 'eth_getCode': 1, 'eth_getBalance': 1,
               'eth_getStorageAt': 2, 'eth_getTransactionCount': 1}


def opts(argv):
    out = {}
    for i in range(0, len(argv) - 1, 2):
        out[argv[i]] = argv[i + 1]
    return out


def rpc(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}),
                                timeout=30) as r:
        return json.loads(r.read())


def record(up, argv):
    if up.get('log'):
        with open(up['log'], 'a') as f:
            f.write(json.dumps(argv) + '\n')
    missing = [a for a in up.get('expect_args', []) if a not in argv]
    if missing:
        sys.stderr.write(f'missing arguments {missing}\n')
        raise SystemExit(2)


def reconstruct(argv):
    o = opts(argv[1:])
    up = json.loads((Path(o['--l1-follower']) / 'upstream.json').read_text())
    record(up, argv)
    target = Path(o['--target'])
    target.mkdir(parents=True, exist_ok=True)
    (target / 'upstream.json').write_text(json.dumps(up))
    head = int(rpc(up['url'], 'eth_blockNumber', [])['result'], 16)
    blocks = []
    for n in range(0, head + 1):
        b = rpc(up['url'], 'eth_getBlockByNumber', [hex(n), False])['result']
        h = b['hash'][2:]
        if up.get('tamper_block') == n:
            h = 'ff' + h[2:]
        blocks.append({'number': n, 'hash': h, 'state_root': b['stateRoot'][2:], 'withdrawal_root': None,
                       'withdrawal_count': 0})
    genesis = up.get('genesis') or blocks[0]['hash']
    print(json.dumps({'genesis': genesis, 'native_blocks': head, 'settled': head, 'blocks': blocks[1:]}))


def serve(argv):
    o = opts(argv)
    up = json.loads((Path(o['--data-dir']) / 'upstream.json').read_text())
    record(up, argv)
    url, status_path, network = up['url'], Path(o['--finality-status']), o['--network'].lower()

    def levels():
        """(finalized number or None, status) as the real binary's verified_levels."""
        try:
            s = json.loads(status_path.read_text())
        except (OSError, ValueError):
            return None, None
        chain = int(rpc(url, 'eth_chainId', [])['result'], 16)
        if (s.get('schema') != 'bloch.l2.native-follower-status.v2' or s.get('network') != network
                or s.get('production_finality') is not False or s.get('chain_id') not in (None, chain)):
            return None, s
        g = s.get('l2_genesis') or {}
        local0 = rpc(url, 'eth_getBlockByNumber', ['0x0', False])['result']['hash'][2:]
        if g.get('hash') != local0:
            return None, s
        best = 0 if g.get('finalized') is True else None
        for i, e in enumerate(s.get('finalized_settlements') or [], 1):
            b = rpc(url, 'eth_getBlockByNumber', [hex(e['l2_number']), False])['result']
            if e['l2_number'] != i or b is None or b['hash'][2:] != e['l2_hash']:
                return None, s
            best = i
        return best, s

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers['content-length'])))
            method, params = req.get('method'), list(req.get('params') or [])
            fin, s = levels()
            if method == 'bloch_finality':
                out = {'jsonrpc': '2.0', 'id': req.get('id'), 'result': None if fin is None else {
                    'finalized': {'number': hex(fin)}, 'finalized_height': fin, 'l2_genesis': s.get('l2_genesis'),
                    'l1': {'finalized': {'epoch': s.get('native_finalized_epoch'),
                                         'root': s.get('native_finalized_block'),
                                         'slot': s.get('native_finalized_slot')},
                           'verified_tip': s.get('verified_tip'), 'verified_blocks': s.get('verified_blocks')}}}
            else:
                i = TAG_METHODS.get(method)
                if i is not None and len(params) > i and params[i] in ('finalized', 'safe'):
                    if fin is None:
                        out = {'jsonrpc': '2.0', 'id': req.get('id'), 'result': None}
                        return self.reply(out)
                    params[i] = hex(fin)
                out = rpc(url, method, params)
                out['id'] = req.get('id')
            self.reply(out)

        def reply(self, out):
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    ThreadingHTTPServer(('127.0.0.1', int(o['--port'])), Handler).serve_forever()


if __name__ == '__main__':
    if sys.argv[1:2] == ['reconstruct']:
        reconstruct(sys.argv[1:])
    else:
        serve(sys.argv[1:])
