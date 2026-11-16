#!/usr/bin/env python3
"""Read-only Ethereum JSON-RPC view of one TRON node, for the unchanged bridge daemons.

  tron_rpc_shim.py --node http://127.0.0.1:8090 [--solidity http://127.0.0.1:8091] --port 42320 [--chain-id 728126428]

The signer's source half (`eth_half.py`), the relayer's reads (`vigia.py`), the guardian (`guardiao.py`) and the
reserves monitor (`reservas.py`) speak Ethereum JSON-RPC and take their safety from one word: `finalized`. java-tron's
own JSON-RPC cannot serve them: its `eth_call`, `eth_getCode` and `eth_getStorageAt` accept only `latest`, and it has
no state at `finalized`. This shim answers the few methods those tools use from java-tron's native HTTP API, with one
rule that carries all the weight:

  `finalized`  = the latest SOLIDIFIED block. Every answer for it comes from `/walletsolidity/*` and from nowhere else.
  `latest`     = the head, from `/wallet/*`.
  a height N   = the solidified answer when N <= the solidified height, the head answer when N is above it for blocks
                 and logs, and an ERROR for state (`eth_call`, `eth_getCode`): a TRON node keeps no historical state.
                 For N at or below the solidified height the state served is the CURRENT solidified state, which is the
                 state at some final block >= N. The tools read only monotone facts this way (immutable code, pure
                 views, set-once flags, append-only chains, counters that only grow), and a value read is never
                 less final than asked.

What it does not do: send transactions (TRON transactions are not Ethereum transactions; `tron_send.py` sends them),
filters, subscriptions, balances in TRX, traces. Unknown methods are refused, never guessed.

Run one per operator, beside the operator's OWN java-tron node, on loopback. It holds no key and no state.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tronlib  # noqa: E402

MAX_LOG_RANGE = 20_000  # blocks per eth_getLogs; each block is one node request


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def h(n):
    return hex(int(n))


def b32(hexstr):
    return '0x' + hexstr.lower().removeprefix('0x').rjust(64, '0')


class Shim:
    def __init__(self, node, chain_id=None):
        self.node = node
        genesis = node.block(0)
        if genesis is None:
            raise SystemExit('the TRON node returned no genesis block')
        # java-tron's eth_chainId and the TVM's CHAINID (with proposal 71 active): the last 4 bytes of the genesis block id.
        self.chain_id = int(genesis['id'][-8:], 16)
        if chain_id is not None and int(chain_id) != self.chain_id:
            raise SystemExit(f'this TRON node serves chain {self.chain_id}, not {chain_id}')

    # ── blocks ───────────────────────────────────────────────────────────────
    def resolve(self, ref):
        """-> (block dict, solid: bool). `ref` is a tag or a hex height."""
        if ref == 'finalized':
            return self.node.solidified(), True
        if ref == 'latest':
            return self.node.head(), False
        if ref in ('pending', 'safe', 'earliest') or not isinstance(ref, str) or not ref.startswith('0x'):
            raise RpcError(-32602, f'block reference {ref!r} is not supported: use latest, finalized or a hex height')
        number = int(ref, 16)
        solid = number <= self.node.solidified()['number']
        block = self.node.block(number, solid=solid)
        return block, solid

    @staticmethod
    def eth_block(b):
        return {'number': h(b['number']), 'hash': '0x' + b['id'], 'parentHash': '0x' + b['parent'].rjust(64, '0'),
                'timestamp': h(b['timestamp_ms'] // 1000), 'transactions': []}

    def state_level(self, ref):
        """True (solidified state) or False (head state) for a state read, or an error for a height above finality."""
        if ref in (None, 'latest'):
            return False
        if ref == 'finalized':
            return True
        if not isinstance(ref, str) or not ref.startswith('0x'):
            raise RpcError(-32602, f'state at {ref!r} is not supported')
        if int(ref, 16) <= self.node.solidified()['number']:
            return True
        raise RpcError(-32602, 'state at a height above the solidified block is not available on TRON; ask for latest')

    # ── logs ─────────────────────────────────────────────────────────────────
    def block_logs(self, number, solid):
        """Every log of one block, in block order, with its ordinal as logIndex (TRON receipts carry no log index)."""
        block = self.node.block(number, solid=solid)
        if block is None:
            return [], None
        out, index = [], 0
        for position, info in enumerate(self.node.block_infos(number, solid=solid)):
            if info.get('blockNumber', 0) != number:
                raise RpcError(-32000, 'the node returned a receipt of another block')
            for log in info.get('log', []):
                out.append({'address': '0x' + log['address'][-40:].lower(),
                            'topics': ['0x' + t.lower() for t in log.get('topics', [])],
                            'data': '0x' + log.get('data', '').lower(), 'blockNumber': h(number),
                            'blockHash': '0x' + block['id'], 'transactionHash': '0x' + info['id'],
                            'transactionIndex': h(position), 'logIndex': h(index), 'removed': False,
                            '_ok': tronlib.receipt_ok(info)})
                index += 1
        return out, block

    def get_logs(self, flt):
        if 'blockHash' in flt:
            raise RpcError(-32602, 'eth_getLogs by blockHash is not supported')
        solid_height = self.node.solidified()['number']
        lo = int(flt.get('fromBlock', '0x0'), 16)
        to = flt.get('toBlock', 'latest')
        hi = solid_height if to == 'finalized' else self.node.head()['number'] if to == 'latest' else int(to, 16)
        if hi - lo >= MAX_LOG_RANGE:
            raise RpcError(-32005, f'eth_getLogs range above {MAX_LOG_RANGE} blocks')
        addresses = flt.get('address')
        addresses = None if addresses is None else {a.lower() for a in ([addresses] if isinstance(addresses, str) else addresses)}
        topics = flt.get('topics') or []
        found = []
        for number in range(lo, hi + 1):
            logs, _ = self.block_logs(number, number <= solid_height)
            for log in logs:
                if addresses is not None and log['address'] not in addresses:
                    continue
                if len(log['topics']) < len(topics) or any(
                        want is not None and log['topics'][i] not in
                        ({want.lower()} if isinstance(want, str) else {w.lower() for w in want})
                        for i, want in enumerate(topics)):
                    continue
                if log.pop('_ok'):  # a reverted call leaves no logs on TRON; a failed receipt with logs is refused
                    found.append(log)
        return found

    # ── transactions ─────────────────────────────────────────────────────────
    def receipt(self, tx_hash):
        tx = tx_hash.lower().removeprefix('0x')
        info = self.node.tx_info(tx, solid=True)
        solid = bool(info and info.get('id') == tx)
        if not solid:
            info = self.node.tx_info(tx, solid=False)
        if not info or info.get('id') != tx:
            return None
        number = info.get('blockNumber', 0)
        logs, block = self.block_logs(number, solid)
        if block is None:
            return None
        mine = [{k: v for k, v in l.items() if k != '_ok'} for l in logs if l['transactionHash'] == '0x' + tx]
        ok = tronlib.receipt_ok(info)
        used = info.get('receipt', {}).get('energy_usage_total', 0)
        return {'transactionHash': '0x' + tx, 'blockNumber': h(number), 'blockHash': '0x' + block['id'],
                'status': '0x1' if ok else '0x0', 'logs': mine if ok else [], 'gasUsed': h(used),
                'cumulativeGasUsed': h(used), 'finalized': solid,
                'contractAddress': None, 'tron': tronlib.energy(info)}

    def transaction(self, tx_hash):
        tx = tx_hash.lower().removeprefix('0x')
        got = self.node.post('gettransactionbyid', {'value': tx})
        if not got or got.get('txID') != tx:
            return None
        info = self.node.tx_info(tx)
        number = info.get('blockNumber') if info and info.get('id') == tx else None
        d = tronlib.describe(bytes.fromhex(got['raw_data_hex'])) if got.get('raw_data_hex') else {}
        return {'hash': '0x' + tx, 'blockNumber': None if number is None else h(number), 'from': d.get('owner'),
                'to': d.get('contract'), 'input': d.get('data'), 'nonce': '0x0', 'gasPrice': '0x0',
                'expiration': d.get('expiration')}

    # ── state ────────────────────────────────────────────────────────────────
    def call(self, tx, ref):
        solid = self.state_level(ref)
        try:
            return self.node.call(tx['to'], tx.get('data', tx.get('input', '0x')), solid=solid, sender=tx.get('from'))
        except tronlib.TronError as e:
            text = str(e)
            if 'constant call failed' in text and ('REVERT' in text or 'revert' in text):
                raise RpcError(3, 'execution reverted') from e
            raise RpcError(-32000, text) from e

    def code(self, address, ref):
        """Runtime code. TRON serves it only from the head; for a final answer the contract must also exist in the
        solidified state (a constant call reaches it there). Deployed code on TRON does not change afterwards."""
        solid = self.state_level(ref)
        runtime = self.node.code(address)['runtime']
        if runtime in ('0x', ''):
            return '0x'
        if solid:
            try:
                self.node.call(address, '0x', solid=True)
            except tronlib.TronError as e:
                if 'REVERT' not in str(e) and 'revert' not in str(e).lower():
                    return '0x'  # not a contract in the solidified state yet
        return runtime

    # ── dispatch ─────────────────────────────────────────────────────────────
    def handle(self, method, p):
        if method in ('eth_chainId', 'net_version'):
            return h(self.chain_id) if method == 'eth_chainId' else str(self.chain_id)
        if method == 'eth_blockNumber':
            return h(self.node.head()['number'])
        if method == 'eth_getBlockByNumber':
            block, _ = self.resolve(p[0])
            return None if block is None else self.eth_block(block)
        if method == 'eth_call':
            return self.call(p[0], p[1] if len(p) > 1 else 'latest')
        if method == 'eth_getCode':
            return self.code(p[0], p[1] if len(p) > 1 else 'latest')
        if method == 'eth_getLogs':
            return self.get_logs(p[0])
        if method == 'eth_getTransactionReceipt':
            return self.receipt(p[0])
        if method == 'eth_getTransactionByHash':
            return self.transaction(p[0])
        if method == 'eth_getTransactionCount':
            return '0x0'  # TRON accounts have no nonce
        if method == 'eth_gasPrice':
            return '0x0'  # energy is priced by the chain, not bid; tron_send.py caps the fee
        raise RpcError(-32601, f'{method} is not served by the TRON shim (read-only; transactions go through tron_send.py)')


def serve(shim, host, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                req = json.loads(self.rfile.read(int(self.headers.get('content-length', 0))))
                one = lambda r: self.answer(shim, r)  # noqa: E731
                body = [one(r) for r in req] if isinstance(req, list) else one(req)
            except (ValueError, TypeError) as e:
                body = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': str(e)}}
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        @staticmethod
        def answer(shim, r):
            out = {'jsonrpc': '2.0', 'id': r.get('id')}
            try:
                out['result'] = shim.handle(r.get('method'), r.get('params') or [])
            except RpcError as e:
                out['error'] = {'code': e.code, 'message': e.message}
            except tronlib.TronError as e:
                out['error'] = {'code': -32000, 'message': str(e)}
            except (KeyError, IndexError, ValueError, TypeError, AttributeError) as e:
                out['error'] = {'code': -32602, 'message': f'bad request or node answer: {type(e).__name__}: {e}'}
            return out

    if host not in ('127.0.0.1', '::1', 'localhost'):
        raise SystemExit('the shim listens on loopback only')
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main():
    args = sys.argv[1:]

    def opt(name, default=None):
        return args[args.index(name) + 1] if name in args else default

    if '--node' not in args or '--port' not in args:
        raise SystemExit(__doc__)
    node = tronlib.Node(opt('--node'), opt('--solidity'), cast=opt('--cast'))
    shim = Shim(node, opt('--chain-id'))
    server = serve(shim, opt('--host', '127.0.0.1'), int(opt('--port')))
    print(json.dumps({'kind': 'tron-shim', 'chain_id': shim.chain_id, 'port': int(opt('--port'))}), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
