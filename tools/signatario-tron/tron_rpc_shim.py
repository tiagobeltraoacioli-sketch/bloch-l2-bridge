#!/usr/bin/env python3
"""Read-only Ethereum JSON-RPC view of one TRON node, for the unchanged bridge daemons.

  tron_rpc_shim.py --node http://127.0.0.1:8090 [--solidity http://127.0.0.1:8091] --port 42320 [--chain-id 728126428]
                   --vault 0xVAULT --from-block N --index DIR [--logs-rpc http://127.0.0.1:8545/jsonrpc]
                   [--recheck-s 30] [--fresh-s 1] [--grace-s 10] [--allow-remote-node]

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

Logs (`eth_getLogs`). The daemons ask for the vault's logs over its whole history. java-tron's HTTP API can answer
that only by reading every block, so the shim keeps a persisted, verified index of the vault named by `--vault`
(`tron_log_index.py`: what it trusts, how it is checked against the vault's own solidified state, how it notices a
changed solidified chain). A query for the vault costs no node request once the index is current, and at most
QUERY_BUDGET (400) plus about 250 while it catches up; a query it cannot answer completely yet is an ERROR, never a
shorter answer. A query for any other address is served for at most MAX_UNINDEXED_RANGE (100) blocks. `--from-block`
is the vault's creation block (`tron_deploy.py verify` prints it). The index is checked against the node (cursor
block id, the vault's deposit count, new blocks) by a background round every 2 s and by any query that finds it older
than `--fresh-s` (1 s); the receipts of the vault's logs of the last day are read again every `--recheck-s` (30 s).
So a log that left the solidified chain is served for at most about `--fresh-s` + `--recheck-s` after the node knows. `--logs-rpc` (the node's own JSON-RPC endpoint) only
names candidate blocks faster; nothing is believed from it. `tron_shimStats` reports the index and the node requests.

What it does not do: send transactions (TRON transactions are not Ethereum transactions; `tron_send.py` sends them),
filters, subscriptions, balances in TRX, traces. Unknown methods are refused, never guessed.

Run one per operator, beside the operator's OWN java-tron node, on loopback (a node that is not on loopback is refused
unless `--allow-remote-node` is given). It holds no key. Its only state is the log index directory, which can be
deleted at any time: it is rebuilt from the chain.
"""
import errno
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tronlib  # noqa: E402
import tron_log_index  # noqa: E402

MAX_UNINDEXED_RANGE = 100  # blocks per eth_getLogs for an address without an index: two node requests per block
HEAD_SPAN = 64             # blocks above the solidified one an indexed query may reach (read at the head, not indexed)
QUERY_BUDGET = 400         # node requests one eth_getLogs may spend bringing the index forward


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def h(n):
    return hex(int(n))


def b32(hexstr):
    return '0x' + hexstr.lower().removeprefix('0x').rjust(64, '0')


class Shim:
    index = None  # tron_log_index.LogIndex of the vault, when the shim was started with --vault
    lock = threading.Lock()
    query_budget = QUERY_BUDGET
    fresh_s = 1.0  # a query for history is answered without a round only if the index was checked this recently

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

    def indexed_logs(self, lo, to, topics):
        """eth_getLogs for the indexed vault: the solidified part from the index (no node request once it is current),
        at most HEAD_SPAN blocks above it from the head. Never a silently shorter range: an index that has not
        reached the block asked for is an error, and the caller asks again."""
        idx = self.index
        with self.lock:
            numeric = to not in ('finalized', 'latest')
            if numeric and int(to, 16) <= idx.verified and time.time() - idx.advanced_at < self.fresh_s:
                return idx.query(lo, int(to, 16), topics)  # history, checked a moment ago: nothing to read from the node
            try:
                solid = idx.advance(self.query_budget)
            except tron_log_index.Broken as e:
                raise RpcError(-32000, f'TRON log index refuses to answer: {e}') from e
            behind = RpcError(-32005, f'TRON log index is catching up: verified to block {idx.verified}, solidified '
                                      f'{solid}; ask again')
            if to == 'finalized':
                if idx.verified < solid:
                    raise behind
                return idx.query(lo, idx.verified, topics)
            hi = self.node.head()['number'] if to == 'latest' else int(to, 16)
            if hi <= idx.verified:
                return idx.query(lo, hi, topics)
            if idx.verified < solid:
                raise behind
            if hi - idx.verified > HEAD_SPAN:
                raise RpcError(-32005, f'eth_getLogs reaches {hi - idx.verified} blocks above the solidified block '
                                       f'(at most {HEAD_SPAN})')
            found = idx.query(lo, idx.verified, topics) if lo <= idx.verified else []
        return found + self.scan_logs(max(lo, idx.verified + 1), hi, {idx.vault}, topics, idx.verified)

    def get_logs(self, flt):
        if 'blockHash' in flt:
            raise RpcError(-32602, 'eth_getLogs by blockHash is not supported')
        lo = int(flt.get('fromBlock', '0x0'), 16)
        to = flt.get('toBlock', 'latest')
        addresses = flt.get('address')
        addresses = None if addresses is None else {a.lower() for a in ([addresses] if isinstance(addresses, str) else addresses)}
        topics = flt.get('topics') or []
        if self.index is not None and addresses == {self.index.vault}:
            return self.indexed_logs(lo, to, topics)
        solid_height = self.node.solidified()['number']
        hi = solid_height if to == 'finalized' else self.node.head()['number'] if to == 'latest' else int(to, 16)
        if hi - lo >= MAX_UNINDEXED_RANGE:
            raise RpcError(-32005, f'eth_getLogs over {hi - lo + 1} blocks for an address this shim keeps no index of '
                                   f'(at most {MAX_UNINDEXED_RANGE}: every block is two node requests). Start the shim '
                                   'with --vault for the vault\'s logs')
        return self.scan_logs(lo, hi, addresses, topics, solid_height)

    def scan_logs(self, lo, hi, addresses, topics, solid_height):
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
        if method == 'tron_shimStats':
            with self.lock:
                return {'node_requests': sum(self.node.requests.values()), 'by_method': dict(self.node.requests),
                        'index': None if self.index is None else self.index.status()}
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
    for attempt in range(40):
        try:
            server = ThreadingHTTPServer((host, port), Handler)
            break
        except OSError as e:
            # The port may be held for a moment by somebody's outgoing connection (it can lie in the system's ephemeral
            # range). A listener that really owns it stays, and the shim then gives up after ten seconds.
            if e.errno != errno.EADDRINUSE or attempt == 39:
                raise
            time.sleep(0.25)
    server.daemon_threads = True
    return server


def follow(shim, poll_s, budget=4000):
    """Keeps the index at the solidified block in the background, so that queries find it current."""
    said = None
    while True:
        try:
            with shim.lock:
                shim.index.advance(budget)
            problem = None
        except tron_log_index.Broken as e:
            problem = str(e)
        except Exception as e:  # noqa: BLE001  (a daemon thread must not die silently)
            problem = f'{type(e).__name__}: {e}'
        if problem != said:
            print(json.dumps({'t': int(time.time()), 'kind': 'alert' if problem else 'resolved', 'severity': 'critical',
                              'id': 'tron-log-index', 'reason': problem}), file=sys.stderr, flush=True)
            said = problem
        time.sleep(poll_s)


def main():
    args = sys.argv[1:]

    def opt(name, default=None):
        return args[args.index(name) + 1] if name in args else default

    if '--node' not in args or '--port' not in args:
        raise SystemExit(__doc__)
    node = tronlib.Node(opt('--node'), opt('--solidity'), cast=opt('--cast'), allow_remote='--allow-remote-node' in args)
    shim = Shim(node, opt('--chain-id'))
    if opt('--vault'):
        if opt('--from-block') is None or opt('--index') is None:
            raise SystemExit('--vault needs --from-block (the vault\'s creation block) and --index (a directory)')
        shim.index = tron_log_index.LogIndex(node, opt('--vault'), int(opt('--from-block')), opt('--index'), shim.chain_id,
                                             logs_rpc=opt('--logs-rpc'), recheck_s=float(opt('--recheck-s', '30')),
                                             grace_s=float(opt('--grace-s', '10')))
        shim.fresh_s = float(opt('--fresh-s', '1'))
    server = serve(shim, opt('--host', '127.0.0.1'), int(opt('--port')))
    if shim.index is not None:
        threading.Thread(target=follow, args=(shim, float(opt('--poll-s', '2'))), daemon=True).start()
    print(json.dumps({'kind': 'tron-shim', 'chain_id': shim.chain_id, 'port': int(opt('--port')),
                      'index': None if shim.index is None else shim.index.status()}), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
