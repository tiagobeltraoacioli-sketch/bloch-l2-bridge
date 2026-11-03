#!/usr/bin/env python3
"""Relay nonces while no block lands, on a private anvil with mining off.

  python3 test_relay_nonce.py <foundry project>

An anvil with `--no-mining` keeps `latest` still as the L2 does between its 8-14 min settlement cycles, and has the same
same-nonce replacement rule. Scenarios: several sends before a block, a restart, a refused send, a full window, a dropped
transaction, an endpoint with no `pending` level. `Vigia.send` runs for real; the transactions are plain calls to
an address with no code, because nonces are the subject. Throwaway keys. Not a settled RPC: its spool limits are copied into
`max_inflight`, and the real admission code was not run here.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vigia  # noqa: E402

FOUNDRY = Path.home() / '.foundry/bin'
KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
FROM = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8'
TO = '0x' + '11' * 20
results = []


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:500]}' if detail and not cond else ''), flush=True)


def rpc(url, method, params):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as r:
        doc = json.load(r)
    if 'error' in doc:
        raise RuntimeError(doc['error'])
    return doc['result']


def main():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    anvil = subprocess.Popen([str(FOUNDRY / 'anvil'), '--chain-id', '700771', '--port', str(port), '--host', '127.0.0.1',
                              '--silent', '--no-mining'])
    work = Path(tempfile.mkdtemp(prefix='relay-nonce-'))
    try:
        for _ in range(50):
            try:
                rpc(url, 'eth_chainId', [])
                break
            except OSError:
                time.sleep(0.2)
        (work / 'gas.key').write_text(KEY + '\n')
        (work / 'gas.key').chmod(0o600)  # vigia refuses a key file others can read
        cfg = {'shared_dir': str(work / 'shared'), 'token': TO, 'source_vault': TO, 'source_route': '0x' + '22' * 32,
               'threshold': 1, 'l2_rpc': url, 'l2_tx_rpc': url, 'l2_chain_id': 700771, 'eth_rpc': url, 'eth_chain_id': 700771,
               'l2_relayer_key': str(work / 'gas.key'), 'eth_relayer_key': str(work / 'gas.key'),
               'cast': str(FOUNDRY / 'cast'), 'resend_after_s': 1800, 'max_inflight': 16,
               # anvil's quote climbs past the 50 gwei L2 default as the unmined pool grows; nonces are the subject here, and
               # the ceiling has its own tests (test_relayer_review GasPrice, agent 229)
               'l2_max_gas_price_gwei': 10000, 'eth_max_gas_price_gwei': 10000}
        path = work / 'cfg.json'
        path.write_text(json.dumps(cfg))
        v = vigia.Vigia(path)
        call = ['ping(uint256)', '1']
        count = lambda level='latest': int(rpc(url, 'eth_getTransactionCount', [FROM, level]), 16)

        sent = [v.send('l2', TO, call) for _ in range(3)]
        nonces = [int(rpc(url, 'eth_getTransactionByHash', [t])['nonce'], 16) for t in sent]
        check('three sends before a block use three nonces', nonces == [0, 1, 2] and count() == 0, nonces)

        v2 = vigia.Vigia(path)
        t = v2.send('l2', TO, call)
        check('a restarted relayer continues from its record', int(rpc(url, 'eth_getTransactionByHash', [t])['nonce'], 16) == 3)

        rpc(url, 'evm_mine', [])
        receipts = [rpc(url, 'eth_getTransactionReceipt', [x]) for x in sent + [t]]
        check('all of them land in the next block', all(r and r['status'] == '0x1' for r in receipts) and count() == 4, receipts)

        real = v.rpc
        def refuses(u, method, params):
            if method == 'eth_sendRawTransaction':
                raise RuntimeError('refused')
            return real(u, method, params)
        before = v.nonce_path.read_text()
        v.rpc = refuses
        try:
            v.send('l2', TO, call)
            refused = False
        except RuntimeError:
            refused = True
        v.rpc = real
        check('a refused send does not move the record', refused and v.nonce_path.read_text() == before)
        t = v.send('l2', TO, call)
        check('the next send takes the nonce the refused one left free', int(rpc(url, 'eth_getTransactionByHash', [t])['nonce'], 16) == 4)
        rpc(url, 'evm_mine', [])

        for _ in range(16):
            v.send('l2', TO, call)
        try:
            v.send('l2', TO, call)
            full = None
        except RuntimeError as e:
            full = str(e)
        check('the 17th unconfirmed send waits, it is not sent', full and 'unconfirmed' in full and count('pending') == 21, (full, count('pending')))
        rpc(url, 'evm_mine', [])
        check('after a block the window is open again', int(rpc(url, 'eth_getTransactionByHash', [v.send('l2', TO, call)])['nonce'], 16) == 21)
        rpc(url, 'evm_mine', [])

        # A dropped transaction leaves a gap: later nonces wait behind it for as long as nothing replaces it.
        first = v.send('l2', TO, call)
        second = v.send('l2', TO, call)
        n = int(rpc(url, 'eth_getTransactionByHash', [first])['nonce'], 16)
        rpc(url, 'anvil_dropTransaction', [first])
        rpc(url, 'evm_mine', [])
        check('a gap: nothing lands behind the dropped nonce', count() == n and rpc(url, 'eth_getTransactionReceipt', [second]) is None, count())
        third = v.send('l2', TO, call)
        check('before resend_after_s the record is kept', int(rpc(url, 'eth_getTransactionByHash', [third])['nonce'], 16) == n + 2)
        doc = json.loads(v.nonce_path.read_text())
        old_price = doc[f'l2:{FROM}']['prices'][str(n)]
        doc[f'l2:{FROM}']['moved'] -= 1801
        v.nonce_path.write_text(json.dumps(doc))
        fix = v.send('l2', TO, call)
        tx = rpc(url, 'eth_getTransactionByHash', [fix])
        check('after resend_after_s the gap is filled at the chain nonce', int(tx['nonce'], 16) == n)
        check('the replacement pays at least 25% more than the record', int(tx['gasPrice'], 16) >= old_price * 125 // 100, (tx['gasPrice'], old_price))
        # anvil_dropTransaction also removes `second`, so the filled nonce leaves one more gap, and `third` waits behind it.
        rpc(url, 'evm_mine', [])
        check('the filled nonce lands', count() == n + 1 and rpc(url, 'eth_getTransactionReceipt', [fix]) is not None, count())
        follow = v.send('l2', TO, call)
        check('the next send takes the next free nonce', int(rpc(url, 'eth_getTransactionByHash', [follow])['nonce'], 16) == n + 1)
        rpc(url, 'evm_mine', [])
        rpc(url, 'evm_mine', [])
        check('the gap closes and what waited behind it lands', count() == n + 3 and rpc(url, 'eth_getTransactionReceipt', [third]) is not None, count())

        # A replaced transaction: same nonce again after a record reset must bump over a transaction still in the pool.
        pool = v.send('l2', TO, call)
        n = int(rpc(url, 'eth_getTransactionByHash', [pool])['nonce'], 16)
        doc = json.loads(v.nonce_path.read_text())
        doc[f'l2:{FROM}']['moved'] -= 1801
        v.nonce_path.write_text(json.dumps(doc))
        replaced = v.send('l2', TO, call)
        check('a stuck transaction still in the pool is replaced, not refused as underpriced',
              int(rpc(url, 'eth_getTransactionByHash', [replaced])['nonce'], 16) == n and replaced != pool)
        rpc(url, 'evm_mine', [])

        def no_pending(u, method, params):
            if method == 'eth_getTransactionCount' and params[1] == 'pending':
                raise RuntimeError('no pending level')
            return real(u, method, params)
        v.rpc = no_pending
        a, b = v.send('l2', TO, call), v.send('l2', TO, call)
        na, nb = [int(rpc(url, 'eth_getTransactionByHash', [x])['nonce'], 16) for x in (a, b)]
        check('an endpoint with no `pending` level still gets consecutive nonces', nb == na + 1, (na, nb))
        v.rpc = real
        rpc(url, 'evm_mine', [])

        v.nonce_path.write_text('{not json')
        c = v.send('l2', TO, call)
        check('an unreadable record falls back to the chain', int(rpc(url, 'eth_getTransactionByHash', [c])['nonce'], 16) == count())
        rpc(url, 'evm_mine', [])
        doc = json.loads(v.nonce_path.read_text())
        doc[f'l2:{FROM}']['next'] = 10**9
        v.nonce_path.write_text(json.dumps(doc))
        d = v.send('l2', TO, call)
        check('a record far ahead of the chain is ignored', int(rpc(url, 'eth_getTransactionByHash', [d])['nonce'], 16) == count())
        rpc(url, 'evm_mine', [])
        v.send('eth', TO, call)
        rpc(url, 'evm_mine', [])
        check('sides keep separate records', set(json.loads(v.nonce_path.read_text())) == {f'l2:{FROM}', f'eth:{FROM}'})
        # A reorg drops a confirmed Ethereum transaction: the next send fills its nonce at once, and what the node lost is forgotten.
        rpc(url, 'anvil_mine', ['0x1'])
        before = count()
        lost = v.send('eth', TO, call)
        rpc(url, 'anvil_mine', ['0x1'])
        check('reorg: the transaction landed first', count() == before + 1)
        rpc(url, 'anvil_reorg', [1, []])
        check('reorg: the chain took it back', count() == before and rpc(url, 'eth_getTransactionReceipt', [lost]) is None, count())
        mark = work / 'sent'
        mark.write_text(lost + '\n')
        os.utime(mark, (time.time() - 1000, time.time() - 1000))
        check('reorg: a lost transaction is forgotten before resend_after_s', v.failed(url, mark) and not mark.exists())
        again = v.send('eth', TO, call)
        tx = rpc(url, 'eth_getTransactionByHash', [again])
        check('reorg: the next send fills the lost nonce', int(tx['nonce'], 16) == before, tx['nonce'])
        rpc(url, 'anvil_mine', ['0x1'])
        check('reorg: it lands', rpc(url, 'eth_getTransactionReceipt', [again]) is not None)
        queued = v.send('l2', TO, call)
        check('reorg: the L2 side is not rewound by it', rpc(url, 'eth_getTransactionByHash', [queued]) is not None)
        # A read before the token is visible says nothing about its version: it must not be kept for the life of the process.
        check('version: an empty address gives no version', v.token_version() is None, v.token_version())
    finally:
        anvil.terminate()
        shutil.rmtree(work, ignore_errors=True)
    print(f'{sum(results)}/{len(results)} passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
